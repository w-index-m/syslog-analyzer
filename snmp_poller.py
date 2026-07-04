"""
SNMP Poller
ネットワーク機器に定期的にSNMP GETを送信してテレメトリデータを収集する
対象MIB: IF-MIB, ENTITY-MIB, HOST-RESOURCES-MIB, Cisco/Fujitsu固有MIB
"""
import os
import threading
import time
import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(os.environ.get("DB_PATH", str(Path(__file__).parent / "syslog.db")))

# ─────────────────────────────────────────
# 収集対象OID定義
# ─────────────────────────────────────────
POLL_OIDS = {
    # システム基本情報
    "sysDescr":      "1.3.6.1.2.1.1.1.0",
    "sysUpTime":     "1.3.6.1.2.1.1.3.0",
    "sysName":       "1.3.6.1.2.1.1.5.0",
    # CPU使用率 (Cisco)
    "cpmCPUTotal5min":  "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1",
    "cpmCPUTotal1min":  "1.3.6.1.4.1.9.9.109.1.1.1.1.7.1",
    # メモリ (Cisco)
    "ciscoMemoryPoolUsed": "1.3.6.1.4.1.9.9.48.1.1.1.5.1",
    "ciscoMemoryPoolFree": "1.3.6.1.4.1.9.9.48.1.1.1.6.1",
    # 環境モニター (Cisco)
    "ciscoEnvMonTemperatureStatusValue": "1.3.6.1.4.1.9.9.13.1.3.1.3.1",
    # インターフェース統計 (IF-MIB) - ifIndex=1のみサンプル
    "ifInOctets.1":   "1.3.6.1.2.1.2.2.1.10.1",
    "ifOutOctets.1":  "1.3.6.1.2.1.2.2.1.16.1",
    "ifInErrors.1":   "1.3.6.1.2.1.2.2.1.14.1",
    "ifOutErrors.1":  "1.3.6.1.2.1.2.2.1.20.1",
    "ifInDiscards.1": "1.3.6.1.2.1.2.2.1.13.1",
    # BGPピア数 (Cisco)
    "bgpPeerState":   "1.3.6.1.2.1.15.3.1.2",
    # ICMP統計 (ICMP-MIB) - 累積カウンタ、差分でスパイク検知
    "icmpInRedirects":  "1.3.6.1.2.1.5.6.0",
    "icmpOutRedirects": "1.3.6.1.2.1.5.13.0",
}

# 累積カウンタOID：前回値との差分でアラート判定
COUNTER_OIDS = {
    "icmpInRedirects":  {"warning": 10, "critical": 50, "unit": "redirects/poll", "label": "ICMP Redirect受信"},
    "icmpOutRedirects": {"warning": 10, "critical": 50, "unit": "redirects/poll", "label": "ICMP Redirect送信"},
}

# 閾値アラート設定
THRESHOLDS = {
    "cpmCPUTotal5min": {"warning": 70, "critical": 90, "unit": "%", "label": "CPU使用率(5分)"},
    "cpmCPUTotal1min": {"warning": 80, "critical": 95, "unit": "%", "label": "CPU使用率(1分)"},
    "ciscoEnvMonTemperatureStatusValue": {"warning": 60, "critical": 75, "unit": "℃", "label": "温度"},
    "ifInErrors.1":    {"warning": 10, "critical": 100, "unit": "errors", "label": "受信エラー"},
    "ifOutErrors.1":   {"warning": 10, "critical": 100, "unit": "errors", "label": "送信エラー"},
}


def _init_snmp_tables():
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS snmp_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                hostname TEXT,
                oid_name TEXT NOT NULL,
                oid TEXT NOT NULL,
                value TEXT,
                unit TEXT,
                alert_level TEXT DEFAULT 'none'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS snmp_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                hostname TEXT,
                community TEXT DEFAULT 'public',
                version TEXT DEFAULT 'v2c',
                port INTEGER DEFAULT 161,
                enabled INTEGER DEFAULT 1,
                interval_sec INTEGER DEFAULT 60,
                last_polled TEXT,
                last_status TEXT DEFAULT 'unknown'
            )
        """)
        # 監視対象インターフェース（SNMP Walk で選んだIFを登録）
        conn.execute("""
            CREATE TABLE IF NOT EXISTS snmp_monitored_ifs (
                ip TEXT NOT NULL,
                ifindex TEXT NOT NULL,
                ifname TEXT,
                last_in_oct TEXT,
                last_out_oct TEXT,
                last_ts TEXT,
                PRIMARY KEY (ip, ifindex)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_snmp_ip ON snmp_metrics(source_ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_snmp_time ON snmp_metrics(recorded_at DESC)")
        conn.commit()


def _run_async(coro):
    """同期コードからasyncioコルーチンを実行するヘルパー"""
    import asyncio
    try:
        loop = asyncio.get_running_loop()
        # 既にイベントループ内（通常Streamlitでは無い）の場合は新スレッドで実行
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    except RuntimeError:
        # イベントループが動いていない（通常ケース）
        return asyncio.run(coro)


async def _snmp_get_async(ip: str, community: str, oid: str, port: int, version: str) -> str | None:
    from pysnmp.hlapi.v3arch.asyncio import (
        get_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity
    )
    ver_map = {"v1": 0, "v2c": 1}
    mp_model = ver_map.get(version, 1)
    target = await UdpTransportTarget.create((ip, port), timeout=3, retries=1)
    error_indication, error_status, error_index, var_binds = await get_cmd(
        SnmpEngine(),
        CommunityData(community, mpModel=mp_model),
        target,
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    if error_indication or error_status:
        return None
    for _, val in var_binds:
        return str(val)
    return None


def snmp_get(ip: str, community: str, oid: str, port: int = 161,
             version: str = "v2c") -> str | None:
    """
    単一OIDのSNMP GETを実行して値を返す（同期ラッパー）
    pysnmp 7.x系の非同期API (hlapi.v3arch.asyncio) に対応。
    """
    try:
        return _run_async(_snmp_get_async(ip, community, oid, port, version))
    except Exception as e:
        print(f"[SNMP GET] {ip} {oid}: {e}")
        return None


def poll_device(ip: str, community: str = "public",
                version: str = "v2c", port: int = 161) -> dict:
    """
    1台の機器からSNMPメトリクスを収集してDBに保存、結果dictを返す
    """
    _init_snmp_tables()
    results = {}
    hostname = None
    recorded_at = datetime.now().isoformat()

    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        for oid_name, oid in POLL_OIDS.items():
            value = snmp_get(ip, community, oid, port, version)
            if value is None:
                continue

            results[oid_name] = value

            # ホスト名取得
            if oid_name == "sysName":
                hostname = value

            # 閾値判定
            alert_level = "none"
            unit = ""
            if oid_name in THRESHOLDS:
                th = THRESHOLDS[oid_name]
                unit = th.get("unit", "")
                try:
                    v = float(value)
                    if v >= th["critical"]:
                        alert_level = "critical"
                    elif v >= th["warning"]:
                        alert_level = "warning"
                except ValueError:
                    pass
            elif oid_name in COUNTER_OIDS:
                # 累積カウンタ：前回値との差分でスパイク検知
                th = COUNTER_OIDS[oid_name]
                unit = th["unit"]
                prev_row = conn.execute("""
                    SELECT value FROM snmp_metrics
                    WHERE source_ip=? AND oid_name=?
                    ORDER BY recorded_at DESC LIMIT 1
                """, (ip, oid_name)).fetchone()
                if prev_row:
                    try:
                        diff = max(0, int(value) - int(prev_row[0]))
                        if diff >= th["critical"]:
                            alert_level = "critical"
                        elif diff >= th["warning"]:
                            alert_level = "warning"
                    except (ValueError, TypeError):
                        pass

            conn.execute("""
                INSERT INTO snmp_metrics
                (recorded_at, source_ip, hostname, oid_name, oid, value, unit, alert_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (recorded_at, ip, hostname or ip, oid_name, oid, value, unit, alert_level))

        # デバイステーブルを更新
        conn.execute("""
            INSERT INTO snmp_devices (ip, hostname, community, version, port, last_polled, last_status)
            VALUES (?, ?, ?, ?, ?, ?, 'ok')
            ON CONFLICT(ip) DO UPDATE SET
                hostname=excluded.hostname,
                last_polled=excluded.last_polled,
                last_status='ok'
        """, (ip, hostname or ip, community, version, port, recorded_at))
        conn.commit()

    return {"ip": ip, "hostname": hostname, "metrics": results, "recorded_at": recorded_at}


async def _snmp_walk_async(ip: str, community: str, oid: str, port: int,
                           version: str, max_rows: int) -> dict:
    from pysnmp.hlapi.v3arch.asyncio import (
        next_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity
    )
    ver_map = {"v1": 0, "v2c": 1}
    mp_model = ver_map.get(version, 1)
    result = {}
    target = await UdpTransportTarget.create((ip, port), timeout=3, retries=1)
    engine = SnmpEngine()
    auth = CommunityData(community, mpModel=mp_model)
    ctx = ContextData()

    base_oid = ObjectIdentity(oid)
    current_var_binds = [ObjectType(base_oid)]
    rows = 0

    while rows < max_rows:
        error_indication, error_status, error_index, var_bind_table = await next_cmd(
            engine, auth, target, ctx, *current_var_binds
        )
        if error_indication:
            break
        if error_status:
            break
        if not var_bind_table:
            break

        new_var_binds = []
        stop = False
        for var_bind in var_bind_table:
            o, v = var_bind
            o_str = str(o)
            # ベースOID配下から外れたら終了（WALK終端）
            if not o_str.startswith(str(base_oid)):
                stop = True
                break
            if v is None or str(v) in ("No more variables left in this MIB View",):
                stop = True
                break
            if_index = o_str.split(".")[-1]
            result[if_index] = str(v)
            new_var_binds.append(ObjectType(o))
        if stop or not new_var_binds:
            break
        current_var_binds = new_var_binds
        rows += 1

    return result


def snmp_walk(ip: str, community: str, oid: str, port: int = 161,
              version: str = "v2c", max_rows: int = 50) -> dict:
    """
    SNMP WALK でテーブルOIDを取得（同期ラッパー）。戻り値: {if_index: value}
    pysnmp 7.x系の非同期API (hlapi.v3arch.asyncio next_cmd) に対応。
    """
    try:
        return _run_async(_snmp_walk_async(ip, community, oid, port, version, max_rows))
    except Exception as e:
        print(f"[SNMP WALK] {ip} {oid}: {e}")
        return {}


def poll_device_health(ip: str, community: str = "public",
                        version: str = "v2c", port: int = 161,
                        llm_mode: str = "none") -> dict:
    """
    機器の健全性に必要なメトリクスを総合収集し、ヘルススコアを算出する。
    インターフェースカウンタはWALKで全IF取得→差分でスループット計算。
    """
    import health_engine as he
    he._init_health_tables()

    # システムメトリクス（スカラOID）をGET
    snmp_metrics = {}
    for name in ["cpmCPUTotal5min", "cpmCPUTotal1min", "cpmCPUTotal5sec",
                 "ciscoMemoryPoolUsed", "ciscoMemoryPoolFree",
                 "ciscoEnvMonTemperatureStatusValue"]:
        oid = he.EXTENDED_OIDS.get(name)
        if oid:
            val = snmp_get(ip, community, oid, port, version)
            if val is not None:
                snmp_metrics[name] = val

    hostname = snmp_get(ip, community, "1.3.6.1.2.1.1.5.0", port, version) or ip

    # インターフェーステーブルをWALK
    def walk(name):
        oid = he.EXTENDED_OIDS.get(name)
        return snmp_walk(ip, community, oid, port, version) if oid else {}

    # 64bit優先、なければ32bit
    in_oct = walk("ifHCInOctets") or walk("ifInOctets")
    out_oct = walk("ifHCOutOctets") or walk("ifOutOctets")
    oper = walk("ifOperStatus")
    in_err = walk("ifInErrors")
    out_err = walk("ifOutErrors")
    in_disc = walk("ifInDiscards")
    out_disc = walk("ifOutDiscards")
    in_bcast = walk("ifInBroadcastPkts")
    out_bcast = walk("ifOutBroadcastPkts")
    in_ucast = walk("ifInUcastPkts")
    speed_mbps = walk("ifHighSpeed")
    speed_bps_raw = walk("ifSpeed")

    oper_map = {"1": "up", "2": "down", "3": "testing"}

    # 各IFのカウンタを保存
    active_ifs = [k for k, v in oper.items() if v in ("1", "up")]
    if not active_ifs:
        active_ifs = list(in_oct.keys())[:20]

    for ifidx in active_ifs:
        # リンク速度(bps)を決定
        sp_bps = None
        if ifidx in speed_mbps and he._to_int(speed_mbps[ifidx]):
            sp_bps = he._to_int(speed_mbps[ifidx]) * 1_000_000
        elif ifidx in speed_bps_raw:
            sp_bps = he._to_int(speed_bps_raw[ifidx])

        counters = {
            "in_octets": he._to_int(in_oct.get(ifidx)),
            "out_octets": he._to_int(out_oct.get(ifidx)),
            "in_errors": he._to_int(in_err.get(ifidx)),
            "out_errors": he._to_int(out_err.get(ifidx)),
            "in_discards": he._to_int(in_disc.get(ifidx)),
            "out_discards": he._to_int(out_disc.get(ifidx)),
            "in_broadcast": he._to_int(in_bcast.get(ifidx)),
            "out_broadcast": he._to_int(out_bcast.get(ifidx)),
            "in_ucast": he._to_int(in_ucast.get(ifidx)),
            "if_speed_bps": sp_bps,
            "oper_status": oper_map.get(oper.get(ifidx, ""), oper.get(ifidx, "")),
        }
        he.save_interface_counters(ip, ifidx, counters)

    # スループット計算（差分。2回目以降のポーリングで値が出る）
    throughput_list = []
    for ifidx in active_ifs:
        tp = he.calculate_throughput(ip, ifidx)
        if tp:
            throughput_list.append(tp)

    # ヘルススコア算出
    health = he.evaluate_device_health(ip, hostname, snmp_metrics, throughput_list)

    # LLM診断（オプション）
    if llm_mode != "none":
        import analyzer
        import db as _db
        recent_logs = _db.get_logs(limit=10, source_ip=ip)
        cfg = _db.get_device_config(ip)
        config_ctx = ""
        if cfg:
            config_ctx = (cfg.get("interfaces_summary","") + "\n" + cfg.get("routing_summary",""))
        diagnosis = analyzer.diagnose_health(health, recent_logs, llm_mode, config_ctx)
        health["llm_diagnosis"] = diagnosis

    return health




def get_latest_metrics(ip: str = None, limit: int = 100) -> list[dict]:
    """最新のSNMPメトリクスを取得"""
    _init_snmp_tables()
    query = "SELECT * FROM snmp_metrics"
    params = []
    if ip:
        query += " WHERE source_ip=?"
        params.append(ip)
    query += " ORDER BY recorded_at DESC LIMIT ?"
    params.append(limit)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(query, params).fetchall()]


def get_devices() -> list[dict]:
    """登録デバイス一覧を取得"""
    _init_snmp_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("SELECT * FROM snmp_devices").fetchall()]


def add_device(ip: str, community: str = "public", version: str = "v2c",
               port: int = 161, interval_sec: int = 60):
    """ポーリング対象デバイスを登録"""
    _init_snmp_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO snmp_devices (ip, community, version, port, interval_sec, enabled)
            VALUES (?, ?, ?, ?, ?, 1)
            ON CONFLICT(ip) DO UPDATE SET
                community=excluded.community, version=excluded.version,
                port=excluded.port, interval_sec=excluded.interval_sec
        """, (ip, community, version, port, interval_sec))
        conn.commit()


def remove_device(ip: str):
    _init_snmp_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM snmp_devices WHERE ip=?", (ip,))
        conn.commit()


# 探索(ディスカバリ)用OID
_DISCOVER_OIDS = {
    "sysDescr":  "1.3.6.1.2.1.1.1.0",
    "sysName":   "1.3.6.1.2.1.1.5.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
}
_IF_DESCR_OID  = "1.3.6.1.2.1.2.2.1.2"       # ifDescr
_IF_NAME_OID   = "1.3.6.1.2.1.31.1.1.1.1"    # ifName
_IF_OPER_OID   = "1.3.6.1.2.1.2.2.1.8"       # ifOperStatus (1=up,2=down)
_IF_ALIAS_OID  = "1.3.6.1.2.1.31.1.1.1.18"   # ifAlias


# 監視対象IF収集用OID（インデックスを付けてGET）
_OID_IF_HC_IN   = "1.3.6.1.2.1.31.1.1.1.6"    # ifHCInOctets
_OID_IF_HC_OUT  = "1.3.6.1.2.1.31.1.1.1.10"   # ifHCOutOctets
_OID_IF_INOCT   = "1.3.6.1.2.1.2.2.1.10"      # ifInOctets(32bit fallback)
_OID_IF_OUTOCT  = "1.3.6.1.2.1.2.2.1.16"
_OID_IF_HISPEED = "1.3.6.1.2.1.31.1.1.1.15"   # ifHighSpeed(Mbps)
_OID_IF_OPER2   = "1.3.6.1.2.1.2.2.1.8"       # ifOperStatus
_OID_IF_INERR2  = "1.3.6.1.2.1.2.2.1.14"      # ifInErrors


def set_monitored_interfaces(ip: str, interfaces: list):
    """
    監視対象インターフェースを登録する。
    interfaces: [{"index": str, "name": str}, ...]（既存はこのIP分を置換）
    """
    _init_snmp_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM snmp_monitored_ifs WHERE ip=?", (ip,))
        for itf in interfaces:
            conn.execute(
                "INSERT OR REPLACE INTO snmp_monitored_ifs (ip, ifindex, ifname) VALUES (?,?,?)",
                (ip, str(itf.get("index")), itf.get("name", "")))
        conn.commit()


def get_monitored_interfaces(ip: str = None) -> list:
    _init_snmp_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if ip:
            rows = conn.execute("SELECT * FROM snmp_monitored_ifs WHERE ip=?", (ip,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM snmp_monitored_ifs").fetchall()
        return [dict(r) for r in rows]


def poll_monitored_interfaces(ip: str, community: str = "public",
                              version: str = "v2c", port: int = 161,
                              hostname: str = None):
    """
    登録済みの監視対象IFについて、送受信オクテットをGETし、
    前回値との差分から bps・帯域使用率を算出して snmp_metrics に保存する。
    （Walkで選んだIFをそのまま自動ポーリングする＝手動OID入力不要）
    """
    ifs = get_monitored_interfaces(ip)
    if not ifs:
        return
    now = datetime.now()
    now_iso = now.isoformat()
    host = hostname or snmp_get(ip, community, "1.3.6.1.2.1.1.5.0", port, version) or ip
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        for mif in ifs:
            idx = mif["ifindex"]
            name = mif.get("ifname") or f"if{idx}"
            in_oct  = snmp_get(ip, community, f"{_OID_IF_HC_IN}.{idx}", port, version) \
                      or snmp_get(ip, community, f"{_OID_IF_INOCT}.{idx}", port, version)
            out_oct = snmp_get(ip, community, f"{_OID_IF_HC_OUT}.{idx}", port, version) \
                      or snmp_get(ip, community, f"{_OID_IF_OUTOCT}.{idx}", port, version)
            oper = snmp_get(ip, community, f"{_OID_IF_OPER2}.{idx}", port, version)
            hispeed = snmp_get(ip, community, f"{_OID_IF_HISPEED}.{idx}", port, version)  # Mbps
            inerr = snmp_get(ip, community, f"{_OID_IF_INERR2}.{idx}", port, version)

            # 状態メトリクス
            status = "up" if str(oper).strip() == "1" else ("down" if str(oper).strip() == "2" else "?")
            _lbl = f"{name}"
            def _save(oid_name, value, unit, alert="none"):
                conn.execute("""INSERT INTO snmp_metrics
                    (recorded_at, source_ip, hostname, oid_name, oid, value, unit, alert_level)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    (now_iso, ip, f"{host} {name}", oid_name, f"if{idx}", value, unit, alert))

            # 差分から bps を計算
            prev = conn.execute(
                "SELECT last_in_oct, last_out_oct, last_ts FROM snmp_monitored_ifs WHERE ip=? AND ifindex=?",
                (ip, idx)).fetchone()
            in_bps = out_bps = util = None
            if prev and prev[2] and in_oct is not None and out_oct is not None:
                try:
                    dt = (now - datetime.fromisoformat(prev[2])).total_seconds()
                    if dt > 0:
                        din = (int(in_oct) - int(prev[0])) if prev[0] is not None else 0
                        dout = (int(out_oct) - int(prev[1])) if prev[1] is not None else 0
                        if din >= 0:
                            in_bps = round(din * 8 / dt)
                        if dout >= 0:
                            out_bps = round(dout * 8 / dt)
                        speed_bps = (int(hispeed) * 1_000_000) if hispeed else 0
                        if speed_bps > 0 and in_bps is not None and out_bps is not None:
                            util = round(max(in_bps, out_bps) / speed_bps * 100, 1)
                except (ValueError, TypeError):
                    pass

            # メトリクス保存（グラフ/ゲージ用）
            if in_bps is not None:
                _save(f"if{idx}_in_bps", in_bps, "bps")
            if out_bps is not None:
                _save(f"if{idx}_out_bps", out_bps, "bps")
            if util is not None:
                alert = "critical" if util >= 90 else ("warning" if util >= 70 else "none")
                _save(f"if{idx}_util", util, "%", alert)
            if inerr is not None:
                _save(f"if{idx}_inerrors", inerr, "errors")
            _save(f"if{idx}_status", status, "", "critical" if status == "down" else "none")

            # 次回差分用に今回値を保存
            conn.execute("UPDATE snmp_monitored_ifs SET last_in_oct=?, last_out_oct=?, last_ts=? WHERE ip=? AND ifindex=?",
                         (str(in_oct) if in_oct is not None else None,
                          str(out_oct) if out_oct is not None else None,
                          now_iso, ip, idx))
        conn.commit()


def discover_device(ip: str, community: str = "public",
                    version: str = "v2c", port: int = 161) -> dict:
    """
    SNMP Walk による機器探索（ディスカバリ）。
    システム情報を GET し、インターフェース一覧を WALK で取得する。
    戻り値: {"reachable": bool, "system": {...}, "interfaces": [{index,name,descr,status}], "error": str}
    """
    result = {"reachable": False, "system": {}, "interfaces": [], "error": ""}
    # システム情報 GET
    for name, oid in _DISCOVER_OIDS.items():
        v = snmp_get(ip, community, oid, port, version)
        if v is not None:
            result["system"][name] = v
            result["reachable"] = True
    if not result["reachable"]:
        result["error"] = "SNMP応答なし（IP/コミュニティ/バージョン/ポート/到達性を確認してください）"
        return result
    # インターフェース一覧 WALK（名前・説明・状態）
    names  = snmp_walk(ip, community, _IF_NAME_OID, port, version, max_rows=200)
    descrs = snmp_walk(ip, community, _IF_DESCR_OID, port, version, max_rows=200)
    opers  = snmp_walk(ip, community, _IF_OPER_OID, port, version, max_rows=200)
    idxs = sorted(set(list(names.keys()) + list(descrs.keys())),
                  key=lambda x: int(x) if str(x).isdigit() else 0)
    for idx in idxs:
        st = str(opers.get(idx, "")).strip()
        status = "up" if st == "1" else ("down" if st == "2" else st or "?")
        result["interfaces"].append({
            "index": idx,
            "name": names.get(idx) or descrs.get(idx) or f"if{idx}",
            "descr": descrs.get(idx, ""),
            "status": status,
        })
    return result


def get_alert_metrics() -> list[dict]:
    """閾値超過中のメトリクスを返す"""
    _init_snmp_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("""
            SELECT * FROM snmp_metrics
            WHERE alert_level != 'none'
            AND recorded_at >= datetime('now', '-10 minutes')
            ORDER BY recorded_at DESC
        """).fetchall()]


def get_icmp_redirect_latest() -> list[dict]:
    """各デバイスの最新ICMP redirect累積カウンタと前回差分を返す"""
    _init_snmp_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT m.source_ip, m.oid_name, m.value, m.alert_level, m.recorded_at
            FROM snmp_metrics m
            INNER JOIN (
                SELECT source_ip, oid_name, MAX(recorded_at) AS max_ts
                FROM snmp_metrics
                WHERE oid_name IN ('icmpInRedirects','icmpOutRedirects')
                GROUP BY source_ip, oid_name
            ) latest
            ON m.source_ip=latest.source_ip
            AND m.oid_name=latest.oid_name
            AND m.recorded_at=latest.max_ts
            ORDER BY m.source_ip, m.oid_name
        """).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            # 前回値を取得して差分計算
            prev = conn.execute("""
                SELECT value FROM snmp_metrics
                WHERE source_ip=? AND oid_name=?
                ORDER BY recorded_at DESC LIMIT 1 OFFSET 1
            """, (d["source_ip"], d["oid_name"])).fetchone()
            if prev:
                try:
                    d["diff"] = max(0, int(d["value"]) - int(prev[0]))
                except (ValueError, TypeError):
                    d["diff"] = None
            else:
                d["diff"] = None
            result.append(d)
        return result


def get_icmp_redirect_trend(ip: str, hours: int = 1) -> list[dict]:
    """指定デバイスのICMP redirect時系列データを返す"""
    _init_snmp_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("""
            SELECT recorded_at, oid_name, value, alert_level
            FROM snmp_metrics
            WHERE source_ip=?
            AND oid_name IN ('icmpInRedirects','icmpOutRedirects')
            AND recorded_at >= datetime('now', ? || ' hours')
            ORDER BY recorded_at ASC
        """, (ip, f"-{hours}")).fetchall()]


def get_metric_trend(ip: str, oid_name: str, hours: int = 1) -> list[dict]:
    """特定メトリクスの時系列データを取得"""
    _init_snmp_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("""
            SELECT recorded_at, value, alert_level FROM snmp_metrics
            WHERE source_ip=? AND oid_name=?
            AND recorded_at >= datetime('now', ? || ' hours')
            ORDER BY recorded_at ASC
        """, (ip, oid_name, f"-{hours}")).fetchall()]


# ─────────────────────────────────────────
# ルーティングテーブル取得（ipRouteTable Walk）
# ─────────────────────────────────────────

# ipRouteTable (RFC1213-MIB) OID
_ROUTE_OIDS = {
    "dest":    "1.3.6.1.2.1.4.21.1.1",   # ipRouteDest
    "mask":    "1.3.6.1.2.1.4.21.1.11",  # ipRouteMask
    "nexthop": "1.3.6.1.2.1.4.21.1.7",   # ipRouteNextHop
    "type":    "1.3.6.1.2.1.4.21.1.8",   # ipRouteType (3=local, 4=remote)
    "proto":   "1.3.6.1.2.1.4.21.1.9",   # ipRouteProto (1=other,2=local,3=netmgmt,9=ospf,13=bgp...)
}
_ROUTE_TYPE_MAP  = {"1": "other", "2": "reject", "3": "local",  "4": "remote"}
_ROUTE_PROTO_MAP = {"1": "other", "2": "local",  "3": "static", "9": "ospf",
                    "10": "isis", "13": "bgp",   "14": "eigrp"}


def _init_routing_table():
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS snmp_routing_table (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                fetched_at TEXT NOT NULL,
                source_ip  TEXT NOT NULL,
                dest       TEXT NOT NULL,
                mask       TEXT NOT NULL,
                nexthop    TEXT NOT NULL,
                route_type TEXT,
                proto      TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rt_ip ON snmp_routing_table(source_ip)")
        conn.commit()


async def _snmp_walk_route_async(ip: str, community: str, base_oid: str,
                                  port: int, version: str, max_rows: int = 300) -> dict:
    """ipRouteTable系OIDをWALKし {インデックス(=宛先IP): 値} を返す。
    インデックスはベースOID以降の数値サフィックス（例: "10.0.0.0"）。"""
    from pysnmp.hlapi.v3arch.asyncio import (
        next_cmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity
    )
    ver_map = {"v1": 0, "v2c": 1}
    mp_model = ver_map.get(version, 1)
    result = {}
    target = await UdpTransportTarget.create((ip, port), timeout=5, retries=1)
    engine = SnmpEngine()
    auth = CommunityData(community, mpModel=mp_model)
    ctx = ContextData()

    current_var_binds = [ObjectType(ObjectIdentity(base_oid))]
    rows = 0

    while rows < max_rows:
        err_ind, err_st, _, var_bind_table = await next_cmd(
            engine, auth, target, ctx, *current_var_binds
        )
        if err_ind or err_st or not var_bind_table:
            break

        new_var_binds = []
        stop = False
        for var_bind in var_bind_table:
            o, v = var_bind
            # 数値OID文字列に変換（名前解決に依存しない）
            numeric = ".".join(str(x) for x in o.asTuple())
            if not numeric.startswith(base_oid + "."):
                stop = True
                break
            val_str = str(v)
            if val_str in ("No more variables left in this MIB View", ""):
                stop = True
                break
            # ベースOID以降のサフィックスをキーにする
            suffix = numeric[len(base_oid) + 1:]
            result[suffix] = val_str
            new_var_binds.append(ObjectType(o))
        if stop or not new_var_binds:
            break
        current_var_binds = new_var_binds
        rows += 1

    return result


def fetch_routing_table(ip: str, community: str = "public",
                        version: str = "v2c", port: int = 161) -> list[dict]:
    """SNMPウォークでルーティングテーブルを取得してDBに保存し、ルート一覧を返す。"""
    _init_routing_table()

    walked = {}
    for key, oid in _ROUTE_OIDS.items():
        try:
            walked[key] = _run_async(
                _snmp_walk_route_async(ip, community, oid, port, version)
            )
        except Exception as e:
            print(f"[RoutingTable WALK] {ip} {key}: {e}")
            walked[key] = {}

    # インデックス（宛先IP）でマージ
    fetched_at = datetime.now().isoformat()
    routes = []
    for idx in walked.get("dest", {}):
        dest    = walked["dest"].get(idx, "")
        mask    = walked["mask"].get(idx, "")
        nexthop = walked["nexthop"].get(idx, "")
        rtype   = _ROUTE_TYPE_MAP.get(walked["type"].get(idx, ""), "")
        proto   = _ROUTE_PROTO_MAP.get(walked["proto"].get(idx, ""), "")
        if dest:
            routes.append({"dest": dest, "mask": mask, "nexthop": nexthop,
                           "type": rtype, "proto": proto})

    # DBに保存（旧データを削除して置き換え）
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("DELETE FROM snmp_routing_table WHERE source_ip=?", (ip,))
        for r in routes:
            conn.execute("""
                INSERT INTO snmp_routing_table
                (fetched_at, source_ip, dest, mask, nexthop, route_type, proto)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (fetched_at, ip, r["dest"], r["mask"], r["nexthop"], r["type"], r["proto"]))
        conn.commit()

    return routes


def get_routing_table(ip: str) -> list[dict]:
    """DBに保存済みのルーティングテーブルを返す。"""
    _init_routing_table()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("""
            SELECT dest, mask, nexthop, route_type, proto, fetched_at
            FROM snmp_routing_table WHERE source_ip=?
            ORDER BY dest
        """, (ip,)).fetchall()]


def route_lookup(ip: str, dest_ip: str) -> dict | None:
    """宛先IPがルーティングテーブルに存在するか最長一致で探す。"""
    import ipaddress
    routes = get_routing_table(ip)
    best = None
    best_plen = -1
    for r in routes:
        try:
            net = ipaddress.ip_network(f"{r['dest']}/{r['mask']}", strict=False)
            if ipaddress.ip_address(dest_ip) in net:
                plen = net.prefixlen
                if plen > best_plen:
                    best = r
                    best_plen = plen
        except Exception:
            continue
    return best


# ─────────────────────────────────────────
# バックグラウンドポーリングスレッド
# ─────────────────────────────────────────
_poller_thread = None
_poller_running = False

def _poller_loop():
    global _poller_running
    _init_snmp_tables()
    while _poller_running:
        devices = get_devices()
        for dev in devices:
            if not dev.get("enabled"):
                continue
            try:
                poll_device(
                    ip=dev["ip"],
                    community=dev.get("community", "public"),
                    version=dev.get("version", "v2c"),
                    port=dev.get("port", 161)
                )
                # 健全性チェック（スループット差分・破棄・ブロードキャスト等）も実行
                poll_device_health(
                    ip=dev["ip"],
                    community=dev.get("community", "public"),
                    version=dev.get("version", "v2c"),
                    port=dev.get("port", 161),
                    llm_mode="none"  # バックグラウンドではLLMは呼ばない
                )
                # 監視対象IF（Walkで選んだIF）のトラフィック/使用率を収集
                poll_monitored_interfaces(
                    ip=dev["ip"],
                    community=dev.get("community", "public"),
                    version=dev.get("version", "v2c"),
                    port=dev.get("port", 161),
                    hostname=dev.get("hostname"),
                )
                # ICMP Redirect → EPC 自動トリガー確認
                _check_epc_trigger(dev["ip"])
            except Exception as e:
                print(f"[Poller] {dev['ip']}: {e}")
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute(
                        "UPDATE snmp_devices SET last_status=? WHERE ip=?",
                        (f"error: {e}", dev["ip"])
                    )
                    conn.commit()
        # 最短インターバル分だけ待機
        intervals = [d.get("interval_sec", 60) for d in devices] if devices else [60]
        time.sleep(min(intervals) if intervals else 60)

def _check_epc_trigger(ip: str):
    """直近の ICMP Redirect 差分を見て、閾値超過なら EPC 自動起動を依頼"""
    try:
        import restconf_client as rc
        rows = get_icmp_redirect_latest()
        for row in rows:
            if row.get("source_ip") != ip:
                continue
            if row.get("oid_name") != "icmpOutRedirects":
                continue
            diff = row.get("diff")
            if diff is not None:
                rc.check_and_trigger_epc(ip, int(diff))
    except Exception as e:
        print(f"[EPC Trigger check] {ip}: {e}")


def start_poller():
    global _poller_thread, _poller_running
    if _poller_running:
        return
    _poller_running = True
    _poller_thread = threading.Thread(target=_poller_loop, daemon=True)
    _poller_thread.start()
    print("[SNMPPoller] Background poller started")

def stop_poller():
    global _poller_running
    _poller_running = False
