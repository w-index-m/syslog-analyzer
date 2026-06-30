"""
SNMP Poller
ネットワーク機器に定期的にSNMP GETを送信してテレメトリデータを収集する
対象MIB: IF-MIB, ENTITY-MIB, HOST-RESOURCES-MIB, Cisco/Fujitsu固有MIB
"""
import threading
import time
import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "syslog.db"

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
                 "ciscoMemoryPoolUsed", "ciscoMemoryPoolFree"]:
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
