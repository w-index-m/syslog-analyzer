"""
ネットワーク健全性チェックエンジン
SNMPメトリクスから機器ごとのヘルススコアを算出し、
スループット・破棄・ブロードキャスト・CPU相関などを評価する。
"""
import os
import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(os.environ.get("DB_PATH", str(Path(__file__).parent / "syslog.db")))

# ─────────────────────────────────────────
# 拡張SNMP収集対象OID（スループット・Cisco輻輳系）
# ─────────────────────────────────────────
EXTENDED_OIDS = {
    # 64bit版カウンタ（高速回線向け、ifHC = High Capacity）
    "ifHCInOctets":      "1.3.6.1.2.1.31.1.1.1.6",   # 64bit 受信バイト
    "ifHCOutOctets":     "1.3.6.1.2.1.31.1.1.1.10",  # 64bit 送信バイト
    "ifHighSpeed":       "1.3.6.1.2.1.31.1.1.1.15",  # Mbps単位のリンク速度
    # 32bit版（フォールバック）
    "ifInOctets":        "1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets":       "1.3.6.1.2.1.2.2.1.16",
    "ifSpeed":           "1.3.6.1.2.1.2.2.1.5",      # bps単位のリンク速度
    "ifOperStatus":      "1.3.6.1.2.1.2.2.1.8",
    # エラー・破棄
    "ifInErrors":        "1.3.6.1.2.1.2.2.1.14",
    "ifOutErrors":       "1.3.6.1.2.1.2.2.1.20",
    "ifInDiscards":      "1.3.6.1.2.1.2.2.1.13",
    "ifOutDiscards":     "1.3.6.1.2.1.2.2.1.19",
    # ブロードキャスト・マルチキャスト（ifXTable）
    "ifInBroadcastPkts":  "1.3.6.1.2.1.31.1.1.1.3",
    "ifOutBroadcastPkts": "1.3.6.1.2.1.31.1.1.1.5",
    "ifInMulticastPkts":  "1.3.6.1.2.1.31.1.1.1.2",
    "ifInUcastPkts":      "1.3.6.1.2.1.2.2.1.11",
    # Cisco CPU（複数の時間窓）
    "cpmCPUTotal5sec":   "1.3.6.1.4.1.9.9.109.1.1.1.1.6.1",
    "cpmCPUTotal1min":   "1.3.6.1.4.1.9.9.109.1.1.1.1.7.1",
    "cpmCPUTotal5min":   "1.3.6.1.4.1.9.9.109.1.1.1.1.8.1",
    # Cisco メモリ
    "ciscoMemoryPoolUsed": "1.3.6.1.4.1.9.9.48.1.1.1.5.1",
    "ciscoMemoryPoolFree": "1.3.6.1.4.1.9.9.48.1.1.1.6.1",
    # Cisco 環境モニター（温度）
    "ciscoEnvMonTemperatureStatusValue": "1.3.6.1.4.1.9.9.13.1.3.1.3.1",
    # Cisco バッファ・インターフェースリセット
    "locIfResets":       "1.3.6.1.4.1.9.2.2.1.1.17.1",
}

# ─────────────────────────────────────────
# 健全性しきい値（Cisco経験則ベース）
# ─────────────────────────────────────────
HEALTH_THRESHOLDS = {
    "cpu_5min":        {"warning": 60, "critical": 80, "unit": "%"},
    "cpu_1min":        {"warning": 70, "critical": 90, "unit": "%"},
    "memory_used_pct": {"warning": 75, "critical": 90, "unit": "%"},
    "bandwidth_util":  {"warning": 70, "critical": 90, "unit": "%"},
    "broadcast_pct":   {"warning": 5,  "critical": 20, "unit": "%"},
    "discard_pct":     {"warning": 0.1, "critical": 1.0, "unit": "%"},
    "error_pct":       {"warning": 0.01, "critical": 0.1, "unit": "%"},
    # スループットが期待値を下回る場合（健全性低下）
    "throughput_low_pct": {"warning": 30, "critical": 10, "unit": "%"},
    "temperature_celsius": {"warning": 60, "critical": 75, "unit": "℃"},
}


def _init_health_tables():
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS interface_counters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                if_index TEXT NOT NULL,
                in_octets INTEGER,
                out_octets INTEGER,
                in_errors INTEGER,
                out_errors INTEGER,
                in_discards INTEGER,
                out_discards INTEGER,
                in_broadcast INTEGER,
                out_broadcast INTEGER,
                in_ucast INTEGER,
                if_speed_bps INTEGER,
                oper_status TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS health_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                hostname TEXT,
                health_score INTEGER,
                status TEXT,
                metrics_json TEXT,
                issues_json TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS interface_expectations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                if_index TEXT NOT NULL,
                if_name TEXT,
                expected_mbps REAL,
                link_mbps REAL,
                UNIQUE(source_ip, if_index)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ifcounter ON interface_counters(source_ip, if_index, recorded_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_health ON health_scores(source_ip, recorded_at DESC)")
        conn.commit()


def _to_int(val) -> int | None:
    try:
        return int(float(str(val)))
    except (ValueError, TypeError):
        return None


def save_interface_counters(source_ip: str, if_index: str, counters: dict):
    """1インターフェース分のカウンタを保存"""
    _init_health_tables()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            INSERT INTO interface_counters
            (recorded_at, source_ip, if_index, in_octets, out_octets,
             in_errors, out_errors, in_discards, out_discards,
             in_broadcast, out_broadcast, in_ucast, if_speed_bps, oper_status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            datetime.now().isoformat(), source_ip, if_index,
            counters.get("in_octets"), counters.get("out_octets"),
            counters.get("in_errors"), counters.get("out_errors"),
            counters.get("in_discards"), counters.get("out_discards"),
            counters.get("in_broadcast"), counters.get("out_broadcast"),
            counters.get("in_ucast"), counters.get("if_speed_bps"),
            counters.get("oper_status")
        ))
        conn.commit()


def calculate_throughput(source_ip: str, if_index: str) -> dict | None:
    """
    直近2回のカウンタ値から差分でスループットを計算する。
    戻り値: { in_bps, out_bps, bandwidth_util_pct, error_pct, discard_pct, broadcast_pct ... }
    """
    _init_health_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT * FROM interface_counters
            WHERE source_ip=? AND if_index=?
            ORDER BY recorded_at DESC LIMIT 2
        """, (source_ip, if_index)).fetchall()

    if len(rows) < 2:
        return None  # 差分計算には最低2サンプル必要

    curr, prev = dict(rows[0]), dict(rows[1])

    t_curr = datetime.fromisoformat(curr["recorded_at"])
    t_prev = datetime.fromisoformat(prev["recorded_at"])
    elapsed = (t_curr - t_prev).total_seconds()
    if elapsed <= 0:
        return None

    def diff(field):
        c, p = curr.get(field), prev.get(field)
        if c is None or p is None:
            return None
        d = c - p
        # カウンタラップ（桁あふれ）した場合は無視
        return d if d >= 0 else None

    in_octets_d = diff("in_octets")
    out_octets_d = diff("out_octets")

    result = {
        "if_index": if_index,
        "elapsed_sec": round(elapsed, 1),
        "oper_status": curr.get("oper_status"),
        "if_speed_bps": curr.get("if_speed_bps"),
    }

    # スループット (bps)
    in_bps = (in_octets_d * 8 / elapsed) if in_octets_d is not None else None
    out_bps = (out_octets_d * 8 / elapsed) if out_octets_d is not None else None
    result["in_bps"] = round(in_bps) if in_bps is not None else None
    result["out_bps"] = round(out_bps) if out_bps is not None else None

    # 帯域使用率
    speed = curr.get("if_speed_bps")
    if speed and speed > 0:
        max_bps = max(in_bps or 0, out_bps or 0)
        result["bandwidth_util_pct"] = round(max_bps / speed * 100, 2)
    else:
        result["bandwidth_util_pct"] = None

    # パケット差分ベースの比率計算
    in_ucast_d = diff("in_ucast") or 0
    in_bcast_d = diff("in_broadcast") or 0
    in_err_d = diff("in_errors") or 0
    in_disc_d = diff("in_discards") or 0
    total_in_pkts = in_ucast_d + in_bcast_d + (diff("in_multicast") or 0)

    if total_in_pkts > 0:
        result["broadcast_pct"] = round(in_bcast_d / total_in_pkts * 100, 2)
        result["error_pct"] = round(in_err_d / total_in_pkts * 100, 3)
        result["discard_pct"] = round(in_disc_d / total_in_pkts * 100, 3)
    else:
        result["broadcast_pct"] = None
        result["error_pct"] = None
        result["discard_pct"] = None

    result["in_errors_delta"] = in_err_d
    result["in_discards_delta"] = in_disc_d
    result["in_broadcast_delta"] = in_bcast_d

    return result


def evaluate_device_health(source_ip: str, hostname: str,
                            snmp_metrics: dict, throughput_list: list) -> dict:
    """
    機器の各種メトリクスから総合ヘルススコア(0-100)とステータスを算出する。
    減点方式: 100点満点から問題ごとに減点。
    """
    score = 100
    issues = []
    metrics_summary = {}

    # ── CPU評価 ──
    cpu_5min = _to_float(snmp_metrics.get("cpmCPUTotal5min"))
    if cpu_5min is not None:
        metrics_summary["cpu_5min"] = cpu_5min
        th = HEALTH_THRESHOLDS["cpu_5min"]
        if cpu_5min >= th["critical"]:
            score -= 25
            issues.append({"level": "critical", "category": "CPU",
                          "msg": f"CPU使用率(5分)が危険水準: {cpu_5min}%"})
        elif cpu_5min >= th["warning"]:
            score -= 10
            issues.append({"level": "warning", "category": "CPU",
                          "msg": f"CPU使用率(5分)が高め: {cpu_5min}%"})

    # ── メモリ評価 ──
    mem_used = _to_float(snmp_metrics.get("ciscoMemoryPoolUsed"))
    mem_free = _to_float(snmp_metrics.get("ciscoMemoryPoolFree"))
    if mem_used is not None and mem_free is not None and (mem_used + mem_free) > 0:
        mem_pct = round(mem_used / (mem_used + mem_free) * 100, 1)
        metrics_summary["memory_used_pct"] = mem_pct
        th = HEALTH_THRESHOLDS["memory_used_pct"]
        if mem_pct >= th["critical"]:
            score -= 20
            issues.append({"level": "critical", "category": "メモリ",
                          "msg": f"メモリ使用率が危険水準: {mem_pct}%"})
        elif mem_pct >= th["warning"]:
            score -= 8
            issues.append({"level": "warning", "category": "メモリ",
                          "msg": f"メモリ使用率が高め: {mem_pct}%"})

    # ── 温度評価（Cisco ciscoEnvMonTemperatureStatusValue）──
    temp_c = _to_float(snmp_metrics.get("ciscoEnvMonTemperatureStatusValue"))
    if temp_c is not None:
        metrics_summary["temperature_celsius"] = temp_c
        th = HEALTH_THRESHOLDS["temperature_celsius"]
        if temp_c >= th["critical"]:
            score -= 20
            issues.append({"level": "critical", "category": "温度",
                          "msg": f"筐体温度が危険水準: {temp_c}℃ (冷却障害の疑い)"})
        elif temp_c >= th["warning"]:
            score -= 8
            issues.append({"level": "warning", "category": "温度",
                          "msg": f"筐体温度が高め: {temp_c}℃"})

    # ── インターフェース別評価 ──
    if_issues_count = 0
    for tp in throughput_list:
        ifidx = tp.get("if_index", "?")

        # ダウン検知
        if tp.get("oper_status") == "down":
            score -= 15
            issues.append({"level": "critical", "category": "インターフェース",
                          "msg": f"IF {ifidx} がダウン"})
            continue

        # 帯域使用率（飽和）
        bw = tp.get("bandwidth_util_pct")
        if bw is not None:
            th = HEALTH_THRESHOLDS["bandwidth_util"]
            if bw >= th["critical"]:
                score -= 12
                issues.append({"level": "critical", "category": "帯域",
                              "msg": f"IF {ifidx} 帯域飽和: {bw}%"})
            elif bw >= th["warning"]:
                score -= 5
                issues.append({"level": "warning", "category": "帯域",
                              "msg": f"IF {ifidx} 帯域使用率高: {bw}%"})

        # ブロードキャスト
        bc = tp.get("broadcast_pct")
        if bc is not None:
            th = HEALTH_THRESHOLDS["broadcast_pct"]
            if bc >= th["critical"]:
                score -= 15
                issues.append({"level": "critical", "category": "ブロードキャスト",
                              "msg": f"IF {ifidx} ブロードキャスト異常: {bc}% (ストームの疑い)"})
            elif bc >= th["warning"]:
                score -= 6
                issues.append({"level": "warning", "category": "ブロードキャスト",
                              "msg": f"IF {ifidx} ブロードキャスト多め: {bc}%"})

        # 破棄
        disc = tp.get("discard_pct")
        if disc is not None:
            th = HEALTH_THRESHOLDS["discard_pct"]
            if disc >= th["critical"]:
                score -= 12
                issues.append({"level": "critical", "category": "破棄",
                              "msg": f"IF {ifidx} パケット破棄多発: {disc}% (輻輳の疑い)"})
            elif disc >= th["warning"]:
                score -= 5
                issues.append({"level": "warning", "category": "破棄",
                              "msg": f"IF {ifidx} パケット破棄: {disc}%"})

        # エラー
        err = tp.get("error_pct")
        if err is not None:
            th = HEALTH_THRESHOLDS["error_pct"]
            if err >= th["critical"]:
                score -= 10
                issues.append({"level": "critical", "category": "エラー",
                              "msg": f"IF {ifidx} 入力エラー多発: {err}% (物理障害の疑い)"})
            elif err >= th["warning"]:
                score -= 4
                issues.append({"level": "warning", "category": "エラー",
                              "msg": f"IF {ifidx} 入力エラー: {err}%"})

        if_issues_count += 1

    score = max(0, min(100, score))

    # ステータス判定
    if score >= 85:
        status = "healthy"
    elif score >= 60:
        status = "warning"
    else:
        status = "critical"

    result = {
        "source_ip": source_ip,
        "hostname": hostname,
        "health_score": score,
        "status": status,
        "metrics": metrics_summary,
        "throughput": throughput_list,
        "issues": issues,
        "evaluated_at": datetime.now().isoformat()
    }

    # DB保存
    _init_health_tables()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            INSERT INTO health_scores
            (recorded_at, source_ip, hostname, health_score, status, metrics_json, issues_json)
            VALUES (?,?,?,?,?,?,?)
        """, (
            result["evaluated_at"], source_ip, hostname, score, status,
            json.dumps(metrics_summary, ensure_ascii=False),
            json.dumps(issues, ensure_ascii=False)
        ))
        conn.commit()

    return result


def _to_float(val):
    try:
        return round(float(str(val)), 1)
    except (ValueError, TypeError):
        return None


def get_latest_health_all() -> list:
    """全機器の最新ヘルススコアを取得"""
    _init_health_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT h.* FROM health_scores h
            INNER JOIN (
                SELECT source_ip, MAX(recorded_at) as max_time
                FROM health_scores GROUP BY source_ip
            ) latest ON h.source_ip=latest.source_ip AND h.recorded_at=latest.max_time
            ORDER BY h.health_score ASC
        """).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["metrics"] = json.loads(d.get("metrics_json") or "{}")
            d["issues"] = json.loads(d.get("issues_json") or "[]")
            result.append(d)
        return result


def get_health_trend(source_ip: str, hours: int = 6) -> list:
    """機器のヘルススコア推移を取得"""
    _init_health_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT recorded_at, health_score, status FROM health_scores
            WHERE source_ip=? AND recorded_at >= datetime('now', ? || ' hours')
            ORDER BY recorded_at ASC
        """, (source_ip, f"-{hours}")).fetchall()
        return [dict(r) for r in rows]


def get_network_overall_health() -> dict:
    """ネットワーク全体の総合健全度を算出"""
    devices = get_latest_health_all()
    if not devices:
        return {"overall_score": None, "device_count": 0,
                "healthy": 0, "warning": 0, "critical": 0}

    scores = [d["health_score"] for d in devices]
    overall = round(sum(scores) / len(scores))

    status_count = {"healthy": 0, "warning": 0, "critical": 0}
    for d in devices:
        status_count[d.get("status", "warning")] += 1

    # 1台でもcriticalがあれば全体スコアを補正（最弱リンク考慮）
    if status_count["critical"] > 0:
        overall = min(overall, 59)

    return {
        "overall_score": overall,
        "device_count": len(devices),
        "healthy": status_count["healthy"],
        "warning": status_count["warning"],
        "critical": status_count["critical"],
        "worst_devices": devices[:3]  # スコアが低い順
    }


def set_interface_expectation(source_ip: str, if_index: str,
                               if_name: str, expected_mbps: float, link_mbps: float):
    _init_health_tables()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            INSERT INTO interface_expectations
            (source_ip, if_index, if_name, expected_mbps, link_mbps)
            VALUES (?,?,?,?,?)
            ON CONFLICT(source_ip, if_index) DO UPDATE SET
                if_name=excluded.if_name,
                expected_mbps=excluded.expected_mbps,
                link_mbps=excluded.link_mbps
        """, (source_ip, if_index, if_name, expected_mbps, link_mbps))
        conn.commit()


def get_interface_expectations(source_ip: str = None) -> list:
    _init_health_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if source_ip:
            rows = conn.execute(
                "SELECT * FROM interface_expectations WHERE source_ip=?", (source_ip,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM interface_expectations").fetchall()
        return [dict(r) for r in rows]
