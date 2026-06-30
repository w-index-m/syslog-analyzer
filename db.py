import sqlite3
import json
import re
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "syslog.db"

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                source_ip TEXT,
                raw TEXT NOT NULL,
                vendor TEXT,
                severity TEXT,
                facility TEXT,
                hostname TEXT,
                process TEXT,
                message TEXT,
                ai_explanation TEXT,
                ai_model TEXT,
                tags TEXT,
                judge_result TEXT,
                judge_model TEXT
            )
        """)
        # 既存DBへのマイグレーション（カラムが無ければ追加）
        existing_cols = [r[1] for r in conn.execute("PRAGMA table_info(logs)").fetchall()]
        if "judge_result" not in existing_cols:
            conn.execute("ALTER TABLE logs ADD COLUMN judge_result TEXT")
        if "judge_model" not in existing_cols:
            conn.execute("ALTER TABLE logs ADD COLUMN judge_model TEXT")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at TEXT NOT NULL,
                source_ip TEXT,
                vendor TEXT,
                severity TEXT,
                count INTEGER DEFAULT 1
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS device_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                hostname TEXT,
                vendor TEXT,
                config_text TEXT NOT NULL,
                interfaces_summary TEXT,
                routing_summary TEXT,
                uploaded_at TEXT NOT NULL,
                notes TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_received ON logs(received_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source_ip)")
        conn.commit()

def insert_log(source_ip, raw, parsed: dict, ai_explanation="", ai_model="") -> int:
    with get_conn() as conn:
        cursor = conn.execute("""
            INSERT INTO logs
            (received_at, source_ip, raw, vendor, severity, facility, hostname, process, message, ai_explanation, ai_model, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            source_ip,
            raw,
            parsed.get("vendor", "unknown"),
            parsed.get("severity", ""),
            parsed.get("facility", ""),
            parsed.get("hostname", ""),
            parsed.get("process", ""),
            parsed.get("message", raw),
            ai_explanation,
            ai_model,
            json.dumps(parsed.get("tags", []), ensure_ascii=False)
        ))
        new_id = cursor.lastrowid
        # テレメトリ集計
        conn.execute("""
            INSERT INTO telemetry (recorded_at, source_ip, vendor, severity, count)
            VALUES (?, ?, ?, ?, 1)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M"),
            source_ip,
            parsed.get("vendor", "unknown"),
            parsed.get("severity", "")
        ))
        conn.commit()
        return new_id

def get_logs(limit=200, source_ip=None, severity=None, vendor=None):
    query = "SELECT * FROM logs WHERE 1=1"
    params = []
    if source_ip:
        query += " AND source_ip = ?"
        params.append(source_ip)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if vendor:
        query += " AND vendor = ?"
        params.append(vendor)
    query += " ORDER BY received_at DESC LIMIT ?"
    params.append(limit)
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(query, params).fetchall()]

def get_telemetry_summary():
    with get_conn() as conn:
        by_severity = conn.execute("""
            SELECT severity, SUM(count) as total FROM telemetry GROUP BY severity
        """).fetchall()
        by_vendor = conn.execute("""
            SELECT vendor, SUM(count) as total FROM telemetry GROUP BY vendor
        """).fetchall()
        by_source = conn.execute("""
            SELECT source_ip, SUM(count) as total FROM telemetry GROUP BY source_ip ORDER BY total DESC LIMIT 10
        """).fetchall()
        trend = conn.execute("""
            SELECT substr(recorded_at,1,16) as minute, SUM(count) as total
            FROM telemetry
            WHERE recorded_at >= datetime('now','-1 hour')
            GROUP BY minute ORDER BY minute
        """).fetchall()
        total = conn.execute("SELECT COUNT(*) as c FROM logs").fetchone()["c"]
    return {
        "by_severity": [dict(r) for r in by_severity],
        "by_vendor": [dict(r) for r in by_vendor],
        "by_source": [dict(r) for r in by_source],
        "trend": [dict(r) for r in trend],
        "total": total
    }

def get_unanalyzed_logs(limit=5):
    with get_conn() as conn:
        return [dict(r) for r in conn.execute("""
            SELECT * FROM logs WHERE (ai_explanation IS NULL OR ai_explanation='')
            ORDER BY received_at DESC LIMIT ?
        """, (limit,)).fetchall()]

def update_ai_explanation(log_id, explanation, model):
    with get_conn() as conn:
        conn.execute(
            "UPDATE logs SET ai_explanation=?, ai_model=? WHERE id=?",
            (explanation, model, log_id)
        )
        conn.commit()

def update_judge_result(log_id, judge_result_dict, judge_model):
    with get_conn() as conn:
        conn.execute(
            "UPDATE logs SET judge_result=?, judge_model=? WHERE id=?",
            (json.dumps(judge_result_dict, ensure_ascii=False), judge_model, log_id)
        )
        conn.commit()

def get_quality_summary() -> dict:
    """品質評価の集計を取得"""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT judge_result FROM logs WHERE judge_result IS NOT NULL AND judge_result != ''"
        ).fetchall()
    grades = {"A": 0, "B": 0, "C": 0, "D": 0}
    scores = []
    issues_count = 0
    for r in rows:
        try:
            jr = json.loads(r["judge_result"])
            grade = jr.get("grade", "")
            if grade in grades:
                grades[grade] += 1
            if "total_score" in jr:
                scores.append(jr["total_score"])
            if jr.get("issues"):
                issues_count += len(jr["issues"])
        except Exception:
            continue
    avg_score = sum(scores) / len(scores) if scores else 0
    return {
        "grades": grades,
        "avg_score": round(avg_score, 1),
        "total_judged": len(rows),
        "total_issues": issues_count
    }

def clear_logs():
    with get_conn() as conn:
        conn.execute("DELETE FROM logs")
        conn.execute("DELETE FROM telemetry")
        conn.commit()

# ─────────────────────────────────────────
# デバイスコンフィグ管理
# ─────────────────────────────────────────
def save_device_config(ip, config_text, hostname="", vendor="", notes=""):
    interfaces_summary = _extract_interfaces(config_text)
    routing_summary = _extract_routing(config_text)
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO device_configs (ip, hostname, vendor, config_text, interfaces_summary, routing_summary, uploaded_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                hostname=excluded.hostname, vendor=excluded.vendor,
                config_text=excluded.config_text,
                interfaces_summary=excluded.interfaces_summary,
                routing_summary=excluded.routing_summary,
                uploaded_at=excluded.uploaded_at,
                notes=excluded.notes
        """, (ip, hostname, vendor, config_text, interfaces_summary, routing_summary,
              datetime.now().isoformat(), notes))
        conn.commit()

def get_device_config(ip: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM device_configs WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None

def get_all_device_configs() -> list:
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id, ip, hostname, vendor, uploaded_at, notes FROM device_configs ORDER BY uploaded_at DESC"
        ).fetchall()]

def delete_device_config(ip: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM device_configs WHERE ip=?", (ip,))
        conn.commit()

def _extract_interfaces(config_text: str) -> str:
    """コンフィグからインターフェース部分の概要を抽出（簡易）"""
    lines = config_text.splitlines()
    summary = []
    capturing = False
    current_block = []
    for line in lines:
        stripped = line.strip()
        if re.match(r"^interface\s+\S+", stripped, re.IGNORECASE) or \
           re.match(r"^!\s*interface\s+\S+", stripped, re.IGNORECASE):
            if current_block:
                summary.append(" / ".join(current_block))
            current_block = [stripped]
            capturing = True
        elif capturing and stripped and not stripped.startswith("!"):
            if any(k in stripped.lower() for k in
                   ["ip address", "description", "shutdown", "no shutdown",
                    "switchport", "vlan", "duplex", "speed", "channel-group"]):
                current_block.append(stripped)
        elif capturing and (stripped.startswith("!") or stripped == ""):
            capturing = False
    if current_block:
        summary.append(" / ".join(current_block))
    return "\n".join(summary[:100])  # 最大100インターフェース分

def _extract_routing(config_text: str) -> str:
    """コンフィグからルーティング部分の概要を抽出（簡易）"""
    patterns = [
        r"^router\s+\w+.*$",
        r"^\s*network\s+\S+.*$",
        r"^\s*neighbor\s+\S+.*$",
        r"^ip\s+route\s+.*$",
        r"^\s*redistribute\s+.*$",
        r"^\s*area\s+\S+.*$",
    ]
    lines = config_text.splitlines()
    matched = []
    for line in lines:
        stripped = line.strip()
        for p in patterns:
            if re.match(p, stripped, re.IGNORECASE):
                matched.append(stripped)
                break
    return "\n".join(matched[:150])  # 最大150行
