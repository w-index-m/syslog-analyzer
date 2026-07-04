"""
アプリケーション応答時間モニター
- HTTP/HTTPS エンドポイントの応答時間を定期計測
- ICMP ping（subprocess経由）
- 結果を SQLite に保存してトレンド表示
"""
import os
import sqlite3
import subprocess
import time
from datetime import datetime
from pathlib import Path
import threading

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DB_PATH = Path(os.environ.get("DB_PATH", str(Path(__file__).parent / "syslog.db")))

# ─────────────────────────────────────────
# DB
# ─────────────────────────────────────────

def _init_tables():
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS probe_targets (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                url         TEXT NOT NULL,
                probe_type  TEXT DEFAULT 'http',
                enabled     INTEGER DEFAULT 1,
                UNIQUE(url)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS probe_results (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                measured_at TEXT NOT NULL,
                target_id   INTEGER NOT NULL,
                target_url  TEXT NOT NULL,
                status_code INTEGER DEFAULT 0,
                rtt_ms      REAL DEFAULT 0,
                success     INTEGER DEFAULT 0,
                error_msg   TEXT DEFAULT ''
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_probe_ts ON probe_results(measured_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_probe_tid ON probe_results(target_id)")
        conn.commit()


def add_target(name: str, url: str, probe_type: str = "http") -> bool:
    _init_tables()
    try:
        with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO probe_targets (name, url, probe_type) VALUES (?,?,?)",
                (name, url, probe_type)
            )
            conn.commit()
        return True
    except Exception:
        return False


def get_targets() -> list[dict]:
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("SELECT * FROM probe_targets ORDER BY id").fetchall()]


def remove_target(target_id: int):
    _init_tables()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("DELETE FROM probe_targets WHERE id=?", (target_id,))
        conn.execute("DELETE FROM probe_results WHERE target_id=?", (target_id,))
        conn.commit()


def set_target_enabled(target_id: int, enabled: bool):
    _init_tables()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("UPDATE probe_targets SET enabled=? WHERE id=?", (int(enabled), target_id))
        conn.commit()


# ─────────────────────────────────────────
# プローブ実行
# ─────────────────────────────────────────

def probe_http(url: str, timeout: int = 10) -> dict:
    """HTTP GET で応答時間を計測する。"""
    t0 = time.perf_counter()
    try:
        resp = requests.get(url, timeout=timeout, verify=False,
                            allow_redirects=True,
                            headers={"User-Agent": "syslog-analyzer-probe/1.0"})
        rtt_ms = (time.perf_counter() - t0) * 1000
        return {
            "success": True,
            "status_code": resp.status_code,
            "rtt_ms": round(rtt_ms, 2),
            "error_msg": "",
        }
    except requests.exceptions.Timeout:
        return {"success": False, "status_code": 0,
                "rtt_ms": timeout * 1000.0, "error_msg": "Timeout"}
    except Exception as e:
        rtt_ms = (time.perf_counter() - t0) * 1000
        return {"success": False, "status_code": 0,
                "rtt_ms": round(rtt_ms, 2), "error_msg": str(e)[:120]}


def probe_ping(host: str, count: int = 4, timeout: int = 5) -> dict:
    """ICMP ping を subprocess で実行して RTT を返す。"""
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), host],
            capture_output=True, text=True, timeout=timeout + 5
        )
        out = result.stdout
        # "rtt min/avg/max/mdev = 1.234/2.345/3.456/0.123 ms"
        for line in out.splitlines():
            if "rtt" in line or "round-trip" in line:
                parts = line.split("=")[-1].strip().split("/")
                if len(parts) >= 2:
                    avg_ms = float(parts[1])
                    return {"success": True, "rtt_ms": round(avg_ms, 2), "error_msg": ""}
        # Packet loss check
        if "100% packet loss" in out or "100.0% packet loss" in out:
            return {"success": False, "rtt_ms": 0, "error_msg": "100% packet loss"}
        return {"success": True, "rtt_ms": 0, "error_msg": "RTT parse error"}
    except subprocess.TimeoutExpired:
        return {"success": False, "rtt_ms": 0, "error_msg": "Timeout"}
    except FileNotFoundError:
        return {"success": False, "rtt_ms": 0, "error_msg": "ping コマンドなし"}
    except Exception as e:
        return {"success": False, "rtt_ms": 0, "error_msg": str(e)[:120]}


def run_all_probes() -> list[dict]:
    """全有効ターゲットをプローブして結果を DB 保存＆返却。"""
    _init_tables()
    targets = [t for t in get_targets() if t["enabled"]]
    now = datetime.now().isoformat()
    results = []
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        for t in targets:
            if t["probe_type"] == "ping":
                host = t["url"].replace("ping://", "").strip()
                r = probe_ping(host)
                r["status_code"] = 0
            else:
                r = probe_http(t["url"])
            conn.execute("""
                INSERT INTO probe_results
                (measured_at, target_id, target_url, status_code, rtt_ms, success, error_msg)
                VALUES (?,?,?,?,?,?,?)
            """, (now, t["id"], t["url"], r["status_code"], r["rtt_ms"],
                  int(r["success"]), r.get("error_msg", "")))
            results.append({**t, **r, "measured_at": now})
        conn.commit()
    return results


def get_probe_history(target_id: int, hours: int = 24) -> list[dict]:
    """特定ターゲットの過去 N 時間の計測履歴を返す。"""
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT measured_at, rtt_ms, success, status_code, error_msg
            FROM probe_results
            WHERE target_id=? AND measured_at >= datetime('now', ? || ' hours')
            ORDER BY measured_at
        """, (target_id, f"-{hours}")).fetchall()
        return [dict(r) for r in rows]


def get_probe_summary(hours: int = 24) -> list[dict]:
    """全ターゲットの直近 N 時間サマリー（平均RTT・成功率）を返す。"""
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT t.id, t.name, t.url, t.probe_type,
                   COUNT(*) AS total,
                   SUM(r.success) AS ok_count,
                   AVG(CASE WHEN r.success=1 THEN r.rtt_ms END) AS avg_rtt,
                   MIN(CASE WHEN r.success=1 THEN r.rtt_ms END) AS min_rtt,
                   MAX(CASE WHEN r.success=1 THEN r.rtt_ms END) AS max_rtt,
                   MAX(r.measured_at) AS last_checked,
                   (SELECT r2.success FROM probe_results r2
                    WHERE r2.target_id=t.id ORDER BY r2.measured_at DESC LIMIT 1) AS last_ok,
                   (SELECT r2.rtt_ms FROM probe_results r2
                    WHERE r2.target_id=t.id ORDER BY r2.measured_at DESC LIMIT 1) AS last_rtt
            FROM probe_targets t
            LEFT JOIN probe_results r
              ON t.id=r.target_id
              AND r.measured_at >= datetime('now', ? || ' hours')
            GROUP BY t.id ORDER BY t.name
        """, (f"-{hours}",)).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["availability_pct"] = round(d["ok_count"] / d["total"] * 100, 1) if d["total"] else 0
            d["avg_rtt"] = round(d["avg_rtt"], 2) if d["avg_rtt"] else None
            result.append(d)
        return result


# ─────────────────────────────────────────
# バックグラウンド自動計測
# ─────────────────────────────────────────

_bg_thread: threading.Thread | None = None
_bg_stop   = threading.Event()


def start_background_probe(interval_sec: int = 60):
    global _bg_thread
    if _bg_thread and _bg_thread.is_alive():
        return
    _bg_stop.clear()

    def _loop():
        while not _bg_stop.is_set():
            try:
                run_all_probes()
            except Exception as e:
                print(f"[probe] background error: {e}")
            _bg_stop.wait(interval_sec)

    _bg_thread = threading.Thread(target=_loop, daemon=True, name="probe-bg")
    _bg_thread.start()


def stop_background_probe():
    _bg_stop.set()
