"""
不正アクセス検知（ブルートフォース・認証突破の疑い）

logsテーブルの「認証失敗」/「認証成功」タグは各ベンダーパーサーが個々の
ログ行単位で付けているだけで、これまで「同一の攻撃元IPから同一機器への
短時間の大量失敗」「大量失敗の直後の成功（突破された疑い）」という
集計・相関は行っていなかった。本モジュールがその集計を担う。

攻撃元IPは logs.source_ip カラムではなく、各ベンダーのログメッセージ本文
（例: "Failed password ... from 203.0.113.1 port 55234 ssh2"、
"Source=203.0.113.200"、"src=1.2.3.4"）から正規表現で抽出する。
source_ipカラムは機器（syslog送信元）自身のIPであり、攻撃元IPとは別物のため。
"""
import os
import re
import sqlite3
from pathlib import Path

DB_PATH = Path(os.environ.get("DB_PATH", str(Path(__file__).parent / "syslog.db")))

# ベンダーごとに書式が異なるため、優先順で複数パターンを試す
_ATTACKER_IP_PATTERNS = [
    re.compile(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE),           # SSH/Linux
    re.compile(r"\bSource\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE),     # Windows EventID
    re.compile(r"\bsrc(?:_?ip)?\s*[:=]\s*(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE),  # FW/汎用
    re.compile(r"\bclient(?:_?ip)?\s*[:=]\s*(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE),
]


def _extract_attacker_ip(message: str) -> str:
    """ログメッセージ本文から攻撃元(接続元)IPを抽出する。見つからなければ空文字。"""
    for pat in _ATTACKER_IP_PATTERNS:
        m = pat.search(message or "")
        if m:
            return m.group(1)
    return ""


def get_brute_force_alerts(hours: float = 1, threshold: int = 5) -> list[dict]:
    """
    同一の攻撃元IPから同一機器へ、直近hours時間でthreshold回以上の認証失敗が
    発生していないかを検知する（ブルートフォース攻撃の兆候。シグネチャ不要）。
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT received_at, source_ip, hostname, message
            FROM logs
            WHERE tags LIKE '%認証失敗%'
              AND received_at >= datetime('now', ? || ' hours')
            ORDER BY received_at ASC
        """, (f"-{hours}",)).fetchall()

    counts: dict[tuple, dict] = {}
    for r in rows:
        atk_ip = _extract_attacker_ip(r["message"] or "")
        if not atk_ip:
            continue
        target = r["hostname"] or r["source_ip"] or "不明"
        key = (atk_ip, target)
        entry = counts.setdefault(key, {"count": 0, "first_ts": r["received_at"], "last_ts": r["received_at"]})
        entry["count"] += 1
        entry["last_ts"] = r["received_at"]

    alerts = []
    for (atk_ip, target), info in counts.items():
        if info["count"] >= threshold:
            alerts.append({
                "attacker_ip": atk_ip, "target": target, "count": info["count"],
                "first_seen": info["first_ts"], "last_seen": info["last_ts"],
                "severity": "critical" if info["count"] >= threshold * 4 else "high",
                "detail": f"{atk_ip} → {target} への認証失敗が {info['count']}回"
                          f"（{info['first_ts'][:19]} 〜 {info['last_ts'][:19]}） — "
                          "ブルートフォース攻撃の可能性",
            })
    alerts.sort(key=lambda a: a["count"], reverse=True)
    return alerts


def get_breach_suspected_alerts(hours: float = 1, fail_threshold: int = 3) -> list[dict]:
    """
    同一の攻撃元IPから同一機器へ、fail_threshold回以上の認証失敗の直後に
    認証成功が発生していないかを検知する（ブルートフォース突破＝不正アクセス
    成功の疑い。最重要アラート）。
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT received_at, source_ip, hostname, message, tags
            FROM logs
            WHERE (tags LIKE '%認証失敗%' OR tags LIKE '%認証成功%' OR tags LIKE '%ログイン成功%')
              AND received_at >= datetime('now', ? || ' hours')
            ORDER BY received_at ASC
        """, (f"-{hours}",)).fetchall()

    fail_history: dict[tuple, int] = {}
    alerts = []
    alerted_keys = set()
    for r in rows:
        atk_ip = _extract_attacker_ip(r["message"] or "")
        if not atk_ip:
            continue
        target = r["hostname"] or r["source_ip"] or "不明"
        key = (atk_ip, target)
        tags = r["tags"] or ""
        is_success = ("認証成功" in tags) or ("ログイン成功" in tags)
        if is_success:
            fail_count = fail_history.get(key, 0)
            if fail_count >= fail_threshold and key not in alerted_keys:
                alerted_keys.add(key)
                alerts.append({
                    "attacker_ip": atk_ip, "target": target, "fail_count": fail_count,
                    "success_at": r["received_at"], "severity": "critical",
                    "detail": f"{atk_ip} が {target} へ {fail_count}回の認証失敗後、"
                              f"{r['received_at'][:19]} に認証成功 — "
                              "ブルートフォース突破（不正アクセス成功）の疑い。至急確認してください",
                })
            fail_history[key] = 0  # 成功したのでリセット
        else:
            fail_history[key] = fail_history.get(key, 0) + 1
    return alerts
