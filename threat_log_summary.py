"""
ファイアウォール/UTM系ログ（FortiGate・Palo Alto等）から、
「どんな攻撃が・何件・遮断できているか」を集計するモジュール。

各ベンダーパーサー（parsers/fortigate.py, parsers/paloalto.py 等）が
ログ1行ごとに付与する tags（例: "侵入検知(IPS)", "マルウェア", "遮断" 等）を
横断的に数え上げる。個々のログ行を1件ずつ読む代わりに、
「直近N時間でIPS検知が何件、うち未遮断が何件」という形でまとめて把握できる。
"""
import os
import re
import sqlite3
from pathlib import Path

DB_PATH = Path(os.environ.get("DB_PATH", str(Path(__file__).parent / "syslog.db")))

# tags内のキーワード -> 表示用の攻撃カテゴリ名（複数キーワードが同カテゴリに集約されることもある）
_ATTACK_TAG_CATEGORIES = [
    ("侵入検知(IPS)",  "🛡️ 侵入検知/脆弱性攻撃(IPS)"),
    ("脆弱性攻撃",      "🛡️ 侵入検知/脆弱性攻撃(IPS)"),
    ("ウイルス検知",    "🦠 マルウェア/ウイルス"),
    ("マルウェア",      "🦠 マルウェア/ウイルス"),
    ("スパイウェア",    "🕵️ スパイウェア"),
    ("WAF",            "🌐 Web攻撃(WAF)"),
    ("Webフィルタ",     "🚫 Webフィルタ検知"),
    ("異常検知(DoS)",   "🌊 DoS/異常トラフィック"),
    ("認証失敗",        "🔑 認証失敗"),
    ("DNSフィルタ",     "🔎 DNSフィルタ検知"),
    ("SSL検査",         "🔒 SSL/TLS検査"),
]

_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _extract_first_ip(message: str) -> str:
    m = _IPV4_RE.search(message or "")
    return m.group(1) if m else ""


def get_attack_summary(hours: float = 24) -> dict:
    """
    直近hours時間のログから、攻撃カテゴリ別の検知件数・遮断状況を集計する。
    戻り値: {"total": int, "by_type": [{"category","count","blocked","unresolved","top_sources":[...]}],
             "unresolved_total": int}
    """
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT received_at, vendor, hostname, source_ip, message, tags
            FROM logs
            WHERE received_at >= datetime('now', ? || ' hours')
              AND (tags LIKE '%セキュリティ%' OR tags LIKE '%脅威%')
            ORDER BY received_at DESC
        """, (f"-{hours}",)).fetchall()

    by_category: dict[str, dict] = {}
    for r in rows:
        tags_raw = r["tags"] or ""
        # tags はJSON配列文字列で保存されているが、キーワード検索だけなので雑にin判定でよい
        matched_categories = set()
        for keyword, category in _ATTACK_TAG_CATEGORIES:
            if keyword in tags_raw:
                matched_categories.add(category)
        if not matched_categories:
            continue

        is_blocked = ("遮断" in tags_raw) or ("防御成功" in tags_raw)
        is_unresolved = ("アラートのみ" in tags_raw) or ("要確認" in tags_raw)
        atk_ip = _extract_first_ip(r["message"] or "") or r["source_ip"] or "(不明)"

        for category in matched_categories:
            e = by_category.setdefault(category, {
                "category": category, "count": 0, "blocked": 0, "unresolved": 0,
                "sources": {},
            })
            e["count"] += 1
            if is_blocked:
                e["blocked"] += 1
            if is_unresolved:
                e["unresolved"] += 1
            e["sources"][atk_ip] = e["sources"].get(atk_ip, 0) + 1

    by_type = []
    unresolved_total = 0
    for e in by_category.values():
        top_sources = sorted(e["sources"].items(), key=lambda kv: -kv[1])[:5]
        unresolved_total += e["unresolved"]
        by_type.append({
            "category":  e["category"],
            "count":     e["count"],
            "blocked":   e["blocked"],
            "unresolved": e["unresolved"],
            "top_sources": [{"ip": ip, "count": c} for ip, c in top_sources],
        })
    by_type.sort(key=lambda x: -x["count"])

    return {
        "total": sum(x["count"] for x in by_type),
        "by_type": by_type,
        "unresolved_total": unresolved_total,
    }
