"""
show logging から「ソフトウェアバグ（不具合）」の疑いを判定するヒューリスティック解析。

各ログ行を次の3判定に分類する:
  🐛 bug     … ソフト/ハードの不具合が疑われる（クラッシュ/メモリ枯渇/watchdog/
                内部エラー/予期しない再起動/装置故障 など）
  ⚙️ ops     … 設定・運用・環境起因（リンクDOWN/認証失敗/経路フラップ 等、想定内）
  ✅ info    … 正常・情報メッセージ

APIキー不要で動作する。詳細な原因推定が必要な場合は既存の analyzer.ask_llm を併用。
"""
import re

# ── バグ疑いシグネチャ（クロスベンダー） ──────────────────────
# (カテゴリ, 正規表現, 理由, 確度[high/medium])
BUG_SIGNATURES = [
    # ソフト異常終了・クラッシュ
    ("クラッシュ/異常終了", r"software[- ]forced (crash|reload)|forced crash|core[ _]?dump|"
     r"core dumped|segfault|segmentation fault|kernel panic|\boops\b|traceback|"
     r"call trace|\bBUG:|assertion failed|assert fail|abort\b|stack overflow|"
     r"unexpected exception|fatal error", "ソフトウェアのクラッシュ/異常終了の痕跡", "high"),
    # メモリ枯渇・リーク
    ("メモリ枯渇/リーク", r"mallocfail|out of memory|\bOOM\b|memory leak|no (free )?memory|"
     r"mem(ory)? (alloc|allocation) (fail|error)|low on memory|memory exhaust",
     "メモリ枯渇/リークの疑い", "high"),
    # CPU ハング・ウォッチドッグ
    ("CPUハング/watchdog", r"cpuhog|watchdog|task ran for|running for longer than expected|"
     r"\bhang\b|deadlock|scheduler.*(stuck|hog)|process.*stuck",
     "CPU ハング/ウォッチドッグ発火の疑い", "high"),
    # 予期しない再起動
    ("予期しない再起動", r"unexpected(ly)? (reset|reboot|restart)|system reset busy|"
     r"software-forced reload|unplanned reload|last reload reason.*(crash|error|watchdog)|"
     r"reset by (error|exception|watchdog)", "予期しない再起動/リセット", "high"),
    # プロセス異常・再起動
    ("プロセス異常", r"process .*(crash|abort|died|unexpected exit|respawn|restart)|"
     r"daemon .*(died|crash|restart)|unexpected (exit|termination)|"
     r"child process (killed|died)|%SYS-\d-PROC", "プロセスの異常終了/再起動", "medium"),
    # データ破損・内部エラー
    ("内部エラー/破損", r"datacorruption|data corruption|internal error|"
     r"inconsistent (state|data)|checksum (error|mismatch|fail)|"
     r"parity error|ecc error|corrupt(ed)?", "データ破損/内部整合性エラー", "medium"),
    # 繰り返し・フラッド（ループ/暴走の兆候）
    ("メッセージ暴走", r"same message repeated \d+ times|message .*repeated|"
     r"log.*flood|rate-limit.*exceed", "同一メッセージ多発（暴走/ループの兆候）", "medium"),
    # ハードウェア障害
    ("ハードウェア障害", r"hardware (error|failure|fault)|hw (error|fault)|"
     r"温度|temperature (high|over)|fan (fail|stop)|power (fail|supply.*fail)|"
     r"module.*(fail|crash|removed unexpectedly)|diagnostic (error|fail)",
     "ハードウェア障害の疑い", "high"),
]

# ── 運用・設定起因（バグではない）と判断するタグ/キーワード ────
OPS_TAG_HINTS = {
    "リンクDOWN", "リンクUP", "認証失敗", "認証成功", "ログイン成功", "ログアウト",
    "トポロジ変更", "ルートブリッジ変更", "冗長切替", "回線切断", "発着信",
    "通信拒否", "通信許可", "設定反映", "ループ検知", "ポート遮断",
}

_COMPILED = [(cat, re.compile(rx, re.IGNORECASE), reason, conf)
             for cat, rx, reason, conf in BUG_SIGNATURES]


def analyze_bug(parsed: dict, raw: str) -> dict:
    """
    1件のログをバグ観点で判定する。
    戻り値: {verdict: "bug"|"ops"|"info", category, reason, confidence}
    """
    text = f"{raw} {parsed.get('message','')}"
    tags = parsed.get("tags", []) or []

    # 1) バグシグネチャ一致を最優先
    for cat, rx, reason, conf in _COMPILED:
        if rx.search(text):
            return {"verdict": "bug", "category": cat, "reason": reason, "confidence": conf}

    # 2) Si-R エラーコード分類（装置交換/再起動/USB/環境 はバグ・故障寄り）
    for t in tags:
        if t.startswith("対処:"):
            label = t[3:]
            if "装置交換" in label:
                return {"verdict": "bug", "category": "ハードウェア障害",
                        "reason": f"Si-Rエラーコード: {label}", "confidence": "high"}
            if "再起動" in label or "USB" in label or "温度" in label or "環境" in label:
                return {"verdict": "bug", "category": "装置エラー",
                        "reason": f"Si-Rエラーコード: {label}", "confidence": "medium"}

    # 3) 運用・設定起因のタグがあれば ops
    if any(t in OPS_TAG_HINTS for t in tags) or "障害候補" in tags:
        return {"verdict": "ops", "category": "運用・設定",
                "reason": "設定/運用/環境起因の事象（想定内）", "confidence": "low"}

    # 4) それ以外は情報
    return {"verdict": "info", "category": "情報", "reason": "正常/情報メッセージ",
            "confidence": "low"}


def analyze_batch(logs: list[dict]) -> dict:
    """
    取り込み済みログ（db.get_logs 形式: raw, tags(JSON文字列) 等）をまとめて判定。
    戻り値: {counts, bugs:[{...}], summary}
    """
    import json
    counts = {"bug": 0, "ops": 0, "info": 0}
    bugs = []
    for lg in logs:
        tags = lg.get("tags")
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except Exception:
                tags = []
        parsed = {"message": lg.get("message", ""), "tags": tags}
        res = analyze_bug(parsed, lg.get("raw", lg.get("message", "")))
        counts[res["verdict"]] += 1
        if res["verdict"] == "bug":
            bugs.append({
                "vendor": lg.get("vendor", ""),
                "hostname": lg.get("hostname", ""),
                "message": lg.get("message", ""),
                "category": res["category"],
                "reason": res["reason"],
                "confidence": res["confidence"],
            })
    total = sum(counts.values())
    if counts["bug"]:
        summary = (f"🐛 バグ疑い {counts['bug']}件 / ⚙️ 運用・設定 {counts['ops']}件 / "
                   f"✅ 情報 {counts['info']}件（全{total}件）。"
                   f"バグ疑いを優先的に調査してください。")
    else:
        summary = (f"バグ疑いは検出されませんでした。⚙️ 運用・設定 {counts['ops']}件 / "
                   f"✅ 情報 {counts['info']}件（全{total}件）。")
    return {"counts": counts, "bugs": bugs, "summary": summary}


if __name__ == "__main__":
    samples = [
        ("bug",  {"message": "%SYS-2-MALLOCFAIL: Memory allocation of 1024 bytes failed", "tags": []}),
        ("bug",  {"message": "%SYS-3-CPUHOG: Task is running for longer than expected", "tags": []}),
        ("bug",  {"message": "Software-forced crash, PC 0x1234", "tags": []}),
        ("bug",  {"message": "system reset busy.", "tags": ["対処:装置交換が必要"]}),
        ("ops",  {"message": "%LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down", "tags": ["リンクDOWN", "障害候補"]}),
        ("ops",  {"message": "failed login admin on ssh from 203.0.113.1", "tags": ["認証失敗"]}),
        ("info", {"message": "Configured from console by admin", "tags": []}),
    ]
    ok = 0
    for expect, p in samples:
        r = analyze_bug(p, p["message"])
        s = "OK" if r["verdict"] == expect else "NG"
        ok += r["verdict"] == expect
        print(f"[{s}] {r['verdict']:<4} ({r['category']}) <- {p['message'][:50]}")
    print(f"--- {ok}/{len(samples)} ---")
