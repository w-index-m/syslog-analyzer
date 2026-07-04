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

    # 3) ルーチンなインターフェース状態変化は「情報」に降格
    #    - Vlan1(既定VLAN)/管理shutdown由来、または通知レベル(NOTICE/INFO)は想定内
    sev = (parsed.get("severity") or "").upper()
    msg_l = text.lower()
    _iface_state = ("changed state to administratively down" in msg_l
                    or "line protocol on interface" in msg_l
                    or ("changed state to" in msg_l
                        and ("up" in msg_l or "down" in msg_l)))
    if _iface_state:
        _routine = ("vlan1" in msg_l                                # 既定VLANのSVI
                    or "administratively down" in msg_l             # 意図的shutdown
                    or sev in ("NOTICE", "INFO", "DEBUG"))          # 通知レベル(Cisco sev5/6)
        if _routine:
            return {"verdict": "info", "category": "インターフェース状態",
                    "reason": "リンク/プロトコルの状態変化（通知レベル・想定内）",
                    "confidence": "low"}

    # 4) 運用・設定起因のタグがあれば ops
    if any(t in OPS_TAG_HINTS for t in tags) or "障害候補" in tags:
        return {"verdict": "ops", "category": "運用・設定",
                "reason": "設定/運用/環境起因の事象（想定内）", "confidence": "low"}

    # 5) それ以外は情報
    return {"verdict": "info", "category": "情報", "reason": "正常/情報メッセージ",
            "confidence": "low"}


# ── ログの意味・アドバイス（日本語） ──────────────────────────
# (正規表現, 日本語の意味/アドバイス)
_EXPLAIN_PATTERNS = [
    # PnP（ゼロタッチ・プラグ&プレイ）
    (r"pnp discovery started",
     "プラグ&プレイ(自動設定)の探索を開始。未設定機が起動時に構成配布サーバを探す動作です。"),
    (r"pnp discovery stopped",
     "プラグ&プレイの探索を停止。手動設定(Config Wizard)に入った等で終了した合図で、異常ではありません。"),
    (r"pnp tech summary.*saved with alarm",
     "PnPサーバに到達できず技術情報をローカル保存(alarm付き)。PnPサーバを使わない環境なら想定内です。"),
    (r"saving pnp tech summary",
     "PnPの技術情報を保存中(数十秒)。処理が終わるまで待てば問題ありません。"),
    (r"pnp_best_udi_update|pnp_cdp_update|best udi|device udi",
     "装置固有ID(型番/シリアル)を認識。PnPやCDPで機器を識別する正常動作です。"),
    # システム起動
    (r"system restart|%sys-5-restart",
     "装置が再起動したことの通知(通常の起動)。クラッシュではありません。直前に意図した再起動か確認を。"),
    (r"read env variable.*license_boot_level",
     "起動時に設定されたライセンス動作レベルを読み込み。情報ログです。"),
    (r"console media-type",
     "コンソールポートの種別(RJ45/USB)を表示。正常な起動情報です。"),
    (r"extended sysid enabled",
     "STPの拡張システムID機能が有効(既定動作)。VLAN毎のブリッジIDに使われます。異常ではありません。"),
    # ライセンス
    (r"no valid license found",
     "有効なライセンスが無い状態。次回起動で機能レベルが下位(ipbase等)に降格する可能性。show license で確認し、必要なら適用を。"),
    (r"license level|license_level",
     "ライセンスの動作レベル情報。必要な機能に対して適切なレベルか確認してください。"),
    # インターフェース状態
    (r"line protocol on interface vlan1.*down",
     "Vlan1(既定VLAN)のプロトコルがダウン。未使用/shutdown運用なら想定内。管理VLANを別に使うなら影響ありません。"),
    (r"interface vlan1.*administratively down",
     "Vlan1が管理的にshutdown。設定(shutdown)通りの状態で、意図的なら問題ありません。"),
    (r"line protocol on interface.*down",
     "該当インターフェースのプロトコルがダウン。対向未接続やshutdownが原因のことが多いです。使用中の回線なら要確認。"),
    (r"changed state to administratively down",
     "該当ポートが管理的にshutdown。設定によるもので、意図通りなら問題ありません。"),
    (r"%link-3-updown.*down|changed state to down",
     "物理ポートがダウン。ケーブル/対向機/SFPを確認してください(使用中ポートなら要対処)。"),
    (r"changed state to up|%link-3-updown.*up",
     "ポートがアップ(リンク確立)。正常な状態変化です。"),
    # ルーティング/STP/認証（代表例）
    (r"%ospf.*adjchg|ospf.*neighbor",
     "OSPF隣接関係の状態変化。FULLなら確立、DOWN/LOADINGが続くなら要確認です。"),
    (r"topology change",
     "STPのトポロジ変更を検知。ポートのUP/DOWNやループ発生時に出ます。頻発するなら物理/冗長構成を確認。"),
    (r"failed password|authentication failure|failed login",
     "ログイン認証に失敗。総当たり攻撃の可能性もあるため、送信元IPと頻度を確認してください。"),
]
_EXPLAIN_COMPILED = [(re.compile(p, re.IGNORECASE), t) for p, t in _EXPLAIN_PATTERNS]


def explain_log(message: str) -> str:
    """
    ログ本文から、日本語の意味/アドバイスを返す。該当が無ければ空文字。
    """
    msg = message or ""
    for rx, text in _EXPLAIN_COMPILED:
        if rx.search(msg):
            return text
    return ""


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
        parsed = {"message": lg.get("message", ""), "tags": tags,
                  "severity": lg.get("severity", "")}
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
