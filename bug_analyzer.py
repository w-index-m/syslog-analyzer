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
    # ── 設定/管理操作（Cisco） ──
    (r"%sys-5-config_i|configured from",
     "設定が変更されました(config modeから)。誰が・どこから(console/vty)変更したか記録されます。意図した変更か確認を。"),
    (r"%sys-6-logginghost|logging.*start",
     "syslog転送先(logging host)の開始/停止通知。ログ転送設定が有効になった合図です。"),
    (r"%sys-5-restart|%sys-6-boot",
     "システムの起動/再起動通知。計画外なら直前のログやreload理由(show version)を確認してください。"),
    # ── ACL / セキュリティ（Cisco） ──
    (r"%sec-6-ipaccesslogp|list \w+ denied|access.?list.*denied",
     "ACLでパケットが遮断(deny)されました。想定した通信が止まっていないか、送信元/宛先を確認してください。"),
    (r"%sec-6-ipaccesslogp.*permit|list \w+ permitted",
     "ACLでパケットが許可(permit)されログ出力。ログ付きACLの正常動作です。"),
    (r"%sec_login-5-login_success|login success",
     "ログインに成功しました。想定した管理者か、時刻・送信元を確認してください。"),
    (r"%sec_login-4-login_failed|%sec-6-login|login failed|failed password|authentication failure|failed login",
     "ログイン認証に失敗。短時間に多発する場合は総当たり攻撃の可能性。送信元IPと頻度を確認してください。"),
    (r"%port_security|%psecure|psecure-2-psecure_violation|security violation",
     "ポートセキュリティ違反。許可外MACの接続でポートがerr-disable/遮断された可能性。接続機器を確認してください。"),
    # ── ルーティング（Cisco） ──
    (r"%ospf.*adjchg|ospf.*neighbor|ospf-5-adjchg",
     "OSPF隣接関係の状態変化。FULL=確立(正常)、DOWN/LOADING/INIT が続く/頻発するなら要確認(MTU/認証/回線)。"),
    (r"%bgp-5-adjchange|bgp.*neighbor.*up",
     "BGPピアの状態変化。Established=確立(正常)。Idle/Active を繰り返すならピア設定や到達性を確認。"),
    (r"%bgp-3-notification|bgp.*notification|hold timer expired",
     "BGPがNOTIFICATIONで切断。Hold Timer満了は回線断や高負荷が原因のことが多いです。対向と回線を確認してください。"),
    (r"%dual-5-nbrchange|eigrp.*neighbor",
     "EIGRP隣接の状態変化。up=確立。down/頻発なら回線・タイマー・認証を確認してください。"),
    (r"%hsrp-\d-statechange|standby.*state|hsrp.*active|hsrp.*standby",
     "HSRP(冗長ゲートウェイ)の状態遷移。Active/Standby切替。頻発するなら優先度/プリエンプト/回線を確認。"),
    (r"vrrp.*master|%vrrp",
     "VRRP(冗長ゲートウェイ)の状態遷移。マスター切替が頻発するなら優先度や監視回線を確認してください。"),
    (r"%ip-4-dupaddr|duplicate address",
     "IPアドレスの重複を検知。同一IPを持つ機器が居ます。該当IP/MACを特定し重複を解消してください。"),
    # ── L2 / STP / ループ（Cisco） ──
    (r"topology change|%spantree-\d-topotrap",
     "STPのトポロジ変更を検知。ポートUP/DOWNやループ時に出ます。頻発するなら物理/冗長構成・ケーブルを確認。"),
    (r"loop_back_detected|loopguard|loop guard|%etchcntr.*loop|loop detected|configuration testing protocol.*loop",
     "ループを検知しました。L2ループはブロードキャスト氾濫で通信不能に直結します。該当ポートと配線を至急確認してください。"),
    (r"bpduguard|bpdu guard|%spantree-2-block_bpduguard",
     "BPDU Guard作動。エッジポートでBPDUを受信しポートを遮断(err-disable)しました。誤って別SWを繋いでいないか確認。"),
    (r"rootguard|root guard|%spantree-2-rootguard",
     "Root Guard作動。想定外の優先スイッチを検知しポートをブロック。トポロジ設計と接続先を確認してください。"),
    (r"%pm-4-err_disable|err.?disable",
     "ポートがerr-disable(自動遮断)状態。原因(ループ/BPDU/セキュリティ/フラップ)を除去後、shut/no shutで復旧してください。"),
    (r"mac.*flap|%sw_matm.*move|mac learning entry moved|host.*moved",
     "MACアドレスがポート間を移動(フラップ)。L2ループや冗長切替の兆候です。頻発するなら物理構成を確認してください。"),
    (r"%cdp-4-duplex_mismatch|duplex mismatch",
     "デュプレックス不一致を検知(CDP)。片側auto/片側固定などで速度低下・エラー増加の原因。両端の設定を揃えてください。"),
    # ── PoE / 環境 / スタック（Cisco） ──
    (r"%ilpower|poe|power.?inline|給電",
     "PoE(給電)関連イベント。給電開始/停止や電力不足の可能性。給電機器の消費電力と上限を確認してください。"),
    (r"%environment|%envmon|temperature|fan|power supply|環境",
     "環境(温度/ファン/電源)の状態通知。critical/failなら物理的な冷却・電源を至急確認してください。"),
    (r"%stackmgr|stack member|スタック",
     "スタック構成の状態変化(メンバ追加/離脱/切替)。意図しない離脱ならスタックケーブルとメンバを確認してください。"),
    # ── DHCP ──
    (r"dhcpd?.*(discover|offer|request|ack)|dhcp.*assigned|dhcpack",
     "DHCPのアドレス割当プロセス。正常なリース動作です。NAK/枯渇が出る場合はスコープ/プール残量を確認してください。"),
    (r"dhcp.*(nak|declined|pool.*empty|no.*address)",
     "DHCPでアドレス割当に失敗(NAK/枯渇)。プールの空きや設定の不整合を確認してください。"),
    # ── 富士通 Si-R / SR-S / IPCOM ──
    (r"isakmp|ike sa|ipsec sa|dpd",
     "IPsec/IKE(VPN)関連。SA確立=正常。DPDでhost down・algorithm mismatched・delete SA が出たらVPN障害。対向と暗号設定を確認。"),
    (r"cmodemctl|wwan|pin code|puk|sim",
     "モバイル(WWAN/LTE)モジュール関連。PIN/PUK/SIMエラーはSIM状態やPINロックが原因。SIMと契約状態を確認してください。"),
    (r"\[line\d*\]|ppp.*line|callout|callin|disconnected by peer",
     "PPP/WAN回線の発着信・接続/切断。想定外の切断が続くなら回線品質・認証・対向を確認してください。"),
    (r"l2loopd|configuration testing protocol",
     "SR-Sのループ検出機能(CTP)。ループ検知やポート遮断(blocked)はL2ループ発生の合図。該当ポートと配線を確認してください。"),
    (r"\bipf\[|\[deny\]|\[permit\]|firewall",
     "IPCOMのファイアウォール(ipf)ログ。DENYは遮断、PERMITは許可。想定通信が止まっていないかルールを確認してください。"),
    # ── リソース逼迫（バグ寄りだが説明を補助） ──
    (r"mallocfail|out of memory|memory.*(fail|leak|low)",
     "メモリ枯渇/確保失敗。処理落ちや再起動の原因になります。プロセス別メモリ(show processes memory)を確認してください。"),
    (r"cpuhog|cpu.*(high|over)|running for longer than expected",
     "CPU高負荷/ハングの兆候。show processes cpu で原因プロセスを特定してください。ループやトラフィック急増も疑われます。"),
    (r"broadcast storm|storm.?control|ブロードキャスト.*(過多|ストーム)",
     "ブロードキャストストーム。L2ループや暴走が原因で帯域を圧迫します。storm-control設定と物理ループを確認してください。"),
    # ── F5 BIG-IP LTM ──
    (r"member .*monitor status down|pool .*member.*down",
     "BIG-IP: プールメンバー(実サーバ)の監視がダウン。該当サーバのサービス/ヘルスモニターを確認してください。負荷分散対象から外れます。"),
    (r"member .*monitor status up|pool .*member.*up",
     "BIG-IP: プールメンバーの監視が復旧(アップ)。負荷分散対象に復帰しました。正常な回復です。"),
    (r"pool .*(no members available|is down)",
     "BIG-IP: プール全体がダウン(利用可能メンバーなし)。該当仮想サーバのサービスが停止します。実サーバ群を至急確認してください。"),
    (r"failover|going active|going standby|ha process",
     "BIG-IP: HA(冗長)フェイルオーバー。Active/Standby切替が発生。going standby/offlineは要注意。頻発するなら監視/回線/設定同期を確認してください。"),
    (r"sync.*(fail|error|mismatch)|configuration.*sync",
     "BIG-IP: 構成同期(config sync)の失敗/不一致。冗長ペア間の設定差異は障害時の切替不良につながります。同期状態を確認してください。"),
    (r"ssl.*(handshake|fail|error)|certificate.*(expired|invalid|error)|tls.*(fail|error)",
     "BIG-IP: SSL/TLSまたは証明書のエラー。ハンドシェイク失敗や証明書期限切れはサービス断の原因。証明書とSSLプロファイルを確認してください。"),
    (r"\b0[0-9a-f]{7}:\d:",
     "BIG-IP: メッセージID付きイベント(msgID:level)。本文の内容と重大度levelを確認してください。levelが小さいほど深刻です。"),
    # ── Palo Alto (PAN-OS) ──
    (r",threat,|threat.*(vulnerability|virus|spyware|wildfire)",
     "Palo Alto: 脅威ログ。脆弱性攻撃/マルウェア等を検知。action が drop/reset なら防御成功、alert のみなら通過しているため要確認です。"),
    (r",threat,.*alert|action.*alert",
     "Palo Alto: 脅威を検知したが alert(通知)のみで通過。防御ポリシー(deny/drop)への変更を検討してください。"),
    (r",traffic,.*(deny|drop)|traffic.*denied",
     "Palo Alto: トラフィックがポリシーで拒否(deny/drop)。想定通信が止まっていないか、セキュリティポリシーを確認してください。"),
    (r",traffic,.*allow",
     "Palo Alto: トラフィックがポリシーで許可(allow)。正常な通信ログです。"),
    (r",system,.*(ha|failover|peer|suspended|tentative)",
     "Palo Alto: HA(冗長)状態の変化。suspended/down/tentativeは要注意。ペア間リンクと優先度、同期状態を確認してください。"),
    (r",config,|config.*(commit|committed)",
     "Palo Alto: 設定変更/コミットログ。誰がどんな変更をしたか記録されます。意図した変更か、失敗(failed)していないか確認してください。"),
    (r"globalprotect|,gp,|gateway.*(login|connect)",
     "Palo Alto: GlobalProtect(VPN)関連。接続失敗/認証エラーが続くならポータル設定・証明書・ユーザ認証を確認してください。"),
    (r"license.*(expired|expire)|autofocus.*expired",
     "Palo Alto: ライセンス/サブスクリプションの期限切れ。脅威防御やURLフィルタ等の更新が止まる可能性。ライセンス状態を確認してください。"),
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
