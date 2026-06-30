import re
import json

# Windows Event Log をsyslog転送した場合のパーサー
# 対応エージェント:
#   - NXLog Community Edition
#   - Winlogbeat (Elastic)
#   - Snare for Windows
#
# NXLog出力例 (RFC3164):
#   <14>Jun 30 10:00:00 WIN-SERVER01 MSWinEventLog[Security]: EventID=4624 ...
#
# Winlogbeat出力例 (JSON埋め込み):
#   <14>Jun 30 10:00:00 WIN-SERVER01 winlogbeat: {"event":{"code":4624},...}
#
# Snare出力例:
#   <13>Jun 30 10:00:00 WIN-SERVER01 MSWinEventLog\t1\tSecurity\t...\t4624\t...

SEVERITY_MAP = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG"
}

# Windows EventID → 意味マッピング（主要なもの）
EVENTID_MAP = {
    # 認証・ログオン
    4624: ("INFO",    "ログオン成功"),
    4625: ("WARNING", "ログオン失敗"),
    4634: ("INFO",    "ログオフ"),
    4647: ("INFO",    "ユーザー開始ログオフ"),
    4648: ("WARNING", "明示的資格情報でログオン"),
    4672: ("NOTICE",  "特権付きログオン"),
    4720: ("NOTICE",  "ユーザーアカウント作成"),
    4722: ("NOTICE",  "ユーザーアカウント有効化"),
    4723: ("NOTICE",  "パスワード変更試行"),
    4724: ("WARNING", "パスワードリセット試行"),
    4725: ("WARNING", "ユーザーアカウント無効化"),
    4726: ("WARNING", "ユーザーアカウント削除"),
    4728: ("NOTICE",  "グループにメンバー追加"),
    4732: ("NOTICE",  "ローカルグループにメンバー追加"),
    4740: ("ERROR",   "ユーザーアカウントロックアウト"),
    4768: ("INFO",    "Kerberosチケット要求(TGT)"),
    4769: ("INFO",    "Kerberosサービスチケット要求"),
    4771: ("WARNING", "Kerberos事前認証失敗"),
    4776: ("INFO",    "NTLM認証試行"),
    # システム
    1074: ("NOTICE",  "システムシャットダウン/再起動"),
    6005: ("NOTICE",  "イベントログサービス開始（起動）"),
    6006: ("NOTICE",  "イベントログサービス停止（シャットダウン）"),
    6008: ("ERROR",   "予期しないシャットダウン"),
    6013: ("INFO",    "システム稼働時間"),
    # オブジェクトアクセス
    4663: ("INFO",    "オブジェクトアクセス試行"),
    4688: ("INFO",    "新しいプロセス作成"),
    4689: ("INFO",    "プロセス終了"),
    # ポリシー変更
    4719: ("WARNING", "システム監査ポリシー変更"),
    4739: ("WARNING", "ドメインポリシー変更"),
    # ネットワーク
    5140: ("INFO",    "ネットワーク共有アクセス"),
    5145: ("INFO",    "ネットワーク共有チェック"),
    # サービス
    7034: ("ERROR",   "サービス予期しない終了"),
    7036: ("NOTICE",  "サービス状態変化"),
    7040: ("NOTICE",  "サービス開始種別変更"),
    7045: ("NOTICE",  "新しいサービスインストール"),
    # Windows Defender / Security
    1116: ("ERROR",   "マルウェア検出"),
    1117: ("WARNING", "マルウェア対処実行"),
    5001: ("ERROR",   "リアルタイム保護無効"),
}

# NXLog形式パターン
NXLOG_PATTERN = re.compile(
    r"(?:<(\d+)>)?"
    r"(?:(\w{3}\s+\d+\s+[\d:]+)\s+)?"
    r"([\w\-\.]+)\s+"
    r"MSWinEventLog(?:\[([^\]]+)\])?[:\s]+"
    r"(.*)"
)

# Winlogbeat JSON埋め込みパターン
WINLOGBEAT_PATTERN = re.compile(
    r"(?:<(\d+)>)?"
    r"(?:(\w{3}\s+\d+\s+[\d:]+)\s+)?"
    r"([\w\-\.]+)\s+"
    r"winlogbeat[:\s]+(.*)"
)

# Snare形式パターン (タブ区切り)
SNARE_PATTERN = re.compile(
    r"(?:<(\d+)>)?"
    r"(?:(\w{3}\s+\d+\s+[\d:]+)\s+)?"
    r"([\w\-\.]+)\s+"
    r"MSWinEventLog\t(\d+)\t(\w+)\t[^\t]+\t(\d+)\t"  # priority, channel, eventid
    r"(.*)"
)

# 汎用Windowsキーワード検出
WIN_KEYWORDS = [
    "MSWinEventLog", "winlogbeat", "EventID", "EvtID",
    "Security", "System", "Application",
    "Microsoft-Windows", "WIN-", "DESKTOP-", "DC-",
    "WinEvent", "snare"
]

def _extract_eventid(message: str) -> int | None:
    patterns = [
        r"EventID[=:\s]+(\d+)",
        r"EvtID[=:\s]+(\d+)",
        r'"code"\s*:\s*(\d+)',
        r"event_id[=:\s]+(\d+)",
    ]
    for p in patterns:
        m = re.search(p, message, re.IGNORECASE)
        if m:
            return int(m.group(1))
    return None

def _extract_channel(message: str) -> str:
    patterns = [
        r"Channel[=:\s]+([^\s,;]+)",
        r'"channel"\s*:\s*"([^"]+)"',
        r"(Security|System|Application|Setup)\b"
    ]
    for p in patterns:
        m = re.search(p, message, re.IGNORECASE)
        if m:
            return m.group(1)
    return "Unknown"

def _build_tags(channel: str, eventid: int | None, severity: str) -> list:
    tags = ["Windows"]
    if channel:
        tags.append(channel)
    if eventid:
        tags.append(f"EventID:{eventid}")
        # EventIDベースのカテゴリタグ
        eid = eventid
        if eid in (4624, 4625, 4634, 4647, 4648, 4672, 4740, 4768, 4769, 4771, 4776):
            tags.append("認証")
        if eid in (4625, 4740, 4771):
            tags.append("障害候補")
        if eid in (4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732):
            tags.append("アカウント管理")
        if eid in (1074, 6005, 6006, 6008):
            tags.append("システムライフサイクル")
        if eid == 6008:
            tags.append("障害候補")
        if eid in (4688, 4689):
            tags.append("プロセス")
        if eid in (7034, 7036, 7040, 7045):
            tags.append("サービス")
        if eid == 7034:
            tags.append("障害候補")
        if eid in (1116, 1117, 5001):
            tags.append("セキュリティ"); tags.append("障害候補")
    if severity in ("ERROR", "CRITICAL", "ALERT", "EMERGENCY"):
        if "障害候補" not in tags:
            tags.append("障害候補")
    return tags

def parse(raw: str, source_ip: str) -> dict | None:
    if not any(k in raw for k in WIN_KEYWORDS):
        return None

    pri = None
    timestamp = ""
    hostname = source_ip
    channel = ""
    message = raw
    eventid = None

    # Snare形式を試す
    ms = SNARE_PATTERN.match(raw)
    if ms:
        pri, timestamp, hostname, priority_str, channel, eventid_str, message = ms.groups()
        eventid = int(eventid_str) if eventid_str else None

    # NXLog形式を試す
    elif "MSWinEventLog" in raw:
        mn = NXLOG_PATTERN.match(raw)
        if mn:
            pri, timestamp, hostname, channel, message = mn.groups()
            channel = channel or _extract_channel(message)
            eventid = _extract_eventid(message)

    # Winlogbeat JSON形式を試す
    elif "winlogbeat" in raw.lower():
        mw = WINLOGBEAT_PATTERN.match(raw)
        if mw:
            pri, timestamp, hostname, json_str = mw.groups()
            try:
                data = json.loads(json_str)
                eventid = (data.get("event", {}).get("code") or
                           data.get("winlog", {}).get("event_id"))
                channel = (data.get("winlog", {}).get("channel") or
                           data.get("log", {}).get("file", {}).get("path", ""))
                message = json_str
            except Exception:
                eventid = _extract_eventid(json_str)
                channel = _extract_channel(json_str)
                message = json_str

    # 汎用Windows（EventIDが含まれるケース）
    else:
        eventid = _extract_eventid(raw)
        channel = _extract_channel(raw)
        # ホスト名抽出
        hm = re.search(r"(?:<\d+>)?(?:\w{3}\s+\d+\s+[\d:]+\s+)?([\w\-\.]+)\s+", raw)
        hostname = hm.group(1) if hm else source_ip

    # PRI→severity
    pri_int = int(pri) if pri else 14  # default: user.info
    severity_from_pri = SEVERITY_MAP.get(pri_int & 0x07, "INFO")

    # EventIDベースのseverity（こちらを優先）
    if eventid and eventid in EVENTID_MAP:
        severity, event_label = EVENTID_MAP[eventid]
        summary_hint = event_label
    else:
        severity = severity_from_pri
        summary_hint = f"EventID:{eventid}" if eventid else "Windowsイベント"

    tags = _build_tags(channel, eventid, severity)

    return {
        "vendor": "Windows",
        "hostname": hostname or source_ip,
        "facility": channel or "Windows",
        "severity": severity,
        "severity_digit": str(pri_int & 0x07) if pri else "",
        "process": f"EventID:{eventid}" if eventid else "WinEvent",
        "message": f"[{summary_hint}] {message[:300]}",
        "timestamp": timestamp or "",
        "tags": tags,
        "eventid": eventid,
        "channel": channel
    }
