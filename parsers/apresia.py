import re

# APRESIA ApresiaLight syslog format例:
# <priority>timestamp hostname EVENT_TYPE: message
# Example: <131>Jun 30 10:00:00 apresia01 LINK_DOWN: Port 1/0/1 link down

SEVERITY_MAP = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG"
}

APRESIA_KEYWORDS = [
    "apresia", "APRESIA", "apresialight", "ApresiaLight",
    "LINK_DOWN", "LINK_UP", "SPANNING_TREE", "MAC_FLOOD",
    "PORT_SECURITY", "LOOP_DETECT", "STP", "RSTP", "MSTP"
]

APRESIA_PATTERN = re.compile(
    r"(?:<(\d+)>)?"
    r"(?:(\w{3}\s+\d+\s+[\d:]+)\s+)?"
    r"([\w\-\.]+)\s+"
    r"(?:([A-Z][A-Z0-9_]+):\s*)?"   # EVENT_TYPE
    r"(.*)"
)

EVENT_SEVERITY = {
    "LINK_DOWN": "ERROR", "PORT_DOWN": "ERROR", "LOOP_DETECT": "CRITICAL",
    "MAC_FLOOD": "WARNING", "PORT_SECURITY": "WARNING",
    "LINK_UP": "NOTICE", "PORT_UP": "NOTICE",
    "STP": "NOTICE", "RSTP": "NOTICE", "MSTP": "NOTICE",
    "CONFIG": "INFO", "LOGIN": "INFO", "LOGOUT": "INFO",
    "SPANNING_TREE": "NOTICE"
}

def parse(raw: str, source_ip: str) -> dict | None:
    if not any(k in raw for k in APRESIA_KEYWORDS):
        # PRIフィールドのみの汎用ケースも試みる（APRESIAはフォーマットが薄い）
        # ホスト名にapresia含む場合のみ通す
        if "apresia" not in raw.lower():
            return None
    m = APRESIA_PATTERN.search(raw)
    if not m:
        return None
    pri, timestamp, hostname, event_type, message = m.groups()
    # severityをイベントタイプから推定
    severity = EVENT_SEVERITY.get(event_type or "", None)
    if not severity and pri:
        severity = SEVERITY_MAP.get(int(pri) & 0x07, "INFO")
    severity = severity or "INFO"
    tags = ["APRESIA"]
    if event_type:
        tags.append(event_type)
    msg_upper = (message or "").upper()
    if "DOWN" in msg_upper or event_type in ("LINK_DOWN", "PORT_DOWN", "LOOP_DETECT"):
        tags.append("障害候補")
    if "STP" in msg_upper or "SPANNING" in msg_upper:
        tags.append("STP")
    if "PORT" in msg_upper:
        tags.append("ポート")
    return {
        "vendor": "APRESIA ApresiaLight",
        "hostname": hostname or source_ip,
        "facility": "APRESIA",
        "severity": severity,
        "severity_digit": "",
        "process": event_type or "APRESIA",
        "message": message.strip() if message else raw,
        "timestamp": timestamp or "",
        "tags": tags
    }
