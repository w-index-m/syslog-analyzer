import re

# 富士通 Si-R syslog format例:
# <priority>timestamp hostname [process]: LEVEL message
# Example: <22>Jun 30 10:00:00 SiR-G120 siRd[123]: INFO PPP line up (BRI0)

SEVERITY_TEXT_MAP = {
    "EMERG": "EMERGENCY", "ALERT": "ALERT", "CRIT": "CRITICAL",
    "ERR": "ERROR", "ERROR": "ERROR", "WARN": "WARNING", "WARNING": "WARNING",
    "NOTICE": "NOTICE", "INFO": "INFO", "DEBUG": "DEBUG",
    "INFORMATION": "INFO"
}

PRI_SEVERITY = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG"
}

SIR_PATTERN = re.compile(
    r"(?:<(\d+)>)?"
    r"(?:(\w{3}\s+\d+\s+[\d:]+)\s+)?"
    r"([\w\-\.]+)\s+"
    r"(?:([\w\[\]0-9]+):\s+)?"
    r"(?:(EMERG|ALERT|CRIT|ERR|ERROR|WARN|WARNING|NOTICE|INFO|INFORMATION|DEBUG)\s+)?"
    r"(.*)"
)

def parse(raw: str, source_ip: str) -> dict | None:
    # Si-R特有キーワードチェック
    sir_keywords = ["siRd", "pppd", "ospfd", "bgpd", "sshd", "Si-R", "SiR", "G100", "G120", "G200"]
    if not any(k.lower() in raw.lower() for k in sir_keywords):
        return None
    m = SIR_PATTERN.search(raw)
    if not m:
        return None
    pri, timestamp, hostname, process, level_text, message = m.groups()
    # severityをPRIフィールドかテキストから決定
    if level_text:
        severity = SEVERITY_TEXT_MAP.get(level_text.upper(), "INFO")
    elif pri:
        severity = PRI_SEVERITY.get(int(pri) & 0x07, "INFO")
    else:
        severity = "INFO"
    tags = ["Si-R"]
    msg_upper = message.upper()
    if "PPP" in msg_upper:
        tags.append("PPP")
    if "LINE UP" in msg_upper or "LINK UP" in msg_upper:
        tags.append("リンクUP")
    if "LINE DOWN" in msg_upper or "LINK DOWN" in msg_upper:
        tags.append("リンクDOWN"); tags.append("障害候補")
    if "OSPF" in msg_upper or "BGP" in msg_upper or "RIP" in msg_upper:
        tags.append("ルーティング")
    if "SSH" in msg_upper or "LOGIN" in msg_upper or "AUTH" in msg_upper:
        tags.append("認証")
    return {
        "vendor": "富士通 Si-R",
        "hostname": hostname or source_ip,
        "facility": "Si-R",
        "severity": severity,
        "severity_digit": "",
        "process": process or "siRd",
        "message": message.strip(),
        "timestamp": timestamp or "",
        "tags": tags
    }
