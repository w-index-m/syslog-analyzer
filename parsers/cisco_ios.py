import re

# Cisco IOS/IOS-XE syslog format:
# <priority>timestamp: %FACILITY-SEVERITY-MNEMONIC: message
# Example: <189>Jun 30 10:00:00 switch01 %SYS-5-CONFIG_I: Configured from console

SEVERITY_MAP = {
    "0": "EMERGENCY", "1": "ALERT", "2": "CRITICAL",
    "3": "ERROR", "4": "WARNING", "5": "NOTICE",
    "6": "INFO", "7": "DEBUG"
}

# RFC5424 severity from PRI field
def pri_to_severity(pri):
    try:
        level = int(pri) & 0x07
        return SEVERITY_MAP.get(str(level), "UNKNOWN")
    except:
        return "UNKNOWN"

IOS_PATTERN = re.compile(
    r"(?:<(\d+)>)?"                              # PRI (optional)
    r"(?:\d+:\s+)?"                              # sequence number (optional)
    r"(?:(\w{3}\s+\d+\s+[\d:]+)\s+)?"           # timestamp
    r"(?:([\w\-\.]+)\s+)?"                       # hostname
    r"%([A-Z0-9_]+)"                             # FACILITY
    r"-(\d)"                                     # SEVERITY digit
    r"-([A-Z0-9_]+)"                             # MNEMONIC
    r":\s*(.*)"                                  # message
)

def parse(raw: str, source_ip: str) -> dict | None:
    m = IOS_PATTERN.search(raw)
    if not m:
        return None
    pri, timestamp, hostname, facility, sev_digit, mnemonic, message = m.groups()
    severity_name = SEVERITY_MAP.get(sev_digit, "UNKNOWN")
    tags = [facility, mnemonic]
    # 重要なニーモニックにタグ追加
    if any(k in mnemonic for k in ["DOWN", "FAIL", "ERR", "DUPLEX", "LOOP"]):
        tags.append("障害候補")
    if "CONFIG" in mnemonic:
        tags.append("設定変更")
    if "AUTH" in mnemonic or "LOGIN" in mnemonic:
        tags.append("認証")
    return {
        "vendor": "Cisco IOS/IOS-XE",
        "hostname": hostname or source_ip,
        "facility": facility,
        "severity": severity_name,
        "severity_digit": sev_digit,
        "process": mnemonic,
        "message": message.strip(),
        "timestamp": timestamp or "",
        "tags": tags
    }
