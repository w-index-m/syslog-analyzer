import re

ICMP_REDIRECT_PATTERN = re.compile(
    r"ICMP redirect sent to ([\d\.]+).*?(?:for dest|for) ([\d\.]+)"
    r"(?:.*?use gw ([\d\.]+))?",
    re.IGNORECASE
)

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
    # ループ検知（Catalyst LoopDetect / keepalive loopback / err-disable loopback）
    _mn = mnemonic.upper()
    _msg_up = (message or "").upper()
    if ("LOOP_BACK_DETECTED" in _mn or "LOOPDETECT" in _mn
            or "LOOPBACK" in _mn or "LOOP" in _mn
            or "LOOP-BACK DETECTED" in _msg_up or "LOOP DETECTED" in _msg_up
            or ("ERR_DISABLE" in _mn and "LOOP" in _msg_up)):
        tags.append("ループ検知")
        if "障害候補" not in tags:
            tags.append("障害候補")
    if "ERR_DISABLE" in _mn or "ERRDISABLE" in _mn:
        tags.append("err-disable")
    if "CONFIG" in mnemonic:
        tags.append("設定変更")
    if "AUTH" in mnemonic or "LOGIN" in mnemonic:
        tags.append("認証")
    if "REDIRECT" in mnemonic or "ICMPREDIRECT" in mnemonic:
        tags.append("ICMP Redirect")
        tags.append("障害候補")
        m = ICMP_REDIRECT_PATTERN.search(message)
        if m:
            tags.append(f"redirect_to:{m.group(1)}")
            tags.append(f"redirect_dest:{m.group(2)}")
            if m.group(3):
                tags.append(f"redirect_gw:{m.group(3)}")
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
