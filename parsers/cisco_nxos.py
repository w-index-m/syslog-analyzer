import re

# Cisco NX-OS syslog format:
# <priority>timestamp switch %FACILITY-SEVERITY-MNEMONIC: message
# Example: <163>2024 Jun 30 10:00:00 JST nexus01 %ETH_PORT_CHANNEL-5-FOP_CHANGED: ...

SEVERITY_MAP = {
    "0": "EMERGENCY", "1": "ALERT", "2": "CRITICAL",
    "3": "ERROR", "4": "WARNING", "5": "NOTICE",
    "6": "INFO", "7": "DEBUG"
}

NXOS_PATTERN = re.compile(
    r"(?:<(\d+)>)?"
    r"(?:(\d{4}\s+\w{3}\s+\d+\s+[\d:]+(?:\s+\w+)?)\s+)?"  # timestamp with optional TZ
    r"([\w\-\.]+)\s+"                                         # hostname
    r"%([A-Z0-9_]+)"                                          # FACILITY
    r"-(\d)"                                                  # SEVERITY
    r"-([A-Z0-9_]+)"                                          # MNEMONIC
    r":\s*(.*)"                                               # message
)

# NX-OS 年先頭タイムスタンプ（例: "2024 Jun 30 10:00:00 JST"）
NXOS_TIMESTAMP = re.compile(r"\d{4}\s+\w{3}\s+\d+\s+[\d:]+")

# NX-OS 固有ファシリティ（IOS/IOS-XE には無いもの）
NXOS_FACILITIES = {
    "VPC", "ETH_PORT_CHANNEL", "ETHPORT", "MODULE", "PLATFORM", "VSHD",
    "VDC_MGR", "FEATURE_MGR", "SATCTRL", "NOHMS", "CARDCLIENT", "IPQOSMGR",
    "ASCII_CFG", "PFMA", "SYSMGR", "PORT_CHANNEL", "MTS", "MCM", "FWM",
}


def parse(raw: str, source_ip: str) -> dict | None:
    m = NXOS_PATTERN.search(raw)
    if not m:
        return None
    facility = m.group(4)
    # NX-OS 確定条件: 年先頭タイムスタンプ or NX-OS 固有ファシリティのいずれか。
    # これが無いものは IOS/IOS-XE に譲る（両者は %FAC-N-MNEM 形式が同一のため）。
    if not (NXOS_TIMESTAMP.search(raw) or facility in NXOS_FACILITIES):
        return None
    pri, timestamp, hostname, facility, sev_digit, mnemonic, message = m.groups()
    severity_name = SEVERITY_MAP.get(sev_digit, "UNKNOWN")
    tags = [facility, mnemonic, "NX-OS"]
    if any(k in mnemonic for k in ["DOWN", "FAIL", "ERR", "SUSPEND"]):
        tags.append("障害候補")
    if "VPC" in mnemonic or "LACP" in mnemonic:
        tags.append("冗長化")
    if "OSPF" in mnemonic or "BGP" in mnemonic or "ISIS" in mnemonic:
        tags.append("ルーティング")
    return {
        "vendor": "Cisco NX-OS",
        "hostname": hostname or source_ip,
        "facility": facility,
        "severity": severity_name,
        "severity_digit": sev_digit,
        "process": mnemonic,
        "message": message.strip(),
        "timestamp": timestamp or "",
        "tags": tags
    }
