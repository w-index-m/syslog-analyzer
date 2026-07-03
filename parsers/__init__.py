from parsers import cisco_ios, cisco_nxos, fujitsu_sir, fujitsu_ipcom, apresia, rhel, windows
import re

SEVERITY_MAP = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG"
}

# パーサーを優先順位順に並べる
# 特定ベンダー固有キーワードを持つものを先に、汎用的なものを後に
PARSERS = [
    ("Cisco IOS/IOS-XE", cisco_ios),
    ("Cisco NX-OS",      cisco_nxos),
    ("富士通 IPCOM",      fujitsu_ipcom),  # IPCOM を Si-R より先に（共通プロセス名の衝突を回避）
    ("富士通 Si-R",       fujitsu_sir),
    ("APRESIA",          apresia),
    ("Windows",          windows),
    ("RHEL/Linux",       rhel),
]

def parse_syslog(raw: str, source_ip: str) -> dict:
    raw = raw.strip()
    for name, parser in PARSERS:
        try:
            result = parser.parse(raw, source_ip)
            if result:
                return result
        except Exception as e:
            print(f"[Parser:{name}] error: {e}")
    return _parse_generic(raw, source_ip)

def _parse_generic(raw: str, source_ip: str) -> dict:
    pri_match = re.match(r"<(\d+)>", raw)
    severity = "INFO"
    facility = "unknown"
    if pri_match:
        pri = int(pri_match.group(1))
        severity = SEVERITY_MAP.get(pri & 0x07, "INFO")
        fac_num = pri >> 3
        facility = f"facility{fac_num}"
    hm = re.search(r">\s*(?:\w{3}\s+\d+\s+[\d:]+\s+)?([\w\-\.]+)\s+", raw)
    hostname = hm.group(1) if hm else source_ip
    return {
        "vendor": "Generic/不明",
        "hostname": hostname,
        "facility": facility,
        "severity": severity,
        "severity_digit": "",
        "process": "",
        "message": raw,
        "timestamp": "",
        "tags": ["未分類"]
    }
