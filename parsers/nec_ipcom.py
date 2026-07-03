"""
NEC IPCOM EX / EX2 / VA シリーズ syslog パーサー

ログフォーマット例:
  <165>Jan  1 00:00:01 IPCOM-EX hostname ipf[1234]: [DENY] TCP 192.168.1.1:12345->10.0.0.1:80
  <165>Jan  1 00:00:01 hostname netd[1234]: IF GigabitEthernet0 link down
  <166>Jan  1 00:00:01 hostname ifmgr[100]: Port 0 state changed to DOWN
  <INFO> Jan 01 00:00:01 IPCOM kernel: message

IPCOM EX2 / VA (新フォーマット):
  <134>2024-01-01T00:00:01+09:00 hostname app_name: LEVEL message
"""
import re

SEVERITY_TEXT_MAP = {
    "EMERG": "EMERGENCY", "ALERT": "ALERT", "CRIT": "CRITICAL",
    "ERR": "ERROR", "ERROR": "ERROR", "WARN": "WARNING", "WARNING": "WARNING",
    "NOTICE": "NOTICE", "INFO": "INFO", "DEBUG": "DEBUG",
    "INFORMATION": "INFO", "CRITICAL": "CRITICAL",
}

PRI_SEVERITY = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}

# IPCOM固有プロセス名（他ベンダーと被らないもののみ）
# bgpd/ospfd/sshd 等は Si-R でも使用するため除外
IPCOM_PROCESSES = {
    "ipf", "natd", "ifmgr", "sslowd", "httpad",
    "ipcomd", "filterd", "cmdd",
}

# IPCOM EX 標準フォーマット
IPCOM_PATTERN = re.compile(
    r"(?:<(\d+)>)?"
    r"(?:(\d{4}-\d{2}-\d{2}T[\d:+]+|"
    r"\w{3}\s+\d+\s+[\d:]+|\w{3}\s+\d{1,2}\s+[\d:]+))?\s*"
    r"([\w\-\.]+)\s+"
    r"([\w\-]+)(?:\[(\d+)\])?:\s*"
    r"(?:(EMERG|ALERT|CRIT|ERR|ERROR|WARN|WARNING|NOTICE|INFO|DEBUG)\s+)?"
    r"(.*)",
    re.IGNORECASE
)

# IPCOM ファイアウォールログ
IPCOM_FW_PATTERN = re.compile(
    r"\[(PERMIT|DENY|REJECT|DROP|ACCEPT)\]\s+"
    r"(TCP|UDP|ICMP|IP)\s+"
    r"([\d\.]+)(?::(\d+))?->([\d\.]+)(?::(\d+))?",
    re.IGNORECASE
)


def _is_ipcom(raw: str) -> bool:
    raw_lower = raw.lower()
    # IPCOM固有キーワード
    keywords = [
        "ipcom", "ipf[", "ifmgr[", "netd[", "sslowd[", "filterd[",
        "ipcomd[", "cmdd[", "watchdog[", "nec ipcom", "ipcom ex",
    ]
    if any(k in raw_lower for k in keywords):
        return True
    # プロセス名パターン（process[pid]:）
    for proc in IPCOM_PROCESSES:
        if re.search(rf"\b{re.escape(proc)}\[\d+\]:", raw_lower):
            return True
    return False


def parse(raw: str, source_ip: str) -> dict | None:
    if not _is_ipcom(raw):
        return None

    m = IPCOM_PATTERN.search(raw)
    if not m:
        return None

    pri, timestamp, hostname, process, pid, level_text, message = m.groups()

    # severity 決定
    if level_text:
        severity = SEVERITY_TEXT_MAP.get(level_text.upper(), "INFO")
    elif pri:
        severity = PRI_SEVERITY.get(int(pri) & 0x07, "INFO")
    else:
        severity = "INFO"

    tags = ["NEC IPCOM"]
    msg_upper = (message or "").upper()
    proc_lower = (process or "").lower()

    # プロセス別タグ
    if proc_lower == "ipf" or "ipf[" in raw.lower():
        tags.append("ファイアウォール")
        fw = IPCOM_FW_PATTERN.search(message or "")
        if fw:
            action, proto, src_ip, src_port, dst_ip, dst_port = fw.groups()
            act_upper = action.upper()
            if act_upper in ("DENY", "REJECT", "DROP"):
                tags.append("通信拒否")
                tags.append("障害候補")
            else:
                tags.append("通信許可")

    if proc_lower in ("ifmgr", "netd"):
        tags.append("インターフェース")
        if "DOWN" in msg_upper:
            tags.append("リンクDOWN"); tags.append("障害候補")
        if "UP" in msg_upper:
            tags.append("リンクUP")

    if proc_lower == "natd":
        tags.append("NAT")

    if proc_lower in ("bgpd", "ospfd", "ripd"):
        tags.append("ルーティング")
        if "DOWN" in msg_upper or "FAIL" in msg_upper:
            tags.append("障害候補")

    if proc_lower == "authd":
        tags.append("認証")
        if "FAIL" in msg_upper or "DENY" in msg_upper:
            tags.append("認証失敗")

    if proc_lower in ("vpnd", "sslowd"):
        tags.append("VPN/SSL-VPN")

    if proc_lower == "dhcpd":
        tags.append("DHCP")

    # 汎用キーワード
    if "LINK DOWN" in msg_upper or "LINE DOWN" in msg_upper or "PORT DOWN" in msg_upper:
        if "障害候補" not in tags:
            tags.append("障害候補")
    if "ATTACK" in msg_upper or "INTRUSION" in msg_upper or "SCAN" in msg_upper:
        tags.append("セキュリティ")
    if "CPU" in msg_upper and ("HIGH" in msg_upper or "OVER" in msg_upper):
        tags.append("高CPU")
    if "MEMORY" in msg_upper and ("FULL" in msg_upper or "LACK" in msg_upper):
        tags.append("メモリ不足")

    return {
        "vendor": "NEC IPCOM",
        "hostname": hostname or source_ip,
        "facility": "IPCOM",
        "severity": severity,
        "severity_digit": "",
        "process": f"{process}[{pid}]" if pid else (process or "ipcomd"),
        "message": (message or "").strip(),
        "timestamp": timestamp or "",
        "tags": tags,
    }
