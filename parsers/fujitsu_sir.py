"""
富士通 Si-R シリーズ syslog パーサー

対応機種: Si-R G100/G200/G210/bx/V20/V30
ログフォーマット例:
  <22>Jun 30 10:00:00 SiR-G120 siRd[123]: INFO PPP line up (BRI0) remote=203.0.113.1
  <19>Jun 30 10:01:00 SiR-G120 siRd[123]: ERR PPP line down (BRI0) reason=LCP timeout
  <22>Jun 30 10:02:00 SiR-G120 ospfd[456]: INFO OSPF neighbor 10.1.1.2 state changed to Full
  <165>Jun 30 10:03:00 SiRbx001 pppd[100]: WARN LCP negotiation failed
  <165>Jun 30 10:03:00 sirg200 iked[200]: INFO IKE SA established peer=203.0.113.1
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

# Si-R 固有キーワード（ホスト名・プロセス名）
SIR_HOST_KEYWORDS = [
    "sir", "si-r", "sirg", "sirbx", "sir-bx", "sir-v",
    "g100", "g120", "g200", "g210", "sirgx",
]

SIR_PROCESS_KEYWORDS = [
    "siRd", "pppd", "ospfd", "bgpd", "ripd", "iked", "l2tpd",
    "sshd", "snmpd", "ntpd", "dhcpd", "dnsd", "natd", "filterd",
    "watchd", "sysd", "netd", "ifmgrd",
]

SIR_PATTERN = re.compile(
    r"(?:<(\d+)>)?"
    r"(?:(\w{3}\s+\d{1,2}\s+[\d:]+)\s+)?"
    r"([\w\-\.]+)\s+"
    r"(?:([\w\[\]0-9\-]+):\s+)?"
    r"(?:(EMERG|ALERT|CRIT|ERR|ERROR|WARN|WARNING|NOTICE|INFO|INFORMATION|DEBUG)\s+)?"
    r"(.*)"
)


def _is_sir(raw: str) -> bool:
    raw_lower = raw.lower()
    # IPCOM ログとの衝突を避ける（hostname に ipcom が含まれれば IPCOM パーサーに任せる）
    if "ipcom" in raw_lower or "ipf[" in raw_lower or "ifmgr[" in raw_lower:
        return False
    # Si-R 固有ホスト名キーワードが一致すれば確定
    for k in SIR_HOST_KEYWORDS:
        if k in raw_lower:
            return True
    # プロセス名だけでの判定は、Si-R 固有プロセス（siRd/pppd 等）に限定
    # bgpd/ospfd/sshd は複数ベンダーで共用するためホスト名なしでは判定しない
    sir_only_procs = ["siRd", "pppd", "iked", "l2tpd", "watchd", "netd", "ifmgrd"]
    for k in sir_only_procs:
        if k.lower() in raw_lower:
            return True
    return False


def parse(raw: str, source_ip: str) -> dict | None:
    if not _is_sir(raw):
        return None

    m = SIR_PATTERN.search(raw)
    if not m:
        return None

    pri, timestamp, hostname, process, level_text, message = m.groups()

    # severity 決定
    if level_text:
        severity = SEVERITY_TEXT_MAP.get(level_text.upper(), "INFO")
    elif pri:
        severity = PRI_SEVERITY.get(int(pri) & 0x07, "INFO")
    else:
        severity = "INFO"

    proc_lower = (process or "").lower().split("[")[0]
    msg_upper  = (message or "").upper()

    tags = ["Si-R"]

    # ── プロトコル/機能別タグ ──────────────────────────────────────
    if "PPP" in msg_upper or proc_lower == "pppd":
        tags.append("PPP")
        if "LINE UP" in msg_upper or "LINK UP" in msg_upper or " UP " in msg_upper:
            tags.append("リンクUP")
        if ("LINE DOWN" in msg_upper or "LINK DOWN" in msg_upper
                or " DOWN " in msg_upper or "DISCONNECT" in msg_upper):
            tags.append("リンクDOWN"); tags.append("障害候補")
        if "FAIL" in msg_upper or "TIMEOUT" in msg_upper or "ERR" in msg_upper:
            tags.append("PPP障害"); tags.append("障害候補")

    if "OSPF" in msg_upper or proc_lower == "ospfd":
        tags.append("ルーティング"); tags.append("OSPF")
        if "FULL" in msg_upper or "STATE.*FULL" in msg_upper:
            tags.append("ネイバー確立")
        if "DOWN" in msg_upper or "DEAD" in msg_upper or "LOST" in msg_upper:
            tags.append("ルーティング障害"); tags.append("障害候補")

    if "BGP" in msg_upper or proc_lower == "bgpd":
        tags.append("ルーティング"); tags.append("BGP")
        if "ESTABLISHED" in msg_upper or "OPEN" in msg_upper:
            tags.append("ネイバー確立")
        if "DOWN" in msg_upper or "IDLE" in msg_upper or "NOTIF" in msg_upper:
            tags.append("ルーティング障害"); tags.append("障害候補")

    if "RIP" in msg_upper or proc_lower == "ripd":
        tags.append("ルーティング"); tags.append("RIP")

    if "IKE" in msg_upper or proc_lower == "iked":
        tags.append("VPN"); tags.append("IPsec")
        if "ESTABLISHED" in msg_upper or "SA" in msg_upper:
            tags.append("VPN確立")
        if "FAIL" in msg_upper or "DOWN" in msg_upper or "DELETE" in msg_upper:
            tags.append("VPN障害"); tags.append("障害候補")

    if "L2TP" in msg_upper or proc_lower == "l2tpd":
        tags.append("VPN"); tags.append("L2TP")

    if proc_lower in ("sshd",) or "SSH" in msg_upper:
        tags.append("リモートアクセス")
        if "ACCEPT" in msg_upper or "LOGIN" in msg_upper:
            tags.append("認証成功")
        if "FAIL" in msg_upper or "INVALID" in msg_upper or "DENY" in msg_upper:
            tags.append("認証失敗"); tags.append("セキュリティ")

    if "NAT" in msg_upper or proc_lower == "natd":
        tags.append("NAT")

    if "DHCP" in msg_upper or proc_lower == "dhcpd":
        tags.append("DHCP")

    if proc_lower == "snmpd" or "SNMP" in msg_upper:
        tags.append("SNMP")

    # 汎用的な障害キーワード
    if any(k in msg_upper for k in ("FAIL", "ERR", "TIMEOUT", "RESET", "ABORT", "LOST")):
        if "障害候補" not in tags:
            tags.append("障害候補")

    if "INTERFACE" in msg_upper or "PORT" in msg_upper:
        if "DOWN" in msg_upper:
            tags.append("インターフェースDOWN"); tags.append("障害候補")
        if "UP" in msg_upper:
            tags.append("インターフェースUP")

    if "CPU" in msg_upper and ("HIGH" in msg_upper or "OVER" in msg_upper):
        tags.append("高CPU"); tags.append("障害候補")

    if "MEMORY" in msg_upper and ("FULL" in msg_upper or "LACK" in msg_upper or "LOW" in msg_upper):
        tags.append("メモリ不足"); tags.append("障害候補")

    return {
        "vendor": "富士通 Si-R",
        "hostname": hostname or source_ip,
        "facility": "Si-R",
        "severity": severity,
        "severity_digit": "",
        "process": process or "siRd",
        "message": (message or "").strip(),
        "timestamp": timestamp or "",
        "tags": tags,
    }
