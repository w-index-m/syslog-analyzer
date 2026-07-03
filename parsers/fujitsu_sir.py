"""
富士通/エフサステクノロジーズ Si-R シリーズ syslog パーサー

出典: Si-R G12x/G21x シリーズ メッセージ集 (2026年6月版) の実メッセージに準拠。
対応機種: Si-R G100/G110/G120/G200/G210 ほか Si-R シリーズ

システムログの形式（メッセージ集より）:
  <date> <host> <machine> : <message>
  ・SYSLOG サーバ送信時は <machine>（機種名）は付かず、
    工場出荷時（RFC 準拠ヘッダなし）では <message>（"<process>: 本文"）のみ送信。

実プロセス名（メッセージ集の出現実績・多い順）:
  protocol(PPP/WAN/リンク), isakmp(IPsec/IKE), bgpd, nsm(VRRP/経路),
  ospfd/ospf6d, ripd/rip6d, aaa_radiusd/aaad/authd(認証), proxydns,
  cmodemctl(WWAN/モバイル), dhcpcd/dhcp6cd(DHCPクライアント),
  ngnd/v6plusd(IPoE/v6プラス), dvpnsd(動的VPN), pimsmd(マルチキャスト),
  mstpd(STP), logon/telnetd/sshlogin/sshd/ftpd/sftpd/httpd(ログイン),
  init/enabled(システム)

実メッセージ例（メッセージ集の原文）:
  protocol: ether 1 1 link up
  protocol: ether 1 3 link down
  protocol: [line0] ch1 disconnected by peer
  isakmp: DPD watching host is down. [203.0.113.1]
  isakmp: IPsec SA encryption algorithm mismatched.
  bgpd: 10.0.0.1 recv NOTIFICATION 6/2 (Cease/Administrative Shutdown)
  nsm: vrrp master router down detection. lan0 vrid1 [192.168.1.1] #3
  cmodemctl: [WWAN1] PIN code error. <modemmodule> (PUK required)
  sshlogin: login admin as administrator on ssh 1 from 10.0.0.5
"""
import re

PRI_SEVERITY = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}

# ── Si-R 固有（ルーター/WAN 系）プロセス。SR-S(L2スイッチ)には存在しないため
#    これらがあれば Si-R と確定できる。
SIR_ROUTER_PROCS = {
    "isakmp", "bgpd", "ospfd", "ospf6d", "ripd", "rip6d",
    "dvpnsd", "ngnd", "v6plusd", "cmodemctl", "proxydns",
    "dhcpcd", "dhcp6cd", "pimsmd", "icmpwatchd", "track_congestiond",
    "pppoe", "pkid", "trackd", "musbd", "infoexcd", "cmodemsd",
}

# ── Si-R でも SR-S でも使われる共有プロセス（単独では判定不可、ホスト名併用）
SIR_SHARED_PROCS = {
    "protocol", "nsm", "mstpd", "aaad", "aaa_radiusd", "authd",
    "logon", "telnetd", "sshlogin", "sshd", "ftpd", "sftpd", "httpd",
    "init", "enabled", "conftryd", "devscand", "mountd", "scheduled",
}

# Si-R 機種名・ホスト名キーワード
SIR_HOST_KEYWORDS = [
    "si-r", "sir-", "sirg", "sirbx", "sir_",
    "g100", "g110", "g120", "g200", "g210",
]

# SR-S 固有シグネチャ（これらがあれば Si-R ではなく SR-S）
SRS_EXCLUSIVE = ["l2loopd", "configuration testing protocol"]

SIR_PATTERN = re.compile(
    r"(?:<(\d+)>)?"
    r"(?:\s*(\w{3}\s+\d{1,2}\s+[\d:]+)\s+)?"      # timestamp (任意)
    r"(?:([\w\-\.]+)\s+)?"                          # hostname (任意)
    r"([A-Za-z][\w\-]*?):\s*"                       # process 名
    r"(.*)"                                         # message 本文
)


def _is_sir(raw: str) -> bool:
    raw_lower = raw.lower()
    # IPCOM / SR-S との衝突回避
    if "ipcom" in raw_lower or "ipf[" in raw_lower:
        return False
    if any(s in raw_lower for s in SRS_EXCLUSIVE):
        return False

    # プロセス名を抽出
    m = re.search(r"(?:^|\s)([a-z][\w\-]*?):\s", raw_lower)
    proc = m.group(1) if m else ""

    # 1) Si-R 固有ルータープロセスがあれば確定
    if proc in SIR_ROUTER_PROCS:
        return True
    # 2) Si-R ホスト名キーワードがあれば確定
    if any(k in raw_lower for k in SIR_HOST_KEYWORDS):
        return True
    # 3) 共有プロセス + Si-R 固有の PPP/WAN パターン
    if proc == "protocol" and re.search(r"\[line\d*\]|\bch\d+\b|callout|callin|disconnected by peer", raw_lower):
        return True
    return False


def parse(raw: str, source_ip: str) -> dict | None:
    if not _is_sir(raw):
        return None

    m = SIR_PATTERN.search(raw)
    if not m:
        return None

    pri, timestamp, hostname, process, message = m.groups()
    process = (process or "").strip()
    message = (message or "").strip()
    proc = process.lower()
    msg = message.lower()

    severity = PRI_SEVERITY.get(int(pri) & 0x07, "INFO") if pri else "INFO"

    tags = ["Si-R"]

    # ── リンク UP/DOWN（protocol: ether/lan/linkaggregation ... link up/down） ──
    link_m = re.search(r"(ether|lan|linkaggregation)\s+([\d ]+?)\s*(link up|link down|is force down)", message, re.IGNORECASE)
    if link_m:
        tags.append("インターフェース")
        state = link_m.group(3).lower()
        if "link up" in state:
            tags.append("リンクUP")
        elif "link down" in state:
            tags.append("リンクDOWN"); tags.append("障害候補")
            severity = "WARNING" if severity == "INFO" else severity
        elif "force down" in state:
            tags.append("ポート閉塞"); tags.append("障害候補")

    # ── PPP / WAN 回線（protocol: [line] ...） ──────────────────
    if proc == "protocol" and ("[line" in msg or re.search(r"\bch\d+\b", msg) or "callout" in msg or "callin" in msg):
        tags.append("WAN"); tags.append("PPP")
        if "disconnected" in msg or "line error" in msg or "failed" in msg:
            tags.append("回線切断"); tags.append("障害候補")
            severity = "WARNING" if severity == "INFO" else severity
        if "call to" in msg or "callout" in msg or "callin" in msg:
            tags.append("発着信")

    # ── IPsec / IKE（isakmp） ───────────────────────────────────
    if proc == "isakmp":
        tags.append("VPN"); tags.append("IPsec")
        if ("sa" in msg and "established" in msg) or ("sa" in msg and "sent" in msg and "delete" not in msg):
            tags.append("VPN確立")
        if "down" in msg or "mismatched" in msg or "failure" in msg or "failed" in msg or "delete" in msg:
            tags.append("VPN障害"); tags.append("障害候補")
            severity = "WARNING" if severity == "INFO" else severity
        if "dpd" in msg and "down" in msg:
            tags.append("DPD検知")

    # ── BGP（bgpd） ─────────────────────────────────────────────
    if proc == "bgpd":
        tags.append("ルーティング"); tags.append("BGP")
        if "notification" in msg or "down" in msg or "reset" in msg:
            tags.append("BGP障害"); tags.append("障害候補")
            severity = "WARNING" if severity == "INFO" else severity
        if "established" in msg:
            tags.append("ネイバー確立")

    # ── OSPF / RIP ─────────────────────────────────────────────
    if proc in ("ospfd", "ospf6d"):
        tags.append("ルーティング"); tags.append("OSPF")
        if "down" in msg or "mismatch" in msg or "overflow" in msg or "fail" in msg:
            tags.append("障害候補")
    if proc in ("ripd", "rip6d"):
        tags.append("ルーティング"); tags.append("RIP")

    # ── VRRP（nsm: vrrp ...） ───────────────────────────────────
    if "vrrp" in msg:
        tags.append("VRRP")
        if "master router down" in msg or "trigger event" in msg or "state is changed" in msg:
            tags.append("冗長切替")
        if "down" in msg or "failed" in msg or "not initialized" in msg:
            tags.append("障害候補")

    # ── 経路管理（nsm: route/routing） ─────────────────────────
    if proc == "nsm" and ("route" in msg or "routing table" in msg):
        tags.append("ルーティング")
        if "overflow" in msg or "cannot" in msg or "failed" in msg or "interrupted" in msg:
            tags.append("障害候補")

    # ── WWAN / モバイル（cmodemctl） ───────────────────────────
    if proc in ("cmodemctl", "cmodemsd"):
        tags.append("モバイル"); tags.append("WWAN")
        if "error" in msg or "fail" in msg or "locked" in msg or "required" in msg:
            tags.append("障害候補")
            severity = "WARNING" if severity == "INFO" else severity

    # ── STP（mstpd） ────────────────────────────────────────────
    if proc == "mstpd" or "bpdu" in msg or "topology change" in msg or "root bridge" in msg:
        tags.append("STP")
        if "topology change" in msg:
            tags.append("トポロジ変更"); tags.append("障害候補")
        if "root bridge" in msg:
            tags.append("ルートブリッジ変更")
        if "invalid bpdu" in msg:
            tags.append("BPDU異常"); tags.append("障害候補")

    # ── DHCP クライアント ──────────────────────────────────────
    if proc in ("dhcpcd", "dhcp6cd"):
        tags.append("DHCP")
        if "nak" in msg or "failure" in msg or "not initialized" in msg:
            tags.append("障害候補")

    # ── IPoE / v6プラス / 動的VPN ──────────────────────────────
    if proc in ("ngnd", "v6plusd"):
        tags.append("IPoE")
    if proc == "dvpnsd":
        tags.append("VPN"); tags.append("動的VPN")

    # ── ログイン / 認証 ────────────────────────────────────────
    login_m = re.search(r"(failed login|login|exit)\s+(\S+)(?:\s+as\s+(\S+))?\s+on\s+(\S+)"
                        r"(?:.*?from\s+([\d\.]+))?", message, re.IGNORECASE)
    if login_m and proc in ("logon", "telnetd", "sshlogin", "sshd", "ftpd", "sftpd", "httpd"):
        action = login_m.group(1).lower()
        from_ip = login_m.group(5)
        tags.append("コンソール" if proc == "logon" else "リモートアクセス")
        if action == "failed login":
            tags.append("認証失敗"); tags.append("セキュリティ")
            severity = "WARNING" if severity == "INFO" else severity
            if from_ip: tags.append(f"src:{from_ip}")
        elif action == "login":
            tags.append("ログイン成功")
            if from_ip: tags.append(f"src:{from_ip}")
        elif action == "exit":
            tags.append("ログアウト")

    # ── RADIUS / 認証デーモン ──────────────────────────────────
    if proc in ("aaa_radiusd", "aaad", "authd"):
        tags.append("認証")
        if "failed" in msg or "reject" in msg or "denied" in msg or "dead" in msg:
            tags.append("認証失敗"); tags.append("障害候補")

    # ── システム起動 / 設定 ────────────────────────────────────
    if proc == "init" and "startup" in msg:
        tags.append("システム起動")
    if "configuration restarted" in msg:
        tags.append("設定反映")

    # ── 汎用障害キーワード ─────────────────────────────────────
    if any(k in msg for k in ("failed", "error", "mismatch", "invalid", "cannot", "overflow", "reject")):
        if "障害候補" not in tags and "リンクUP" not in tags and "ログイン成功" not in tags:
            tags.append("障害候補")

    return {
        "vendor": "富士通 Si-R",
        "hostname": hostname or source_ip,
        "facility": "Si-R",
        "severity": severity,
        "severity_digit": "",
        "process": process,
        "message": message,
        "timestamp": timestamp or "",
        "tags": tags,
    }
