"""
富士通/エフサステクノロジーズ SR-S シリーズ syslog パーサー

出典: SR-S シリーズ メッセージ集 (P3NK-7072-07Z0 / 2026年4月 第7版)

システムログの形式（メッセージ集「システムログの形式について」より）:
  <date> <host> <machine> : <message>
  ・SYSLOG サーバ送信時は <machine>（機種名）は付かず、
    RFC 準拠ヘッダ設定なし（工場出荷時）では <message> 部のみが送信される。
  ・<message> は「<process>: 本文」形式（プロセス名に [pid] は付かない）。

実メッセージ例（すべてメッセージ集の原文）:
  protocol: ether 1 link up
  protocol: ether 3 link down
  l2loopd: Configuration Testing Protocol detects a loop in port 5 and port 6
  l2loopd: Configuration Testing Protocol blocked port 5
  l2nsm:   Configuration Testing Protocol unblocked port 5
  mstpd:   Topology Change detected
  mstpd:   Bridge became new Root Bridge
  mstpd:   Invalid BPDU received on port 12
  protocol: MAC learning entry moved from ether 1 to ether 2 [00:11:22:33:44:55 vid=10]
  logon:   login admin as administrator on console
  telnetd: failed login guest on telnet from 192.168.1.100
  sshlogin: login admin as administrator on ssh from 10.0.0.5
  init:    system startup now.
"""
import re

# SR-S のプライオリティ表記（メッセージ集の【プライオリティ】欄）→ severity
LOGLEVEL_MAP = {
    "LOG_EMERG": "EMERGENCY", "LOG_ALERT": "ALERT", "LOG_CRIT": "CRITICAL",
    "LOG_ERROR": "ERROR", "LOG_ERR": "ERROR", "LOG_WARNING": "WARNING",
    "LOG_WARN": "WARNING", "LOG_NOTICE": "NOTICE", "LOG_INFO": "INFO",
    "LOG_DEBUG": "DEBUG",
}

PRI_SEVERITY = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}

# SR-S 固有のプロセス（デーモン）名。メッセージ集の実プロセス名に限定。
# ── 他ベンダーと衝突しにくい固有性の高いもの
SRS_UNIQUE_PROCS = {
    "l2loopd", "l2nsm", "mstpd", "sshlogin", "conftryd", "devscand",
    "nodemanagerd", "nodemgr_infod", "nodemgr_land", "nodemgr_logd",
    "nodemgr_wland", "aaad", "aaa_radiusd", "dhcp6relay", "dhcp6sd",
    "mountd", "cmdexec",
}
# ── SR-S でよく使われるが汎用的な名前（ホスト名 or 固有メッセージと併用で判定）
SRS_GENERIC_PROCS = {
    "protocol", "logon", "telnetd", "sshd", "ftpd", "httpd", "authd",
    "enabled", "init", "nsm", "dhcpd",
}

# SR-S 機種名・ホスト名キーワード
SRS_HOST_KEYWORDS = ["sr-s", "srs"]

# SR-S 固有のメッセージ本文シグネチャ（このベンダー特有の言い回し）
SRS_MSG_SIGNATURES = [
    "configuration testing protocol",       # ループ検出(CTP)
    "mac learning entry moved",             # MACテーブルフラッシュ
    "became new root bridge",               # STP
    "topology change detected",             # STP
]

# syslog ヘッダ + "<process>: <message>" を分解
SRS_PATTERN = re.compile(
    r"(?:<(\d+)>)?"                                  # PRI (任意)
    r"(?:\s*(\w{3}\s+\d{1,2}\s+[\d:]+)\s+)?"         # timestamp (任意)
    r"(?:([\w\-\.]+)\s+)?"                            # hostname (任意)
    r"([A-Za-z][\w\-]*?):\s*"                         # process 名
    r"(.*)"                                           # message 本文
)

# ループ検出（ポート番号抽出用）
CTP_LOOP_PATTERN = re.compile(
    r"detects a loop in port\s+(\S+)(?:\s+and port\s+(\S+))?", re.IGNORECASE)
CTP_BLOCK_PATTERN = re.compile(
    r"Configuration Testing Protocol\s+(blocked|unblocked)\s+port\s+(\S+)", re.IGNORECASE)
# リンク UP/DOWN
LINK_PATTERN = re.compile(
    r"(ether|linkaggregation|lan)\s+(\S+)\s+(link up|link down|is force down|is force up)",
    re.IGNORECASE)
# ログイン
LOGIN_PATTERN = re.compile(
    r"(failed login|login|exit)\s+(\S+)(?:\s+as\s+(\S+))?\s+on\s+(\S+)"
    r"(?:.*?from\s+([\d\.]+))?", re.IGNORECASE)
# MAC フラップ
MACMOVE_PATTERN = re.compile(
    r"MAC learning entry moved from\s+(\w+)\s+(\S+)\s+to\s+(\w+)\s+(\S+)"
    r"(?:\s+\[([0-9a-fA-F:]+)\s+vid=(\d+)\])?", re.IGNORECASE)


def _is_srs(raw: str) -> bool:
    raw_lower = raw.lower()
    # 他ベンダーとの明示的な衝突回避
    if "ipcom" in raw_lower or "ipf[" in raw_lower:
        return False
    # 1) SR-S 固有メッセージシグネチャがあれば確定
    for sig in SRS_MSG_SIGNATURES:
        if sig in raw_lower:
            return True
    # 2) SR-S 固有プロセス名（process:）があれば確定
    for proc in SRS_UNIQUE_PROCS:
        if re.search(rf"(?:^|\s){re.escape(proc)}:\s", raw_lower):
            return True
    # 3) 汎用プロセス名は、SR-S ホスト名キーワードと併用の場合のみ確定
    has_host_kw = any(k in raw_lower for k in SRS_HOST_KEYWORDS)
    if has_host_kw:
        for proc in SRS_GENERIC_PROCS:
            if re.search(rf"(?:^|\s){re.escape(proc)}:\s", raw_lower):
                return True
    return False


def parse(raw: str, source_ip: str) -> dict | None:
    if not _is_srs(raw):
        return None

    m = SRS_PATTERN.search(raw)
    if not m:
        return None

    pri, timestamp, hostname, process, message = m.groups()
    process = (process or "").strip()
    message = (message or "").strip()
    proc_lower = process.lower()
    msg_lower = message.lower()

    # severity 決定（PRI 優先、なければメッセージ内容から推定）
    if pri:
        severity = PRI_SEVERITY.get(int(pri) & 0x07, "INFO")
    else:
        severity = "INFO"

    tags = ["SR-S"]

    # ── ループ検出機能（1.41） ───────────────────────────────
    if "configuration testing protocol" in msg_lower:
        tags.append("ループ検出")
        loop_m = CTP_LOOP_PATTERN.search(message)
        block_m = CTP_BLOCK_PATTERN.search(message)
        if loop_m:
            tags.append("ループ検知")
            tags.append("障害候補")
            tags.append(f"loop_port:{loop_m.group(1)}")
            if loop_m.group(2):
                tags.append(f"loop_port2:{loop_m.group(2)}")
            severity = "WARNING" if severity == "INFO" else severity
        if block_m:
            status = block_m.group(1).lower()
            if status == "blocked":
                tags.append("ポート遮断")
                tags.append("障害候補")
                severity = "WARNING" if severity == "INFO" else severity
            else:
                tags.append("ポート遮断解除")
        if "pause frame" in msg_lower:
            tags.append("ループ継続")
            tags.append("障害候補")

    # ── 物理/論理ポートのリンク UP/DOWN（1.11） ─────────────
    link_m = LINK_PATTERN.search(message)
    if link_m:
        port_type, port_num, state = link_m.group(1), link_m.group(2), link_m.group(3).lower()
        tags.append("インターフェース")
        tags.append(f"{port_type}{port_num}")
        if "link up" in state or "force up" in state:
            tags.append("リンクUP")
        elif "link down" in state:
            tags.append("リンクDOWN")
            tags.append("障害候補")
            severity = "WARNING" if severity == "INFO" else severity
        elif "force down" in state:
            tags.append("ポート閉塞")
            tags.append("障害候補")
    if "is force down" in msg_lower and "link down relay" in msg_lower:
        tags.append("リンクダウンリレー")
        tags.append("障害候補")

    # ── ブリッジ/STP（1.27） ─────────────────────────────────
    if proc_lower == "mstpd" or "bpdu" in msg_lower or "topology change" in msg_lower \
            or "root bridge" in msg_lower:
        tags.append("STP")
        if "topology change" in msg_lower:
            tags.append("トポロジ変更")
            tags.append("障害候補")
            severity = "NOTICE" if severity == "INFO" else severity
        if "became new root bridge" in msg_lower:
            tags.append("ルートブリッジ変更")
        if "invalid bpdu" in msg_lower or "could not validate bpdu" in msg_lower:
            tags.append("BPDU異常")
            tags.append("障害候補")
            severity = "WARNING" if severity == "INFO" else severity

    # ── MAC テーブルフラッシュ / MAC フラッピング（1.42） ────
    if "mac learning entry moved" in msg_lower:
        tags.append("MACアドレス移動")
        tags.append("MACフラップ")
        tags.append("障害候補")   # ポート間 MAC 移動はループ/冗長切替の兆候
        mac_m = MACMOVE_PATTERN.search(message)
        if mac_m:
            tags.append(f"from:{mac_m.group(1)}{mac_m.group(2)}")
            tags.append(f"to:{mac_m.group(3)}{mac_m.group(4)}")
            if mac_m.group(5):
                tags.append(f"mac:{mac_m.group(5)}")
        severity = "NOTICE" if severity == "INFO" else severity

    # ── ログイン/認証（logon/telnetd/sshlogin/ftpd/httpd） ──
    login_m = LOGIN_PATTERN.search(message)
    if login_m and proc_lower in ("logon", "telnetd", "sshlogin", "sshd", "ftpd", "httpd"):
        action, user, cls, via, from_ip = login_m.groups()
        action = action.lower()
        tags.append("リモートアクセス" if proc_lower != "logon" else "コンソール")
        if action == "failed login":
            tags.append("認証失敗")
            tags.append("セキュリティ")
            severity = "WARNING" if severity == "INFO" else severity
            if from_ip:
                tags.append(f"src:{from_ip}")
        elif action == "login":
            tags.append("ログイン成功")
            if from_ip:
                tags.append(f"src:{from_ip}")
        elif action == "exit":
            tags.append("ログアウト")

    # ── LACP リンクアグリゲーション ─────────────────────────
    if "lacp" in msg_lower or "linkaggregation" in msg_lower:
        if "リンクアグリゲーション" not in tags:
            tags.append("リンクアグリゲーション")
        if "collecting/distributing start" in msg_lower:
            tags.append("LAG参加")
        if "collecting/distributing stop" in msg_lower:
            tags.append("LAG離脱")
            tags.append("障害候補")

    # ── VRRP（nsm） ─────────────────────────────────────────
    if "vrrp" in msg_lower:
        tags.append("VRRP")
        if "master" in msg_lower and ("down" in msg_lower or "changed into the master" in msg_lower):
            tags.append("冗長切替")
        if "failed" in msg_lower:
            tags.append("障害候補")

    # ── システム起動/再起動（1.1） ──────────────────────────
    if proc_lower == "init" and "system startup" in msg_lower:
        tags.append("システム起動")
    if "system configuration restarted" in msg_lower:
        tags.append("設定反映")

    # ── ルーティング（nsm） ─────────────────────────────────
    if proc_lower == "nsm" and ("route" in msg_lower or "routing table" in msg_lower):
        tags.append("ルーティング")
        if "overflow" in msg_lower or "cannot add" in msg_lower or "failed" in msg_lower:
            tags.append("障害候補")

    # ── 汎用障害キーワード ──────────────────────────────────
    if any(k in msg_lower for k in ("failed", "invalid", "error", "cannot", "overflow", "down")):
        if "障害候補" not in tags:
            # link up など明確に正常なものは除外済みなので、残りは候補に
            if "リンクUP" not in tags and "ログイン成功" not in tags:
                tags.append("障害候補")

    return {
        "vendor": "富士通 SR-S",
        "hostname": hostname or source_ip,
        "facility": "SR-S",
        "severity": severity,
        "severity_digit": "",
        "process": process,
        "message": message,
        "timestamp": timestamp or "",
        "tags": tags,
    }
