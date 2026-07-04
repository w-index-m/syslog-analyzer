"""
F5 BIG-IP (LTM シリーズ) syslog パーサー

ログ形式例:
  <133>Jul  4 10:00:00 bigip1 tmm[1234]: 01010028:4: Pool /Common/pool1 member /Common/10.0.0.1:80 monitor status down.
  <134>Jul  4 10:01:00 bigip1 tmm1[1234]: 01010221:5: Pool /Common/pool1 member /Common/10.0.0.1:80 monitor status up.
  <131>Jul  4 10:02:00 bigip1 mcpd[1000]: 01070417:3: Error ...
  <134>Jul  4 10:03:00 bigip1 tmm[1234]: 01340011:5: HA process failover: going active.
  <133>Jul  4 10:04:00 bigip1 tmm[1234]: 01260009:4: Connection error / SSL handshake failed.

BIG-IP のメッセージは「msgID:level: 本文」形式（msgIDは8桁16進、levelは0-7相当）。
"""
import re

PRI_SEVERITY = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}

# BIG-IP 固有プロセス（デーモン）名
F5_PROCS = {
    "tmm", "mcpd", "bigd", "ltm", "alertd", "tmrouted", "sod", "chmand",
    "mprov", "icrd", "restjavad", "gtmd", "big3d", "csyncd", "tmsh",
    "syslog-ng", "logger", "clusterd", "lacpd", "statd", "cbrd",
}
# tmm はマルチプロセス(tmm0, tmm1 ...)
_F5_PROC_RE = re.compile(r"\b(tmm\d*|mcpd|bigd|ltm|alertd|tmrouted|sod|chmand|"
                         r"gtmd|big3d|csyncd|clusterd|lacpd|statd)\b", re.IGNORECASE)

# BIG-IP メッセージ ID（例 "01010028:4:"）
F5_MSGID_RE = re.compile(r"\b([0-9a-fA-F]{8}):(\d):")

# ホスト名キーワード
F5_HOST_KEYWORDS = ["bigip", "big-ip", "f5", "-ltm", "ltm-"]

# syslog ヘッダ + process[pid]: 本文 を分解
F5_PATTERN = re.compile(
    r"(?:<(\d+)>)?"
    r"(?:\s*(\w{3}\s+\d{1,2}\s+[\d:]+)\s+)?"
    r"(?:([\w\-\.]+)\s+)?"
    r"([\w\-]+)(?:\[(\d+)\])?:\s*"
    r"(.*)"
)


def _is_f5(raw: str) -> bool:
    raw_lower = raw.lower()
    if any(k in raw_lower for k in F5_HOST_KEYWORDS):
        return True
    # msgID + F5 プロセスの組み合わせ、または F5 固有プロセス名
    m = re.search(r"(?:^|\s)([a-z][\w\-]*?)(?:\[\d+\])?:\s", raw_lower)
    proc = (m.group(1) if m else "").split("[")[0]
    if proc in F5_PROCS or _F5_PROC_RE.search(proc or ""):
        # tmm/mcpd 等は F5 固有性が高い。msgID があれば確定度アップ
        if F5_MSGID_RE.search(raw) or proc in ("tmm", "mcpd", "bigd"):
            return True
        if _F5_PROC_RE.fullmatch(proc or ""):
            return True
    return False


def parse(raw: str, source_ip: str) -> dict | None:
    if not _is_f5(raw):
        return None

    m = F5_PATTERN.search(raw)
    if not m:
        return None
    pri, timestamp, hostname, process, pid, message = m.groups()
    process = (process or "").strip()
    message = (message or "").strip()
    msg = message.lower()

    # severity: msgID の level を優先、なければ PRI
    severity = None
    mid = F5_MSGID_RE.search(message)
    if mid:
        severity = PRI_SEVERITY.get(int(mid.group(2)) & 0x07)
    if severity is None:
        severity = PRI_SEVERITY.get(int(pri) & 0x07, "INFO") if pri else "INFO"

    tags = ["BIG-IP", "LTM"]

    # ── プール / ノード監視 ──
    if "monitor status down" in msg or ("member" in msg and "down" in msg):
        tags += ["プールメンバー", "監視ダウン", "障害候補"]
        severity = "ERROR" if severity in ("INFO", "NOTICE") else severity
    elif "monitor status up" in msg or ("member" in msg and "up" in msg):
        tags += ["プールメンバー", "監視アップ"]
    if "node" in msg and "down" in msg:
        tags += ["ノードダウン", "障害候補"]
    if "pool" in msg and ("no members available" in msg or "is down" in msg):
        tags += ["プールダウン", "障害候補"]
        severity = "CRITICAL" if severity in ("INFO", "NOTICE", "WARNING") else severity

    # ── 仮想サーバ / 接続 ──
    if "virtual server" in msg or "/common/vs" in msg or "virtual" in msg:
        tags.append("仮想サーバ")
    if "connection" in msg and ("error" in msg or "reset" in msg or "limit" in msg):
        tags += ["接続エラー", "障害候補"]

    # ── HA / フェイルオーバー / 同期 ──
    if "failover" in msg or "going active" in msg or "going standby" in msg or "ha process" in msg:
        tags += ["冗長化", "フェイルオーバー"]
        if "going standby" in msg or "offline" in msg:
            tags.append("障害候補")
    if "sync" in msg and ("fail" in msg or "error" in msg or "mismatch" in msg):
        tags += ["構成同期", "同期エラー", "障害候補"]

    # ── SSL / 証明書 ──
    if "ssl" in msg or "certificate" in msg or "handshake" in msg or "tls" in msg:
        tags.append("SSL/TLS")
        if "fail" in msg or "expired" in msg or "error" in msg or "invalid" in msg:
            tags += ["SSL障害", "障害候補"]

    # ── 認証 / 管理 ──
    if "authentication" in msg or "login" in msg or "auth" in msg:
        tags.append("認証")
        if "fail" in msg or "denied" in msg or "invalid" in msg:
            tags += ["認証失敗", "セキュリティ"]

    # ── 設定 (mcpd/tmsh) ──
    if (process or "").lower().startswith(("mcpd", "tmsh")):
        tags.append("設定")

    # ── リソース逼迫 ──
    if "cpu" in msg and ("high" in msg or "exceeded" in msg):
        tags += ["高CPU", "障害候補"]
    if "memory" in msg and ("low" in msg or "exceeded" in msg or "denied" in msg):
        tags += ["メモリ不足", "障害候補"]
    if "aborted" in msg or "core" in msg or "panic" in msg or "crash" in msg:
        tags += ["異常終了", "障害候補"]

    # ── 汎用障害キーワード ──
    if any(k in msg for k in ("error", "fail", "down", "denied", "unavailable")):
        if "障害候補" not in tags and "監視アップ" not in tags:
            tags.append("障害候補")

    return {
        "vendor": "F5 BIG-IP LTM",
        "hostname": hostname or source_ip,
        "facility": "BIG-IP",
        "severity": severity,
        "severity_digit": "",
        "process": f"{process}[{pid}]" if pid else process,
        "message": message,
        "timestamp": timestamp or "",
        "tags": tags,
    }
