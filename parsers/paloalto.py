"""
Palo Alto Networks (PAN-OS) syslog パーサー

PAN-OS のログはカンマ区切り(CSV)。ヘッダ後のフィールド構成:
  FUTURE_USE, RecvTime, SerialNumber, Type, Subtype/ContentVer, ...
  Type は TRAFFIC / THREAT / SYSTEM / CONFIG / HIP-MATCH / GLOBALPROTECT など。

ログ形式例:
  <14>Jul  4 10:00:00 PA-VM 1,2024/07/04 10:00:00,001801000000,TRAFFIC,end,2049,...,10.0.0.5,203.0.113.1,...,allow,...
  <14>Jul  4 10:00:00 PA-FW 1,2024/07/04 10:00:00,001801000000,THREAT,vulnerability,...,critical,...,drop,...
  <14>Jul  4 10:00:00 PA-FW 1,2024/07/04 10:00:00,001801000000,SYSTEM,general,...,high,...,message
  <14>Jul  4 10:00:00 PA-FW 1,2024/07/04 10:00:00,001801000000,CONFIG,...,admin,...,commit,...

CSV の位置はサブタイプで変わるため、Type と主要キーワードで分類する。
"""
import re

PRI_SEVERITY = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}

PANOS_TYPES = {"TRAFFIC", "THREAT", "SYSTEM", "CONFIG", "HIP-MATCH",
               "GLOBALPROTECT", "USERID", "AUTHENTICATION", "DECRYPTION",
               "CORRELATION", "GTP", "SCTP", "URL", "DATA", "WILDFIRE"}

# PAN-OS 重大度語 → severity
PAN_SEVERITY = {
    "critical": "CRITICAL", "high": "ERROR", "medium": "WARNING",
    "low": "NOTICE", "informational": "INFO", "info": "INFO",
}

# ホスト名/本文キーワード
PAN_HOST_KEYWORDS = ["pa-", "palo", "panorama", "pan-os", "panos", "-fw", "gp-"]

# syslog ヘッダを剥がすための正規表現
PAN_HEADER_RE = re.compile(
    r"(?:<(\d+)>)?"
    r"(?:\s*(\w{3}\s+\d{1,2}\s+[\d:]+)\s+)?"
    r"(?:([\w\-\.]+)\s+)?"
    r"(.*)"
)

# CSV 内に Type が含まれるか（先頭付近のフィールド）
_TYPE_RE = re.compile(r"(?:^|,)\s*(TRAFFIC|THREAT|SYSTEM|CONFIG|HIP-MATCH|"
                      r"GLOBALPROTECT|USERID|AUTHENTICATION|DECRYPTION|"
                      r"CORRELATION|URL|WILDFIRE)\s*(?:,|$)", re.IGNORECASE)


def _is_panos(raw: str) -> bool:
    raw_lower = raw.lower()
    # CSV に PAN-OS の Type フィールドがあり、かつカンマ区切りが多い
    if _TYPE_RE.search(raw) and raw.count(",") >= 4:
        return True
    # ホスト名キーワード + CSV っぽさ
    if any(k in raw_lower for k in PAN_HOST_KEYWORDS) and raw.count(",") >= 4:
        return True
    return False


def parse(raw: str, source_ip: str) -> dict | None:
    if not _is_panos(raw):
        return None

    m = PAN_HEADER_RE.search(raw)
    if not m:
        return None
    pri, timestamp, hostname, body = m.groups()
    body = (body or "").strip()
    fields = [f.strip() for f in body.split(",")]
    low = body.lower()

    # ログ種別 Type を特定
    tm = _TYPE_RE.search(body)
    log_type = tm.group(1).upper() if tm else "UNKNOWN"

    severity = PRI_SEVERITY.get(int(pri) & 0x07, "INFO") if pri else "INFO"
    tags = ["Palo Alto", f"種別:{log_type}"]

    # PAN-OS 重大度語があれば反映
    for w, sev in PAN_SEVERITY.items():
        if re.search(rf"(?:^|,)\s*{w}\s*(?:,|$)", low):
            severity = sev
            break

    # ── 種別ごとの分類 ──
    if log_type == "THREAT":
        tags.append("脅威")
        # サブタイプ/アクション
        if "vulnerability" in low:
            tags.append("脆弱性攻撃")
        if "virus" in low or "wildfire" in low:
            tags.append("マルウェア")
        if "spyware" in low:
            tags.append("スパイウェア")
        if re.search(r"(?:^|,)\s*(deny|drop|reset-both|reset-client|reset-server|block)", low):
            tags += ["遮断", "防御成功"]
        elif re.search(r"(?:^|,)\s*alert", low):
            tags += ["アラートのみ", "要確認"]
        tags.append("セキュリティ")
        if severity in ("CRITICAL", "ERROR"):
            tags.append("障害候補")

    elif log_type == "TRAFFIC":
        tags.append("トラフィック")
        if re.search(r"(?:^|,)\s*(deny|drop)", low):
            tags += ["通信拒否"]
        elif re.search(r"(?:^|,)\s*allow", low):
            tags.append("通信許可")

    elif log_type == "SYSTEM":
        tags.append("システム")
        if any(k in low for k in ("ha ", "failover", "peer", "suspended", "tentative")):
            tags += ["冗長化(HA)"]
            if "suspended" in low or "down" in low or "fail" in low:
                tags.append("障害候補")
        if "autofocus" in low or "license" in low or "expired" in low:
            tags.append("ライセンス")
        if "certificate" in low or "cert " in low:
            tags.append("証明書")
        if any(k in low for k in ("fan", "temperature", "power", "disk", "raid")):
            tags += ["ハードウェア"]
            if "fail" in low or "warn" in low:
                tags.append("障害候補")
        if "commit" in low:
            tags.append("設定コミット")

    elif log_type == "CONFIG":
        tags.append("設定変更")
        if "commit" in low:
            tags.append("コミット")
        if re.search(r"(?:^|,)\s*(failed|error)", low):
            tags += ["設定失敗", "障害候補"]

    elif log_type == "GLOBALPROTECT":
        tags.append("GlobalProtect(VPN)")
        if "fail" in low or "denied" in low or "error" in low:
            tags += ["接続失敗", "障害候補"]

    elif log_type in ("USERID", "AUTHENTICATION"):
        tags.append("認証/User-ID")
        if "fail" in low or "denied" in low:
            tags += ["認証失敗", "セキュリティ"]

    # ── 汎用 ──
    if severity in ("CRITICAL", "EMERGENCY", "ALERT"):
        if "障害候補" not in tags:
            tags.append("障害候補")

    # メッセージ本文（末尾の説明的フィールドがあれば採用、無ければ body 全体）
    message = fields[-1] if fields and len(fields[-1]) > 8 else body

    return {
        "vendor": "Palo Alto",
        "hostname": hostname or source_ip,
        "facility": f"PAN-{log_type}",
        "severity": severity,
        "severity_digit": "",
        "process": log_type,
        "message": message[:500],
        "timestamp": timestamp or "",
        "tags": tags,
    }
