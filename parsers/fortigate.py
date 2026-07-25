"""
Fortinet FortiGate syslog パーサー

FortiGateのログは key=value（一部は "..." でクォート）形式。
  <PRI>date=2024-07-04 time=10:00:00 devname="FGT60F" devid="FGT60FTK20012345"
  logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root"
  srcip=192.168.1.10 srcport=52341 dstip=203.0.113.5 dstport=443 action="accept"
  policyid=1 service="HTTPS" msg="..."

type は traffic(通信ログ) / utm(セキュリティUTM: virus/ips/webfilter/app-ctrl/dns/ssl等)
/ event(システム/VPN/HA等) / anomaly(DoS) など。level がそのままsyslog重大度に対応する。
"""
import re

# FortiGateのlevelはsyslog重大度語とほぼ1:1
FGT_LEVEL_SEVERITY = {
    "emergency": "EMERGENCY", "alert": "ALERT", "critical": "CRITICAL",
    "error": "ERROR", "warning": "WARNING", "notice": "NOTICE",
    "information": "INFO", "debug": "DEBUG",
}

FGT_HOST_KEYWORDS = ["fgt", "fortigate", "fortinet"]

# syslog ヘッダを剥がすための正規表現（PRI + 任意のタイムスタンプ/ホスト名）
FGT_HEADER_RE = re.compile(
    r"(?:<(\d+)>)?"
    r"(?:\s*(\w{3}\s+\d{1,2}\s+[\d:]+)\s+)?"
    r"(?:([\w\-\.]+)\s+)?"
    r"(.*)"
)

# key=value / key="quoted value" を抽出
_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def _parse_kv(body: str) -> dict:
    kv = {}
    for m in _KV_RE.finditer(body):
        key, val = m.group(1), m.group(2)
        if val.startswith('"') and val.endswith('"') and len(val) >= 2:
            val = val[1:-1]
        kv[key] = val
    return kv


def _is_fortigate(raw: str) -> bool:
    raw_lower = raw.lower()
    has_kv_shape = bool(re.search(r"\bdevname=|\blogid=|\bvd=", raw))
    has_type_subtype = bool(re.search(r"\btype=\"?\w+\"?", raw)) and "=" in raw
    if has_kv_shape and has_type_subtype:
        return True
    if any(k in raw_lower for k in FGT_HOST_KEYWORDS) and "=" in raw and raw.count("=") >= 4:
        return True
    return False


def parse(raw: str, source_ip: str) -> dict | None:
    if not _is_fortigate(raw):
        return None

    m = FGT_HEADER_RE.search(raw)
    if not m:
        return None
    pri, timestamp, hdr_hostname, body = m.groups()
    body = (body or "").strip()
    kv = _parse_kv(body)
    if not kv:
        return None

    log_type = (kv.get("type") or "unknown").lower()
    subtype = (kv.get("subtype") or "").lower()
    action = (kv.get("action") or "").lower()

    severity = FGT_LEVEL_SEVERITY.get((kv.get("level") or "").lower(), "INFO")
    if pri and "level" not in kv:
        pri_severities = {0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
                          4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG"}
        severity = pri_severities.get(int(pri) & 0x07, "INFO")

    hostname = kv.get("devname") or hdr_hostname or source_ip
    tags = ["FortiGate", f"種別:{log_type}"]
    if subtype:
        tags.append(f"サブタイプ:{subtype}")

    if log_type == "traffic":
        tags.append("トラフィック")
        if action in ("deny", "block", "blocked", "dropped", "close", "reset"):
            tags.append("通信拒否")
        elif action in ("accept", "allow"):
            tags.append("通信許可")

    elif log_type == "utm":
        tags.append("UTM/セキュリティ")
        if subtype == "virus":
            tags += ["マルウェア", "ウイルス検知"]
        elif subtype == "ips":
            tags.append("侵入検知(IPS)")
        elif subtype == "webfilter":
            tags.append("Webフィルタ")
        elif subtype == "app-ctrl":
            tags.append("アプリケーション制御")
        elif subtype == "dns":
            tags.append("DNSフィルタ")
        elif subtype == "ssl":
            tags.append("SSL検査")
        elif subtype == "waf":
            tags.append("WAF")
        if action in ("blocked", "dropped", "block", "reset"):
            tags += ["遮断", "防御成功"]
        elif action in ("passthrough", "monitored", "allowed", "detected"):
            tags += ["アラートのみ", "要確認"]
        tags.append("セキュリティ")
        if severity in ("CRITICAL", "ERROR", "ALERT", "EMERGENCY"):
            tags.append("障害候補")

    elif log_type == "event":
        tags.append("システム")
        if subtype in ("ha", "system"):
            if any(k in body.lower() for k in ("failover", "down", "lost", "member")):
                tags += ["冗長化(HA)", "障害候補"]
        if subtype == "vpn":
            tags.append("VPN")
            if action in ("negotiate_error", "tunnel-down", "phase1-down", "phase2-down"):
                tags += ["接続失敗", "障害候補"]
        if subtype == "user":
            tags.append("認証/User")
            if "fail" in body.lower() or "denied" in body.lower():
                tags += ["認証失敗", "セキュリティ"]

    elif log_type == "anomaly":
        tags += ["異常検知(DoS)", "セキュリティ"]
        if severity in ("CRITICAL", "ERROR", "ALERT", "EMERGENCY"):
            tags.append("障害候補")

    if severity in ("CRITICAL", "EMERGENCY", "ALERT"):
        if "障害候補" not in tags:
            tags.append("障害候補")

    # msg= があればそれを主メッセージに、attack=/virus= があれば補足情報として付与
    parts = []
    if kv.get("msg"):
        parts.append(kv["msg"])
    if kv.get("attack"):
        parts.append(f"attack={kv['attack']}")
    if kv.get("virus"):
        parts.append(f"virus={kv['virus']}")
    if kv.get("srcip") and kv.get("dstip"):
        parts.append(f"{kv['srcip']} -> {kv['dstip']}"
                     + (f":{kv['dstport']}" if kv.get("dstport") else ""))
    if kv.get("action"):
        parts.append(f"action={kv['action']}")
    message = " | ".join(parts) if parts else body

    return {
        "vendor": "FortiGate",
        "hostname": hostname,
        "facility": f"FGT-{log_type}",
        "severity": severity,
        "severity_digit": "",
        "process": subtype or log_type,
        "message": message[:500],
        "timestamp": kv.get("date", "") + (" " + kv.get("time", "") if kv.get("time") else "")
                     if kv.get("date") else (timestamp or ""),
        "tags": tags,
    }
