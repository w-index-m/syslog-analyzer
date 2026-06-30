"""
SNMP Trap パーサー
受信したTrapのOID・varbindを解析して構造化データに変換する
"""

# ─────────────────────────────────────────
# 標準Trap OID (RFC 1215 / SNMPv2-MIB)
# ─────────────────────────────────────────
STANDARD_TRAPS = {
    # SNMPv1 generic trap types
    "coldStart":          ("NOTICE",  "coldStart",  "機器のコールドスタート（電源投入/完全再起動）"),
    "warmStart":          ("NOTICE",  "warmStart",  "機器のウォームスタート（ソフトウェア再起動）"),
    "linkDown":           ("ERROR",   "linkDown",   "インターフェースがダウン"),
    "linkUp":             ("NOTICE",  "linkUp",     "インターフェースがアップ"),
    "authenticationFailure": ("WARNING","authFail", "SNMPコミュニティ名認証失敗"),
    "egpNeighborLoss":    ("WARNING", "egpLoss",    "EGPネイバーロスト"),

    # SNMPv2-MIB OID形式
    "1.3.6.1.6.3.1.1.5.1": ("NOTICE",  "coldStart",  "機器のコールドスタート"),
    "1.3.6.1.6.3.1.1.5.2": ("NOTICE",  "warmStart",  "機器のウォームスタート"),
    "1.3.6.1.6.3.1.1.5.3": ("ERROR",   "linkDown",   "インターフェースダウン"),
    "1.3.6.1.6.3.1.1.5.4": ("NOTICE",  "linkUp",     "インターフェースアップ"),
    "1.3.6.1.6.3.1.1.5.5": ("WARNING", "authFail",   "SNMP認証失敗"),
    "1.3.6.1.6.3.1.1.5.6": ("WARNING", "egpLoss",    "EGPネイバーロスト"),
}

# ─────────────────────────────────────────
# Cisco 固有 Trap OID
# ─────────────────────────────────────────
CISCO_TRAPS = {
    # CISCO-SYSLOG-MIB
    "1.3.6.1.4.1.9.9.41.2.0.1":  ("WARNING", "clogMessageGenerated", "Ciscoシスログメッセージ生成"),
    # CISCO-ENVMON-MIB
    "1.3.6.1.4.1.9.9.13.3.0.1":  ("ERROR",   "ciscoEnvMonVoltageNotification",     "電圧異常"),
    "1.3.6.1.4.1.9.9.13.3.0.2":  ("ERROR",   "ciscoEnvMonTemperatureNotification", "温度異常"),
    "1.3.6.1.4.1.9.9.13.3.0.3":  ("ERROR",   "ciscoEnvMonFanNotification",         "ファン異常"),
    "1.3.6.1.4.1.9.9.13.3.0.4":  ("CRITICAL","ciscoEnvMonSupplyNotification",      "電源異常"),
    # CISCO-STACK-MIB
    "1.3.6.1.4.1.9.9.500.0.1":   ("ERROR",   "stpInstanceBecomeRootTrap",  "STPルートブリッジ変更"),
    # CISCO-OSPF
    "1.3.6.1.4.1.9.9.228.2.0.1": ("WARNING", "ospfNbrStateChange",  "OSPFネイバー状態変化"),
    # CISCO-BGP4-MIB
    "1.3.6.1.4.1.9.9.187.2.0.1": ("ERROR",   "bgpEstablished",      "BGPセッション確立"),
    "1.3.6.1.4.1.9.9.187.2.0.2": ("ERROR",   "bgpBackwardTransition","BGPセッション切断"),
    # CISCO-PORT-SECURITY
    "1.3.6.1.4.1.9.9.315.0.0.1": ("WARNING", "cpsSecureMacAddrViolation", "MACアドレス違反"),
    # ENTITY-MIB (Cisco実装)
    "1.3.6.1.2.1.47.2.0.1":      ("ERROR",   "entConfigChange",     "機器構成変更"),
}

# ─────────────────────────────────────────
# 富士通 Si-R 固有 Trap OID
# ─────────────────────────────────────────
FUJITSU_SIR_TRAPS = {
    # 富士通ネットワークソリューションズ OID (1.3.6.1.4.1.211)
    "1.3.6.1.4.1.211.4.1.1.1.1":  ("ERROR",  "sirLinkDown",    "Si-R インターフェースダウン"),
    "1.3.6.1.4.1.211.4.1.1.1.2":  ("NOTICE", "sirLinkUp",      "Si-R インターフェースアップ"),
    "1.3.6.1.4.1.211.4.1.1.1.3":  ("ERROR",  "sirPPPDown",     "Si-R PPP回線切断"),
    "1.3.6.1.4.1.211.4.1.1.1.4":  ("NOTICE", "sirPPPUp",       "Si-R PPP回線接続"),
    "1.3.6.1.4.1.211.4.1.1.1.5":  ("WARNING","sirOSPFChange",  "Si-R OSPFネイバー状態変化"),
    "1.3.6.1.4.1.211.4.1.1.1.10": ("CRITICAL","sirHWFailure",  "Si-R ハードウェア障害"),
}

# ─────────────────────────────────────────
# APRESIA 固有 Trap OID
# ─────────────────────────────────────────
APRESIA_TRAPS = {
    # APRESIA OID (1.3.6.1.4.1.16177)
    "1.3.6.1.4.1.16177.1.1":  ("ERROR",   "apresiaLinkDown",    "APRESIA ポートダウン"),
    "1.3.6.1.4.1.16177.1.2":  ("NOTICE",  "apresiaLinkUp",      "APRESIA ポートアップ"),
    "1.3.6.1.4.1.16177.1.3":  ("CRITICAL","apresiaLoopDetect",  "APRESIA ループ検出・ポートブロック"),
    "1.3.6.1.4.1.16177.1.4":  ("WARNING", "apresiaSTPChange",   "APRESIA STPトポロジ変化"),
    "1.3.6.1.4.1.16177.1.5":  ("WARNING", "apresiaMACFlood",    "APRESIA MACフラッド検出"),
    "1.3.6.1.4.1.16177.1.6":  ("WARNING", "apresiaPortSecurity","APRESIA ポートセキュリティ違反"),
    "1.3.6.1.4.1.16177.1.10": ("ERROR",   "apresiaHWError",     "APRESIA ハードウェアエラー"),
}

# ─────────────────────────────────────────
# 汎用 IF-MIB OID (インターフェース情報)
# ─────────────────────────────────────────
IF_MIB = {
    "1.3.6.1.2.1.2.2.1.1":  "ifIndex",
    "1.3.6.1.2.1.2.2.1.2":  "ifDescr",
    "1.3.6.1.2.1.2.2.1.7":  "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8":  "ifOperStatus",
    "1.3.6.1.2.1.31.1.1.1.1": "ifName",
}

IF_STATUS = {
    "1": "up", "2": "down", "3": "testing",
    1: "up", 2: "down", 3: "testing"
}

# ─────────────────────────────────────────
# 全OID辞書マージ
# ─────────────────────────────────────────
ALL_TRAP_OIDS = {}
ALL_TRAP_OIDS.update(STANDARD_TRAPS)
ALL_TRAP_OIDS.update(CISCO_TRAPS)
ALL_TRAP_OIDS.update(FUJITSU_SIR_TRAPS)
ALL_TRAP_OIDS.update(APRESIA_TRAPS)

def lookup_trap(oid: str) -> tuple[str, str, str] | None:
    """OIDからTrap情報を返す (severity, mnemonic, description)"""
    # 完全一致
    if oid in ALL_TRAP_OIDS:
        return ALL_TRAP_OIDS[oid]
    # プレフィックス一致（末尾の.0など）
    base = oid.rstrip(".0")
    if base in ALL_TRAP_OIDS:
        return ALL_TRAP_OIDS[base]
    return None

def detect_vendor_from_oid(oid: str) -> str:
    """OIDからベンダーを推定"""
    if oid.startswith("1.3.6.1.4.1.9."):
        return "Cisco"
    if oid.startswith("1.3.6.1.4.1.211."):
        return "富士通 Si-R"
    if oid.startswith("1.3.6.1.4.1.16177."):
        return "APRESIA"
    return "Generic"

def parse_varbinds(varbinds: list) -> dict:
    """
    varbindリストから有用な情報を抽出する
    varbinds: [(oid_str, value_str), ...]
    """
    result = {
        "if_index": None,
        "if_name": None,
        "if_descr": None,
        "if_oper_status": None,
        "if_admin_status": None,
        "extra": {}
    }
    for oid, val in varbinds:
        oid_str = str(oid)
        val_str = str(val)
        # IFインデックス
        if "1.3.6.1.2.1.2.2.1.1" in oid_str:
            result["if_index"] = val_str
        # IFディスクリプション
        elif "1.3.6.1.2.1.2.2.1.2" in oid_str:
            result["if_descr"] = val_str
        # IF名
        elif "1.3.6.1.2.1.31.1.1.1.1" in oid_str:
            result["if_name"] = val_str
        # Oper Status
        elif "1.3.6.1.2.1.2.2.1.8" in oid_str:
            result["if_oper_status"] = IF_STATUS.get(val_str, val_str)
        # Admin Status
        elif "1.3.6.1.2.1.2.2.1.7" in oid_str:
            result["if_admin_status"] = IF_STATUS.get(val_str, val_str)
        else:
            result["extra"][oid_str] = val_str
    return result

def build_parsed_dict(source_ip: str, trap_oid: str, varbinds: list,
                      community: str = "public", version: str = "v2c") -> dict:
    """
    Trap情報をログDB互換の構造化dictに変換する
    """
    trap_info = lookup_trap(trap_oid)
    vb_info = parse_varbinds(varbinds)
    vendor = detect_vendor_from_oid(trap_oid)

    if trap_info:
        severity, mnemonic, description = trap_info
    else:
        severity = "INFO"
        mnemonic = "unknownTrap"
        description = f"未知のTrap OID: {trap_oid}"

    # インターフェース情報を含める
    if_label = (vb_info.get("if_name") or
                vb_info.get("if_descr") or
                (f"ifIndex:{vb_info['if_index']}" if vb_info.get("if_index") else ""))
    oper = vb_info.get("if_oper_status", "")
    message_parts = [description]
    if if_label:
        message_parts.append(f"インターフェース: {if_label}")
    if oper:
        message_parts.append(f"状態: {oper}")
    message = " | ".join(message_parts)

    tags = ["SNMP-Trap", vendor, mnemonic]
    if "Down" in mnemonic or "down" in mnemonic or "Failure" in mnemonic or "Error" in mnemonic:
        tags.append("障害候補")
    if "Loop" in mnemonic or "loop" in mnemonic:
        tags.append("ループ")
    if "Auth" in mnemonic or "auth" in mnemonic:
        tags.append("認証失敗")
    if if_label:
        tags.append(f"IF:{if_label}")

    raw_summary = (
        f"SNMP-Trap({version}) from={source_ip} "
        f"community={community} oid={trap_oid} "
        + " ".join(f"{k}={v}" for k, v in vb_info["extra"].items())
    )

    return {
        "vendor": f"{vendor} (SNMP)",
        "hostname": source_ip,
        "facility": "SNMP-Trap",
        "severity": severity,
        "severity_digit": "",
        "process": mnemonic,
        "message": message,
        "timestamp": "",
        "tags": tags,
        "raw_for_ai": raw_summary,
        "trap_oid": trap_oid,
        "varbind_info": vb_info,
    }
