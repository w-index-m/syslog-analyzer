"""
ベンダー推奨設定集
各メーカーの公式ドキュメント・ベストプラクティスに基づくsyslog/SNMP関連の推奨設定。
コンフィグレビュー時の参照や、新規導入時のテンプレートとして利用する。

注意: 実際の設定値（コミュニティ名、IPアドレス等）は環境に応じて必ず変更すること。
特にSNMP community名 "public"/"private" は初期値のままにせず、独自の文字列に変更すること。
"""

RECOMMENDED_SETTINGS = {

    "Cisco IOS/IOS-XE": {
        "category": "Catalyst シリーズ",
        "syslog": """
! ── syslog 基本設定 ──
logging buffered 16384 informational
logging host 192.168.x.x transport udp port 5140
logging trap informational
logging source-interface Loopback0
logging facility local6
service timestamps log datetime msec localtime show-timezone

! ── 推奨: タイムスタンプ精度を上げる ──
service timestamps debug datetime msec localtime show-timezone
""",
        "snmp": """
! ── SNMP 基本設定（v2c、開発・検証用） ──
snmp-server community ${独自の文字列に変更} RO
snmp-server location "Server-Room-1F"
snmp-server contact "network-team@example.com"
snmp-server host 192.168.x.x version 2c ${独自の文字列に変更}
snmp-server enable traps snmp linkdown linkup coldstart warmstart
snmp-server enable traps envmon
snmp-server enable traps ospf
snmp-server enable traps bgp
snmp-server enable traps config

! ── 推奨: 本番環境はSNMPv3を使用 ──
snmp-server group NETMON v3 priv
snmp-server user monitor NETMON v3 auth sha ${認証パスワード} priv aes 128 ${暗号化パスワード}
""",
        "security_notes": [
            "SNMP community名はデフォルト(public/private)を絶対に使わない",
            "可能な限りSNMPv3 (認証+暗号化)を使用する",
            "logging host への通信はACLで管理セグメントからのみ許可する",
            "NTP同期を必ず設定する（ログの時刻精度に直結）: ntp server 192.168.x.x",
        ],
        "reference": "Cisco公式: Network Management Configuration Guide"
    },

    "Cisco NX-OS": {
        "category": "Nexus シリーズ",
        "syslog": """
! ── syslog 基本設定 ──
logging server 192.168.x.x 6 use-vrf management facility local6
logging level local6 6
logging timestamp milliseconds
logging logfile messages 6 size 4096

! ── VPC/HA環境での推奨 ──
logging server 192.168.x.x 6 use-vrf management port 5140
""",
        "snmp": """
! ── SNMP 基本設定 ──
snmp-server community ${独自の文字列に変更} ro
snmp-server host 192.168.x.x traps version 2c ${独自の文字列に変更}
snmp-server enable traps link linkDown
snmp-server enable traps link linkUp
snmp-server enable traps vpc all
snmp-server enable traps stpx loop-inconsistency
snmp-server enable traps bgp

! ── 推奨: SNMPv3使用 ──
snmp-server user monitor network-operator auth sha ${認証パスワード} priv aes-128 ${暗号化パスワード}
""",
        "security_notes": [
            "VPC構成時はピアリンク状態のTrap (vpc all) を必ず有効化する",
            "management VRFを使い、SNMP/syslog通信を業務トラフィックと分離する",
            "STPループ検知Trapを有効化し、ループ障害を即時検知する",
        ],
        "reference": "Cisco公式: Nexus 9000 System Management Configuration Guide"
    },

    "富士通 Si-R": {
        "category": "Si-R G100/G120/G200 シリーズ",
        "syslog": """
# ── syslog 基本設定 ──
syslog host 192.168.x.x
syslog facility local0
syslog priority info
syslog port 5140

# ── 推奨: バッファログも有効化 ──
syslog buffer enable
syslog buffer size 1024
""",
        "snmp": """
# ── SNMP 基本設定 ──
snmp host 192.168.x.x community ${独自の文字列に変更} version 2c
snmp trap enable
snmp trap host 192.168.x.x community ${独自の文字列に変更}
snmp community ${独自の文字列に変更} ro

# ── PPP/専用線回線の監視には特に以下を有効化 ──
snmp trap linkdown enable
snmp trap linkup enable
""",
        "security_notes": [
            "WAN回線（PPP/専用線）はリンクUP/DOWN Trapを必ず有効化する（拠点間断線の即時検知）",
            "OSPF/RIPを使う場合はネイバー状態変化のログレベルをinfo以上に設定する",
            "リモート拠点設置の場合、コンフィグのバックアップ（write file等）を定期的に取得する",
        ],
        "reference": "富士通公式: Si-R シリーズ コマンドリファレンス"
    },

    "APRESIA ApresiaLight": {
        "category": "ApresiaLight シリーズ",
        "syslog": """
# ── syslog 基本設定 ──
syslog-server 192.168.x.x
syslog-server port 5140
syslog-level informational

# ── ループ検知関連は必ずログ出力を有効化 ──
loop-detect enable
loop-detect syslog enable
""",
        "snmp": """
# ── SNMP 基本設定 ──
snmp-server community ${独自の文字列に変更} ro
snmp-server host 192.168.x.x community ${独自の文字列に変更}
snmp-server trap enable
snmp-server trap link-status enable
snmp-server trap loop-detect enable
snmp-server trap stp-topology-change enable
""",
        "security_notes": [
            "ループ検知Trap (loop-detect) は必ず有効化する（ブロードキャストストーム対策）",
            "STPトポロジ変化通知を有効化し、意図しない経路変更を即検知する",
            "アクセスポートはport-securityでMACアドレス数を制限する",
        ],
        "reference": "APRESIA公式: ApresiaLight シリーズ コンフィグレーションガイド"
    },

    "RHEL/Linux": {
        "category": "RHEL 8/9, CentOS, Rocky Linux",
        "syslog": """
# ── /etc/rsyslog.conf 推奨設定 ──
*.* @192.168.x.x:5140          # UDP転送（軽量、ログ欠落の可能性あり）
*.* @@192.168.x.x:5140         # TCP転送（推奨、信頼性が高い）

# ── 認証ログは個別に転送（重要度が高いため） ──
auth,authpriv.*  @@192.168.x.x:5140

# 設定後は再起動
# systemctl restart rsyslog
""",
        "snmp": """
# ── net-snmp 基本設定 (/etc/snmp/snmpd.conf) ──
rocommunity ${独自の文字列に変更}  192.168.x.0/24
syslocation "Server-Room-1F"
syscontact  "infra-team@example.com"

# ── SNMPv3推奨設定 ──
createUser monitor SHA "${認証パスワード}" AES "${暗号化パスワード}"
rouser monitor priv

# systemctl restart snmpd
""",
        "security_notes": [
            "authpriv（認証関連）ログは個別にTCP転送し、欠落を防ぐ",
            "auditdを有効化し、重要な操作の監査ログを取得する: systemctl enable --now auditd",
            "SELinuxを無効化せず、必要な例外のみ追加する",
            "sshdのログレベルをVERBOSEに上げ、ログイン試行の詳細を記録する: LogLevel VERBOSE",
        ],
        "reference": "Red Hat公式: System Administrator's Guide - Viewing and Managing Log Files"
    },

    "Windows": {
        "category": "Windows Server (NXLog/Winlogbeat経由)",
        "syslog": """
# ── NXLog Community Edition 推奨設定 (nxlog.conf) ──
<Input eventlog>
    Module      im_msvistalog
    Query       <QueryList>\\
                  <Query Id="0">\\
                    <Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4740 or EventID=4720)]]</Select>\\
                    <Select Path="System">*[System[(EventID=6005 or EventID=6006 or EventID=6008 or EventID=7034)]]</Select>\\
                  </Query>\\
                </QueryList>
</Input>

<Output syslog_out>
    Module  om_udp
    Host    192.168.x.x
    Port    5140
    Exec    to_syslog_bsd();
</Output>

<Route eventlog_to_syslog>
    Path    eventlog => syslog_out
</Route>
""",
        "snmp": """
# Windows標準SNMPサービスは古いため非推奨。
# 代わりにWinlogbeat / NXLogでのログ転送を強く推奨。
# SNMPを使う場合は「SNMPサービス」機能の追加インストールが必要：
# Install-WindowsFeature SNMP-Service

# snmp.iniでの community 設定例（レガシー、要セキュリティ強化）
# [TrapDestinations]
# public = 192.168.x.x
""",
        "security_notes": [
            "Windows標準SNMPは脆弱性が多いため、できればNXLog/Winlogbeatでのログ転送に統一する",
            "イベントID 4625（ログオン失敗）・4740（ロックアウト）は必ず転送対象に含める",
            "イベントID 1116/1117（Defenderマルウェア検出）も重要度が高いため転送推奨",
            "ローカルセキュリティポリシーで監査ポリシーを有効化する: 'ログオンの監査'等",
        ],
        "reference": "Microsoft公式: Windows Server セキュリティ監査ポリシーの推奨事項"
    },
}


def get_settings(vendor: str) -> dict | None:
    """ベンダー名から推奨設定を取得"""
    return RECOMMENDED_SETTINGS.get(vendor)


def get_all_vendors() -> list:
    """対応ベンダー一覧を返す"""
    return list(RECOMMENDED_SETTINGS.keys())
