"""
ワーム/ボットが横展開（ラテラルムーブメント）でよく狙うポート。

pcap解析(pcap_analyzer.py)とNetFlow解析(netflow_collector.py)の両方で、
「同一送信元から短時間に多数の異なる宛先へ同一ポートで接続」という
振る舞い検知の重大度判定に共用する。
"""

WORM_TARGET_PORTS = {
    22: "SSH", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5555: "ADB", 6379: "Redis", 7547: "TR-069", 1900: "UPnP", 5900: "VNC",
    2323: "Telnet(IoT)", 9200: "Elasticsearch", 27017: "MongoDB", 11211: "Memcached",
}
