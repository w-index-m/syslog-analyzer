"""
NetFlow v5 受信サーバー
- Cisco IOS/IOS-XE の ip flow-export で送信される NetFlow v5 パケットを受信
- フロー集計・トップトーカー・プロトコル分布・タイムライン を提供

ルーター側の設定例（Cisco IOS-XE）:
    ip flow-export version 5
    ip flow-export destination <このPCのIP> 9995
    ip flow-cache timeout active 1
    !
    interface GigabitEthernet1/0/1
     ip flow ingress
     ip flow egress
"""
import os
import struct
import socket
import sqlite3
import threading
import socketserver
from datetime import datetime
from pathlib import Path

DB_PATH      = Path(os.environ.get("DB_PATH", str(Path(__file__).parent / "syslog.db")))
NETFLOW_PORT = int(os.environ.get("NETFLOW_PORT", 9995))

PROTOCOL_NAMES = {
    1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE",
    50: "ESP", 51: "AH", 89: "OSPF", 132: "SCTP",
}

WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 161: "SNMP", 162: "SNMP-trap", 179: "BGP",
    389: "LDAP", 443: "HTTPS", 514: "Syslog", 520: "RIP",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5060: "SIP", 5061: "SIP-TLS", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


# ─────────────────────────────────────────
# DB
# ─────────────────────────────────────────

def _init_tables():
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS netflow_flows (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at TEXT NOT NULL,
                exporter_ip TEXT NOT NULL,
                src_ip      TEXT NOT NULL,
                dst_ip      TEXT NOT NULL,
                src_port    INTEGER DEFAULT 0,
                dst_port    INTEGER DEFAULT 0,
                protocol    INTEGER DEFAULT 0,
                packets     INTEGER DEFAULT 0,
                bytes       INTEGER DEFAULT 0,
                tcp_flags   INTEGER DEFAULT 0,
                tos         INTEGER DEFAULT 0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_nf_recv ON netflow_flows(received_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_nf_exp  ON netflow_flows(exporter_ip)")
        conn.commit()


def _save_flows(flows: list[dict]):
    if not flows:
        return
    _init_tables()
    now = datetime.now().isoformat()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.executemany("""
            INSERT INTO netflow_flows
            (received_at, exporter_ip, src_ip, dst_ip,
             src_port, dst_port, protocol, packets, bytes, tcp_flags, tos)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, [(now, f["exporter_ip"], f["src_ip"], f["dst_ip"],
               f["src_port"], f["dst_port"], f["protocol"],
               f["packets"], f["bytes"], f["tcp_flags"], f["tos"])
              for f in flows])
        conn.commit()


# ─────────────────────────────────────────
# NetFlow v5 パーサー
# ─────────────────────────────────────────

def _parse_v5(data: bytes, exporter_ip: str) -> list[dict]:
    if len(data) < 24:
        return []
    version, count = struct.unpack("!HH", data[:4])
    if version != 5:
        return []
    flows = []
    for i in range(min(count, 30)):
        offset = 24 + i * 48
        if offset + 48 > len(data):
            break
        try:
            rec = struct.unpack("!IIIHHIIIIHHBBBBHHBBxx", data[offset:offset + 48])
        except struct.error:
            break
        src_int, dst_int = rec[0], rec[1]
        d_pkts, d_oct   = rec[5], rec[6]
        src_port, dst_port = rec[9], rec[10]
        tcp_flags, proto, tos = rec[12], rec[13], rec[14]
        flows.append({
            "exporter_ip": exporter_ip,
            "src_ip":    socket.inet_ntoa(struct.pack("!I", src_int)),
            "dst_ip":    socket.inet_ntoa(struct.pack("!I", dst_int)),
            "src_port":  src_port,
            "dst_port":  dst_port,
            "protocol":  proto,
            "packets":   d_pkts,
            "bytes":     d_oct,
            "tcp_flags": tcp_flags,
            "tos":       tos,
        })
    return flows


# ─────────────────────────────────────────
# UDP サーバー
# ─────────────────────────────────────────

class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        exporter_ip = self.client_address[0]
        if len(data) >= 2:
            version = struct.unpack("!H", data[:2])[0]
            if version == 5:
                flows = _parse_v5(data, exporter_ip)
                if flows:
                    _save_flows(flows)
                    print(f"[NetFlow] {exporter_ip}: {len(flows)} flows")
            else:
                print(f"[NetFlow] {exporter_ip}: unsupported version {version} (v5 only)")


class NetFlowServer:
    def __init__(self, host="0.0.0.0", port=NETFLOW_PORT):
        self.host  = host
        self.port  = port
        self._srv  = None
        self._th   = None
        self.running = False
        self.error   = None

    def start(self):
        try:
            self._srv = socketserver.UDPServer((self.host, self.port), _Handler)
            self._srv.socket.settimeout(1.0)
            self._th = threading.Thread(target=self._serve, daemon=True)
            self._th.start()
            self.running = True
            self.error   = None
            print(f"[NetFlowServer] UDP {self.host}:{self.port}")
        except Exception as e:
            self.error   = str(e)
            self.running = False

    def _serve(self):
        while self.running:
            try:
                self._srv.handle_request()
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self._srv:
            self._srv.server_close()


_instance = None

def get_server(port: int = NETFLOW_PORT) -> NetFlowServer:
    global _instance
    if _instance is None:
        _instance = NetFlowServer(port=port)
    return _instance


# ─────────────────────────────────────────
# クエリ関数
# ─────────────────────────────────────────

def get_summary(hours: int = 1) -> dict:
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("""
            SELECT COUNT(*) as flows,
                   COALESCE(SUM(bytes),0)   as total_bytes,
                   COALESCE(SUM(packets),0) as total_packets,
                   COUNT(DISTINCT src_ip)   as unique_src,
                   COUNT(DISTINCT exporter_ip) as exporters
            FROM netflow_flows
            WHERE received_at >= datetime('now', ? || ' hours')
        """, (f"-{hours}",)).fetchone()
        return {"total_flows": row[0], "total_bytes": row[1],
                "total_packets": row[2], "unique_src": row[3], "exporters": row[4]}


def get_top_talkers(hours: int = 1, limit: int = 20) -> list[dict]:
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT src_ip as ip,
                   SUM(bytes)   as total_bytes,
                   SUM(packets) as total_packets,
                   COUNT(*)     as flows
            FROM netflow_flows
            WHERE received_at >= datetime('now', ? || ' hours')
            GROUP BY src_ip ORDER BY total_bytes DESC LIMIT ?
        """, (f"-{hours}", limit)).fetchall()
        return [dict(r) for r in rows]


def get_protocol_stats(hours: int = 1) -> list[dict]:
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT protocol,
                   SUM(bytes)   as total_bytes,
                   SUM(packets) as total_packets,
                   COUNT(*)     as flows
            FROM netflow_flows
            WHERE received_at >= datetime('now', ? || ' hours')
            GROUP BY protocol ORDER BY total_bytes DESC
        """, (f"-{hours}",)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["protocol_name"] = PROTOCOL_NAMES.get(d["protocol"], f"proto/{d['protocol']}")
            result.append(d)
        return result


def get_port_stats(hours: int = 1, limit: int = 15) -> list[dict]:
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT dst_port,
                   SUM(bytes)   as total_bytes,
                   SUM(packets) as total_packets,
                   COUNT(*)     as flows
            FROM netflow_flows
            WHERE received_at >= datetime('now', ? || ' hours')
              AND protocol IN (6, 17)
            GROUP BY dst_port ORDER BY total_bytes DESC LIMIT ?
        """, (f"-{hours}", limit)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["app"] = WELL_KNOWN_PORTS.get(d["dst_port"], f":{d['dst_port']}")
            result.append(d)
        return result


def get_traffic_timeline(hours: int = 1) -> list[dict]:
    _init_tables()
    fmt = "%Y-%m-%d %H:%M" if hours <= 12 else "%Y-%m-%d %H:00"
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(f"""
            SELECT strftime('{fmt}', received_at, 'localtime') as ts,
                   SUM(bytes) as total_bytes,
                   COUNT(*)   as flows
            FROM netflow_flows
            WHERE received_at >= datetime('now', ? || ' hours')
            GROUP BY ts ORDER BY ts
        """, (f"-{hours}",)).fetchall()
        return [dict(r) for r in rows]


def get_recent_flows(hours: int = 1, limit: int = 500) -> list[dict]:
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT received_at, exporter_ip, src_ip, dst_ip,
                   src_port, dst_port, protocol, packets, bytes
            FROM netflow_flows
            WHERE received_at >= datetime('now', ? || ' hours')
            ORDER BY received_at DESC LIMIT ?
        """, (f"-{hours}", limit)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["proto_name"] = PROTOCOL_NAMES.get(d["protocol"], str(d["protocol"]))
            d["app"]        = WELL_KNOWN_PORTS.get(d["dst_port"], "")
            result.append(d)
        return result


# ─────────────────────────────────────────
# DDoS 検出
# ─────────────────────────────────────────

def get_ddos_alerts(hours: int = 1) -> list[dict]:
    """NetFlowデータから DDoS/攻撃パターンを検出する。"""
    _init_tables()
    alerts = []
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        # 1. ボリューム攻撃: 単一送信元から 100MB 超
        for r in conn.execute("""
            SELECT src_ip, SUM(bytes) AS tb, SUM(packets) AS tp,
                   COUNT(*) AS flows, COUNT(DISTINCT dst_ip) AS uniq_dst
            FROM netflow_flows
            WHERE received_at >= datetime('now', ? || ' hours')
            GROUP BY src_ip HAVING tb > 100000000
            ORDER BY tb DESC LIMIT 20
        """, (f"-{hours}",)).fetchall():
            alerts.append({
                "type": "volumetric",
                "severity": "high" if r["tb"] > 500_000_000 else "medium",
                "src_ip": r["src_ip"],
                "detail": f"大量転送: {r['tb']/1024/1024:.1f} MB / {r['flows']} フロー / 宛先 {r['uniq_dst']} IP",
                "bytes": r["tb"],
            })

        # 2. ポートスキャン: 単一送信元から 50 以上の異なる宛先ポート
        for r in conn.execute("""
            SELECT src_ip, COUNT(DISTINCT dst_port) AS dp,
                   COUNT(DISTINCT dst_ip) AS di, COUNT(*) AS flows
            FROM netflow_flows
            WHERE received_at >= datetime('now', ? || ' hours') AND protocol IN (6,17)
            GROUP BY src_ip HAVING dp > 50
            ORDER BY dp DESC LIMIT 20
        """, (f"-{hours}",)).fetchall():
            alerts.append({
                "type": "port_scan",
                "severity": "high" if r["dp"] > 200 else "medium",
                "src_ip": r["src_ip"],
                "detail": f"ポートスキャン: {r['dp']} ポート / 宛先 {r['di']} IP / {r['flows']} フロー",
                "ports": r["dp"],
            })

        # 3. SYN フラッド: SYN のみ（ACK なし）フローが 100 超
        for r in conn.execute("""
            SELECT src_ip, COUNT(*) AS syn_flows, SUM(packets) AS tp
            FROM netflow_flows
            WHERE received_at >= datetime('now', ? || ' hours')
              AND protocol = 6
              AND (tcp_flags & 2) = 2
              AND (tcp_flags & 16) = 0
            GROUP BY src_ip HAVING syn_flows > 100
            ORDER BY syn_flows DESC LIMIT 20
        """, (f"-{hours}",)).fetchall():
            alerts.append({
                "type": "syn_flood",
                "severity": "high" if r["syn_flows"] > 500 else "medium",
                "src_ip": r["src_ip"],
                "detail": f"SYNフラッド: {r['syn_flows']} SYN-only フロー / {r['tp']} パケット",
                "syn_flows": r["syn_flows"],
            })

        # 4. ICMP フラッド: 単一送信元から 10000 パケット超
        for r in conn.execute("""
            SELECT src_ip, SUM(packets) AS tp, COUNT(*) AS flows
            FROM netflow_flows
            WHERE received_at >= datetime('now', ? || ' hours') AND protocol = 1
            GROUP BY src_ip HAVING tp > 10000
            ORDER BY tp DESC LIMIT 10
        """, (f"-{hours}",)).fetchall():
            alerts.append({
                "type": "icmp_flood",
                "severity": "medium",
                "src_ip": r["src_ip"],
                "detail": f"ICMPフラッド: {r['tp']:,} パケット / {r['flows']} フロー",
                "packets": r["tp"],
            })

    severity_order = {"high": 0, "medium": 1, "low": 2}
    alerts.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 2))
    return alerts


# ─────────────────────────────────────────
# 帯域トレンド（容量計画用）
# ─────────────────────────────────────────

def get_bandwidth_history(days: int = 7) -> list[dict]:
    """時間別帯域使用量（容量計画・トレンド分析用）"""
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT strftime('%Y-%m-%d %H:00', received_at, 'localtime') AS hour,
                   SUM(bytes)   AS total_bytes,
                   SUM(packets) AS total_packets,
                   COUNT(*)     AS flows
            FROM netflow_flows
            WHERE received_at >= datetime('now', ? || ' days')
            GROUP BY hour ORDER BY hour
        """, (f"-{days}",)).fetchall()
        return [dict(r) for r in rows]
