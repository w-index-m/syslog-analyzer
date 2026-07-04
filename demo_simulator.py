"""
動作シミュレーター
実機なしで全機能をデモするためのサンプルデータ生成モジュール。

生成データ:
  - syslog イベント → logs / telemetry テーブル
  - NetFlow フロー  → netflow_flows テーブル
  - pcap バイト列   → メモリ上で返却（ファイル保存不要）
"""
import io
import os
import random
import socket
import sqlite3
import struct
import time
from datetime import datetime, timedelta
from pathlib import Path

import dpkt

import db
from parsers import parse_syslog

DB_PATH = Path(os.environ.get("DB_PATH", str(Path(__file__).parent / "syslog.db")))

# ─── シナリオ定義 ──────────────────────────────────────────────────
SCENARIOS = {
    "normal":        "🟢 通常運用（軽微なイベントのみ）",
    "bgp_incident":  "🟠 BGPネイバーダウン → 自動復旧",
    "ddos":          "🔴 DDoS攻撃（ポートスキャン + SYNフラッド）",
    "icmp_redirect": "🟡 ICMPリダイレクト多発（ルーティング設計ミス）",
    "voip_degraded": "📞 VoIP品質劣化（ジッター増大・パケットロス）",
}

# ─── サンプル IP ───────────────────────────────────────────────────
ROUTER1   = "192.168.1.1"
ROUTER2   = "10.0.0.1"
SWITCH1   = "192.168.1.2"
SWITCH2   = "192.168.1.3"
DNS_SRV   = "8.8.8.8"
CLIENT_IPS = [f"192.168.10.{i}" for i in range(1, 21)]
EXT_IPS    = ["203.0.113.10", "198.51.100.5", "93.184.216.34"]
ATTACK_IPS = ["45.33.32.156", "104.16.99.1", "185.220.101.45", "23.92.27.4"]

HOSTNAMES = {
    ROUTER1:  "Core-Router-01",
    ROUTER2:  "Edge-Router-01",
    SWITCH1:  "Core-SW-01",
    SWITCH2:  "Access-SW-01",
}

# ═══════════════════════════════════════════════════════════════════
#  syslog 生成ヘルパー
# ═══════════════════════════════════════════════════════════════════

def _syslog_raw(device_ip: str, facility_sev: str, mnemonic: str, message: str) -> str:
    hn = HOSTNAMES.get(device_ip, device_ip)
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    return f"<{random.randint(130,191)}>{ts} {hn} : {facility_sev}-{mnemonic}: {message}"


def _insert_syslog(device_ip: str, raw: str):
    parsed = parse_syslog(raw, device_ip)
    db.insert_log(device_ip, raw, parsed)


# ═══════════════════════════════════════════════════════════════════
#  NetFlow 生成ヘルパー
# ═══════════════════════════════════════════════════════════════════

def _insert_flows(flows: list[dict]):
    """netflow_flows テーブルに直接インサートする。"""
    if not flows:
        return
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS netflow_flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        conn.executemany("""
            INSERT INTO netflow_flows
            (received_at, exporter_ip, src_ip, dst_ip,
             src_port, dst_port, protocol, packets, bytes, tcp_flags, tos)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, [(f["ts"], f["exp"], f["src"], f["dst"],
               f["sp"], f["dp"], f["proto"], f["pkts"], f["bytes"],
               f.get("flags", 0), 0)
              for f in flows])
        conn.commit()


def _ts_ago(minutes: int) -> str:
    return (datetime.now() - timedelta(minutes=minutes)).isoformat()


def _gen_http_flows(exporter: str, n: int = 80, minutes_range: int = 60) -> list[dict]:
    flows = []
    for _ in range(n):
        src = random.choice(CLIENT_IPS)
        dst = random.choice(EXT_IPS + [DNS_SRV])
        flows.append({
            "ts": _ts_ago(random.randint(0, minutes_range)),
            "exp": exporter, "src": src, "dst": dst,
            "sp": random.randint(40000, 60000), "dp": random.choice([80, 443, 8080]),
            "proto": 6,
            "pkts": random.randint(5, 200),
            "bytes": random.randint(500, 500_000),
            "flags": 0x18,  # PSH+ACK
        })
    return flows


# ═══════════════════════════════════════════════════════════════════
#  pcap 生成ヘルパー
# ═══════════════════════════════════════════════════════════════════

_MAC_SRC = b"\x00\x11\x22\x33\x44\x55"
_MAC_DST = b"\x66\x77\x88\x99\xaa\xbb"


def _eth(ip_pkt: dpkt.ip.IP) -> bytes:
    eth = dpkt.ethernet.Ethernet(
        src=_MAC_SRC, dst=_MAC_DST,
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip_pkt,
    )
    return bytes(eth)


def _ip_udp(src: str, dst: str, sport: int, dport: int, data: bytes) -> bytes:
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=data)
    udp.ulen = 8 + len(data)
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src), dst=socket.inet_aton(dst),
        p=dpkt.ip.IP_PROTO_UDP, data=udp, len=20 + 8 + len(data),
    )
    return _eth(ip)


def _ip_tcp(src: str, dst: str, sport: int, dport: int,
            flags: int, seq: int = 0, ack: int = 0, data: bytes = b"") -> bytes:
    tcp = dpkt.tcp.TCP(
        sport=sport, dport=dport, flags=flags,
        seq=seq, ack=ack, off=5, data=data,
    )
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src), dst=socket.inet_aton(dst),
        p=dpkt.ip.IP_PROTO_TCP, data=tcp,
    )
    return _eth(ip)


def _ip_icmp(src: str, dst: str, icmp_type: int, icmp_code: int,
             extra: bytes = b"") -> bytes:
    icmp = dpkt.icmp.ICMP(type=icmp_type, code=icmp_code, data=extra)
    ip   = dpkt.ip.IP(
        src=socket.inet_aton(src), dst=socket.inet_aton(dst),
        p=dpkt.ip.IP_PROTO_ICMP, data=icmp,
    )
    return _eth(ip)


def _rtp_pkt(src: str, dst: str, sport: int, dport: int,
             ssrc: int, seq: int, rtp_ts: int, pt: int = 0) -> bytes:
    """G.711 RTP パケット (version=2, payload 160バイト)"""
    header = struct.pack("!BBHII", 0x80, pt & 0x7F, seq, rtp_ts, ssrc)
    payload = bytes(random.randint(0, 127) for _ in range(160))
    return _ip_udp(src, dst, sport, dport, header + payload)


def _dns_query(src: str, name: str, txid: int) -> bytes:
    """A レコードクエリ"""
    try:
        dns = dpkt.dns.DNS(
            id=txid, op=dpkt.dns.DNS_RD,
            qd=[dpkt.dns.DNS.Q(name=name, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN)],
        )
        return _ip_udp(src, DNS_SRV, random.randint(40000, 60000), 53, bytes(dns))
    except Exception:
        return b""


def _dns_nxdomain(src: str, name: str, txid: int) -> bytes:
    """NXDOMAIN レスポンス"""
    try:
        dns = dpkt.dns.DNS(
            id=txid,
            op=dpkt.dns.DNS_RA | dpkt.dns.DNS_QR,
            rcode=3,  # NXDOMAIN
            qd=[dpkt.dns.DNS.Q(name=name, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN)],
        )
        return _ip_udp(DNS_SRV, src, 53, random.randint(40000, 60000), bytes(dns))
    except Exception:
        return b""


def _write_pcap(packets: list[tuple[float, bytes]]) -> bytes:
    """(timestamp, raw_bytes) リストを pcap バイト列に変換する。"""
    buf = io.BytesIO()
    w = dpkt.pcap.Writer(buf)
    for ts, pkt in packets:
        if pkt:
            w.writepkt(pkt, ts=ts)
    return buf.getvalue()


# ═══════════════════════════════════════════════════════════════════
#  シナリオ別 syslog
# ═══════════════════════════════════════════════════════════════════

def _syslogs_normal() -> list[tuple[str, str]]:
    events = []
    for _ in range(20):
        ip = random.choice([ROUTER1, ROUTER2, SWITCH1])
        events.append((ip, _syslog_raw(ip, "%SYS-5", "CONFIG_I",
            "Configured from console by admin on vty0 (192.168.1.100)")))
    for _ in range(10):
        events.append((ROUTER1, _syslog_raw(ROUTER1, "%SEC_LOGIN-5", "LOGIN_SUCCESS",
            f"Login Success [user: admin] [Source: 192.168.1.{random.randint(100,110)}]")))
    events.append((ROUTER1, _syslog_raw(ROUTER1, "%SNMP-5", "COLDSTART",
        "SNMP agent on host Core-Router-01 is undergoing a cold start")))
    return events


def _syslogs_bgp_incident() -> list[tuple[str, str]]:
    events = []
    # インターフェースダウン
    events.append((ROUTER1, _syslog_raw(ROUTER1, "%LINK-3", "UPDOWN",
        "Interface GigabitEthernet0/1, changed state to down")))
    events.append((ROUTER1, _syslog_raw(ROUTER1, "%LINEPROTO-5", "UPDOWN",
        "Line protocol on Interface GigabitEthernet0/1, changed state to down")))
    # BGP ダウン
    events.append((ROUTER1, _syslog_raw(ROUTER1, "%BGP-5", "ADJCHANGE",
        "neighbor 10.0.0.2 Down Interface flap")))
    events.append((ROUTER2, _syslog_raw(ROUTER2, "%BGP-5", "ADJCHANGE",
        "neighbor 192.168.1.1 Down BFD adjacency down")))
    # OSPF 再収束
    events.append((ROUTER1, _syslog_raw(ROUTER1, "%OSPF-5", "ADJCHG",
        "Process 1, Nbr 10.0.0.2 on GigabitEthernet0/0 from FULL to DOWN")))
    for _ in range(3):
        events.append((SWITCH1, _syslog_raw(SWITCH1, "%STP-2", "TOPOLOGY_CHANGE",
            "vlan 1, detected on GigabitEthernet0/1")))
    # 復旧
    events.append((ROUTER1, _syslog_raw(ROUTER1, "%LINK-3", "UPDOWN",
        "Interface GigabitEthernet0/1, changed state to up")))
    events.append((ROUTER1, _syslog_raw(ROUTER1, "%BGP-5", "ADJCHANGE",
        "neighbor 10.0.0.2 Up")))
    events.append((ROUTER1, _syslog_raw(ROUTER1, "%OSPF-5", "ADJCHG",
        "Process 1, Nbr 10.0.0.2 on GigabitEthernet0/0 from LOADING to FULL")))
    return events


def _syslogs_ddos() -> list[tuple[str, str]]:
    events = []
    for atk in ATTACK_IPS:
        for _ in range(10):
            events.append((ROUTER1, _syslog_raw(ROUTER1, "%SEC-6", "IPACCESSLOGP",
                f"list OUTSIDE_IN denied tcp {atk}({random.randint(1024,65535)}) "
                f"-> 192.168.1.1(22), {random.randint(10,200)} packets")))
    events.append((ROUTER1, _syslog_raw(ROUTER1, "%IOS_FIREWALL-6", "DROP",
        f"Dropped: 5432 SYN packets from 45.33.32.156 to 192.168.1.1")))
    events.append((ROUTER1, _syslog_raw(ROUTER1, "%QOS-4", "POLICER_DROP",
        "Policy-map ANTI_DDOS class SYN_POLICE: 8921 packets dropped")))
    events.append((ROUTER1, _syslog_raw(ROUTER1, "%SYS-3", "CPUHOG",
        "Task is running for longer than expected: SYN processing 98% CPU")))
    return events


def _syslogs_icmp_redirect() -> list[tuple[str, str]]:
    events = []
    for _ in range(15):
        client = random.choice(CLIENT_IPS)
        gw = f"192.168.1.{random.randint(2,5)}"
        events.append((ROUTER1, _syslog_raw(ROUTER1, "%ICMP-4", "REDIRECT",
            f"GigabitEthernet0/1: ICMP redirect sent to {client}, "
            f"use gateway {gw} for destination {random.choice(EXT_IPS)}")))
    events.append((ROUTER1, _syslog_raw(ROUTER1, "%IP-4", "DUPADDR",
        "Duplicate address 192.168.1.1 on GigabitEthernet0/0, sourced by 00:11:22:33:44:01")))
    return events


def _syslogs_voip() -> list[tuple[str, str]]:
    events = []
    events.append((ROUTER1, _syslog_raw(ROUTER1, "%VOICE-3", "POOR_QUALITY",
        "RTP stream 192.168.10.5:16384 → 10.0.0.10:16384 MOS=2.8 (jitter=45ms loss=5%)")))
    events.append((SWITCH1, _syslog_raw(SWITCH1, "%QOS-4", "QUEUE_DROP",
        "Interface Gi0/3 voice queue drop rate 12% — check QoS policy")))
    for _ in range(5):
        events.append((ROUTER1, _syslog_raw(ROUTER1, "%SCCP-6", "REGREJ",
            f"Registration rejected for IP Phone {random.choice(CLIENT_IPS)}")))
    return events


# ═══════════════════════════════════════════════════════════════════
#  シナリオ別 NetFlow
# ═══════════════════════════════════════════════════════════════════

def _netflow_normal() -> list[dict]:
    flows = _gen_http_flows(ROUTER1, n=100)
    # DNS
    for _ in range(30):
        c = random.choice(CLIENT_IPS)
        flows.append({"ts": _ts_ago(random.randint(0, 60)), "exp": ROUTER1,
                      "src": c, "dst": DNS_SRV,
                      "sp": random.randint(40000, 60000), "dp": 53,
                      "proto": 17, "pkts": 2, "bytes": 200})
    return flows


def _netflow_ddos() -> list[dict]:
    flows = _gen_http_flows(ROUTER1, n=30)
    # ボリューム攻撃（200MB超）
    flows.append({"ts": _ts_ago(5), "exp": ROUTER1,
                  "src": ATTACK_IPS[0], "dst": ROUTER1,
                  "sp": 12345, "dp": 80, "proto": 6,
                  "pkts": 500_000, "bytes": 250_000_000, "flags": 0x02})
    # ポートスキャン（100ポート以上）
    for port in range(1, 120):
        flows.append({"ts": _ts_ago(random.randint(0, 30)), "exp": ROUTER1,
                      "src": ATTACK_IPS[1], "dst": ROUTER1,
                      "sp": random.randint(50000, 60000), "dp": port,
                      "proto": 6, "pkts": 1, "bytes": 60, "flags": 0x02})
    # SYN フラッド
    for _ in range(200):
        flows.append({"ts": _ts_ago(random.randint(0, 10)), "exp": ROUTER1,
                      "src": ATTACK_IPS[2], "dst": ROUTER1,
                      "sp": random.randint(1024, 65535), "dp": 443,
                      "proto": 6, "pkts": 1, "bytes": 60, "flags": 0x02})
    return flows


def _netflow_icmp_redirect() -> list[dict]:
    flows = _gen_http_flows(ROUTER1, n=50)
    # ICMP リダイレクト元フロー（三角ルーティング）
    for c in random.sample(CLIENT_IPS, 8):
        flows.append({"ts": _ts_ago(random.randint(0, 60)), "exp": ROUTER1,
                      "src": c, "dst": random.choice(EXT_IPS),
                      "sp": random.randint(40000, 60000), "dp": 80,
                      "proto": 1, "pkts": random.randint(20, 100), "bytes": random.randint(1000, 50000)})
    return flows


def _netflow_voip() -> list[dict]:
    flows = _gen_http_flows(ROUTER1, n=30)
    # VoIP RTP フロー（UDP 5004）
    for i in range(5):
        src = CLIENT_IPS[i]
        flows.append({"ts": _ts_ago(random.randint(0, 60)), "exp": ROUTER1,
                      "src": src, "dst": "10.0.0.10",
                      "sp": 16384 + i * 2, "dp": 16384 + i * 2,
                      "proto": 17, "pkts": random.randint(500, 2000),
                      "bytes": random.randint(80_000, 320_000)})
    return flows


# ═══════════════════════════════════════════════════════════════════
#  シナリオ別 pcap
# ═══════════════════════════════════════════════════════════════════

def _pcap_normal() -> bytes:
    pkts = []
    t = time.time() - 300
    # HTTP GET (plain text)
    for i in range(10):
        t += 0.1
        pkts.append((t, _ip_tcp("192.168.10.1", "93.184.216.34",
                                random.randint(40000,60000), 80,
                                dpkt.tcp.TH_SYN, seq=i*1000)))
    # DNS queries + responses
    for name in ["example.com", "google.com", "github.com"]:
        t += 0.05
        txid = random.randint(1, 65535)
        pkts.append((t, _dns_query("192.168.10.2", name, txid)))
        t += 0.01
        pkts.append((t + 0.01, _ip_udp(DNS_SRV, "192.168.10.2",
                                        53, random.randint(40000,60000),
                                        struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0))))
    # ARP 正常
    t += 0.1
    arp = dpkt.arp.ARP(
        hrd=1, pro=0x0800, hln=6, pln=4,
        op=dpkt.arp.ARP_OP_REQUEST,
        sha=_MAC_SRC, spa=socket.inet_aton("192.168.10.1"),
        tha=b"\x00"*6, tpa=socket.inet_aton("192.168.1.1"),
    )
    eth = dpkt.ethernet.Ethernet(src=_MAC_SRC, dst=b"\xff"*6,
                                  type=dpkt.ethernet.ETH_TYPE_ARP, data=arp)
    pkts.append((t, bytes(eth)))
    return _write_pcap(pkts)


def _pcap_icmp_redirect() -> bytes:
    pkts = []
    t = time.time() - 200
    # ICMP redirect (type=5, code=1: host redirect)
    for client in random.sample(CLIENT_IPS, 8):
        t += 0.3
        gw_ip = "192.168.1.2"
        # 内部 IP ヘッダ（元パケットの最初 8 バイト）
        inner_ip = dpkt.ip.IP(
            src=socket.inet_aton(client),
            dst=socket.inet_aton(random.choice(EXT_IPS)),
            p=dpkt.ip.IP_PROTO_TCP,
        )
        inner_tcp_hdr = struct.pack("!HHI", 12345, 80, 0)  # src/dst port + seq (8 bytes)
        # ICMP Redirect data: 4-byte gateway IP + original IP header + 8-byte original payload
        icmp_raw = socket.inet_aton(gw_ip) + bytes(inner_ip)[:20] + inner_tcp_hdr[:8]
        icmp = dpkt.icmp.ICMP(type=5, code=1)
        icmp.data = icmp_raw
        ip = dpkt.ip.IP(src=socket.inet_aton(ROUTER1),
                        dst=socket.inet_aton(client),
                        p=dpkt.ip.IP_PROTO_ICMP, data=icmp)
        pkts.append((t, _eth(ip)))
    # DNS NXDOMAIN
    for bad_name in ["nonexistent.local", "typo.example.cm", "malware-c2.xyz"]:
        t += 0.2
        txid = random.randint(1, 65535)
        pkts.append((t, _dns_query("192.168.10.1", bad_name, txid)))
        t += 0.05
        pkt = _dns_nxdomain("192.168.10.1", bad_name, txid)
        if pkt:
            pkts.append((t, pkt))
    # ARP 異常（MACアドレス変化）
    for mac_suffix in [b"\xaa\xbb", b"\xcc\xdd"]:
        t += 0.1
        arp = dpkt.arp.ARP(
            hrd=1, pro=0x0800, hln=6, pln=4,
            op=dpkt.arp.ARP_OP_REPLY,
            sha=b"\xde\xad\xbe\xef" + mac_suffix,
            spa=socket.inet_aton("192.168.1.1"),
            tha=_MAC_DST, tpa=socket.inet_aton("192.168.10.5"),
        )
        eth = dpkt.ethernet.Ethernet(
            src=b"\xde\xad\xbe\xef" + mac_suffix, dst=_MAC_DST,
            type=dpkt.ethernet.ETH_TYPE_ARP, data=arp,
        )
        pkts.append((t, bytes(eth)))
    # TCP RST（接続失敗）
    for port in [22, 23, 3389]:
        t += 0.05
        pkts.append((t, _ip_tcp("192.168.10.5", ROUTER1,
                                 random.randint(40000,60000), port,
                                 dpkt.tcp.TH_SYN, seq=random.randint(1,100000))))
        t += 0.01
        pkts.append((t, _ip_tcp(ROUTER1, "192.168.10.5",
                                 port, random.randint(40000,60000),
                                 dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK,
                                 seq=0, ack=1)))
    # TCP 再送（同一 seq を 3 回送信）
    t += 0.1
    for _ in range(4):
        t += 0.2
        pkts.append((t, _ip_tcp("192.168.10.3", "93.184.216.34",
                                 54321, 80,
                                 dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
                                 seq=1000, ack=500,
                                 data=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")))
    return _write_pcap(pkts)


def _pcap_voip() -> bytes:
    pkts = []
    t = time.time() - 120
    streams = [
        ("192.168.10.1", "10.0.0.10", 16384, 16384, 0xAABBCC01, 0),   # 良好
        ("192.168.10.2", "10.0.0.10", 16386, 16386, 0xAABBCC02, 0),   # ジッター大
        ("192.168.10.3", "10.0.0.10", 16388, 16388, 0xAABBCC03, 0),   # パケットロス
    ]
    for stream_idx, (src, dst, sport, dport, ssrc, _) in enumerate(streams):
        seq = random.randint(0, 1000)
        rtp_ts = random.randint(0, 100000)
        prev_real_t = t
        for pkt_i in range(150):
            # ストリーム 1: 正常 (20ms 間隔)
            if stream_idx == 0:
                prev_real_t += 0.020
                rtp_ts += 160
            # ストリーム 2: ジッター大 (10〜50ms 不規則)
            elif stream_idx == 1:
                jitter_ms = random.uniform(5, 80)
                prev_real_t += jitter_ms / 1000
                rtp_ts += 160
            # ストリーム 3: パケットロス (20% 欠落)
            else:
                prev_real_t += 0.020
                rtp_ts += 160
                if random.random() < 0.20:
                    seq += 1
                    continue  # パケット欠落（seq 番号だけ進める）
            pkts.append((prev_real_t,
                          _rtp_pkt(src, dst, sport, dport, ssrc, seq, rtp_ts, pt=0)))
            seq = (seq + 1) % 65536
    pkts.sort(key=lambda x: x[0])
    return _write_pcap(pkts)


def _pcap_ddos() -> bytes:
    pkts = []
    t = time.time() - 60
    # SYN フラッド
    for _ in range(100):
        t += 0.005
        pkts.append((t, _ip_tcp(random.choice(ATTACK_IPS), ROUTER1,
                                 random.randint(1024, 65535), 443,
                                 dpkt.tcp.TH_SYN, seq=random.randint(0, 2**32))))
    # ポートスキャン
    for port in range(1, 60):
        t += 0.002
        pkts.append((t, _ip_tcp(ATTACK_IPS[1], ROUTER1,
                                 54321, port, dpkt.tcp.TH_SYN, seq=12345)))
        t += 0.001
        pkts.append((t, _ip_tcp(ROUTER1, ATTACK_IPS[1],
                                 port, 54321,
                                 dpkt.tcp.TH_RST | dpkt.tcp.TH_ACK, seq=0, ack=12346)))
    # ICMP フラッド
    for _ in range(50):
        t += 0.01
        pkts.append((t, _ip_icmp(ATTACK_IPS[3], ROUTER1, 8, 0)))
    return _write_pcap(pkts)


# ═══════════════════════════════════════════════════════════════════
#  パブリック API
# ═══════════════════════════════════════════════════════════════════

def run_scenario(scenario: str) -> dict:
    """
    指定シナリオのデモデータを生成・挿入する。
    戻り値: { "syslog_count": int, "flow_count": int, "pcap_bytes": bytes }
    """
    # ── syslog ──
    syslog_fn = {
        "normal":        _syslogs_normal,
        "bgp_incident":  _syslogs_bgp_incident,
        "ddos":          _syslogs_ddos,
        "icmp_redirect": _syslogs_icmp_redirect,
        "voip_degraded": _syslogs_voip,
    }.get(scenario, _syslogs_normal)

    syslog_events = syslog_fn()
    # 共通ノーマルイベントも少し追加
    syslog_events += _syslogs_normal()[:5]

    for device_ip, raw in syslog_events:
        try:
            _insert_syslog(device_ip, raw)
        except Exception as e:
            print(f"[sim syslog] {e}")

    # ── NetFlow ──
    flow_fn = {
        "normal":        _netflow_normal,
        "bgp_incident":  _netflow_normal,
        "ddos":          _netflow_ddos,
        "icmp_redirect": _netflow_icmp_redirect,
        "voip_degraded": _netflow_voip,
    }.get(scenario, _netflow_normal)

    flows = flow_fn()
    try:
        _insert_flows(flows)
    except Exception as e:
        print(f"[sim netflow] {e}")

    # ── pcap ──
    pcap_fn = {
        "normal":        _pcap_normal,
        "bgp_incident":  _pcap_normal,
        "ddos":          _pcap_ddos,
        "icmp_redirect": _pcap_icmp_redirect,
        "voip_degraded": _pcap_voip,
    }.get(scenario, _pcap_normal)

    try:
        pcap_bytes = pcap_fn()
    except Exception as e:
        print(f"[sim pcap] {e}")
        pcap_bytes = b""

    return {
        "syslog_count": len(syslog_events),
        "flow_count":   len(flows),
        "pcap_bytes":   pcap_bytes,
        "scenario":     scenario,
    }
