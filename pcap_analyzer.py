"""
Wireshark pcap/pcapng ファイルのパーサー。
ICMP redirect を中心に RIP / ARP / TCP / DNS / HTTP / TLS / DHCP /
IPフラグメント / フロー解析 / pcap内syslog を抽出する。
"""
import io
import struct
import socket
from collections import defaultdict
from datetime import datetime

import dpkt


# ── ポート定数 ──────────────────────────────────────────────────
SYSLOG_PORTS = {514, 5140, 5141, 516, 601}
RIP_PORT     = 520
DNS_PORT     = 53
DHCP_PORTS   = {67, 68}
TLS_PORTS    = {443, 8443, 465, 993, 995, 636, 5061}

# ── ICMP ────────────────────────────────────────────────────────
ICMP_REDIRECT = 5
ICMP_REDIRECT_CODES = {
    0: "ネットワーク宛リダイレクト",
    1: "ホスト宛リダイレクト",
    2: "TOS+ネットワーク宛リダイレクト",
    3: "TOS+ホスト宛リダイレクト",
}
ICMP_TYPE_NAMES = {
    0: "Echo Reply",       3: "Destination Unreachable",
    5: "Redirect",         8: "Echo Request",
    11: "Time Exceeded",   12: "Parameter Problem",
}

# ── DNS ─────────────────────────────────────────────────────────
DNS_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
    3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}
DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}

# ── DHCP ────────────────────────────────────────────────────────
DHCP_MAGIC     = b'\x63\x82\x53\x63'
DHCP_MSG_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
    5: "ACK",      6: "NAK",   7: "RELEASE", 8: "INFORM",
}

# ── TLS ─────────────────────────────────────────────────────────
TLS_VERSIONS = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0",
    0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}
TLS_ALERT_DESCS = {
    0: "close_notify",          10: "unexpected_message",
    20: "bad_record_mac",       40: "handshake_failure",
    42: "bad_certificate",      43: "unsupported_certificate",
    44: "certificate_revoked",  45: "certificate_expired",
    46: "certificate_unknown",  47: "illegal_parameter",
    48: "unknown_ca",           49: "access_denied",
    50: "decode_error",         70: "protocol_version",
    80: "internal_error",       86: "inappropriate_fallback",
    112: "unrecognized_name",
}

PROTO_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 89: "OSPF"}

# ── VoIP/RTP ────────────────────────────────────────────────────
RTP_CLOCK_RATES = {
    0: 8000, 8: 8000,   # G.711 u-law / a-law
    3: 8000,             # GSM
    4: 8000,             # G.723
    9: 8000,             # G.722
    18: 8000,            # G.729
    96: 48000, 97: 48000, 98: 48000, 99: 48000, 100: 48000,
    101: 8000,           # telephone-event (RFC 2833)
    111: 48000,          # Opus
    120: 90000,          # H.264 video
}

RTP_CODEC_NAMES = {
    0: "G.711μ", 8: "G.711a", 3: "GSM", 4: "G.723",
    9: "G.722", 18: "G.729", 96: "動的", 97: "動的",
    101: "DTMF", 111: "Opus",
}

MOS_LABELS = {
    (4.3, 5.0): "最高 (≥4.3)",
    (4.0, 4.3): "良好 (4.0-4.3)",
    (3.6, 4.0): "普通 (3.6-4.0)",
    (3.1, 3.6): "やや悪い (3.1-3.6)",
    (1.0, 3.1): "悪い (<3.1)",
}


# ── ユーティリティ ───────────────────────────────────────────────
def _ip_str(raw: bytes) -> str:
    try:   return socket.inet_ntoa(raw)
    except Exception: return "?"


def _ts_str(ts: float) -> str:
    try:   return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except Exception: return str(ts)


def _is_rtp(payload: bytes) -> bool:
    """RTPパケットのヒューリスティック判定 (version=2, payload type が有効範囲)。"""
    if len(payload) < 12:
        return False
    v  = (payload[0] >> 6) & 0x3
    pt = payload[1] & 0x7F
    return v == 2 and (pt <= 34 or 96 <= pt <= 127)


def _r_to_mos(r: float) -> float:
    """R値 (0-100) を MOS (1.0-4.5) に変換 (ITU-T G.107 近似)。"""
    if r < 0:
        return 1.0
    if r > 100:
        return 4.5
    mos = 1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6
    return round(max(1.0, min(4.5, mos)), 2)


def _mos_label(mos: float) -> str:
    if mos >= 4.3: return "最高"
    if mos >= 4.0: return "良好"
    if mos >= 3.6: return "普通"
    if mos >= 3.1: return "やや悪い"
    return "悪い"


def _open_capture(data: bytes):
    """pcap または pcapng を自動判別して (reader, is_pcapng) を返す。"""
    if len(data) >= 4 and struct.unpack("<I", data[:4])[0] == 0x0A0D0D0A:
        return dpkt.pcapng.Reader(io.BytesIO(data)), True
    return dpkt.pcap.Reader(io.BytesIO(data)), False


def _tcp_flag_str(flags: int) -> str:
    f = []
    if flags & dpkt.tcp.TH_SYN:  f.append("SYN")
    if flags & dpkt.tcp.TH_ACK:  f.append("ACK")
    if flags & dpkt.tcp.TH_FIN:  f.append("FIN")
    if flags & dpkt.tcp.TH_RST:  f.append("RST")
    if flags & dpkt.tcp.TH_PUSH: f.append("PSH")
    if flags & dpkt.tcp.TH_URG:  f.append("URG")
    return "|".join(f) or "—"


# ── DNS パーサー ─────────────────────────────────────────────────
def _parse_dns_name(data: bytes, offset: int) -> tuple:
    labels, visited = [], set()
    while offset < len(data):
        if offset in visited: break
        visited.add(offset)
        length = data[offset]
        if length == 0:  offset += 1; break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data): break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            sub, _ = _parse_dns_name(data, ptr)
            labels.append(sub); offset += 2; break
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), offset


def _parse_dns(payload: bytes) -> dict | None:
    try:
        if len(payload) < 12: return None
        flags   = int.from_bytes(payload[2:4], "big")
        is_qr   = bool(flags & 0x8000)
        rcode   = flags & 0xF
        qdcount = int.from_bytes(payload[4:6], "big")
        offset  = 12
        questions = []
        for _ in range(min(qdcount, 4)):
            name, offset = _parse_dns_name(payload, offset)
            if offset + 4 > len(payload): break
            qtype = int.from_bytes(payload[offset:offset+2], "big")
            offset += 4
            questions.append({"name": name, "qtype": DNS_QTYPES.get(qtype, str(qtype))})
        return {
            "txid": int.from_bytes(payload[0:2], "big"),
            "is_response": is_qr,
            "rcode": rcode,
            "rcode_name": DNS_RCODES.get(rcode, f"rcode={rcode}"),
            "questions": questions,
        }
    except Exception:
        return None


# ── DHCP パーサー ────────────────────────────────────────────────
def _parse_dhcp(payload: bytes) -> dict | None:
    """BOOTP/DHCP ペイロードをパース。magic cookie 確認後に option 53 などを返す。"""
    try:
        if len(payload) < 240: return None
        if payload[236:240] != DHCP_MAGIC: return None
        opts = {}
        i = 240
        while i < len(payload):
            code = payload[i]
            if code == 255: break
            if code == 0:   i += 1; continue
            if i + 1 >= len(payload): break
            length = payload[i + 1]
            if i + 2 + length > len(payload): break
            opts[code] = payload[i + 2 : i + 2 + length]
            i += 2 + length

        result: dict = {
            "xid": int.from_bytes(payload[4:8], "big"),
        }
        if 53 in opts:
            mtype = opts[53][0]
            result["msg_type"]      = mtype
            result["msg_type_name"] = DHCP_MSG_TYPES.get(mtype, f"type={mtype}")
        if len(payload) >= 20:
            yiaddr = payload[16:20]
            if any(yiaddr): result["assigned_ip"] = socket.inet_ntoa(yiaddr)
        if len(payload) >= 34:
            result["client_mac"] = ":".join(f"{b:02x}" for b in payload[28:34])
        if 12 in opts:
            result["hostname"] = opts[12].decode("ascii", errors="replace")
        if 50 in opts and len(opts[50]) == 4:
            result["requested_ip"] = socket.inet_ntoa(opts[50])
        if 54 in opts and len(opts[54]) == 4:
            result["server_id"] = socket.inet_ntoa(opts[54])
        return result
    except Exception:
        return None


# ── TLS パーサー ─────────────────────────────────────────────────
def _parse_tls_client_hello(payload: bytes) -> dict | None:
    """TLS ClientHello から SNI・TLS バージョンを抽出する。"""
    try:
        if len(payload) < 6 or payload[0] != 22: return None  # Handshake record
        rec_ver = int.from_bytes(payload[1:3], "big")
        hs_data = payload[5:]
        if not hs_data or hs_data[0] != 1: return None  # ClientHello
        # Skip handshake header (4 bytes) + legacy_version (2) + random (32)
        offset = 4 + 2 + 32
        if offset >= len(hs_data): return None
        sid_len = hs_data[offset]; offset += 1 + sid_len
        if offset + 2 > len(hs_data): return None
        cs_len = int.from_bytes(hs_data[offset:offset+2], "big"); offset += 2 + cs_len
        if offset + 1 > len(hs_data): return None
        cm_len = hs_data[offset]; offset += 1 + cm_len
        if offset + 2 > len(hs_data): return None
        ext_total = int.from_bytes(hs_data[offset:offset+2], "big"); offset += 2
        ext_end = offset + ext_total
        sni = None
        negotiated_ver = None
        while offset + 4 <= ext_end and offset + 4 <= len(hs_data):
            ext_type = int.from_bytes(hs_data[offset:offset+2], "big")
            ext_len  = int.from_bytes(hs_data[offset+2:offset+4], "big")
            offset += 4
            if ext_type == 0 and offset + 5 <= len(hs_data):   # SNI
                name_len = int.from_bytes(hs_data[offset+3:offset+5], "big")
                if offset + 5 + name_len <= len(hs_data):
                    sni = hs_data[offset+5:offset+5+name_len].decode("ascii", errors="replace")
            elif ext_type == 43 and ext_len >= 3:               # supported_versions (TLS 1.3)
                vlist_len = hs_data[offset]
                for vi in range(1, vlist_len // 2 + 1):
                    if offset + vi * 2 + 1 <= len(hs_data):
                        v = int.from_bytes(hs_data[offset + vi*2 - 1: offset + vi*2 + 1], "big")
                        if v in TLS_VERSIONS:
                            negotiated_ver = TLS_VERSIONS[v]; break
            offset += ext_len
        return {
            "sni": sni,
            "tls_version": negotiated_ver or TLS_VERSIONS.get(rec_ver, f"0x{rec_ver:04x}"),
        }
    except Exception:
        return None


def _parse_tls_alert(payload: bytes) -> dict | None:
    """TLS Alert レコードをパースする（fatal のみ問題として扱う）。"""
    try:
        if len(payload) < 7 or payload[0] != 21: return None  # Alert record
        level = payload[5]
        desc  = payload[6]
        return {
            "level":     "fatal" if level == 2 else "warning",
            "desc":      TLS_ALERT_DESCS.get(desc, f"alert={desc}"),
            "code":      desc,
        }
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════
#  メイン解析関数
# ══════════════════════════════════════════════════════════════════
def analyze_pcap(data: bytes) -> dict:
    """
    pcap/pcapng バイト列を解析し、各種パケット情報を返す。

    Returns dict:
        icmp_redirects      ICMP redirect パケット一覧
        icmp_summary        ICMP type 別集計
        rip_packets         RIP パケット一覧
        arp_anomalies       ARP 重複/変化
        tcp_issues          TCP 問題 (RST多発・再送・接続失敗・ゼロウィンドウ)
        tcp_retransmissions TCP 再送多発フロー
        tcp_syn_no_synack   SYN 未応答（接続失敗）
        tcp_zero_window     TCP ゼロウィンドウ発生フロー
        ip_fragments        IP フラグメント発生フロー
        http_errors         HTTP 4xx/5xx エラー一覧
        http_summary        HTTP ステータスコード集計
        tls_sessions        TLS 接続先 (SNI) 一覧
        tls_alerts          TLS Fatal Alert 一覧
        tls_summary         TLS 集計
        dhcp_issues         DHCP エラー (NAK / DECLINE / 無応答)
        dhcp_summary        DHCP メッセージタイプ別集計
        dns_issues          DNS エラー / 遅延
        dns_summary         DNS 集計
        syslog_packets      pcap内syslog
        total_packets       int
        capture_start / capture_end  str
        error               str | None
    """
    result = {
        "icmp_redirects": [], "icmp_summary": {},
        "rip_packets": [],    "arp_anomalies": [],
        "tcp_issues": [],     "tcp_retransmissions": [],
        "tcp_syn_no_synack": [], "tcp_zero_window": [],
        "ip_fragments": [],
        "http_errors": [],    "http_summary": {},
        "tls_sessions": [],   "tls_alerts": [],
        "tls_summary": {"sessions": 0, "unique_sites": 0, "fatal_alerts": 0,
                        "deprecated_tls": 0},
        "dhcp_issues": [],
        "dhcp_summary": {},
        "dns_issues": [],
        "dns_summary": {"queries": 0, "responses": 0, "nxdomain": 0,
                        "servfail": 0, "refused": 0, "slow": 0},
        "syslog_packets": [],
        "voip_streams": [], "voip_avg_mos": 0.0, "voip_stream_count": 0, "voip_poor_streams": 0,
        "total_packets": 0,
        "capture_start": "", "capture_end": "",
        "error": None,
    }

    try:
        reader, _ = _open_capture(data)
    except Exception as e:
        result["error"] = f"ファイル読み込みエラー: {e}"; return result

    timestamps   = []
    arp_table:   dict[str, str]   = {}
    tcp_rst_count:   dict[tuple, int]  = defaultdict(int)
    tcp_flow_seqs:   dict[tuple, set]  = defaultdict(set)
    tcp_retrans_count: dict[tuple, int] = defaultdict(int)
    syn_sent:    dict[tuple, float] = {}
    syn_ack_received: set            = set()
    zero_win_count: dict[tuple, int] = defaultdict(int)
    ip_frag_count:  dict[tuple, int] = defaultdict(int)

    # TLS: canonical flow key -> {sni, tls_version}
    tls_flow_info: dict[tuple, dict] = {}
    tls_unique_sites: set = set()

    # DNS pending queries
    dns_pending: dict[int, dict] = {}

    # DHCP: xid -> {ts, client_mac, hostname, has_offer}
    dhcp_pending_discover: dict[int, dict] = {}

    # VoIP/RTP: ssrc -> {pkts:[{ts,seq,rtp_ts,size}], src, dst, pt}
    rtp_streams: dict[int, dict] = {}

    try:
        for ts, raw_pkt in reader:
            result["total_packets"] += 1
            timestamps.append(ts)

            try:
                eth = dpkt.ethernet.Ethernet(raw_pkt)
            except Exception:
                continue

            # ── IP ──────────────────────────────────────
            if isinstance(eth.data, dpkt.ip.IP):
                ip  = eth.data
                src = _ip_str(ip.src)
                dst = _ip_str(ip.dst)

                # IP フラグメント検出
                is_mf      = bool(ip.off & dpkt.ip.IP_MF)
                frag_offset = ip.off & dpkt.ip.IP_OFFMASK  # 8-byte units
                if is_mf or frag_offset > 0:
                    ip_frag_count[(src, dst, ip.p)] += 1

                # ── ICMP ────────────────────────────────
                if isinstance(ip.data, dpkt.icmp.ICMP):
                    icmp = ip.data
                    t = icmp.type
                    result["icmp_summary"][t] = result["icmp_summary"].get(t, 0) + 1
                    if t == ICMP_REDIRECT:
                        try:   gw = _ip_str(icmp.data.gw)
                        except Exception:
                            try:   gw = _ip_str(bytes(icmp.data)[:4])
                            except Exception: gw = "?"
                        orig_dst = orig_src = orig_proto = "?"
                        try:
                            inner     = dpkt.ip.IP(bytes(icmp.data)[4:])
                            orig_dst  = _ip_str(inner.dst)
                            orig_src  = _ip_str(inner.src)
                            orig_proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(inner.p, str(inner.p))
                        except Exception: pass
                        code_desc = ICMP_REDIRECT_CODES.get(icmp.code, f"code={icmp.code}")
                        result["icmp_redirects"].append({
                            "timestamp": _ts_str(ts), "router_ip": src, "target_ip": dst,
                            "gateway": gw, "orig_src": orig_src, "orig_dst": orig_dst,
                            "orig_proto": orig_proto, "code": icmp.code, "code_desc": code_desc,
                        })

                # ── TCP ─────────────────────────────────
                elif isinstance(ip.data, dpkt.tcp.TCP):
                    tcp    = ip.data
                    flags  = tcp.flags
                    sport  = tcp.sport
                    dport  = tcp.dport
                    is_syn = bool(flags & dpkt.tcp.TH_SYN)
                    is_ack = bool(flags & dpkt.tcp.TH_ACK)
                    is_rst = bool(flags & dpkt.tcp.TH_RST)

                    if is_rst:
                        tcp_rst_count[(src, dst, sport, dport)] += 1
                    if is_syn and not is_ack:
                        key = (src, dst, sport, dport)
                        if key not in syn_sent: syn_sent[key] = ts
                    elif is_syn and is_ack:
                        syn_ack_received.add((src, dst, sport, dport))
                    data_len = len(tcp.data)
                    if data_len > 0:
                        flow_key = (src, dst, sport, dport)
                        pkt_sig  = (tcp.seq, data_len)
                        if pkt_sig in tcp_flow_seqs[flow_key]:
                            tcp_retrans_count[flow_key] += 1
                        else:
                            tcp_flow_seqs[flow_key].add(pkt_sig)
                    if tcp.win == 0 and not is_syn and not is_rst:
                        zero_win_count[(src, dst, sport, dport)] += 1

                    # ── HTTP (平文) ──────────────────────
                    if data_len > 0:
                        try:
                            preview = bytes(tcp.data[:20]).decode("ascii", errors="ignore")
                            if preview.startswith("HTTP/"):
                                parts = preview.split(" ", 2)
                                if len(parts) >= 2 and parts[1].isdigit():
                                    code = int(parts[1])
                                    result["http_summary"][code] = result["http_summary"].get(code, 0) + 1
                                    if code >= 400:
                                        reason = parts[2].split("\r")[0].strip() if len(parts) > 2 else ""
                                        result["http_errors"].append({
                                            "timestamp":   _ts_str(ts),
                                            "server":      src,
                                            "client":      dst,
                                            "server_port": sport,
                                            "status_code": code,
                                            "reason":      reason[:60],
                                            "category":    "クライアントエラー" if code < 500 else "サーバーエラー",
                                        })
                        except Exception: pass

                    # ── TLS / HTTPS ──────────────────────
                    if sport in TLS_PORTS or dport in TLS_PORTS:
                        payload_b = bytes(tcp.data) if tcp.data else b""
                        if payload_b:
                            # Canonical flow key for TLS session
                            if (src, sport) <= (dst, dport):
                                ck = (src, dst, sport, dport)
                            else:
                                ck = (dst, src, dport, sport)

                            # ClientHello → SNI
                            ch = _parse_tls_client_hello(payload_b)
                            if ch:
                                if ck not in tls_flow_info:
                                    tls_flow_info[ck] = ch
                                    ver = ch.get("tls_version", "")
                                    sni = ch.get("sni") or ""
                                    if sni: tls_unique_sites.add(sni)
                                    result["tls_sessions"].append({
                                        "timestamp":   _ts_str(ts),
                                        "client":      src,
                                        "server":      dst,
                                        "server_port": dport,
                                        "sni":         sni,
                                        "tls_version": ver,
                                    })
                                    result["tls_summary"]["sessions"] += 1
                                    if ver in ("SSL 3.0", "TLS 1.0", "TLS 1.1"):
                                        result["tls_summary"]["deprecated_tls"] += 1

                            # TLS Alert
                            alert = _parse_tls_alert(payload_b)
                            if alert and alert["level"] == "fatal":
                                fi = tls_flow_info.get(ck, {})
                                result["tls_alerts"].append({
                                    "timestamp":   _ts_str(ts),
                                    "client":      src if dport in TLS_PORTS else dst,
                                    "server":      dst if dport in TLS_PORTS else src,
                                    "server_port": dport if dport in TLS_PORTS else sport,
                                    "sni":         fi.get("sni", ""),
                                    "alert":       alert["desc"],
                                    "issue":       f"TLS Fatal Alert: {alert['desc']}",
                                })
                                result["tls_summary"]["fatal_alerts"] += 1

                # ── UDP ─────────────────────────────────
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data

                    # RIP
                    if udp.dport == RIP_PORT or udp.sport == RIP_PORT:
                        try:
                            rip_ver = udp.data[1] if len(udp.data) > 1 else 0
                            cmd     = udp.data[0] if len(udp.data) > 0 else 0
                            cmd_str = {1: "Request", 2: "Response"}.get(cmd, f"cmd={cmd}")
                            result["rip_packets"].append({
                                "timestamp": _ts_str(ts), "src": src, "dst": dst,
                                "version": f"RIPv{rip_ver}", "command": cmd_str, "size": len(udp.data),
                            })
                        except Exception: pass

                    # DNS
                    elif udp.dport == DNS_PORT or udp.sport == DNS_PORT:
                        dns = _parse_dns(bytes(udp.data))
                        if dns:
                            q_name = dns["questions"][0]["name"] if dns["questions"] else ""
                            q_type = dns["questions"][0]["qtype"] if dns["questions"] else ""
                            if not dns["is_response"]:
                                result["dns_summary"]["queries"] += 1
                                dns_pending[dns["txid"]] = {
                                    "ts": ts, "src": src, "dst": dst,
                                    "name": q_name, "qtype": q_type,
                                }
                            else:
                                result["dns_summary"]["responses"] += 1
                                rcode = dns["rcode"]
                                if rcode == 3:
                                    result["dns_summary"]["nxdomain"] += 1
                                    result["dns_issues"].append({
                                        "timestamp": _ts_str(ts), "client": dst, "server": src,
                                        "name": q_name, "qtype": q_type, "rcode": "NXDOMAIN",
                                        "rtt_ms": None, "issue": "名前解決失敗 (NXDOMAIN)",
                                    })
                                elif rcode == 2:
                                    result["dns_summary"]["servfail"] += 1
                                    result["dns_issues"].append({
                                        "timestamp": _ts_str(ts), "client": dst, "server": src,
                                        "name": q_name, "qtype": q_type, "rcode": "SERVFAIL",
                                        "rtt_ms": None, "issue": "DNS サーバーエラー (SERVFAIL)",
                                    })
                                elif rcode == 5:
                                    result["dns_summary"]["refused"] += 1
                                    result["dns_issues"].append({
                                        "timestamp": _ts_str(ts), "client": dst, "server": src,
                                        "name": q_name, "qtype": q_type, "rcode": "REFUSED",
                                        "rtt_ms": None, "issue": "クエリ拒否 (REFUSED) — ACL/設定確認",
                                    })
                                if dns["txid"] in dns_pending:
                                    pend    = dns_pending.pop(dns["txid"])
                                    rtt_ms  = round((ts - pend["ts"]) * 1000, 1)
                                    if rtt_ms > 500:
                                        result["dns_summary"]["slow"] += 1
                                        result["dns_issues"].append({
                                            "timestamp": _ts_str(ts), "client": pend["src"], "server": dst,
                                            "name": pend["name"], "qtype": pend["qtype"],
                                            "rcode": dns["rcode_name"], "rtt_ms": rtt_ms,
                                            "issue": f"DNS 応答遅延 {rtt_ms} ms",
                                        })

                    # DHCP
                    elif udp.dport in DHCP_PORTS or udp.sport in DHCP_PORTS:
                        dhcp = _parse_dhcp(bytes(udp.data))
                        if dhcp and "msg_type" in dhcp:
                            mtype = dhcp["msg_type"]
                            mname = dhcp["msg_type_name"]
                            result["dhcp_summary"][mname] = result["dhcp_summary"].get(mname, 0) + 1
                            xid   = dhcp.get("xid", 0)
                            mac   = dhcp.get("client_mac", "?")
                            host  = dhcp.get("hostname", "")

                            if mtype == 1:   # DISCOVER
                                dhcp_pending_discover.setdefault(xid, {
                                    "ts": ts, "client_mac": mac, "hostname": host, "src": src,
                                })
                            elif mtype == 2: # OFFER
                                dhcp_pending_discover.pop(xid, None)
                            elif mtype == 5: # ACK
                                ip_assigned = dhcp.get("assigned_ip", "?")
                                dhcp_pending_discover.pop(xid, None)
                                # record successful assignment (not an issue, just info)
                            elif mtype == 6: # NAK
                                pend = dhcp_pending_discover.pop(xid, {})
                                result["dhcp_issues"].append({
                                    "timestamp":  _ts_str(ts),
                                    "server":     src,
                                    "client_mac": pend.get("client_mac", mac),
                                    "hostname":   pend.get("hostname", host),
                                    "event":      "NAK",
                                    "detail":     dhcp.get("server_id", src),
                                    "issue":      "DHCP NAK — IPアドレス割り当て拒否（サーバーが拒否）",
                                })
                            elif mtype == 4: # DECLINE
                                result["dhcp_issues"].append({
                                    "timestamp":  _ts_str(ts),
                                    "server":     dst,
                                    "client_mac": mac,
                                    "hostname":   host,
                                    "event":      "DECLINE",
                                    "detail":     dhcp.get("requested_ip", "?"),
                                    "issue":      f"DHCP DECLINE — クライアントがIPを拒否（IPアドレス競合の可能性: {dhcp.get('requested_ip','?')}）",
                                })

                    # RTP/VoIP
                    elif _is_rtp(udp.data):
                        try:
                            pl = udp.data
                            seq     = struct.unpack("!H", pl[2:4])[0]
                            rtp_ts  = struct.unpack("!I", pl[4:8])[0]
                            ssrc    = struct.unpack("!I", pl[8:12])[0]
                            pt      = pl[1] & 0x7F
                            if ssrc not in rtp_streams:
                                rtp_streams[ssrc] = {"src": src, "dst": dst, "pt": pt, "pkts": []}
                            rtp_streams[ssrc]["pkts"].append({"ts": float(ts), "seq": seq, "rtp_ts": rtp_ts})
                        except Exception:
                            pass

                    # syslog
                    elif udp.dport in SYSLOG_PORTS or udp.sport in SYSLOG_PORTS:
                        try:
                            raw_msg = udp.data.decode("utf-8", errors="replace").strip()
                            if raw_msg:
                                result["syslog_packets"].append({
                                    "timestamp": _ts_str(ts), "src_ip": src, "dst_ip": dst,
                                    "port": udp.dport, "raw": raw_msg,
                                })
                        except Exception: pass

            # ── ARP ─────────────────────────────────────
            elif isinstance(eth.data, dpkt.arp.ARP):
                arp = eth.data
                try:
                    sender_ip  = _ip_str(arp.spa)
                    sender_mac = ":".join(f"{b:02x}" for b in arp.sha)
                    if sender_ip in arp_table and arp_table[sender_ip] != sender_mac:
                        result["arp_anomalies"].append({
                            "timestamp": _ts_str(ts), "ip": sender_ip,
                            "old_mac": arp_table[sender_ip], "new_mac": sender_mac,
                            "description": "MACアドレス変化（ARPスプーフィングの疑い）",
                        })
                    arp_table[sender_ip] = sender_mac
                except Exception: pass

    except Exception as e:
        result["error"] = f"パケット解析中エラー: {e}"

    # ── 後処理 ─────────────────────────────────────────────────────

    # TCP RST 多発
    for (src, dst, sp, dp), cnt in tcp_rst_count.items():
        if cnt >= 3:
            result["tcp_issues"].append({
                "type": "RST多発", "src": src, "dst": dst, "src_port": sp, "dst_port": dp,
                "count": cnt, "description": f"TCP RST 多発 ({cnt}回) — 接続拒否/強制切断の可能性",
            })

    # TCP 再送多発
    for (src, dst, sp, dp), cnt in tcp_retrans_count.items():
        if cnt >= 3:
            entry = {
                "src": src, "dst": dst, "src_port": sp, "dst_port": dp,
                "retrans_count": cnt,
                "description": f"TCP 再送 ({cnt}回) — ネットワーク品質低下/輻輳の可能性",
            }
            result["tcp_retransmissions"].append(entry)
            result["tcp_issues"].append({
                "type": "再送多発", "src": src, "dst": dst, "src_port": sp, "dst_port": dp,
                "count": cnt, "description": entry["description"],
            })

    # SYN 未応答
    cap_end = max(timestamps) if timestamps else 0
    for (src, dst, sp, dp), syn_ts in syn_sent.items():
        if (dst, src, dp, sp) not in syn_ack_received:
            wait = cap_end - syn_ts
            if wait >= 1.0:
                desc = f"SYN未応答 ({wait:.1f}秒待機) — 接続タイムアウト/サービス停止の可能性"
                result["tcp_syn_no_synack"].append({
                    "src": src, "dst": dst, "src_port": sp, "dst_port": dp,
                    "syn_at": _ts_str(syn_ts), "wait_sec": round(wait, 3), "description": desc,
                })
                result["tcp_issues"].append({
                    "type": "接続失敗", "src": src, "dst": dst, "src_port": sp, "dst_port": dp,
                    "count": 1, "description": desc,
                })

    # TCP ゼロウィンドウ
    for (src, dst, sp, dp), cnt in zero_win_count.items():
        if cnt >= 2:
            desc = f"ゼロウィンドウ {cnt}回 — 受信バッファ枯渇/フロー制御問題の可能性"
            result["tcp_zero_window"].append({
                "src": src, "dst": dst, "src_port": sp, "dst_port": dp,
                "count": cnt, "description": desc,
            })
            result["tcp_issues"].append({
                "type": "ゼロウィンドウ", "src": src, "dst": dst, "src_port": sp, "dst_port": dp,
                "count": cnt, "description": desc,
            })

    # IP フラグメント
    for (src, dst, proto_num), cnt in ip_frag_count.items():
        proto_name = PROTO_NAMES.get(proto_num, f"proto={proto_num}")
        result["ip_fragments"].append({
            "src": src, "dst": dst, "protocol": proto_name, "fragment_count": cnt,
            "description": f"IPフラグメント {cnt}パケット — MTU問題/VPN/ジャンボフレーム非対応の可能性",
        })
    result["ip_fragments"].sort(key=lambda x: x["fragment_count"], reverse=True)

    # DHCP DISCOVER 無応答（capture終了まで OFFER が来なかった）
    for xid, pend in dhcp_pending_discover.items():
        wait = cap_end - pend["ts"]
        if wait >= 3.0:
            result["dhcp_issues"].append({
                "timestamp":  _ts_str(pend["ts"]),
                "server":     "（応答なし）",
                "client_mac": pend.get("client_mac", "?"),
                "hostname":   pend.get("hostname", ""),
                "event":      "DISCOVER無応答",
                "detail":     f"{wait:.1f}秒待機",
                "issue":      f"DHCP DISCOVER に OFFER なし ({wait:.1f}秒) — DHCPサーバー停止/到達不能の可能性",
            })

    # VoIP/RTP MOS 計算
    voip_list = []
    for ssrc, st in rtp_streams.items():
        pkts = sorted(st["pkts"], key=lambda p: p["ts"])
        if len(pkts) < 4:
            continue
        pt = st["pt"]
        clock_rate = RTP_CLOCK_RATES.get(pt, 8000)
        jitter = 0.0
        for i in range(1, len(pkts)):
            d_recv = (pkts[i]["ts"] - pkts[i-1]["ts"]) * clock_rate
            d_send = pkts[i]["rtp_ts"] - pkts[i-1]["rtp_ts"]
            jitter += (abs(d_recv - d_send) - jitter) / 16.0
        jitter_ms = jitter / clock_rate * 1000
        seqs = [p["seq"] for p in pkts]
        expected = max(seqs) - min(seqs) + 1
        loss_pct = max(0.0, (expected - len(pkts)) / expected * 100) if expected > 0 else 0.0
        ie = loss_pct * 2.5
        id_val = min(jitter_ms * 0.5, 30.0)
        r_val = max(0.0, 93.2 - ie - id_val)
        mos = _r_to_mos(r_val)
        duration = pkts[-1]["ts"] - pkts[0]["ts"]
        voip_list.append({
            "src_ip": st["src"], "dst_ip": st["dst"],
            "ssrc": f"{ssrc:08X}",
            "codec": RTP_CODEC_NAMES.get(pt, f"PT={pt}"),
            "packets": len(pkts),
            "duration_s": round(duration, 2),
            "jitter_ms": round(jitter_ms, 2),
            "loss_pct": round(loss_pct, 2),
            "mos": mos,
            "r_value": round(r_val, 1),
            "quality": _mos_label(mos),
        })
    voip_list.sort(key=lambda x: x["mos"])
    result["voip_streams"]      = voip_list
    result["voip_stream_count"] = len(voip_list)
    result["voip_avg_mos"]      = round(sum(s["mos"] for s in voip_list) / len(voip_list), 2) if voip_list else 0.0
    result["voip_poor_streams"] = sum(1 for s in voip_list if s["mos"] < 3.6)

    # TLS unique sites 集計
    result["tls_summary"]["unique_sites"] = len(tls_unique_sites)

    # ICMP summary 変換
    result["icmp_summary"] = [
        {"type": t, "name": ICMP_TYPE_NAMES.get(t, f"type={t}"), "count": c}
        for t, c in sorted(result["icmp_summary"].items())
    ]

    # HTTP summary をソート済みリストに変換
    result["http_summary"] = [
        {"status_code": c, "count": n}
        for c, n in sorted(result["http_summary"].items())
    ]

    if timestamps:
        result["capture_start"] = _ts_str(min(timestamps))
        result["capture_end"]   = _ts_str(max(timestamps))

    if result["syslog_packets"]:
        try:
            from parsers import parse_syslog
            for pkt in result["syslog_packets"]:
                pkt["parsed"] = parse_syslog(pkt["raw"], pkt["src_ip"])
        except Exception: pass

    return result


# ══════════════════════════════════════════════════════════════════
#  フロー解析
# ══════════════════════════════════════════════════════════════════
def get_conversations(data: bytes) -> list:
    """
    TCP/UDP の双方向会話フロー一覧を返す。
    RTT（SYN→SYN-ACK）・スループット・TCPフラグも付与する。
    """
    try:
        reader, _ = _open_capture(data)
    except Exception:
        return []

    flows:      dict[tuple, dict]  = {}
    syn_ts_map: dict[tuple, float] = {}

    for ts, raw_pkt in reader:
        try:
            eth = dpkt.ethernet.Ethernet(raw_pkt)
        except Exception:
            continue
        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip    = eth.data
        src   = _ip_str(ip.src)
        dst   = _ip_str(ip.dst)
        proto = PROTO_NAMES.get(ip.p, f"proto={ip.p}")
        pkt_len = len(raw_pkt)

        sport = dport = 0
        has_syn = has_fin = has_rst = False
        is_syn_ack = False

        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            sport, dport = tcp.sport, tcp.dport
            flags      = tcp.flags
            has_syn    = bool(flags & dpkt.tcp.TH_SYN)
            has_fin    = bool(flags & dpkt.tcp.TH_FIN)
            has_rst    = bool(flags & dpkt.tcp.TH_RST)
            is_syn_ack = has_syn and bool(flags & dpkt.tcp.TH_ACK)
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            sport, dport = udp.sport, udp.dport
        else:
            continue

        if (src, sport) <= (dst, dport):
            flow_key = (proto, src, dst, sport, dport)
        else:
            flow_key = (proto, dst, src, dport, sport)

        if flow_key not in flows:
            flows[flow_key] = {
                "protocol": flow_key[0], "src_ip": flow_key[1], "dst_ip": flow_key[2],
                "src_port": flow_key[3], "dst_port": flow_key[4],
                "packets": 0, "bytes": 0,
                "_start": ts, "_end": ts,
                "has_syn": False, "has_fin": False, "has_rst": False, "rtt_ms": None,
            }

        f = flows[flow_key]
        f["packets"] += 1
        f["bytes"]   += pkt_len
        if ts < f["_start"]: f["_start"] = ts
        if ts > f["_end"]:   f["_end"]   = ts
        f["has_syn"] = f["has_syn"] or has_syn
        f["has_fin"] = f["has_fin"] or has_fin
        f["has_rst"] = f["has_rst"] or has_rst

        if proto == "TCP":
            if has_syn and not is_syn_ack:
                syn_ts_map.setdefault(flow_key, ts)
            elif is_syn_ack and f["rtt_ms"] is None:
                syn_ts = syn_ts_map.get(flow_key)
                if syn_ts is not None:
                    f["rtt_ms"] = round((ts - syn_ts) * 1000, 2)

    result = []
    for f in flows.values():
        dur = f["_end"] - f["_start"]
        f["start"]           = _ts_str(f.pop("_start"))
        f["end"]             = _ts_str(f.pop("_end"))
        f["duration_sec"]    = round(dur, 3)
        f["throughput_kbps"] = round(f["bytes"] / dur / 1024, 2) if dur > 0 else 0
        s = []
        if f.get("has_syn"): s.append("SYN")
        if f.get("has_fin"): s.append("FIN")
        if f.get("has_rst"): s.append("RST")
        f["tcp_state"] = "|".join(s) if s else ("—" if f["protocol"] == "TCP" else "")
        result.append(f)

    result.sort(key=lambda x: x["bytes"], reverse=True)
    return result


def get_top_talkers(data: bytes, top_n: int = 20) -> list:
    """送受信バイト数が多いIPアドレスランキング。"""
    try:
        reader, _ = _open_capture(data)
    except Exception:
        return []

    ip_stats: dict[str, dict] = defaultdict(
        lambda: {"sent_bytes": 0, "recv_bytes": 0, "sent_pkts": 0, "recv_pkts": 0}
    )
    for ts, raw_pkt in reader:
        try:
            eth = dpkt.ethernet.Ethernet(raw_pkt)
        except Exception:
            continue
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        pip  = eth.data
        src  = _ip_str(pip.src)
        dst  = _ip_str(pip.dst)
        plen = len(raw_pkt)
        ip_stats[src]["sent_bytes"] += plen;  ip_stats[src]["sent_pkts"] += 1
        ip_stats[dst]["recv_bytes"] += plen;  ip_stats[dst]["recv_pkts"] += 1

    result = [
        {"ip": addr, **s, "total_bytes": s["sent_bytes"] + s["recv_bytes"]}
        for addr, s in ip_stats.items()
    ]
    result.sort(key=lambda x: x["total_bytes"], reverse=True)
    return result[:top_n]


def filter_pcap(
    data: bytes,
    src_ip: str   = "",
    dst_ip: str   = "",
    ip: str       = "",
    port: int     = 0,
    protocol: str = "",
    keyword: str  = "",
    max_packets: int = 500,
) -> list:
    """IP・ポート・プロトコル・キーワードでパケットを絞り込む。"""
    try:
        reader, _ = _open_capture(data)
    except Exception:
        return []

    protocol_upper = (protocol or "").upper()
    kw_lower       = (keyword or "").lower()
    matched        = []

    for ts, raw_pkt in reader:
        if len(matched) >= max_packets: break
        try:
            eth = dpkt.ethernet.Ethernet(raw_pkt)
        except Exception:
            continue

        pkt_src = pkt_dst = "?"
        pkt_sport = pkt_dport = 0
        pkt_proto = ""; pkt_info = ""; payload_text = ""

        if isinstance(eth.data, dpkt.ip.IP):
            pip = eth.data
            pkt_src = _ip_str(pip.src)
            pkt_dst = _ip_str(pip.dst)
            if isinstance(pip.data, dpkt.tcp.TCP):
                tcp = pip.data
                pkt_proto = "TCP"; pkt_sport = tcp.sport; pkt_dport = tcp.dport
                pkt_info  = f"TCP {pkt_sport}→{pkt_dport} [{_tcp_flag_str(tcp.flags)}] seq={tcp.seq}"
                if tcp.data: payload_text = tcp.data.decode("utf-8", errors="replace")
            elif isinstance(pip.data, dpkt.udp.UDP):
                udp = pip.data
                pkt_proto = "UDP"; pkt_sport = udp.sport; pkt_dport = udp.dport
                pkt_info  = f"UDP {pkt_sport}→{pkt_dport}"
                if udp.data: payload_text = udp.data.decode("utf-8", errors="replace")
            elif isinstance(pip.data, dpkt.icmp.ICMP):
                icmp = pip.data
                pkt_proto = "ICMP"
                pkt_info  = f"ICMP {ICMP_TYPE_NAMES.get(icmp.type, f'type={icmp.type}')} (type={icmp.type} code={icmp.code})"
            else:
                pkt_proto = PROTO_NAMES.get(pip.p, f"IP/{pip.p}"); pkt_info = pkt_proto
        elif isinstance(eth.data, dpkt.arp.ARP):
            arp = eth.data
            pkt_proto = "ARP"; pkt_src = _ip_str(arp.spa); pkt_dst = _ip_str(arp.tpa)
            op = {1: "Request", 2: "Reply"}.get(arp.op, f"op={arp.op}")
            pkt_info = f"ARP {op}: who has {pkt_dst}? tell {pkt_src}"
        else:
            continue

        if protocol_upper and pkt_proto != protocol_upper: continue
        if src_ip and pkt_src != src_ip: continue
        if dst_ip and pkt_dst != dst_ip: continue
        if ip and ip not in (pkt_src, pkt_dst): continue
        if port and port not in (pkt_sport, pkt_dport): continue
        if kw_lower and kw_lower not in payload_text.lower(): continue

        matched.append({
            "timestamp": _ts_str(ts), "protocol": pkt_proto,
            "src_ip": pkt_src, "src_port": pkt_sport,
            "dst_ip": pkt_dst, "dst_port": pkt_dport,
            "length": len(raw_pkt), "info": pkt_info,
            "payload_text": payload_text[:300] if kw_lower else "",
        })

    return matched
