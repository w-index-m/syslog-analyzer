"""
Wireshark pcap/pcapng ファイルのパーサー。
ICMP redirect を中心に、RIP / ARP 異常 / TCP 問題 / DNS / フロー解析 / pcap内syslog も抽出する。
"""
import io
import struct
import socket
from collections import defaultdict
from datetime import datetime

import dpkt


# syslog が流れる可能性のある UDP ポート
SYSLOG_PORTS = {514, 5140, 5141, 516, 601}

# ICMP type / code 定義
ICMP_REDIRECT = 5
ICMP_REDIRECT_CODES = {
    0: "ネットワーク宛リダイレクト",
    1: "ホスト宛リダイレクト",
    2: "TOS+ネットワーク宛リダイレクト",
    3: "TOS+ホスト宛リダイレクト",
}

RIP_PORT    = 520
DNS_PORT    = 53

ICMP_TYPE_NAMES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
}

DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
    12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
    33: "SRV", 255: "ANY",
}

PROTO_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 89: "OSPF"}


def _ip_str(raw: bytes) -> str:
    try:
        return socket.inet_ntoa(raw)
    except Exception:
        return "?"


def _ts_str(ts: float) -> str:
    try:
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except Exception:
        return str(ts)


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


def _parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """DNS ラベル列をデコードして (name, next_offset) を返す。"""
    labels = []
    visited = set()
    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:   # pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            sub, _ = _parse_dns_name(data, ptr)
            labels.append(sub)
            offset += 2
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), offset


def _parse_dns(payload: bytes) -> dict | None:
    """DNS メッセージを最低限パースして dict を返す。失敗時は None。"""
    try:
        if len(payload) < 12:
            return None
        txid   = int.from_bytes(payload[0:2], "big")
        flags  = int.from_bytes(payload[2:4], "big")
        is_qr  = bool(flags & 0x8000)   # 1=Response, 0=Query
        opcode = (flags >> 11) & 0xF
        rcode  = flags & 0xF
        qdcount = int.from_bytes(payload[4:6], "big")

        offset = 12
        questions = []
        for _ in range(min(qdcount, 4)):
            name, offset = _parse_dns_name(payload, offset)
            if offset + 4 > len(payload):
                break
            qtype  = int.from_bytes(payload[offset:offset+2], "big")
            offset += 4
            questions.append({"name": name, "qtype": DNS_QTYPES.get(qtype, str(qtype))})

        return {
            "txid":       txid,
            "is_response": is_qr,
            "rcode":      rcode,
            "rcode_name": DNS_RCODES.get(rcode, f"rcode={rcode}"),
            "questions":  questions,
        }
    except Exception:
        return None


def analyze_pcap(data: bytes) -> dict:
    """
    pcap/pcapng バイト列を解析し、各種パケット情報を返す。

    Returns dict:
        icmp_redirects      : list[dict]  ICMP redirect パケット一覧
        icmp_summary        : list[dict]  ICMP type 別集計
        rip_packets         : list[dict]  RIP パケット一覧
        arp_anomalies       : list[dict]  ARP 重複/変化
        tcp_issues          : list[dict]  TCP 問題 (RST多発・再送・接続失敗・ゼロウィンドウ)
        tcp_retransmissions : list[dict]  TCP 再送多発フロー
        tcp_syn_no_synack   : list[dict]  SYN 未応答（接続失敗）
        tcp_zero_window     : list[dict]  TCP ゼロウィンドウ発生フロー
        dns_issues          : list[dict]  DNS エラー / 遅延 / NXDOMAIN
        dns_summary         : dict        DNS 集計
        syslog_packets      : list[dict]  pcap内syslog
        total_packets       : int
        capture_start       : str
        capture_end         : str
        error               : str | None
    """
    result = {
        "icmp_redirects": [],
        "icmp_summary": {},
        "rip_packets": [],
        "arp_anomalies": [],
        "tcp_issues": [],
        "tcp_retransmissions": [],
        "tcp_syn_no_synack": [],
        "tcp_zero_window": [],
        "dns_issues": [],
        "dns_summary": {"queries": 0, "responses": 0, "nxdomain": 0,
                        "servfail": 0, "refused": 0, "slow": 0},
        "syslog_packets": [],
        "total_packets": 0,
        "capture_start": "",
        "capture_end": "",
        "error": None,
    }

    try:
        reader, is_ng = _open_capture(data)
    except Exception as e:
        result["error"] = f"ファイル読み込みエラー: {e}"
        return result

    timestamps = []
    arp_table: dict[str, str] = {}

    # TCP RST: (src, dst, sport, dport) -> count
    tcp_rst_count: dict[tuple, int] = defaultdict(int)

    # TCP retransmission: flow -> set of (seq, data_len) already seen
    tcp_flow_seqs: dict[tuple, set] = defaultdict(set)
    tcp_retrans_count: dict[tuple, int] = defaultdict(int)

    # SYN/SYN-ACK tracking: (src, dst, sport, dport) -> first SYN ts
    syn_sent: dict[tuple, float] = {}
    syn_ack_received: set = set()   # (responder, initiator, resp_port, init_port)

    # RTT tracking: txid for SYN-based RTT (stored in get_conversations)
    # Zero-window: (src, dst, sport, dport) -> count
    zero_win_count: dict[tuple, int] = defaultdict(int)

    # DNS: txid -> (ts, src, dst, question) for pending queries
    dns_pending: dict[int, dict] = {}

    try:
        for ts, raw_pkt in reader:
            result["total_packets"] += 1
            timestamps.append(ts)

            try:
                eth = dpkt.ethernet.Ethernet(raw_pkt)
            except Exception:
                continue

            # ── IP パケット ──────────────────────────
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                src = _ip_str(ip.src)
                dst = _ip_str(ip.dst)

                # ICMP
                if isinstance(ip.data, dpkt.icmp.ICMP):
                    icmp = ip.data
                    t = icmp.type
                    result["icmp_summary"][t] = result["icmp_summary"].get(t, 0) + 1

                    if t == ICMP_REDIRECT:
                        try:
                            gw = _ip_str(icmp.data.gw)
                        except Exception:
                            try:
                                gw = _ip_str(bytes(icmp.data)[:4])
                            except Exception:
                                gw = "?"

                        orig_dst = orig_src = orig_proto = "?"
                        try:
                            inner = dpkt.ip.IP(bytes(icmp.data)[4:])
                            orig_dst  = _ip_str(inner.dst)
                            orig_src  = _ip_str(inner.src)
                            orig_proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(inner.p, str(inner.p))
                        except Exception:
                            pass

                        code_desc = ICMP_REDIRECT_CODES.get(icmp.code, f"code={icmp.code}")
                        result["icmp_redirects"].append({
                            "timestamp":  _ts_str(ts),
                            "router_ip":  src,
                            "target_ip":  dst,
                            "gateway":    gw,
                            "orig_src":   orig_src,
                            "orig_dst":   orig_dst,
                            "orig_proto": orig_proto,
                            "code":       icmp.code,
                            "code_desc":  code_desc,
                        })

                # TCP
                elif isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
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
                        if key not in syn_sent:
                            syn_sent[key] = ts
                    elif is_syn and is_ack:
                        syn_ack_received.add((src, dst, sport, dport))

                    # Retransmission: data-carrying packets only
                    data_len = len(tcp.data)
                    if data_len > 0:
                        flow_key = (src, dst, sport, dport)
                        pkt_sig  = (tcp.seq, data_len)
                        if pkt_sig in tcp_flow_seqs[flow_key]:
                            tcp_retrans_count[flow_key] += 1
                        else:
                            tcp_flow_seqs[flow_key].add(pkt_sig)

                    # Zero Window: receiver advertises win=0 (not SYN/RST)
                    if tcp.win == 0 and not is_syn and not is_rst:
                        zero_win_count[(src, dst, sport, dport)] += 1

                # UDP: RIP / DNS / syslog
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data

                    if udp.dport == RIP_PORT or udp.sport == RIP_PORT:
                        try:
                            rip_ver = udp.data[1] if len(udp.data) > 1 else 0
                            cmd     = udp.data[0] if len(udp.data) > 0 else 0
                            cmd_str = {1: "Request", 2: "Response"}.get(cmd, f"cmd={cmd}")
                            result["rip_packets"].append({
                                "timestamp": _ts_str(ts),
                                "src":       src,
                                "dst":       dst,
                                "version":   f"RIPv{rip_ver}",
                                "command":   cmd_str,
                                "size":      len(udp.data),
                            })
                        except Exception:
                            pass

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
                                        "timestamp": _ts_str(ts),
                                        "client": dst,
                                        "server": src,
                                        "name":   q_name,
                                        "qtype":  q_type,
                                        "rcode":  "NXDOMAIN",
                                        "rtt_ms": None,
                                        "issue":  "名前解決失敗 (NXDOMAIN)",
                                    })
                                elif rcode == 2:
                                    result["dns_summary"]["servfail"] += 1
                                    result["dns_issues"].append({
                                        "timestamp": _ts_str(ts),
                                        "client": dst,
                                        "server": src,
                                        "name":   q_name,
                                        "qtype":  q_type,
                                        "rcode":  "SERVFAIL",
                                        "rtt_ms": None,
                                        "issue":  "DNS サーバーエラー (SERVFAIL)",
                                    })
                                elif rcode == 5:
                                    result["dns_summary"]["refused"] += 1
                                    result["dns_issues"].append({
                                        "timestamp": _ts_str(ts),
                                        "client": dst,
                                        "server": src,
                                        "name":   q_name,
                                        "qtype":  q_type,
                                        "rcode":  "REFUSED",
                                        "rtt_ms": None,
                                        "issue":  "クエリ拒否 (REFUSED) — ACL/設定確認",
                                    })
                                # RTT for this transaction
                                if dns["txid"] in dns_pending:
                                    pend = dns_pending.pop(dns["txid"])
                                    rtt_ms = round((ts - pend["ts"]) * 1000, 1)
                                    if rtt_ms > 500:   # > 500 ms は遅延として記録
                                        result["dns_summary"]["slow"] += 1
                                        result["dns_issues"].append({
                                            "timestamp": _ts_str(ts),
                                            "client": pend["src"],
                                            "server": dst,
                                            "name":   pend["name"],
                                            "qtype":  pend["qtype"],
                                            "rcode":  dns["rcode_name"],
                                            "rtt_ms": rtt_ms,
                                            "issue":  f"DNS 応答遅延 {rtt_ms} ms",
                                        })

                    elif udp.dport in SYSLOG_PORTS or udp.sport in SYSLOG_PORTS:
                        try:
                            raw_msg = udp.data.decode("utf-8", errors="replace").strip()
                            if raw_msg:
                                result["syslog_packets"].append({
                                    "timestamp": _ts_str(ts),
                                    "src_ip":    src,
                                    "dst_ip":    dst,
                                    "port":      udp.dport,
                                    "raw":       raw_msg,
                                })
                        except Exception:
                            pass

            # ── ARP ──────────────────────────────────
            elif isinstance(eth.data, dpkt.arp.ARP):
                arp = eth.data
                try:
                    sender_ip  = _ip_str(arp.spa)
                    sender_mac = ":".join(f"{b:02x}" for b in arp.sha)
                    if sender_ip in arp_table:
                        if arp_table[sender_ip] != sender_mac:
                            result["arp_anomalies"].append({
                                "timestamp":   _ts_str(ts),
                                "ip":          sender_ip,
                                "old_mac":     arp_table[sender_ip],
                                "new_mac":     sender_mac,
                                "description": "MACアドレス変化（ARPスプーフィングの疑い）",
                            })
                    arp_table[sender_ip] = sender_mac
                except Exception:
                    pass

    except Exception as e:
        result["error"] = f"パケット解析中エラー: {e}"

    # ── TCP RST 多発 ─────────────────────────────
    for (src, dst, sport, dport), cnt in tcp_rst_count.items():
        if cnt >= 3:
            result["tcp_issues"].append({
                "type":        "RST多発",
                "src":         src,
                "dst":         dst,
                "src_port":    sport,
                "dst_port":    dport,
                "count":       cnt,
                "description": f"TCP RST 多発 ({cnt}回) — 接続拒否/強制切断の可能性",
            })

    # ── TCP 再送多発 ─────────────────────────────
    for (src, dst, sport, dport), cnt in tcp_retrans_count.items():
        if cnt >= 3:
            entry = {
                "src":           src,
                "dst":           dst,
                "src_port":      sport,
                "dst_port":      dport,
                "retrans_count": cnt,
                "description":   f"TCP 再送 ({cnt}回) — ネットワーク品質低下/輻輳の可能性",
            }
            result["tcp_retransmissions"].append(entry)
            result["tcp_issues"].append({
                "type":        "再送多発",
                "src":         src,
                "dst":         dst,
                "src_port":    sport,
                "dst_port":    dport,
                "count":       cnt,
                "description": entry["description"],
            })

    # ── SYN 未応答（接続失敗）─────────────────────
    cap_end = max(timestamps) if timestamps else 0
    for (src, dst, sport, dport), syn_ts in syn_sent.items():
        if (dst, src, dport, sport) not in syn_ack_received:
            wait_sec = cap_end - syn_ts
            if wait_sec >= 1.0:
                desc = f"SYN未応答 ({wait_sec:.1f}秒待機) — 接続タイムアウト/サービス停止の可能性"
                result["tcp_syn_no_synack"].append({
                    "src":         src,
                    "dst":         dst,
                    "src_port":    sport,
                    "dst_port":    dport,
                    "syn_at":      _ts_str(syn_ts),
                    "wait_sec":    round(wait_sec, 3),
                    "description": desc,
                })
                result["tcp_issues"].append({
                    "type":        "接続失敗",
                    "src":         src,
                    "dst":         dst,
                    "src_port":    sport,
                    "dst_port":    dport,
                    "count":       1,
                    "description": desc,
                })

    # ── TCP ゼロウィンドウ ────────────────────────
    for (src, dst, sport, dport), cnt in zero_win_count.items():
        if cnt >= 2:
            desc = f"ゼロウィンドウ {cnt}回 — 受信バッファ枯渇/フロー制御問題の可能性"
            result["tcp_zero_window"].append({
                "src":         src,
                "dst":         dst,
                "src_port":    sport,
                "dst_port":    dport,
                "count":       cnt,
                "description": desc,
            })
            result["tcp_issues"].append({
                "type":        "ゼロウィンドウ",
                "src":         src,
                "dst":         dst,
                "src_port":    sport,
                "dst_port":    dport,
                "count":       cnt,
                "description": desc,
            })

    # ── ICMP summary を名称付きリストに変換 ────────
    result["icmp_summary"] = [
        {"type": t, "name": ICMP_TYPE_NAMES.get(t, f"type={t}"), "count": c}
        for t, c in sorted(result["icmp_summary"].items())
    ]

    if timestamps:
        result["capture_start"] = _ts_str(min(timestamps))
        result["capture_end"]   = _ts_str(max(timestamps))

    if result["syslog_packets"]:
        try:
            from parsers import parse_syslog
            for pkt in result["syslog_packets"]:
                pkt["parsed"] = parse_syslog(pkt["raw"], pkt["src_ip"])
        except Exception:
            pass

    return result


def get_conversations(data: bytes) -> list:
    """
    pcap/pcapng から TCP/UDP の双方向会話フロー一覧を返す。
    RTT（SYN→SYN-ACK）・スループット・TCPフラグも付与する。

    Returns list[dict]:
        protocol, src_ip, src_port, dst_ip, dst_port,
        packets, bytes, throughput_kbps, duration_sec,
        start, end, rtt_ms, has_syn, has_fin, has_rst, tcp_state
    """
    try:
        reader, _ = _open_capture(data)
    except Exception:
        return []

    flows: dict[tuple, dict] = {}
    # SYN tracking for RTT: canonical flow_key -> SYN timestamp
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
            continue  # TCP/UDP のみ集計

        # 双方向正規化
        if (src, sport) <= (dst, dport):
            flow_key = (proto, src, dst, sport, dport)
        else:
            flow_key = (proto, dst, src, dport, sport)

        if flow_key not in flows:
            flows[flow_key] = {
                "protocol": flow_key[0],
                "src_ip":   flow_key[1],
                "dst_ip":   flow_key[2],
                "src_port": flow_key[3],
                "dst_port": flow_key[4],
                "packets":  0,
                "bytes":    0,
                "_start":   ts,
                "_end":     ts,
                "has_syn":  False,
                "has_fin":  False,
                "has_rst":  False,
                "rtt_ms":   None,
            }

        f = flows[flow_key]
        f["packets"] += 1
        f["bytes"]   += pkt_len
        if ts < f["_start"]: f["_start"] = ts
        if ts > f["_end"]:   f["_end"]   = ts
        f["has_syn"] = f["has_syn"] or has_syn
        f["has_fin"] = f["has_fin"] or has_fin
        f["has_rst"] = f["has_rst"] or has_rst

        # RTT = SYN送信 → SYN-ACK受信 の時間差
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
        f["start"]            = _ts_str(f.pop("_start"))
        f["end"]              = _ts_str(f.pop("_end"))
        f["duration_sec"]     = round(dur, 3)
        # スループット (KB/s)
        f["throughput_kbps"]  = round(f["bytes"] / dur / 1024, 2) if dur > 0 else 0

        # TCP 状態サマリ
        s = []
        if f.get("has_syn"): s.append("SYN")
        if f.get("has_fin"): s.append("FIN")
        if f.get("has_rst"): s.append("RST")
        f["tcp_state"] = "|".join(s) if s else ("—" if f["protocol"] == "TCP" else "")

        result.append(f)

    result.sort(key=lambda x: x["bytes"], reverse=True)   # バイト数の多い順
    return result


def get_top_talkers(data: bytes, top_n: int = 20) -> list:
    """
    送受信バイト数が多い IP アドレスランキングを返す。

    Returns list[dict]:
        ip, sent_bytes, recv_bytes, total_bytes, sent_pkts, recv_pkts
    """
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

        ip  = eth.data
        src = _ip_str(ip.src)
        dst = _ip_str(ip.dst)
        pkt_len = len(raw_pkt)

        ip_stats[src]["sent_bytes"] += pkt_len
        ip_stats[src]["sent_pkts"]  += 1
        ip_stats[dst]["recv_bytes"] += pkt_len
        ip_stats[dst]["recv_pkts"]  += 1

    result = []
    for ip_addr, s in ip_stats.items():
        total = s["sent_bytes"] + s["recv_bytes"]
        result.append({
            "ip":          ip_addr,
            "sent_bytes":  s["sent_bytes"],
            "recv_bytes":  s["recv_bytes"],
            "total_bytes": total,
            "sent_pkts":   s["sent_pkts"],
            "recv_pkts":   s["recv_pkts"],
        })

    result.sort(key=lambda x: x["total_bytes"], reverse=True)
    return result[:top_n]


def filter_pcap(
    data: bytes,
    src_ip: str = "",
    dst_ip: str = "",
    ip: str = "",        # 送受信どちらかに一致
    port: int = 0,       # 送受信どちらかに一致
    protocol: str = "",  # "TCP" / "UDP" / "ICMP" / "ARP"
    keyword: str = "",   # ペイロード内キーワード（UTF-8 デコード後）
    max_packets: int = 500,
) -> list:
    """
    pcap から条件に一致するパケット一覧を返す。

    Returns list[dict]:
        timestamp, protocol, src_ip, src_port, dst_ip, dst_port,
        length, info, payload_text
    """
    try:
        reader, _ = _open_capture(data)
    except Exception:
        return []

    protocol_upper = (protocol or "").upper()
    kw_lower = (keyword or "").lower()
    matched = []

    for ts, raw_pkt in reader:
        if len(matched) >= max_packets:
            break

        try:
            eth = dpkt.ethernet.Ethernet(raw_pkt)
        except Exception:
            continue

        pkt_src = pkt_dst = "?"
        pkt_sport = pkt_dport = 0
        pkt_proto = ""
        pkt_info  = ""
        payload_text = ""

        if isinstance(eth.data, dpkt.ip.IP):
            pip = eth.data
            pkt_src = _ip_str(pip.src)
            pkt_dst = _ip_str(pip.dst)

            if isinstance(pip.data, dpkt.tcp.TCP):
                tcp = pip.data
                pkt_proto = "TCP"
                pkt_sport = tcp.sport
                pkt_dport = tcp.dport
                flag_str  = _tcp_flag_str(tcp.flags)
                pkt_info  = f"TCP {pkt_sport}→{pkt_dport} [{flag_str}] seq={tcp.seq}"
                if tcp.data:
                    payload_text = tcp.data.decode("utf-8", errors="replace")

            elif isinstance(pip.data, dpkt.udp.UDP):
                udp = pip.data
                pkt_proto = "UDP"
                pkt_sport = udp.sport
                pkt_dport = udp.dport
                pkt_info  = f"UDP {pkt_sport}→{pkt_dport}"
                if udp.data:
                    payload_text = udp.data.decode("utf-8", errors="replace")

            elif isinstance(pip.data, dpkt.icmp.ICMP):
                icmp = pip.data
                pkt_proto = "ICMP"
                type_name = ICMP_TYPE_NAMES.get(icmp.type, f"type={icmp.type}")
                pkt_info  = f"ICMP {type_name} (type={icmp.type} code={icmp.code})"

            else:
                pkt_proto = PROTO_NAMES.get(pip.p, f"IP/{pip.p}")
                pkt_info  = pkt_proto

        elif isinstance(eth.data, dpkt.arp.ARP):
            arp = eth.data
            pkt_proto = "ARP"
            arp_src = _ip_str(arp.spa)
            arp_dst = _ip_str(arp.tpa)
            op = {1: "Request", 2: "Reply"}.get(arp.op, f"op={arp.op}")
            pkt_src  = arp_src
            pkt_dst  = arp_dst
            pkt_info = f"ARP {op}: who has {arp_dst}? tell {arp_src}"
        else:
            continue

        # ── フィルター適用 ──
        if protocol_upper and pkt_proto != protocol_upper:
            continue
        if src_ip and pkt_src != src_ip:
            continue
        if dst_ip and pkt_dst != dst_ip:
            continue
        if ip and ip not in (pkt_src, pkt_dst):
            continue
        if port and port not in (pkt_sport, pkt_dport):
            continue
        if kw_lower and kw_lower not in payload_text.lower():
            continue

        matched.append({
            "timestamp":    _ts_str(ts),
            "protocol":     pkt_proto,
            "src_ip":       pkt_src,
            "src_port":     pkt_sport,
            "dst_ip":       pkt_dst,
            "dst_port":     pkt_dport,
            "length":       len(raw_pkt),
            "info":         pkt_info,
            "payload_text": payload_text[:300] if kw_lower else "",
        })

    return matched
