"""
Wireshark pcap/pcapng ファイルのパーサー。
ICMP redirect を中心に、RIP / ARP 異常 / TCP 問題なども抽出する。
"""
import io
import struct
import socket
from datetime import datetime

import dpkt


# ICMP type / code 定義
ICMP_REDIRECT = 5
ICMP_REDIRECT_CODES = {
    0: "ネットワーク宛リダイレクト",
    1: "ホスト宛リダイレクト",
    2: "TOS+ネットワーク宛リダイレクト",
    3: "TOS+ホスト宛リダイレクト",
}

# RIP は UDP 520
RIP_PORT = 520

# ICMP type 名称
ICMP_TYPE_NAMES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
}


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
    # pcapng: magic = 0x0A0D0D0A
    if len(data) >= 4 and struct.unpack("<I", data[:4])[0] == 0x0A0D0D0A:
        return dpkt.pcapng.Reader(io.BytesIO(data)), True
    return dpkt.pcap.Reader(io.BytesIO(data)), False


def analyze_pcap(data: bytes) -> dict:
    """
    pcap/pcapng バイト列を解析し、各種パケット情報を返す。

    Returns dict:
        icmp_redirects  : list[dict]  ICMP redirect パケット一覧
        icmp_summary    : list[dict]  ICMP type 別集計
        rip_packets     : list[dict]  RIP パケット一覧
        arp_anomalies   : list[dict]  ARP 重複/変化
        tcp_issues      : list[dict]  RST 多発など
        total_packets   : int
        capture_start   : str
        capture_end     : str
        error           : str | None
    """
    result = {
        "icmp_redirects": [],
        "icmp_summary": {},
        "rip_packets": [],
        "arp_anomalies": [],
        "tcp_issues": [],
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
    arp_table: dict[str, str] = {}   # ip -> mac (最初に見たもの)
    tcp_rst_count: dict[tuple, int] = {}

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
                        # redirect ゲートウェイアドレスは ICMP データの先頭4バイト
                        try:
                            gw = _ip_str(icmp.data.gw)
                        except Exception:
                            try:
                                gw = _ip_str(bytes(icmp.data)[:4])
                            except Exception:
                                gw = "?"

                        # 元のIPヘッダ（ICMP payload 内）
                        orig_dst = "?"
                        orig_src = "?"
                        orig_proto = "?"
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
                            "router_ip":  src,       # redirectを送ったルーター
                            "target_ip":  dst,       # redirectを受け取るホスト
                            "gateway":    gw,        # 本来のネクストホップ
                            "orig_src":   orig_src,  # 元パケットの送信元
                            "orig_dst":   orig_dst,  # 元パケットの宛先
                            "orig_proto": orig_proto,
                            "code":       icmp.code,
                            "code_desc":  code_desc,
                        })

                # TCP RST 集計
                elif isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    if tcp.flags & dpkt.tcp.TH_RST:
                        key = (src, dst)
                        tcp_rst_count[key] = tcp_rst_count.get(key, 0) + 1

                # UDP RIP
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

    # TCP RST 多発をまとめる
    for (src, dst), cnt in tcp_rst_count.items():
        if cnt >= 5:
            result["tcp_issues"].append({
                "src": src,
                "dst": dst,
                "rst_count": cnt,
                "description": f"TCP RST 多発 ({cnt}回) — 接続拒否/セッション強制切断の可能性",
            })

    # ICMP summary を名称付きに変換
    result["icmp_summary"] = [
        {"type": t, "name": ICMP_TYPE_NAMES.get(t, f"type={t}"), "count": c}
        for t, c in sorted(result["icmp_summary"].items())
    ]

    if timestamps:
        result["capture_start"] = _ts_str(min(timestamps))
        result["capture_end"]   = _ts_str(max(timestamps))

    return result
