"""
Wireshark/pcap解析 MCPサーバー

このリポジトリのpcap_analyzer.py（ICMP redirect・TCP異常・DNS/DHCP/TLS/IPsec/
OSPF・ワーム横展開/ビーコニング等の振る舞い検知・脅威インテリジェンス・
生成AIサービス宛通信検知など）をMCPツールとして公開し、Claude Desktop等の
MCPクライアントから、ローカルのpcapファイルを直接指定して解析できるようにする。

セットアップ:
    pip install mcp
    claude mcp add pcap-analyzer -- python3 /path/to/pcap_mcp_server.py
（またはClaude Desktopのclaude_desktop_config.jsonに mcpServers として登録）

このアプリのStreamlit UI（パケット解析タブ）と全く同じ解析エンジンを
使うため、検知内容はUIでの結果と一致する。
"""
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

import pcap_analyzer

mcp = FastMCP("pcap-analyzer")


def _load_pcap_bytes(file_path: str) -> bytes:
    p = Path(file_path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"ファイルが見つかりません: {file_path}")
    data = p.read_bytes()
    # zip/gz等で圧縮されたキャプチャは自動解凍する（アプリのアップロード処理と同じ挙動）
    decompressed = pcap_analyzer.decompress_upload(data, filename=p.name)
    if decompressed.get("data"):
        return decompressed["data"]
    return data


def _trim_list(items: list, limit: int) -> dict:
    """MCPクライアントへ返すJSONが肥大化しないよう、リストを先頭limit件に切り詰める。"""
    if not isinstance(items, list):
        return items
    return {"total": len(items), "shown": items[:limit]} if len(items) > limit else {
        "total": len(items), "shown": items}


# リスト型フィールドのうち、件数が多くなりがちなものだけ切り詰め対象にする
_TRIM_FIELDS = [
    "tcp_issues", "tcp_retransmissions", "tcp_syn_no_synack", "tcp_zero_window",
    "scan_patterns", "ctf_flag_hits", "dns_tunneling", "icmp_exfil", "ips_alerts",
    "worm_propagation", "beaconing", "suspicious_destinations", "data_exfil",
    "host_risk", "threat_intel_hits", "geo_alerts", "ssh_handshakes", "ospf_issues",
    "ip_fragments", "http_errors", "tls_sessions", "tls_alerts", "ai_service_sessions",
    "tls_handshakes", "dhcp_issues", "dns_issues", "syslog_packets",
    "unknown_proto_hints", "session_id_correlations", "voip_streams",
    "icmp_redirects", "rip_packets", "arp_anomalies", "quic_sessions",
    "industrial_alerts",
]


@mcp.tool()
def analyze_pcap(file_path: str, max_items_per_category: int = 20) -> str:
    """
    pcap/pcapngファイルを総合解析する（ICMP redirect・TCP異常・ポートスキャン/DDoS・
    ワーム横展開/ビーコニング等の振る舞い検知・DNS/DHCP/TLS/IPsec/OSPF・
    脅威インテリジェンス照合・GeoIP・生成AIサービス宛通信検知など）。

    Args:
        file_path: ローカルのpcap/pcapng/zip/gzファイルへの絶対パス
        max_items_per_category: 各検知カテゴリごとに返す件数の上限（デフォルト20件）
    """
    try:
        data = _load_pcap_bytes(file_path)
        result = pcap_analyzer.analyze_pcap(data)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)

    if result.get("error"):
        return json.dumps({"error": result["error"]}, ensure_ascii=False)

    trimmed = dict(result)
    for field in _TRIM_FIELDS:
        if field in trimmed and isinstance(trimmed[field], list):
            trimmed[field] = _trim_list(trimmed[field], max_items_per_category)

    return json.dumps(trimmed, ensure_ascii=False, default=str)


@mcp.tool()
def grep_pcap_content(file_path: str, pattern: str, mode: str = "text",
                       scope: str = "packet", case_sensitive: bool = False,
                       max_matches: int = 50) -> str:
    """
    pcapファイルのパケット中身をgrepする。

    Args:
        file_path: ローカルのpcap/pcapngファイルへの絶対パス
        pattern: 検索パターン
        mode: "text"(部分一致) / "regex"(正規表現) / "hex"(16進バイト列 例 'deadbeef')
        scope: "packet"(パケット単位) / "stream"(TCPストリーム再構成後・跨ぎ検索)
        case_sensitive: 大文字小文字を区別するか
        max_matches: 返す最大一致件数
    """
    try:
        data = _load_pcap_bytes(file_path)
        result = pcap_analyzer.grep_pcap(
            data, pattern, mode=mode, case_sensitive=case_sensitive,
            scope=scope, max_matches=max_matches)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)
    return json.dumps(result, ensure_ascii=False, default=str)


@mcp.tool()
def get_pcap_conversations(file_path: str, limit: int = 30) -> str:
    """
    pcapファイル内のTCP/UDP会話（送信元⇔宛先の双方向フロー）を、
    バイト数の多い順に取得する。RTT・スループット・TCP状態(SYN/FIN/RST)付き。

    Args:
        file_path: ローカルのpcap/pcapngファイルへの絶対パス
        limit: 返す最大件数
    """
    try:
        data = _load_pcap_bytes(file_path)
        convs = pcap_analyzer.get_conversations(data)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)
    convs_sorted = sorted(convs, key=lambda c: c.get("bytes", 0), reverse=True)
    return json.dumps({"total": len(convs), "shown": convs_sorted[:limit]},
                       ensure_ascii=False, default=str)


@mcp.tool()
def get_pcap_top_talkers(file_path: str, top_n: int = 20) -> str:
    """
    pcapファイル内で最も通信量(バイト数)が多い送信元/宛先IPアドレスの
    ランキングを取得する。

    Args:
        file_path: ローカルのpcap/pcapngファイルへの絶対パス
        top_n: 返す最大件数
    """
    try:
        data = _load_pcap_bytes(file_path)
        talkers = pcap_analyzer.get_top_talkers(data, top_n=top_n)
    except Exception as e:
        return json.dumps({"error": str(e)}, ensure_ascii=False)
    return json.dumps(talkers, ensure_ascii=False, default=str)


if __name__ == "__main__":
    mcp.run()
