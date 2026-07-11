"""
pyshark / tshark 連携（Wiresharkの全ディセクタ・Expert Info）

このアプリのpcap解析(pcap_analyzer.py)はdpktで主要プロトコル約20種を手書きで
パースしているが、pyshark(github.com/KimiNewt/pyshark)はtshark(Wireshark CLI)を
ラップし、Wiresharkの数千のプロトコルディセクタと「Expert Info」（Wireshark
自身が検出した再送・不正パケット・シーケンス異常等の警告）を利用できる。

そこで本モジュールは、我々の手書きパーサでは扱わない広範なプロトコルの
可視化と、Wireshark Expert Infoによる異常検知を「補完」として提供する。

tsharkはシステムバイナリ（apt install tshark 等）が必要で、Streamlit Cloud等
には導入できないため、llmshark連携と同様に**tsharkが在る場合のみ有効になる
オプトイン機能**として実装する（無い場合は自動的に無効化）。

実装上、per-packet反復ではなくtsharkの集計モード(-z)・フィールド抽出(-T fields)を
subprocessで直接呼ぶ（pysharkの内部と同じtsharkを使うが、集計統計はこの方が
高速・堅牢）。pysharkライブラリ自体のimport可否も TSHARK_AVAILABLE に含める。
"""
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

_TSHARK_BIN = shutil.which("tshark")
try:
    import pyshark  # noqa: F401
    _PYSHARK_IMPORTED = True
except ImportError:
    _PYSHARK_IMPORTED = False

TSHARK_AVAILABLE = bool(_TSHARK_BIN)

# Wireshark Expert Info の重大度コード -> ラベル
_EXPERT_SEVERITY = {
    "2097152": ("chat", "会話"),
    "4194304": ("note", "注意"),
    "6291456": ("warn", "警告"),
    "8388608": ("error", "エラー"),
}

# 我々のdpktパーサ(pcap_analyzer.py)が個別に解析しているプロトコル。
# tsharkが検出したプロトコルのうち、この集合に無いものを「手書き非対応
# （pyshark連携で新たに見える）」として提示する。
_BUILTIN_PROTOCOLS = {
    "eth", "ethertype", "ip", "ipv6", "tcp", "udp", "icmp", "icmpv6", "arp",
    "ospf", "dns", "bootp", "dhcp", "tls", "ssl", "isakmp", "esp", "ah",
    "http", "http2", "rip", "ripng", "modbus", "mbtcp", "dnp3", "quic",
    "ssh", "rtp", "gre", "data", "vlan", "llc",
}


def _write_temp(data: bytes) -> Path:
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.write(data)
    tmp.close()
    return Path(tmp.name)


def _run_tshark(args: list[str]) -> str:
    proc = subprocess.run(
        [_TSHARK_BIN, *args],
        capture_output=True, text=True, timeout=120,
    )
    return proc.stdout


def get_protocol_hierarchy(pcap_path: Path) -> list[dict]:
    """tshark の Protocol Hierarchy Statistics (-z io,phs) を構造化して返す。"""
    out = _run_tshark(["-r", str(pcap_path), "-q", "-z", "io,phs"])
    rows = []
    in_table = False
    for line in out.splitlines():
        if line.startswith("==="):
            in_table = not in_table
            continue
        if not in_table or not line.strip():
            continue
        if line.strip().startswith(("Protocol Hierarchy", "Filter:")):
            continue
        indent = len(line) - len(line.lstrip())
        parts = line.split()
        if len(parts) < 2:
            continue
        proto = parts[0]
        frames = bytes_ = 0
        for p in parts:
            if p.startswith("frames:"):
                frames = int(p.split(":")[1])
            elif p.startswith("bytes:"):
                bytes_ = int(p.split(":")[1])
        rows.append({"protocol": proto, "depth": indent // 2,
                     "frames": frames, "bytes": bytes_})
    return rows


def get_expert_info(pcap_path: Path, limit: int = 200) -> list[dict]:
    """
    tshark の Expert Info を構造化して返す（Wireshark自身が検出した
    再送・不正パケット・シーケンス異常等の警告）。重大度・件数で集約する。
    """
    # 1フレームに複数のExpert項目がある場合、tsharkは各フィールドを区切り文字で
    # 連結する。既定はカンマだが、Expertメッセージ本文にもカンマが含まれるため
    # 分割が破綻する。衝突しにくいパイプ(|)を集約区切りに指定する。
    out = _run_tshark([
        "-r", str(pcap_path), "-Y", "_ws.expert", "-T", "fields",
        "-E", "aggregator=|",
        "-e", "_ws.expert.severity", "-e", "_ws.expert.group",
        "-e", "_ws.expert.message", "-e", "frame.protocols",
    ])
    agg: dict[tuple, dict] = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        if len(cols) < 3:
            continue
        severities = cols[0].split("|")
        messages = cols[2].split("|")
        proto_chain = cols[3] if len(cols) > 3 else ""
        proto = proto_chain.split(":")[-1] if proto_chain else ""
        for sev, msg in zip(severities, messages):
            sev = sev.strip()
            msg = msg.strip()
            if not msg:
                continue
            sev_key, sev_label = _EXPERT_SEVERITY.get(sev, ("unknown", "不明"))
            key = (sev_key, msg, proto)
            entry = agg.setdefault(key, {
                "severity": sev_key, "severity_label": sev_label,
                "message": msg, "protocol": proto, "count": 0})
            entry["count"] += 1

    _order = {"error": 0, "warn": 1, "note": 2, "chat": 3, "unknown": 4}
    result = sorted(agg.values(),
                    key=lambda e: (_order.get(e["severity"], 4), -e["count"]))
    return result[:limit]


def analyze_with_tshark(data: bytes) -> dict:
    """
    pcapバイト列をtsharkで補完解析する。
    戻り値: {available, protocol_hierarchy, expert_info, protocols_beyond_builtin, error}
    """
    if not TSHARK_AVAILABLE:
        return {"available": False,
                "error": "tsharkが未インストールです（例: apt install tshark）。"}

    pcap_path = _write_temp(data)
    try:
        hierarchy = get_protocol_hierarchy(pcap_path)
        expert = get_expert_info(pcap_path)

        detected = {r["protocol"].lower() for r in hierarchy}
        # _ws.* はWiresharkの疑似プロトコル（malformed等）で実プロトコルでは
        # ないため、未対応プロトコル一覧からは除外する（不正パケットは
        # expert_info側で別途surfaceされる）。
        beyond = sorted(p for p in (detected - _BUILTIN_PROTOCOLS)
                        if not p.startswith("_ws."))

        return {
            "available": True,
            "pyshark_imported": _PYSHARK_IMPORTED,
            "protocol_hierarchy": hierarchy,
            "expert_info": expert,
            "protocols_beyond_builtin": beyond,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {"available": True, "error": "tshark解析がタイムアウトしました。"}
    except Exception as e:
        return {"available": True, "error": f"tshark解析エラー: {e}"}
    finally:
        pcap_path.unlink(missing_ok=True)
