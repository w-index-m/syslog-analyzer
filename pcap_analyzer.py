"""
Wireshark pcap/pcapng ファイルのパーサー。
ICMP redirect を中心に RIP / ARP / TCP / DNS / HTTP / TLS / DHCP /
IPフラグメント / フロー解析 / pcap内syslog を抽出する。
"""
import base64
import binascii
import gzip
import io
import re
import struct
import socket
import urllib.parse
import zlib
from collections import defaultdict
from datetime import datetime

import dpkt


# ── ポート定数 ──────────────────────────────────────────────────
SYSLOG_PORTS = {514, 5140, 5141, 516, 601}
RIP_PORT     = 520

# ワーム/ボットが横展開でよく狙うポート（振る舞い検知の重大度判定に使う）
_WORM_TARGET_PORTS = {
    22: "SSH", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5555: "ADB", 6379: "Redis", 7547: "TR-069", 1900: "UPnP", 5900: "VNC",
    2323: "Telnet(IoT)", 9200: "Elasticsearch", 27017: "MongoDB", 11211: "Memcached",
}

# マルウェアがコード保管/持ち出しに悪用しがちな公開サービス（配下端末が
# サーバ的にこれらへアクセスしていたら要確認 = GitPaste-12型/C2の兆候）。
_SUSPICIOUS_HOST_RE = __import__("re").compile(
    r"(?i)(pastebin\.com|hastebin\.com|ghostbin\.|controlc\.com|0x0\.st|ix\.io|"
    r"termbin\.com|transfer\.sh|anonfiles\.|file\.io|paste\.ee|"
    r"raw\.githubusercontent\.com|gist\.githubusercontent\.com)")

# マルウェアに悪用されやすい無料/動的DNS・TLD（誤検知を避けるため低〜中重大度）。
_SUSPICIOUS_TLD_RE = __import__("re").compile(
    r"(?i)\.(tk|ml|ga|cf|gq|top|xyz|duckdns\.org|no-ip\.\w+|ddns\.net|hopto\.org)$")
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

# ── プロトコル不明時のキーワード検索（ID/session） ──────────────
# 既存パーサーで識別できない通信でも、平文に "id" や "session" が
# 含まれていれば独自/セッション型プロトコルの手がかりとして拾う。
# "session_id" (snake_case) や "SessionID" (camelCase) のような複合語も
# 拾えるよう、camelCase境界と非英数字で区切ってから単語単位で判定する。
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALNUM_RE       = re.compile(r"[^A-Za-z0-9]+")
_UNKNOWN_PROTO_TOKENS = {"id", "session"}


def _find_unknown_proto_keywords(payload: bytes) -> list:
    """プロトコル不明なペイロードから 'ID' / 'session' という単語を探す（ヒューリスティック）。"""
    if not payload:
        return []
    try:
        text = payload[:300].decode("utf-8", errors="ignore")
    except Exception:
        return []
    spaced = _CAMEL_BOUNDARY_RE.sub("_", text)
    tokens = (t.lower() for t in _NON_ALNUM_RE.split(spaced) if t)
    return sorted({t for t in tokens if t in _UNKNOWN_PROTO_TOKENS})


# ID/session の「値」を抽出して、複数フローにまたがる出現を突き合わせるための正規表現。
# 例: "session_id=555" "SessionID: abc123" "sid=99" "id=42"
_ID_VALUE_RE = re.compile(
    r"\b(?:session[_-]?id|sid|id)\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.]{2,64})[\"']?",
    re.IGNORECASE,
)


def _extract_id_values(payload: bytes) -> list:
    """プロトコル不明なペイロードから ID/session の値を抽出する（人手では困難な突き合わせ用）。"""
    if not payload:
        return []
    try:
        text = payload[:300].decode("utf-8", errors="ignore")
    except Exception:
        return []
    return _ID_VALUE_RE.findall(text)


# ── CTF問題向け: flag{...}パターン / Base64らしき文字列の検出 ────────
# ネットワークフォレンジック系CTF問題で頻出する「flagがパケット内の
# どこかに平文/Base64で埋まっている」ケースをハントするヒューリスティック。
_CTF_FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,20}\{[^{}\r\n]{2,200}\}")
_BASE64_CANDIDATE_RE = re.compile(rb"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def try_decode_base64(text: str) -> str | None:
    """Base64候補文字列のデコードを試みる。印字可能な結果が得られた場合のみ返す。"""
    try:
        padded = text + "=" * (-len(text) % 4)
        raw = base64.b64decode(padded, validate=False)
        decoded = raw.decode("utf-8", errors="strict")
        if not decoded:
            return None
        printable_ratio = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t") / len(decoded)
        if printable_ratio >= 0.9 and len(decoded) >= 4:
            return decoded
    except Exception:
        pass
    return None


def _mostly_printable(b: bytes, threshold: float = 0.85) -> bool:
    if not b:
        return False
    try:
        s = b.decode("utf-8", errors="strict")
    except Exception:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return printable / len(s) >= threshold


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def _is_dga_like(domain: str) -> bool:
    """ドメイン生成アルゴリズム(DGA)らしい高エントロピー/ランダムなドメインか判定する。"""
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    # 判定対象は2nd-levelラベル（例: xn3k9fq2.example.com なら example ではなく…最も長いラベル）
    cand = max((l for l in labels[:-1]), key=len, default="")
    if len(cand) < 12:
        return False
    ent = _shannon_entropy(cand)
    digits = sum(c.isdigit() for c in cand)
    vowels = sum(c in "aeiou" for c in cand.lower())
    # 高エントロピー かつ (数字が多い または 母音が極端に少ない)
    return ent >= 3.6 and (digits / len(cand) >= 0.25 or vowels / len(cand) <= 0.20)


def _dec_base64(b: bytes):
    text = b.decode("ascii", errors="strict").strip()
    core = re.sub(r"\s", "", text)
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", core) or len(core) < 8 or len(core) % 4 == 1:
        return None
    return base64.b64decode(core + "=" * (-len(core) % 4), validate=False)


def _dec_hex(b: bytes):
    text = re.sub(r"\s", "", b.decode("ascii", errors="strict")).strip()
    if len(text) < 8 or len(text) % 2 != 0 or not re.fullmatch(r"[0-9A-Fa-f]+", text):
        return None
    return binascii.unhexlify(text)


def _dec_url(b: bytes):
    text = b.decode("utf-8", errors="strict")
    if "%" not in text:
        return None
    out = urllib.parse.unquote_to_bytes(text)
    return out if out != b else None


def _dec_gzip(b: bytes):
    if len(b) < 2 or b[:2] != b"\x1f\x8b":
        return None
    return gzip.decompress(b)


def _dec_zlib(b: bytes):
    if len(b) < 2 or b[0] != 0x78:
        return None
    return zlib.decompress(b)


_ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")

_DECODERS = [
    ("base64", _dec_base64),
    ("hex", _dec_hex),
    ("url", _dec_url),
    ("gzip", _dec_gzip),
    ("zlib", _dec_zlib),
    ("rot13", lambda b: b.decode("ascii", errors="strict").translate(_ROT13_TABLE).encode()
     if re.search(r"[A-Za-z]", b.decode("ascii", errors="ignore")) else None),
]


# よくあるflag接頭辞。多段デコードの「本物のflag」判定に使う
# （ROT13等では中間結果も {} を持つため、接頭辞で本物を見分ける）。
_KNOWN_FLAG_PREFIXES = ("flag", "ctf", "key", "pctf", "htb", "thm", "picoctf", "fwctf")


def _looks_like_real_flag(m) -> bool:
    prefix = m.group(0).split(b"{", 1)[0].decode("ascii", errors="ignore").lower()
    return any(p in prefix for p in _KNOWN_FLAG_PREFIXES)


def multi_layer_decode(data, max_rounds: int = 6) -> dict:
    """
    多段エンコードされたデータを自動デコードする。
    base64 / hex / URL / gzip / zlib / ROT13 を順に試し、既知接頭辞のflag{...}が
    出るか、それ以上デコードできなくなるまで繰り返す（CTFの多段エンコード問題向け）。
    戻り値: {"steps": [{"method","preview"}], "final": str, "flag": str|None}
    """
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")
    steps = []
    current = data
    seen = {current}
    for _ in range(max_rounds):
        flag_m = _CTF_FLAG_RE.search(current)
        if flag_m and _looks_like_real_flag(flag_m):
            return {"steps": steps, "final": current.decode("utf-8", errors="ignore")[:500],
                    "flag": flag_m.group(0).decode("utf-8", errors="ignore")}
        progressed = False
        for name, fn in _DECODERS:
            try:
                out = fn(current)
            except Exception:
                out = None
            if not out or out in seen or len(out) > 1_000_000:
                continue
            # 意味のある結果のみ採用: 印字可能 / flagを含む / 既知の圧縮形式ヘッダ
            if (_mostly_printable(out) or _CTF_FLAG_RE.search(out)
                    or out[:2] == b"\x1f\x8b" or (out and out[0] == 0x78)):
                steps.append({"method": name, "preview": out.decode("utf-8", errors="replace")[:200]})
                seen.add(out)
                current = out
                progressed = True
                break
        if not progressed:
            break
    final_text = current.decode("utf-8", errors="ignore")
    flag_m = _CTF_FLAG_RE.search(current)
    return {"steps": steps, "final": final_text[:500],
            "flag": flag_m.group(0).decode("utf-8", errors="ignore") if flag_m else None}


def scan_ctf_indicators(payload: bytes) -> list:
    """CTF問題でよくある flag{...} パターンやBase64らしき文字列を検出する（ヒューリスティック）。"""
    hits = []
    if not payload:
        return hits
    for m in _CTF_FLAG_RE.finditer(payload):
        text = m.group(0).decode("utf-8", errors="ignore")
        hits.append({"type": "flag_pattern", "text": text[:200], "decoded": ""})
    for m in _BASE64_CANDIDATE_RE.finditer(payload):
        raw = m.group(0)
        if len(raw) >= 20:
            text = raw.decode("ascii", errors="ignore")[:200]
            hits.append({"type": "base64_candidate", "text": text,
                         "decoded": try_decode_base64(text) or ""})
    return hits


# ══════════════════════════════════════════════════════════════════
#  シグネチャ型IPS: 既知の攻撃パターンをペイロードから検出（Snort/Suricata風）
#  シグネチャ定義はリポジトリ内の ips_signatures.json で一元管理する
#  （GitHubを唯一の正とし、各デプロイはpull時に最新を取得する。サーバ個別の
#   シグネチャ保持は不要）。ファイルが無い/壊れている場合は空で動作する。
#  ※ヒューリスティックな簡易シグネチャです。誤検知もあり得るため参考情報として扱う。
# ══════════════════════════════════════════════════════════════════
import json as _json_ips
from pathlib import Path as _Path_ips

_IPS_SIGNATURES_PATH = _Path_ips(__file__).parent / "ips_signatures.json"


def _load_ips_signatures(path=_IPS_SIGNATURES_PATH) -> list:
    """ips_signatures.json を読み込み、正規表現をコンパイルして返す。"""
    sigs = []
    try:
        doc = _json_ips.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[ips] シグネチャ定義の読み込みに失敗: {e}")
        return sigs
    for s in doc.get("signatures", []):
        try:
            sigs.append({
                "id": s["id"], "cat": s["category"], "sev": s["severity"],
                "bin": bool(s.get("binary", False)),
                "re": re.compile(s["pattern"].encode("latin-1")),
                "cve": s.get("cve", ""), "desc": s.get("description", ""),
                "action": s.get("recommended_action", ""), "ref": s.get("reference", ""),
                "source": s.get("source", ""),
            })
        except Exception as e:
            print(f"[ips] 不正なシグネチャ {s.get('id')}: {e}")
    return sigs


_IPS_SIGNATURES = _load_ips_signatures()


def reload_ips_signatures() -> int:
    """シグネチャ定義を再読み込みする（更新後に呼ぶ）。読み込んだ件数を返す。"""
    global _IPS_SIGNATURES
    _IPS_SIGNATURES = _load_ips_signatures()
    return len(_IPS_SIGNATURES)


def scan_ips_signatures(payload: bytes) -> list:
    """ペイロードを簡易IPSシグネチャと照合し、一致した攻撃パターンを返す。"""
    hits = []
    if not payload:
        return hits
    chunk = payload[:2000]
    # テキスト系シグネチャは印字可能なペイロードのみ対象（バイナリでの誤検知防止）。
    # バイナリ系シグネチャ(binary=true)は暗号化されていない生バイト列を常に検査する。
    is_text = _mostly_printable(chunk, threshold=0.75)
    # URLエンコードを回避した攻撃も拾えるよう、デコード版でも照合する
    try:
        decoded = urllib.parse.unquote_to_bytes(chunk)
    except Exception:
        decoded = chunk
    text_targets = [chunk] if decoded == chunk else [chunk, decoded]
    for sig in _IPS_SIGNATURES:
        if sig.get("bin"):
            targets = [chunk]
        elif is_text:
            targets = text_targets
        else:
            continue
        m = None
        for tgt in targets:
            m = sig["re"].search(tgt)
            if m:
                break
        if m:
            hits.append({
                "sig_id": sig["id"], "category": sig["cat"], "severity": sig["sev"],
                "matched": m.group(0)[:80].decode("utf-8", errors="replace"),
                "cve": sig.get("cve", ""), "description": sig.get("desc", ""),
                "recommended_action": sig.get("action", ""), "reference": sig.get("ref", ""),
            })
    return hits


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


def _is_private_ip(ip: str) -> bool:
    """RFC1918プライベート/ローカルIPか判定する（外部宛て持ち出し判定用）。"""
    try:
        o = [int(x) for x in ip.split(".")]
    except Exception:
        return False
    if len(o) != 4:
        return False
    return (o[0] == 10 or (o[0] == 172 and 16 <= o[1] <= 31) or (o[0] == 192 and o[1] == 168)
            or o[0] == 127 or (o[0] == 169 and o[1] == 254) or o[0] == 0)


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
        tcp_retrans_summary 再送率サマリー(total_retrans/flows_affected/total_packets/retrans_rate_pct)
        tcp_syn_no_synack   SYN 未応答（接続失敗）
        tcp_zero_window     TCP ゼロウィンドウ発生フロー
        scan_patterns       ポートスキャン/DDoS(SYNフラッド)の兆候（送信元・宛先の集約から検出）
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
        unknown_proto_hints プロトコル不明な通信でID/sessionキーワードを検出したフロー
        session_id_correlations  同一ID値が複数フローにまたがって出現した突き合わせ結果
        ctf_flag_hits       flag{...}パターン/Base64らしき文字列の検出結果（CTF向け）
        total_packets       int
        capture_start / capture_end  str
        error               str | None
    """
    result = {
        "icmp_redirects": [], "icmp_summary": {},
        "rip_packets": [],    "arp_anomalies": [],
        "tcp_issues": [],     "tcp_retransmissions": [],
        "tcp_syn_no_synack": [], "tcp_zero_window": [],
        "scan_patterns": [],
        "ctf_flag_hits": [],
        "dns_tunneling": [],
        "icmp_exfil": [],
        "ips_alerts": [],
        "worm_propagation": [],
        "beaconing": [],
        "suspicious_destinations": [],
        "data_exfil": [],
        "host_risk": [],
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
        "unknown_proto_hints": [],
        "session_id_correlations": [],
        "voip_streams": [], "voip_avg_mos": 0.0, "voip_stream_count": 0, "voip_poor_streams": 0,
        "total_packets": 0,
        "capture_start": "", "capture_end": "", "capture_duration_sec": 0,
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
    # 振る舞い検知用
    horiz_scan: dict[tuple, set]     = defaultdict(set)   # (src, dport) -> {dst,...} 横展開/ラテラルムーブメント
    conn_times: dict[tuple, list]    = defaultdict(list)  # (src, dst, dport) -> [ts,...] ビーコニング
    accessed_domains: dict[str, dict] = {}               # domain -> {clients:set, count, via:set} アクセス先ドメイン
    outbound_bytes: dict[tuple, int] = defaultdict(int)  # (src, dst) -> 送信バイト数 大容量エクスフィル用

    def _record_domain(domain, client, via):
        if not domain or "." not in domain:
            return
        d = accessed_domains.setdefault(domain.lower(), {"clients": set(), "count": 0, "via": set()})
        d["clients"].add(client)
        d["count"] += 1
        d["via"].add(via)

    # TLS: canonical flow key -> {sni, tls_version}
    tls_flow_info: dict[tuple, dict] = {}
    tls_unique_sites: set = set()

    # DNS pending queries
    dns_pending: dict[int, dict] = {}

    # DHCP: xid -> {ts, client_mac, hostname, has_offer}
    dhcp_pending_discover: dict[int, dict] = {}

    # VoIP/RTP: ssrc -> {pkts:[{ts,seq,rtp_ts,size}], src, dst, pt}
    rtp_streams: dict[int, dict] = {}

    # プロトコル不明の通信: (proto, src, dst, sport, dport) -> {count, keywords, sample}
    unknown_proto_hints: dict[tuple, dict] = {}

    # ID/session値 -> {count, flows: {(proto,src,dst,sp,dp): count}, events: [{ts, flow}]}
    # 人手では困難な「同じID値が複数フローにまたがって出現していないか」の突き合わせと、
    # 出現順（シーケンス）チェックに使う。
    session_id_index: dict[str, dict] = {}

    # CTF問題向け flag{...}/Base64候補の検出結果
    ctf_flag_hits: list = []

    # シグネチャ型IPS: (src,dst,dport,sig_id) -> {count, sample, ...} で重複集約
    ips_hits: dict = {}

    def _record_ips(proto_name, src, dst, sp, dp, payload, ts):
        for sig in scan_ips_signatures(payload):
            key = (src, dst, dp, sig["sig_id"])
            entry = ips_hits.get(key)
            if entry is None:
                ips_hits[key] = {
                    "protocol": proto_name, "src": src, "dst": dst,
                    "src_port": sp, "dst_port": dp,
                    "sig_id": sig["sig_id"], "category": sig["category"],
                    "severity": sig["severity"], "matched": sig["matched"],
                    "cve": sig.get("cve", ""), "description": sig.get("description", ""),
                    "recommended_action": sig.get("recommended_action", ""),
                    "reference": sig.get("reference", ""),
                    "count": 1, "first_seen": _ts_str(ts),
                }
            else:
                entry["count"] += 1

    # DNSトンネリング検出用: ベースドメイン -> {queries, sub_lengths, qtypes, sample_subs, clients}
    dns_by_domain: dict[str, dict] = {}

    # ICMPエクスフィル検出用: echo(type 0/8)のペイロード収集
    icmp_echo_payloads: list = []

    def _record_unknown_hint(proto_name, src, dst, sp, dp, payload, ts):
        kw = _find_unknown_proto_keywords(payload)
        if not kw:
            return
        key = (proto_name, src, dst, sp, dp)
        entry = unknown_proto_hints.setdefault(key, {"count": 0, "keywords": set(), "sample": ""})
        entry["count"] += 1
        entry["keywords"].update(kw)
        if not entry["sample"]:
            entry["sample"] = payload[:120].decode("utf-8", errors="replace")

        for id_val in _extract_id_values(payload):
            idx = session_id_index.setdefault(id_val, {"count": 0, "flows": {}, "events": []})
            idx["count"] += 1
            fl = idx["flows"].setdefault(key, 0)
            idx["flows"][key] = fl + 1
            idx["events"].append({"ts": ts, "flow": key})

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
                        try:
                            gw_raw = icmp.data.gw
                            # dpkt parses Redirect.gw as an integer
                            if isinstance(gw_raw, int):
                                import struct as _struct
                                gw = socket.inet_ntoa(_struct.pack(">I", gw_raw))
                            else:
                                gw = _ip_str(gw_raw)
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
                    elif t in (0, 8):  # Echo Reply / Request → エクスフィル検査用にペイロード収集
                        try:
                            _icmp_pl = bytes(icmp.data.data) if hasattr(icmp.data, "data") else bytes(icmp.data)
                        except Exception:
                            _icmp_pl = b""
                        if _icmp_pl:
                            icmp_echo_payloads.append({
                                "ts": ts, "src": src, "dst": dst,
                                "type": "request" if t == 8 else "reply", "payload": _icmp_pl,
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
                        # 振る舞い検知: 横展開（同一ポートへ多数の宛先）とビーコニング
                        horiz_scan[(src, dport)].add(dst)
                        conn_times[(src, dst, dport)].append(ts)
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
                        outbound_bytes[(src, dst)] += data_len
                    if tcp.win == 0 and not is_syn and not is_rst:
                        zero_win_count[(src, dst, sport, dport)] += 1

                    # CTF flag{...}/Base64候補の検出（暗号化されたTLSポートは除く）
                    if data_len > 0 and not (sport in TLS_PORTS or dport in TLS_PORTS):
                        for _ctf_hit in scan_ctf_indicators(bytes(tcp.data)):
                            ctf_flag_hits.append({
                                "timestamp": _ts_str(ts), "protocol": "TCP",
                                "src": src, "dst": dst, "src_port": sport, "dst_port": dport,
                                **_ctf_hit,
                            })
                        # シグネチャ型IPS検査
                        _record_ips("TCP", src, dst, sport, dport, bytes(tcp.data), ts)

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
                                    if sni:
                                        tls_unique_sites.add(sni)
                                        _record_domain(sni, src, "TLS-SNI")
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

                    # ── プロトコル不明時: ID/session キーワード検索 ──
                    # HTTPレスポンス/TLS(暗号化)以外の平文ペイロードが対象。
                    if data_len > 0 and not (sport in TLS_PORTS or dport in TLS_PORTS):
                        try:
                            _is_http_resp = bytes(tcp.data[:5]) == b"HTTP/"
                        except Exception:
                            _is_http_resp = False
                        if not _is_http_resp:
                            _record_unknown_hint("TCP", src, dst, sport, dport, bytes(tcp.data), ts)

                # ── UDP ─────────────────────────────────
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data

                    # CTF flag{...}/Base64候補の検出（プロトコル種別によらず全UDPペイロード対象）
                    if udp.data:
                        for _ctf_hit in scan_ctf_indicators(bytes(udp.data)):
                            ctf_flag_hits.append({
                                "timestamp": _ts_str(ts), "protocol": "UDP",
                                "src": src, "dst": dst, "src_port": udp.sport, "dst_port": udp.dport,
                                **_ctf_hit,
                            })
                        # シグネチャ型IPS検査
                        _record_ips("UDP", src, dst, udp.sport, udp.dport, bytes(udp.data), ts)

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
                                _record_domain(q_name, src, "DNS")
                                # DNSトンネリング検出用にベースドメイン単位で集計
                                if q_name and "." in q_name:
                                    _labels = q_name.split(".")
                                    _base = ".".join(_labels[-2:]) if len(_labels) >= 2 else q_name
                                    _sub = ".".join(_labels[:-2]) if len(_labels) > 2 else ""
                                    _d = dns_by_domain.setdefault(_base, {
                                        "queries": 0, "sub_len_total": 0, "qtypes": set(),
                                        "sample_subs": [], "clients": set(), "max_sub_len": 0})
                                    _d["queries"] += 1
                                    _d["sub_len_total"] += len(_sub)
                                    _d["max_sub_len"] = max(_d["max_sub_len"], len(_sub))
                                    _d["qtypes"].add(q_type)
                                    _d["clients"].add(src)
                                    if _sub and len(_d["sample_subs"]) < 5:
                                        _d["sample_subs"].append(_sub[:60])
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

                    # ── プロトコル不明時: ID/session キーワード検索 ──
                    else:
                        _record_unknown_hint("UDP", src, dst, udp.sport, udp.dport, bytes(udp.data), ts)

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

    # 再送率サマリー（LLMが「問題あり/正常範囲内」を定量的に判断できるように）
    _total_retrans = sum(tcp_retrans_count.values())
    result["tcp_retrans_summary"] = {
        "total_retrans": _total_retrans,
        "flows_affected": len([c for c in tcp_retrans_count.values() if c >= 3]),
        "total_packets": result["total_packets"],
        "retrans_rate_pct": (round(_total_retrans / result["total_packets"] * 100, 3)
                             if result["total_packets"] else 0),
    }

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

    # ポートスキャン / DDoS(SYNフラッド) の兆候検出
    # ・ポートスキャン: 単一送信元IPが多数の異なる宛先ポートへSYNを送信
    # ・SYNフラッド/DDoS: 単一の宛先(IP:ポート)へ多数の送信元IPからSYN未応答が集中
    _scan_ports_by_src = {}
    for (src, dst, sp, dp) in syn_sent:
        _scan_ports_by_src.setdefault(src, set()).add(dp)
    for src, ports in _scan_ports_by_src.items():
        if len(ports) >= 8:
            result["scan_patterns"].append({
                "type": "port_scan",
                "severity": "high" if len(ports) >= 30 else "medium",
                "src": src,
                "detail": f"{src} から {len(ports)} 個の異なるポートへ接続要求 — ポートスキャンの可能性",
            })

    _flood_src_by_dst = {}
    for e in result["tcp_syn_no_synack"]:
        _flood_src_by_dst.setdefault((e["dst"], e["dst_port"]), set()).add(e["src"])
    for (dst, dp), srcs in _flood_src_by_dst.items():
        if len(srcs) >= 4:
            result["scan_patterns"].append({
                "type": "ddos_synflood",
                "severity": "high" if len(srcs) >= 10 else "medium",
                "dst": dst, "dst_port": dp,
                "detail": f"{dst}:{dp} へ {len(srcs)} 個の異なる送信元IPからSYNが集中し応答なし "
                          "— DDoS(分散SYNフラッド)の可能性",
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
        result["capture_duration_sec"] = round(max(timestamps) - min(timestamps), 1)

    if result["syslog_packets"]:
        try:
            from parsers import parse_syslog
            for pkt in result["syslog_packets"]:
                pkt["parsed"] = parse_syslog(pkt["raw"], pkt["src_ip"])
        except Exception: pass

    # プロトコル不明の通信（ID/sessionキーワード検出）
    for (proto, src, dst, sp, dp), info in unknown_proto_hints.items():
        kw_str = "/".join(info["keywords"])
        result["unknown_proto_hints"].append({
            "protocol": proto, "src": src, "dst": dst, "src_port": sp, "dst_port": dp,
            "count": info["count"], "keywords": kw_str, "sample": info["sample"],
            "description": f"プロトコル不明の通信に「{kw_str}」を含む語を検出 "
                            f"({info['count']}パケット) — 未対応の独自/セッション型プロトコルの可能性",
        })
    result["unknown_proto_hints"].sort(key=lambda x: x["count"], reverse=True)

    # 同一ID/session値が複数フローにまたがって出現していないかの突き合わせ
    # （1フロー内だけの出現は「その通信が持続している」だけなので対象外とし、
    #   複数フローにまたがる出現のみを「突き合わせ結果」として拾う）
    for id_val, info in session_id_index.items():
        flow_keys = list(info["flows"].keys())
        if len(flow_keys) < 2:
            continue
        distinct_src_ips = {fk[1] for fk in flow_keys}
        flows_list = [
            {"protocol": fk[0], "src": fk[1], "dst": fk[2], "src_port": fk[3], "dst_port": fk[4],
             "count": cnt}
            for fk, cnt in info["flows"].items()
        ]
        anomaly_multi_src = len(distinct_src_ips) > 1

        # 出現順（シーケンス）チェック: 時刻順に並べ、フロー間の遷移と間隔を追う
        events_sorted = sorted(info["events"], key=lambda e: e["ts"])
        timeline = []
        prev_ts = None
        for e in events_sorted:
            fk = e["flow"]
            gap_sec = round(e["ts"] - prev_ts, 3) if prev_ts is not None else None
            timeline.append({
                "timestamp": _ts_str(e["ts"]),
                "protocol": fk[0], "src": fk[1], "dst": fk[2],
                "src_port": fk[3], "dst_port": fk[4],
                "gap_sec": gap_sec,
            })
            prev_ts = e["ts"]
        gaps = [t["gap_sec"] for t in timeline if t["gap_sec"] is not None]
        max_gap_sec = max(gaps) if gaps else 0

        desc = (f"ID値「{id_val}」が{len(flow_keys)}個の異なる通信フローに"
                f"計{info['count']}回出現しています。")
        if anomaly_multi_src:
            desc += f"送信元IPが{len(distinct_src_ips)}種類にまたがっており、要確認です。"
        result["session_id_correlations"].append({
            "id_value": id_val,
            "total_occurrences": info["count"],
            "distinct_flows": len(flow_keys),
            "distinct_src_ips": len(distinct_src_ips),
            "anomaly_multi_src": anomaly_multi_src,
            "flows": flows_list,
            "timeline": timeline,
            "max_gap_sec": round(max_gap_sec, 3),
            "description": desc,
        })
    result["session_id_correlations"].sort(
        key=lambda x: (x["anomaly_multi_src"], x["total_occurrences"]), reverse=True)

    # CTF flag / Base64候補（重複排除: 同一フロー・種別・文字列は1件にまとめる）
    _seen_ctf = set()
    for h in ctf_flag_hits:
        _ckey = (h["src"], h["dst"], h["src_port"], h["dst_port"], h["type"], h["text"])
        if _ckey in _seen_ctf:
            continue
        _seen_ctf.add(_ckey)
        result["ctf_flag_hits"].append(h)
    result["ctf_flag_hits"].sort(key=lambda x: 0 if x["type"] == "flag_pattern" else 1)

    # ── DNSトンネリング/エクスフィルの兆候検出 ──
    # 同一ベースドメインへの大量クエリ＋長い/高エントロピーなサブドメイン、
    # あるいはTXT/NULL型の多用は、DNSトンネリングの典型的な兆候。
    for _base, _d in dns_by_domain.items():
        if _d["queries"] < 20:
            continue
        avg_sub = _d["sub_len_total"] / _d["queries"]
        _suspicious = avg_sub >= 20 or _d["max_sub_len"] >= 40 or \
            bool(_d["qtypes"] & {"TXT", "NULL", "CNAME"}) and avg_sub >= 10
        if _suspicious:
            result["dns_tunneling"].append({
                "domain": _base,
                "query_count": _d["queries"],
                "avg_subdomain_len": round(avg_sub, 1),
                "max_subdomain_len": _d["max_sub_len"],
                "qtypes": ",".join(sorted(_d["qtypes"])),
                "client_count": len(_d["clients"]),
                "sample_subdomains": _d["sample_subs"],
                "detail": f"ドメイン {_base} へ {_d['queries']}件のクエリ、"
                          f"平均サブドメイン長 {avg_sub:.0f}文字（最大{_d['max_sub_len']}）"
                          f"— DNSトンネリング/データ持ち出しの可能性",
            })
    result["dns_tunneling"].sort(key=lambda x: x["query_count"], reverse=True)

    # ── ICMPエクスフィル検出 ──
    # ping(echo)のペイロードに flag/Base64 やデコード可能なデータが含まれていれば
    # データ持ち出しの疑い。通常のping(連番バイトや固定パターン)は無視する。
    _icmp_pair_hits: dict = {}
    for e in icmp_echo_payloads:
        _hits = scan_ctf_indicators(e["payload"])
        _ml = multi_layer_decode(e["payload"])
        _has_data = bool(_hits) or bool(_ml.get("flag"))
        if _has_data:
            _key = (e["src"], e["dst"])
            _entry = _icmp_pair_hits.setdefault(_key, {
                "src": e["src"], "dst": e["dst"], "packet_count": 0,
                "findings": [], "sample": ""})
            _entry["packet_count"] += 1
            if not _entry["sample"]:
                _entry["sample"] = e["payload"][:80].decode("utf-8", errors="replace")
            for _h in _hits:
                if _h["text"] not in [f.get("text") for f in _entry["findings"]]:
                    _entry["findings"].append(_h)
            if _ml.get("flag") and _ml["flag"] not in [f.get("text") for f in _entry["findings"]]:
                _entry["findings"].append({"type": "flag_pattern", "text": _ml["flag"], "decoded": ""})
    for _entry in _icmp_pair_hits.values():
        _entry["detail"] = (f"{_entry['src']} → {_entry['dst']} のICMP echoペイロードに"
                            f"flag/エンコードデータを検出（{_entry['packet_count']}パケット）"
                            "— ICMPトンネリング/データ持ち出しの可能性")
        result["icmp_exfil"].append(_entry)
    result["icmp_exfil"].sort(key=lambda x: x["packet_count"], reverse=True)

    # ── シグネチャ型IPSアラート（重大度順にソート） ──
    _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    result["ips_alerts"] = sorted(
        ips_hits.values(),
        key=lambda x: (_sev_rank.get(x["severity"], 9), -x["count"]))

    # ── 振る舞い検知①: ワーム横展開/ラテラルムーブメント（横スキャン） ──
    # 1台の送信元が「同じ宛先ポート」へ多数の異なる宛先IPへ接続 = ワーム拡散の典型。
    # 既知のワーム/管理系ポート宛ては重大度を上げる（シグネチャ無しの新型ワームも捕捉）。
    _dur = result.get("capture_duration_sec", 0) or 0
    for (src, dport), dsts in horiz_scan.items():
        if len(dsts) >= 10:
            _worm_port = dport in _WORM_TARGET_PORTS
            _sev = "critical" if (_worm_port and len(dsts) >= 20) else "high" if _worm_port else "medium"
            _rate = f"（約{len(dsts)/_dur*60:.0f}宛先/分）" if _dur > 0 else ""
            _pname = _WORM_TARGET_PORTS.get(dport, "")
            result["worm_propagation"].append({
                "src": src, "dst_port": dport, "port_name": _pname,
                "distinct_dsts": len(dsts), "severity": _sev,
                "detail": f"{src} が ポート{dport}"
                          + (f"({_pname})" if _pname else "")
                          + f" へ {len(dsts)}個の異なる宛先に接続{_rate}"
                            " — ワーム横展開/ラテラルムーブメントの可能性",
            })
    result["worm_propagation"].sort(key=lambda x: x["distinct_dsts"], reverse=True)

    # ── 振る舞い検知②: ビーコニング（C2への定期コールバック） ──
    # 同一(src,dst,port)への接続が、ほぼ一定間隔で繰り返される = C2ビーコンの典型。
    # AI生成でシグネチャの無いマルウェアも「振る舞い」で捕捉できる。
    for (src, dst, dport), times in conn_times.items():
        if len(times) < 6:
            continue
        ts_sorted = sorted(times)
        intervals = [ts_sorted[i + 1] - ts_sorted[i] for i in range(len(ts_sorted) - 1)]
        intervals = [iv for iv in intervals if iv > 0.5]  # 高速連続(スキャン)は除外
        if len(intervals) < 5:
            continue
        mean_iv = sum(intervals) / len(intervals)
        if mean_iv <= 0:
            continue
        var = sum((iv - mean_iv) ** 2 for iv in intervals) / len(intervals)
        cv = (var ** 0.5) / mean_iv  # 変動係数。小さいほど「一定間隔」
        if cv <= 0.25:  # 間隔が非常に規則的
            result["beaconing"].append({
                "src": src, "dst": dst, "dst_port": dport,
                "count": len(ts_sorted), "interval_sec": round(mean_iv, 1),
                "regularity": round(1 - cv, 2),
                "detail": f"{src} → {dst}:{dport} へ 約{mean_iv:.0f}秒間隔で{len(ts_sorted)}回の"
                          "規則的な接続 — C2ビーコニング（マルウェアの定期通信）の可能性",
            })
    result["beaconing"].sort(key=lambda x: x["count"], reverse=True)

    # ── 振る舞い検知③: 配下端末→怪しい外部サイトへのアクセス ──
    # アクセス先ドメイン(DNS/TLS-SNI)から、コード共有/持ち出しサイト・DGAらしき
    # ランダムドメイン・悪用されやすいTLDを検出する（C2/持ち出しの兆候）。
    _tunnel_bases = {d["domain"] for d in result["dns_tunneling"]}  # 重複報告を避ける
    for _dom, _info in accessed_domains.items():
        _labels2 = _dom.split(".")
        _dom_base = ".".join(_labels2[-2:]) if len(_labels2) >= 2 else _dom
        if _dom_base in _tunnel_bases:
            continue  # DNSトンネリングとして別途報告済み
        _reason = ""
        _sev = "medium"
        if _SUSPICIOUS_HOST_RE.search(_dom):
            _reason = "コード共有/ファイル持ち出しに悪用されやすいサービス"
        elif _is_dga_like(_dom):
            _reason = "DGA(自動生成)らしい高エントロピーなドメイン"
            _sev = "high"
        elif _SUSPICIOUS_TLD_RE.search(_dom):
            _reason = "マルウェアに悪用されやすい無料/動的DNS・TLD"
        if _reason:
            result["suspicious_destinations"].append({
                "domain": _dom, "severity": _sev,
                "clients": sorted(_info["clients"])[:10], "client_count": len(_info["clients"]),
                "access_count": _info["count"], "via": ",".join(sorted(_info["via"])),
                "detail": f"配下端末({len(_info['clients'])}台) が {_dom} へアクセス — {_reason}",
            })
    _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    result["suspicious_destinations"].sort(
        key=lambda x: (_sev_rank.get(x["severity"], 9), -x["access_count"]))

    # ── 振る舞い検知④: 大容量の外部送信（データ持ち出し） ──
    # 単一の送信元→宛先で送信量が突出している場合、データ持ち出しの疑い。
    # ローカル同士は除外し、外部宛て(グローバルIP)のみを対象にする。
    for (src, dst), nbytes in outbound_bytes.items():
        if nbytes >= 1_000_000 and _is_private_ip(src) and not _is_private_ip(dst):
            result["data_exfil"].append({
                "src": src, "dst": dst, "bytes": nbytes, "mb": round(nbytes / 1_048_576, 1),
                "detail": f"{src} → {dst} へ {nbytes/1_048_576:.1f}MB を送信 "
                          "— 大容量データ持ち出しの可能性（外部宛て）",
            })
    result["data_exfil"].sort(key=lambda x: x["bytes"], reverse=True)

    # ── 振る舞い検知⑤: ホスト別リスクスコアリング ──
    # 個々の検知を送信元ホスト単位で束ね、重み付き合計で危険度(0-100)を算出する。
    # 「単一行動では安全でも、複数の怪しい挙動が重なると危険」を定量化する。
    _risk: dict = {}

    def _add_risk(host, points, factor):
        if not host:
            return
        r = _risk.setdefault(host, {"score": 0, "factors": []})
        r["score"] += points
        r["factors"].append(factor)

    for a in result["ips_alerts"]:
        _pts = {"critical": 40, "high": 25, "medium": 12, "low": 5}.get(a["severity"], 5)
        _add_risk(a["src"], _pts, f"IPS検知:{a['category']}")
    for wp in result["worm_propagation"]:
        _pts = {"critical": 35, "high": 25, "medium": 15}.get(wp["severity"], 15)
        _add_risk(wp["src"], _pts, "ワーム横展開")
    for b in result["beaconing"]:
        _add_risk(b["src"], 25, "C2ビーコニング")
    for sp_item in result.get("scan_patterns", []):
        if sp_item["type"] == "port_scan":
            _add_risk(sp_item.get("src"), 20, "ポートスキャン")
    for dt in result.get("dns_tunneling", []):
        # DNSトンネリングはクライアント側をリスク計上
        for _c in dns_by_domain.get(dt["domain"], {}).get("clients", []):
            _add_risk(_c, 25, "DNSトンネリング")
    for ie in result.get("icmp_exfil", []):
        _add_risk(ie["src"], 25, "ICMPエクスフィル")
    for sd in result["suspicious_destinations"]:
        _pts = 20 if sd["severity"] == "high" else 12
        for _c in sd["clients"]:
            _add_risk(_c, _pts, f"怪しい外部アクセス:{sd['domain']}")
    for de in result["data_exfil"]:
        _add_risk(de["src"], 25, "大容量外部送信")

    for host, r in _risk.items():
        score = min(100, r["score"])
        level = "重大" if score >= 70 else "高" if score >= 40 else "中" if score >= 20 else "低"
        # 複数種別の挙動が重なっているものを上位に（相関検知）
        _uniq_factors = list(dict.fromkeys(r["factors"]))
        result["host_risk"].append({
            "host": host, "risk_score": score, "risk_level": level,
            "factor_count": len(_uniq_factors), "factors": _uniq_factors,
        })
    result["host_risk"].sort(key=lambda x: x["risk_score"], reverse=True)

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


# ══════════════════════════════════════════════════════════════════
#  TCPストリーム再構成（Wiresharkの「Follow TCP Stream」相当）
#  CTF問題（ネットワークフォレンジック）でのファイル抽出・flag探索を想定。
# ══════════════════════════════════════════════════════════════════
def _reassemble_segments(segments: list) -> bytes:
    """(seq, payload)のリストをseq順に並べ替え・重複排除して連結する（簡易再構成）。"""
    if not segments:
        return b""
    segments = sorted(segments, key=lambda s: s[0])
    buf = bytearray()
    next_seq = None
    for seq, payload in segments:
        if next_seq is None:
            buf.extend(payload)
            next_seq = seq + len(payload)
            continue
        if seq >= next_seq:
            buf.extend(payload)
            next_seq = seq + len(payload)
        else:
            overlap = next_seq - seq
            if overlap < len(payload):
                buf.extend(payload[overlap:])
                next_seq = seq + len(payload)
    return bytes(buf)


def get_tcp_streams(data: bytes) -> list:
    """
    TCPストリームを方向別（client→server / server→client）に再構成する。
    シーケンス番号順の並べ替え・重複除去のみを行う簡易実装で、大きく順序が
    乱れたキャプチャでの完全な正確性は保証しない（CTF問題等の比較的単純な
    キャプチャでの利用を想定）。
    """
    try:
        reader, _ = _open_capture(data)
    except Exception:
        return []

    flows: dict = {}
    for ts, raw_pkt in reader:
        try:
            eth = dpkt.ethernet.Ethernet(raw_pkt)
        except Exception:
            continue
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue
        tcp = ip.data
        if not tcp.data:
            continue
        src, dst = _ip_str(ip.src), _ip_str(ip.dst)
        sport, dport = tcp.sport, tcp.dport

        if (src, sport) <= (dst, dport):
            ckey, is_c2s = (src, dst, sport, dport), True
        else:
            ckey, is_c2s = (dst, src, dport, sport), False

        f = flows.setdefault(ckey, {
            "src": ckey[0], "dst": ckey[1], "src_port": ckey[2], "dst_port": ckey[3],
            "c2s_segments": [], "s2c_segments": [], "packets": 0,
            "start_ts": ts, "end_ts": ts,
        })
        f["packets"] += 1
        f["start_ts"] = min(f["start_ts"], ts)
        f["end_ts"] = max(f["end_ts"], ts)
        (f["c2s_segments"] if is_c2s else f["s2c_segments"]).append((tcp.seq, bytes(tcp.data)))

    result = []
    for f in flows.values():
        c2s_bytes = _reassemble_segments(f["c2s_segments"])
        s2c_bytes = _reassemble_segments(f["s2c_segments"])
        if not c2s_bytes and not s2c_bytes:
            continue
        result.append({
            "src": f["src"], "dst": f["dst"], "src_port": f["src_port"], "dst_port": f["dst_port"],
            "packets": f["packets"],
            "start_ts": _ts_str(f["start_ts"]), "end_ts": _ts_str(f["end_ts"]),
            "client_to_server": c2s_bytes, "server_to_client": s2c_bytes,
            "c2s_bytes": len(c2s_bytes), "s2c_bytes": len(s2c_bytes),
        })
    result.sort(key=lambda x: x["c2s_bytes"] + x["s2c_bytes"], reverse=True)
    return result


# 既知のファイルシグネチャ(マジックバイト)。CTFのpcap問題で頻出する
# 「HTTP/FTP等の通信に隠されたファイル」の抽出（ファイルカービング）用。
_FILE_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"PK\x03\x04", "zip"),
    (b"%PDF-", "pdf"),
    (b"\x7fELF", "elf"),
    (b"Rar!\x1a\x07\x00", "rar"),
]


def find_embedded_files(stream_bytes: bytes) -> list:
    """
    再構成したTCPストリームから既知のファイルシグネチャを検出し、
    そこから次のシグネチャ出現位置（または末尾）までを候補として切り出す。
    正確なファイル長は保証しないベストエフォート実装（ファイルカービング）。
    """
    if not stream_bytes:
        return []
    hits = []
    for sig, ext in _FILE_SIGNATURES:
        start = 0
        while True:
            idx = stream_bytes.find(sig, start)
            if idx == -1:
                break
            hits.append({"offset": idx, "ext": ext})
            start = idx + len(sig)
    hits.sort(key=lambda h: h["offset"])
    files = []
    for i, h in enumerate(hits):
        end = hits[i + 1]["offset"] if i + 1 < len(hits) else len(stream_bytes)
        chunk = stream_bytes[h["offset"]:end]
        if len(chunk) < 8:
            continue
        files.append({"ext": h["ext"], "offset": h["offset"], "size": len(chunk), "data": chunk})
    return files


# ══════════════════════════════════════════════════════════════════
#  メール添付ファイルのウイルスチェック（SMTP/POP3/IMAP）
# ══════════════════════════════════════════════════════════════════
_MAIL_PORTS = {25, 587, 465, 110, 143, 993, 995}
_DANGEROUS_EXT_RE = __import__("re").compile(
    r"(?i)\.(exe|scr|pif|com|bat|cmd|js|jse|vbs|vbe|wsf|wsh|hta|jar|ps1|lnk|"
    r"dll|cpl|msi|reg|docm|xlsm|pptm|iso|img|ace)$")


def _extract_rfc822_messages(blob: bytes) -> list:
    """メールストリームから RFC822 メッセージ本体（ヘッダ+MIME）を抽出する。"""
    msgs = []
    # SMTP: DATA コマンド後～ \r\n.\r\n までが本文
    lo = 0
    while True:
        di = blob.find(b"\r\nDATA\r\n", lo)
        if di == -1:
            break
        start = di + len(b"\r\nDATA\r\n")
        end = blob.find(b"\r\n.\r\n", start)
        if end == -1:
            end = len(blob)
        msgs.append(blob[start:end])
        lo = end + 1
    if msgs:
        return msgs
    # SMTP以外(POP3/IMAP等): MIMEヘッダらしき箇所から末尾までを1通として扱う
    for marker in (b"MIME-Version:", b"Content-Type: multipart", b"Content-Type: text"):
        mi = blob.find(marker)
        if mi != -1:
            return [blob[mi:]]
    return []


def _check_attachment(filename: str, payload: bytes) -> list:
    """添付ファイルのマルウェア兆候を検査する（EICAR/実行ファイル/危険拡張子/マクロ/シグネチャ）。"""
    verdicts = []
    if _CTF_FLAG_RE and b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in payload:
        verdicts.append({"severity": "critical", "type": "EICAR",
                         "detail": "EICARテストウイルス文字列を検出（AV動作確認用の既知パターン）"})
    if payload[:2] == b"MZ":
        verdicts.append({"severity": "high", "type": "実行ファイル",
                         "detail": "Windows実行ファイル(PE/MZヘッダ)の添付を検出"})
    if payload[:4] == b"\x7fELF":
        verdicts.append({"severity": "high", "type": "実行ファイル",
                         "detail": "Linux実行ファイル(ELFヘッダ)の添付を検出"})
    if _DANGEROUS_EXT_RE.search(filename or ""):
        verdicts.append({"severity": "high", "type": "危険な拡張子",
                         "detail": f"危険な拡張子の添付ファイル: {filename}"})
    if b"vbaProject.bin" in payload or b"ActiveMime" in payload[:200]:
        verdicts.append({"severity": "high", "type": "マクロ",
                         "detail": "Officeマクロ(VBA)を含む添付ファイルの可能性"})
    if payload[:4] == b"PK\x03\x04" and _DANGEROUS_EXT_RE.search(
            payload[:4000].decode("latin-1", errors="ignore")):
        verdicts.append({"severity": "medium", "type": "圧縮内の実行ファイル",
                         "detail": "ZIP/書庫内に実行ファイル・スクリプトを含む可能性"})
    for sig in scan_ips_signatures(payload):
        verdicts.append({"severity": sig["severity"], "type": f"シグネチャ:{sig['category']}",
                         "detail": f"添付内容がシグネチャに一致: {sig['category']}"})
    return verdicts


def scan_email_attachments(data: bytes = b"", streams: list = None) -> list:
    """
    pcap内のメール通信(SMTP/POP3/IMAP)から添付ファイルを取り出し、
    「一旦開いて」中身をウイルスチェックする。
    streams（get_tcp_streamsの結果）を渡せば再解析を省略する。
    戻り値: 検知した添付の一覧（filename, verdicts[], size, flow）。
    """
    import email as _email_mod
    results = []
    if streams is None:
        try:
            streams = get_tcp_streams(data)
        except Exception:
            return results
    for s in streams:
        if s["dst_port"] not in _MAIL_PORTS and s["src_port"] not in _MAIL_PORTS:
            continue
        blob = s["client_to_server"] + b"\r\n" + s["server_to_client"]
        for raw_msg in _extract_rfc822_messages(blob):
            try:
                msg = _email_mod.message_from_bytes(raw_msg)
            except Exception:
                continue
            subject = str(msg.get("Subject", ""))[:120]
            for part in msg.walk():
                if part.is_multipart():
                    continue
                fname = part.get_filename()
                cdisp = part.get_content_disposition()
                if not fname and cdisp != "attachment":
                    continue
                try:
                    payload = part.get_payload(decode=True) or b""
                except Exception:
                    payload = b""
                if not payload:
                    continue
                verdicts = _check_attachment(fname or "(名前なし)", payload)
                if verdicts:
                    _worst = min(verdicts, key=lambda v: {"critical":0,"high":1,"medium":2,"low":3}.get(v["severity"],9))
                    results.append({
                        "filename": fname or "(名前なし)", "subject": subject,
                        "size": len(payload), "src": s["src"], "dst": s["dst"],
                        "dst_port": s["dst_port"], "severity": _worst["severity"],
                        "verdicts": verdicts, "data": payload,
                    })
    results.sort(key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x["severity"],9))
    return results


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
