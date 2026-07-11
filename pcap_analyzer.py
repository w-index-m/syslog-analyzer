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

import ai_service_domains as _ai_svc
import worm_target_ports as _worm_ports

# ══════════════════════════════════════════════════════════════════
#  アップロード自動解凍（zip/gzip でまとめられた pcap・syslog を展開）
# ══════════════════════════════════════════════════════════════════
_DECOMP_MAX = 200 * 1024 * 1024   # 解凍後サイズ上限（解凍爆弾対策）
_PCAP_MAGICS = (
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",   # pcap little/big endian
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",   # pcap ns
    b"\x0a\x0d\x0d\x0a",                          # pcapng
)


def _looks_like_pcap(data: bytes) -> bool:
    return bool(data) and any(data[:4] == m for m in _PCAP_MAGICS)


def _gunzip_bounded(data: bytes) -> bytes | None:
    """gzipを上限付きで解凍する（解凍爆弾対策）。失敗時 None。"""
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)   # gzipヘッダ対応
        out = d.decompress(data, _DECOMP_MAX + 1)
        if len(out) > _DECOMP_MAX:
            return None
        return out
    except Exception:
        return None


def decompress_upload(data: bytes, filename: str = "", prefer: str = "pcap") -> dict:
    """
    アップロードされたファイルが zip/gzip なら中身を取り出す。
    prefer="pcap" なら pcap/pcapng を、"log" なら syslog/テキストログを優先選択。
    戻り値: {"data", "name", "extracted"(bool), "source", "candidates":[名前...]}
    非圧縮ならそのまま返す（extracted=False）。
    """
    result = {"data": data, "name": filename, "extracted": False,
              "source": "", "candidates": []}
    if not data:
        return result
    name_l = (filename or "").lower()

    # ── gzip（単一ファイル。例: capture.pcap.gz / messages.log.gz） ──
    if data[:2] == b"\x1f\x8b" or name_l.endswith(".gz"):
        dec = _gunzip_bounded(data)
        if dec:
            inner = filename[:-3] if name_l.endswith(".gz") else (filename or "extracted")
            return {"data": dec, "name": inner or "extracted", "extracted": True,
                    "source": "gzip", "candidates": [inner]}

    # ── zip（複数ファイルから目的のものを選ぶ） ──
    if data[:4] == b"PK\x03\x04" or name_l.endswith(".zip"):
        import zipfile
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except Exception:
            return result
        members = [i for i in zf.infolist() if not i.is_dir()]
        result["candidates"] = [i.filename for i in members]
        if prefer == "pcap":
            want_ext = (".pcap", ".pcapng", ".cap")
        else:
            want_ext = (".log", ".txt", ".syslog", ".cfg", ".conf", ".out")

        def _read(info):
            if info.file_size > _DECOMP_MAX:
                return None
            try:
                with zf.open(info) as fp:
                    return fp.read(min(info.file_size + 1, _DECOMP_MAX))
            except Exception:
                return None

        # 1) 拡張子一致のうち最大サイズ、2) pcapはマジック一致、3) 単一メンバー
        cand = sorted([i for i in members if i.filename.lower().endswith(want_ext)],
                      key=lambda i: i.file_size, reverse=True)
        for info in cand:
            b = _read(info)
            if b is not None:
                return {"data": b, "name": info.filename, "extracted": True,
                        "source": "zip", "candidates": result["candidates"]}
        if prefer == "pcap":
            for info in sorted(members, key=lambda i: i.file_size, reverse=True):
                b = _read(info)
                if b is not None and _looks_like_pcap(b):
                    return {"data": b, "name": info.filename, "extracted": True,
                            "source": "zip", "candidates": result["candidates"]}
        if len(members) == 1:
            b = _read(members[0])
            if b is not None:
                return {"data": b, "name": members[0].filename, "extracted": True,
                        "source": "zip", "candidates": result["candidates"]}
    return result


# ── ポート定数 ──────────────────────────────────────────────────
SYSLOG_PORTS = {514, 5140, 5141, 516, 601}
RIP_PORT     = 520

# ワーム/ボットが横展開でよく狙うポート（振る舞い検知の重大度判定に使う。
# worm_target_ports.py でNetFlow解析と共用）
_WORM_TARGET_PORTS = _worm_ports.WORM_TARGET_PORTS

# マルウェアがコード保管/持ち出しに悪用しがちな公開サービス（配下端末が
# サーバ的にこれらへアクセスしていたら要確認 = GitPaste-12型/C2の兆候）。
_SUSPICIOUS_HOST_RE = __import__("re").compile(
    r"(?i)(pastebin\.com|hastebin\.com|ghostbin\.|controlc\.com|0x0\.st|ix\.io|"
    r"termbin\.com|transfer\.sh|anonfiles\.|file\.io|paste\.ee|"
    r"raw\.githubusercontent\.com|gist\.githubusercontent\.com)")

# マルウェアに悪用されやすい無料/動的DNS・TLD（誤検知を避けるため低〜中重大度）。
_SUSPICIOUS_TLD_RE = __import__("re").compile(
    r"(?i)\.(tk|ml|ga|cf|gq|top|xyz|duckdns\.org|no-ip\.\w+|ddns\.net|hopto\.org)$")

# 表示言語の自動判定用: 日本を含むアジア圏 ccTLD / 明確に非アジア圏の ccTLD。
# アクセス先ドメインの地域が「日本含むアジア圏中心」なら日本語、それ以外なら英語を既定にする。
_ASIAN_CCTLDS = {
    "jp", "cn", "kr", "tw", "hk", "mo", "sg", "th", "vn", "in", "id", "my",
    "ph", "kh", "la", "mm", "bn", "np", "lk", "bd", "pk", "mn",
}
_WESTERN_CCTLDS = {
    "uk", "de", "fr", "us", "ca", "au", "nz", "ru", "br", "es", "it", "nl",
    "se", "no", "fi", "pl", "ch", "at", "be", "dk", "ie", "pt", "mx", "ar",
}


def _tld_region(domain: str) -> str:
    """ドメインのccTLDから地域を判定する: 'asian' / 'western' / 'neutral'。"""
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return "neutral"
    tld = labels[-1]
    if tld in _ASIAN_CCTLDS:
        return "asian"
    if tld in _WESTERN_CCTLDS:
        return "western"
    return "neutral"  # com/net/org/io 等の汎用TLDは地域中立


DNS_PORT     = 53
DHCP_PORTS   = {67, 68}
TLS_PORTS    = {443, 8443, 465, 993, 995, 636, 5061}
MODBUS_PORT  = 502      # Modbus TCP（産業/OT制御系）
DNP3_PORT    = 20000    # DNP3（電力/水道等のSCADA）
QUIC_PORTS   = {443, 80}  # QUIC/HTTP3 は主にUDP 443

# Modbus 書き込み系ファンクションコード（不正な制御コマンドの可能性）
_MODBUS_WRITE_FC = {
    5: "単一コイル書込", 6: "単一レジスタ書込", 15: "複数コイル書込",
    16: "複数レジスタ書込", 22: "マスク書込", 23: "読み書き複数レジスタ",
}
_MODBUS_READ_FC = {1: "コイル読取", 2: "入力読取", 3: "保持レジスタ読取", 4: "入力レジスタ読取"}

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

# 既知の主要生成AI/LLMサービスの判定（ai_service_domains.py で共用）。
# TLS ClientHelloのSNI(暗号化されない接続先ホスト名)と照合し、「どのAIサービスと
# 通信しているか」を検知する（内容は暗号化されているため見えない。宛先の可視化のみ）。
_AI_SESSION_LONGLIVED_SEC = _ai_svc.AI_SESSION_LONGLIVED_SEC
_match_ai_service = _ai_svc.match_ai_service


# TLS CipherSuite ID -> (簡易名, 弱点)。既知の脆弱/非推奨な組み合わせのみ収録。
# （NULL暗号化・輸出グレード・RC4・DES・匿名鍵交換・静的RSA鍵交換(前方秘匿性なし)等）
_WEAK_CIPHER_SUITES = {
    0x0000: ("NULL_WITH_NULL_NULL", "暗号化なし"),
    0x0001: ("RSA_WITH_NULL_MD5", "暗号化なし＋MD5"),
    0x0002: ("RSA_WITH_NULL_SHA", "暗号化なし"),
    0x0003: ("RSA_EXPORT_WITH_RC4_40_MD5", "輸出グレード(40bit)＋RC4＋MD5"),
    0x0004: ("RSA_WITH_RC4_128_MD5", "RC4(既知の脆弱性)＋MD5"),
    0x0005: ("RSA_WITH_RC4_128_SHA", "RC4(既知の脆弱性)"),
    0x0006: ("RSA_EXPORT_WITH_RC2_CBC_40_MD5", "輸出グレード(40bit)"),
    0x0008: ("RSA_EXPORT_WITH_DES40_CBC_SHA", "輸出グレード(40bit)"),
    0x0009: ("RSA_WITH_DES_CBC_SHA", "DES(56bit・総当たり可能)"),
    0x000A: ("RSA_WITH_3DES_EDE_CBC_SHA", "静的RSA鍵交換(前方秘匿性なし)＋3DES(SWEET32)"),
    0x000C: ("DH_DSS_WITH_DES_CBC_SHA", "DES(56bit)"),
    0x000F: ("DH_RSA_WITH_DES_CBC_SHA", "DES(56bit)"),
    0x0012: ("DHE_DSS_WITH_DES_CBC_SHA", "DES(56bit)"),
    0x0015: ("DHE_RSA_WITH_DES_CBC_SHA", "DES(56bit)"),
    0x0017: ("DH_anon_EXPORT_WITH_RC4_40_MD5", "匿名鍵交換(中間者攻撃に脆弱)＋輸出グレード"),
    0x0018: ("DH_anon_WITH_RC4_128_MD5", "匿名鍵交換(中間者攻撃に脆弱)＋RC4"),
    0x0019: ("DH_anon_EXPORT_WITH_DES40_CBC_SHA", "匿名鍵交換(中間者攻撃に脆弱)＋輸出グレード"),
    0x001A: ("DH_anon_WITH_DES_CBC_SHA", "匿名鍵交換(中間者攻撃に脆弱)＋DES"),
    0x001B: ("DH_anon_WITH_3DES_EDE_CBC_SHA", "匿名鍵交換(中間者攻撃に脆弱)"),
    0x002F: ("RSA_WITH_AES_128_CBC_SHA", "静的RSA鍵交換(前方秘匿性なし)"),
    0x0035: ("RSA_WITH_AES_256_CBC_SHA", "静的RSA鍵交換(前方秘匿性なし)"),
    0x003C: ("RSA_WITH_AES_128_CBC_SHA256", "静的RSA鍵交換(前方秘匿性なし)"),
    0x003D: ("RSA_WITH_AES_256_CBC_SHA256", "静的RSA鍵交換(前方秘匿性なし)"),
    0x009C: ("RSA_WITH_AES_128_GCM_SHA256", "静的RSA鍵交換(前方秘匿性なし)"),
    0x009D: ("RSA_WITH_AES_256_GCM_SHA384", "静的RSA鍵交換(前方秘匿性なし)"),
    0xC001: ("ECDH_ECDSA_WITH_NULL_SHA", "暗号化なし"),
    0xC002: ("ECDH_ECDSA_WITH_RC4_128_SHA", "RC4(既知の脆弱性)"),
    0xC006: ("ECDHE_ECDSA_WITH_NULL_SHA", "暗号化なし"),
    0xC007: ("ECDHE_ECDSA_WITH_RC4_128_SHA", "RC4(既知の脆弱性)"),
    0xC00B: ("ECDH_RSA_WITH_NULL_SHA", "暗号化なし"),
    0xC00C: ("ECDH_RSA_WITH_RC4_128_SHA", "RC4(既知の脆弱性)"),
    0xC010: ("ECDHE_RSA_WITH_NULL_SHA", "暗号化なし"),
    0xC011: ("ECDHE_RSA_WITH_RC4_128_SHA", "RC4(既知の脆弱性)"),
    0xC012: ("ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "3DES(SWEET32攻撃に脆弱)"),
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
# Snort/Suricata から取り込んだシグネチャ（ips_rule_import.py が生成）。あればマージ。
_IPS_IMPORTED_PATH = _Path_ips(__file__).parent / "ips_signatures_imported.json"


def _load_signatures_from(path) -> list:
    sigs = []
    try:
        doc = _json_ips.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return sigs
    for s in doc.get("signatures", []):
        try:
            sigs.append({
                "id": s["id"], "cat": s["category"], "sev": s["severity"],
                "bin": bool(s.get("binary", False)),
                "re": re.compile(s["pattern"].encode("utf-8")),
                "cve": s.get("cve", ""), "desc": s.get("description", ""),
                "action": s.get("recommended_action", ""), "ref": s.get("reference", ""),
                "source": s.get("source", ""),
            })
        except Exception as e:
            print(f"[ips] 不正なシグネチャ {s.get('id')}: {e}")
    return sigs


def _load_ips_signatures(path=_IPS_SIGNATURES_PATH) -> list:
    """組み込みシグネチャ＋取り込みシグネチャ(あれば)をマージして返す。"""
    if not path.exists():
        print(f"[ips] シグネチャ定義が見つかりません: {path}")
        return []
    sigs = _load_signatures_from(path)
    if _IPS_IMPORTED_PATH.exists():
        _imported = _load_signatures_from(_IPS_IMPORTED_PATH)
        if _imported:
            print(f"[ips] 取り込みシグネチャ {len(_imported)}件をマージ")
            sigs += _imported
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


def _parse_tls_server_hello(payload: bytes) -> dict | None:
    """TLS ServerHello から合意された CipherSuite・バージョンを抽出する。"""
    try:
        if len(payload) < 6 or payload[0] != 22: return None  # Handshake record
        rec_ver = int.from_bytes(payload[1:3], "big")
        hs_data = payload[5:]
        if not hs_data or hs_data[0] != 2: return None  # ServerHello
        offset = 4 + 2 + 32  # handshake header + server_version + random
        if offset >= len(hs_data): return None
        sid_len = hs_data[offset]; offset += 1 + sid_len
        if offset + 2 > len(hs_data): return None
        cipher_suite = int.from_bytes(hs_data[offset:offset + 2], "big"); offset += 2
        offset += 1   # compression_method
        negotiated_ver = None
        if offset + 2 <= len(hs_data):
            ext_total = int.from_bytes(hs_data[offset:offset + 2], "big"); offset += 2
            ext_end = offset + ext_total
            while offset + 4 <= ext_end and offset + 4 <= len(hs_data):
                ext_type = int.from_bytes(hs_data[offset:offset + 2], "big")
                ext_len = int.from_bytes(hs_data[offset + 2:offset + 4], "big")
                offset += 4
                if ext_type == 43 and ext_len == 2 and offset + 2 <= len(hs_data):
                    v = int.from_bytes(hs_data[offset:offset + 2], "big")
                    if v in TLS_VERSIONS:
                        negotiated_ver = TLS_VERSIONS[v]
                offset += ext_len
        return {
            "cipher_suite": cipher_suite,
            "tls_version": negotiated_ver or TLS_VERSIONS.get(rec_ver, f"0x{rec_ver:04x}"),
        }
    except Exception:
        return None


def _parse_tls_certificate(payload: bytes) -> bytes | None:
    """TLS Certificateメッセージから最初(leaf)証明書のDERバイト列を取り出す。"""
    try:
        if len(payload) < 6 or payload[0] != 22: return None  # Handshake record
        hs_data = payload[5:]
        if not hs_data or hs_data[0] != 11: return None  # Certificate
        hs_len = int.from_bytes(hs_data[1:4], "big")
        body = hs_data[4:4 + hs_len]

        def _try(off):
            if off + 3 > len(body): return None
            p = off + 3
            if p + 3 > len(body): return None
            clen = int.from_bytes(body[p:p + 3], "big")
            p += 3
            cert = body[p:p + clen]
            return cert if cert[:1] == b"\x30" else None  # DER SEQUENCE tag

        cert = _try(0)                          # TLS 1.2形式
        if not cert and body:                    # TLS 1.3形式(context長を先頭に持つ)
            cert = _try(1 + body[0])
        return cert
    except Exception:
        return None


def analyze_tls_certificate(cert_der: bytes, sni: str = "") -> dict:
    """
    TLS証明書(DER)を検証する: 有効期限切れ・未来開始・自己署名・SNIとのCN/SAN不一致。
    戻り値: {"subject","issuer","not_before","not_after","expired","not_yet_valid",
             "self_signed","hostname_mismatch","sans","issues"}
    """
    out = {"subject": "", "issuer": "", "not_before": "", "not_after": "",
           "expired": False, "not_yet_valid": False, "self_signed": False,
           "hostname_mismatch": False, "sans": [], "issues": []}
    try:
        from cryptography import x509
        from datetime import datetime, timezone
    except Exception:
        out["issues"].append("cryptographyライブラリが利用できません")
        return out
    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as e:
        out["issues"].append(f"証明書の解析に失敗: {e}")
        return out
    try:
        out["subject"] = cert.subject.rfc4514_string()
        out["issuer"] = cert.issuer.rfc4514_string()
        try:
            nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
        except AttributeError:
            nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
            na = cert.not_valid_after.replace(tzinfo=timezone.utc)
        out["not_before"], out["not_after"] = nb.isoformat(), na.isoformat()
        now = datetime.now(timezone.utc)
        if now > na:
            out["expired"] = True
            out["issues"].append(f"有効期限切れ（{na.date()}まで）")
        if now < nb:
            out["not_yet_valid"] = True
            out["issues"].append(f"有効期間前（{nb.date()}から）")
        if cert.issuer == cert.subject:
            out["self_signed"] = True
            out["issues"].append("自己署名証明書（信頼された認証局の署名なし）")
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            out["sans"] = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass
        if sni:
            import fnmatch
            names = set(out["sans"])
            try:
                cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                if cn_attrs:
                    names.add(cn_attrs[0].value)
            except Exception:
                pass
            if names and not any(fnmatch.fnmatch(sni.lower(), n.lower()) for n in names):
                out["hostname_mismatch"] = True
                out["issues"].append(f"接続先ホスト名({sni})が証明書のCN/SAN"
                                     f"({', '.join(list(names)[:5])})と一致しません")
    except Exception as e:
        out["issues"].append(f"証明書検証中にエラー: {e}")
    return out


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


def _iter_tls_records(payload: bytes):
    """
    TCPペイロード内のTLSレコードを走査し (content_type, handshake_type, version, record_bytes) を返す。
    1パケットに複数レコードが載ることがあるためレコード境界で分割する。
    content_type: 20=ChangeCipherSpec,21=Alert,22=Handshake,23=ApplicationData
    handshake_type: 22のときのみ 1=ClientHello,2=ServerHello,11=Cert,12=SKE,
                    14=ServerHelloDone,16=ClientKeyExchange,20=Finished（暗号化後は不明）
    """
    off, n = 0, len(payload)
    while off + 5 <= n:
        ctype = payload[off]
        ver   = int.from_bytes(payload[off + 1:off + 3], "big")
        rlen  = int.from_bytes(payload[off + 3:off + 5], "big")
        if ctype not in (20, 21, 22, 23) or rlen == 0 or rlen > 0x4000:
            return  # TLSレコードとして不正 → 打ち切り
        hs_type = None
        if ctype == 22 and off + 5 < n:
            hs_type = payload[off + 5]
        yield (ctype, hs_type, ver, payload[off:off + 5 + rlen])
        off += 5 + rlen


# OSPF Hello パケットの認証タイプ（RFC2328）
_OSPF_AUTH_TYPES = {0: "認証なし", 1: "簡易パスワード", 2: "MD5等(暗号学的認証)"}


def _parse_ospf_hello(data: bytes) -> dict | None:
    """
    OSPF Helloパケットをパースする。ヘッダ(24B, dpktでは基本情報のみ)以降の
    Hello専用フィールド(network mask/hello interval/dead interval/area等)を
    自前で解釈する。認証の有無に関わらずタイマー値自体は平文。
    戻り値: {"router_id","area","hello_interval","dead_interval","auth_type","priority"}
    """
    try:
        if len(data) < 24 or data[1] != 1:   # type=1 = Hello
            return None
        router_id = socket.inet_ntoa(data[4:8])
        area = socket.inet_ntoa(data[8:12])
        auth_type = int.from_bytes(data[14:16], "big")
        body = data[24:]
        if len(body) < 20:
            return None
        hello_interval = int.from_bytes(body[4:6], "big")
        priority = body[6]
        dead_interval = int.from_bytes(body[8:12], "big")
        return {"router_id": router_id, "area": area,
                "hello_interval": hello_interval, "dead_interval": dead_interval,
                "auth_type": _OSPF_AUTH_TYPES.get(auth_type, f"type={auth_type}"),
                "priority": priority}
    except Exception:
        return None


def _parse_ike_header(payload: bytes, on_4500: bool) -> dict | None:
    """
    ISAKMP/IKE ヘッダ(28バイト)をパースする。NAT-T(4500)は先頭4バイトの
    non-ESPマーカー(0x00000000)を剥がす。ESP(4500上の暗号化データ)は None。
    戻り値: {"ispi","rspi","version"(1/2),"exchange","flags","msgid",
             "is_response","is_initiator","next_payload","body"}
    body は最初のペイロード(通常SA)から始まるヘッダ以降のバイト列。
    """
    try:
        p = payload
        if on_4500:
            if len(p) >= 4 and p[:4] == b"\x00\x00\x00\x00":
                p = p[4:]              # non-ESP marker → 後続がISAKMP
            else:
                return None            # 先頭がSPI(非ゼロ) = ESPデータ
        if len(p) < 28:
            return None
        ispi = p[0:8]; rspi = p[8:16]
        next_payload = p[16]
        version = p[17]
        major = (version >> 4) & 0xF   # 1=IKEv1, 2=IKEv2
        if major not in (1, 2):
            return None
        exch = p[18]
        flags = p[19]
        msgid = int.from_bytes(p[20:24], "big")
        length = int.from_bytes(p[24:28], "big")
        if length < 28 or length > 0x100000:
            return None
        if major == 2:
            is_response  = bool(flags & 0x20)   # IKEv2 Response bit
            is_initiator = bool(flags & 0x08)   # IKEv2 Initiator bit
        else:
            # IKEv1 はフラグに応答ビットが無い（方向はメッセージ流で判断）
            is_response = False
            is_initiator = (rspi == b"\x00\x00\x00\x00\x00\x00\x00\x00")
        return {"ispi": ispi.hex(), "rspi": rspi.hex(), "version": major,
                "exchange": exch, "flags": flags, "msgid": msgid,
                "is_response": is_response, "is_initiator": is_initiator,
                "next_payload": next_payload, "body": p[28:]}
    except Exception:
        return None


# IKE 交換タイプ名（v1/v2）
_IKEV1_EXCH = {2: "Main Mode(ID保護)", 4: "Aggressive Mode", 5: "Informational",
               6: "Transaction", 32: "Quick Mode(Phase2)"}
_IKEV2_EXCH = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA",
               37: "INFORMATIONAL"}

# ── IKE SA(鍵交換)ペイロードの暗号アルゴリズム/DHグループ判定 ──
_IKEV1_ATTR_ENC  = {1: "DES", 2: "IDEA", 3: "Blowfish", 4: "RC5", 5: "3DES", 6: "CAST", 7: "AES-CBC"}
_IKEV1_ATTR_HASH = {1: "MD5", 2: "SHA1", 3: "Tiger", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512"}
_IKEV1_ATTR_AUTH = {1: "事前共有鍵(PSK)", 2: "DSS署名", 3: "RSA署名", 4: "RSA暗号化",
                    5: "改訂RSA暗号化", 64221: "Hybrid", 65001: "XAUTH"}
_DH_GROUPS = {1: "768bit MODP", 2: "1024bit MODP", 5: "1536bit MODP", 14: "2048bit MODP",
              15: "3072bit MODP", 16: "4096bit MODP", 19: "256bit ECP", 20: "384bit ECP",
              21: "521bit ECP", 24: "2048bit MODP(POS256)", 28: "256bit Brainpool",
              29: "384bit Brainpool", 30: "512bit Brainpool"}
_WEAK_DH_GROUPS = {1, 2, 5}   # 1536bit以下は現代基準で脆弱（総当たり/実績のある攻撃あり）
_IKEV2_ENCR = {1: "DES-IV64", 2: "DES", 3: "3DES", 5: "CAST", 6: "Blowfish", 7: "AES-CBC",
               11: "NULL", 12: "AES-CTR", 13: "AES-CCM8", 18: "AES-GCM16", 19: "AES-GCM12",
               20: "AES-GCM8", 23: "ChaCha20-Poly1305"}
_WEAK_IKEV2_ENCR = {1, 2, 3, 11}   # DES系(56bit)・3DES(SWEET32)・NULL(暗号化なし)


def _parse_ike_sa_payload(sa_body: bytes, version: int) -> dict:
    """
    IKE SA(Security Association)ペイロード本体の最初のProposal/Transformから
    暗号アルゴリズム・DHグループ・(IKEv1のみ)認証方式を抽出する(ベストエフォート)。
    戻り値: {"encr","dh_group","auth_method","weak":[...]}
    """
    out = {"encr": None, "dh_group": None, "auth_method": None, "weak": []}
    try:
        body = sa_body[8:] if version == 1 else sa_body   # v1: DOI(4)+Situation(4)をスキップ
        if len(body) < 8:
            return out
        proto_id, spi_size, num_tf = body[5], body[6], body[7]
        off = 8 + spi_size
        for _ in range(num_tf):
            if off + 8 > len(body):
                break
            t_len = int.from_bytes(body[off + 2:off + 4], "big")
            if t_len < 8 or off + t_len > len(body):
                break
            if version == 2:
                t_type, t_id = body[off + 4], int.from_bytes(body[off + 6:off + 8], "big")
                if t_type == 1:
                    out["encr"] = _IKEV2_ENCR.get(t_id, f"ID{t_id}")
                    if t_id in _WEAK_IKEV2_ENCR:
                        out["weak"].append(f"暗号化アルゴリズムが脆弱({out['encr']})")
                elif t_type == 4:
                    out["dh_group"] = _DH_GROUPS.get(t_id, f"Group{t_id}")
                    if t_id in _WEAK_DH_GROUPS:
                        out["weak"].append(f"DHグループが脆弱({out['dh_group']})")
            else:
                attr_off, attr_end = off + 8, off + t_len
                while attr_off + 4 <= attr_end and attr_off + 4 <= len(body):
                    a_type_raw = int.from_bytes(body[attr_off:attr_off + 2], "big")
                    is_tv = bool(a_type_raw & 0x8000)
                    a_type = a_type_raw & 0x7FFF
                    if is_tv:
                        a_val = int.from_bytes(body[attr_off + 2:attr_off + 4], "big")
                        attr_off += 4
                    else:
                        a_len = int.from_bytes(body[attr_off + 2:attr_off + 4], "big")
                        a_val_bytes = body[attr_off + 4:attr_off + 4 + a_len]
                        a_val = int.from_bytes(a_val_bytes, "big") if a_val_bytes else 0
                        attr_off += 4 + a_len
                    if a_type == 1:
                        out["encr"] = _IKEV1_ATTR_ENC.get(a_val, f"ID{a_val}")
                        if a_val in (1, 2, 3):
                            out["weak"].append(f"暗号化アルゴリズムが脆弱({out['encr']})")
                    elif a_type == 2 and a_val == 1:
                        out["weak"].append("ハッシュがMD5(脆弱)")
                    elif a_type == 3:
                        out["auth_method"] = _IKEV1_ATTR_AUTH.get(a_val, f"ID{a_val}")
                    elif a_type == 4:
                        out["dh_group"] = _DH_GROUPS.get(a_val, f"Group{a_val}")
                        if a_val in _WEAK_DH_GROUPS:
                            out["weak"].append(f"DHグループが脆弱({out['dh_group']})")
            off += t_len
    except Exception:
        pass
    return out


def _find_ike_sa_body(body: bytes, first_type: int, version: int) -> bytes | None:
    """ISAKMPヘッダ直後のペイロード連鎖からSA(v1:1 / v2:33)ペイロード本体を探す。"""
    sa_type = 1 if version == 1 else 33
    off, cur = 0, first_type
    try:
        while cur != 0 and off + 4 <= len(body):
            nxt = body[off]
            p_len = int.from_bytes(body[off + 2:off + 4], "big")
            if p_len < 4 or off + p_len > len(body):
                return None
            if cur == sa_type:
                return body[off + 4:off + p_len]
            off += p_len
            cur = nxt
    except Exception:
        return None
    return None


# IKE Notify/Notification のエラーコード（v1: RFC2408, v2: RFC7296）。
# 番号の意味はv1/v2でほぼ共通（提案不一致・認証失敗など、トラブルシュートで
# 最も知りたい「なぜ鍵交換が失敗したか」を機器が明示的に伝えてくる値）。
# label=表示名、remedy=対処、verify=確認コマンド（Cisco/Junosの代表例）。
_IKE_NOTIFY_ERRORS = {
    1: {"label": "UNSUPPORTED_CRITICAL_PAYLOAD（未対応の必須ペイロード）",
        "remedy": "対向機器のIKE実装/バージョンの互換性を確認してください。",
        "verify": "show crypto ikev2 sa detail（Cisco）／show security ike security-associations detail（Junos）"},
    4: {"label": "INVALID_IKE_SPI（SPI不正）",
        "remedy": "SA状態の食い違いです。片側のSAをクリアして再ネゴシエーションさせてください。",
        "verify": "clear crypto isakmp / clear crypto ikev2 sa（Cisco）"},
    5: {"label": "INVALID_MAJOR_VERSION（IKEバージョン不一致）",
        "remedy": "片方がIKEv1(ISAKMP)、他方がIKEv2で待ち受けています。双方のIKEバージョン設定"
                  "（crypto map系=v1 / crypto ikev2 profile系=v2）を揃えてください。",
        "verify": "show crypto isakmp sa と show crypto ikev2 sa の両方を確認し、"
                  "どちらで応答が来ているか切り分けてください（Cisco）／"
                  "show security ike security-associations（Junos, version列を確認）"},
    7: {"label": "INVALID_SYNTAX（メッセージ構文不正）",
        "remedy": "IKEメッセージの構文/SPIが不正です。双方の実装バージョンの相性・"
                  "既知バグ（ソフトウェアの既知不具合）を確認してください。",
        "verify": "debug crypto ikev2 packet（Cisco）／show log kmd（Junos）で実際のメッセージ内容を確認"},
    9: {"label": "INVALID_MESSAGE_ID", "remedy": "メッセージ順序の不整合です。SAをクリアして再試行してください。",
        "verify": "clear crypto ikev2 sa（Cisco）"},
    11: {"label": "INVALID_SPI", "remedy": "SPI不整合です。片側のSAが残存している可能性があるためクリアしてください。",
         "verify": "show crypto ikev2 sa（Cisco）／show security ike security-associations（Junos）"},
    13: {"label": "ATTRIBUTES_NOT_SUPPORTED（提案した属性が未対応）",
         "remedy": "提案した暗号/DHグループ等の属性を対向がサポートしていません。"
                   "policy/proposalの組み合わせを対向の対応範囲に合わせてください。",
         "verify": "show crypto ikev2 proposal（Cisco）／show security ike proposal <name>（Junos）"},
    14: {"label": "NO_PROPOSAL_CHOSEN（提案する暗号スイート/DHグループ/認証方式が双方で一致しない）",
         "remedy": "双方のIKEポリシー（暗号アルゴリズム・ハッシュ・DHグループ・認証方式）を"
                   "完全一致させてください（1項目でも不一致だと拒否されます）。",
         "verify": "show crypto isakmp policy／show crypto ikev2 proposal（Cisco）／"
                   "show security ike proposal <name>（Junos）"},
    15: {"label": "BAD_PROPOSAL_SYNTAX", "remedy": "提案(Proposal)の構文が不正です。設定の再投入を検討してください。",
         "verify": "show crypto ikev2 proposal（Cisco）"},
    17: {"label": "INVALID_KE_PAYLOAD（DHグループ不一致）",
         "remedy": "Diffie-HellmanグループNo.を双方で一致させてください（例: 双方group14に統一）。",
         "verify": "show crypto ikev2 proposal（Cisco）／show security ike proposal <name>（Junos, dh-groupを確認）"},
    18: {"label": "INVALID_ID_INFORMATION（ID不一致）",
         "remedy": "IKE ID（IPアドレス/FQDN/DN等）の設定を対向と一致させてください。",
         "verify": "show crypto isakmp sa detail（Cisco）／show security ike security-associations detail（Junos）"},
    24: {"label": "AUTHENTICATION_FAILED（認証失敗：事前共有鍵(PSK)または証明書が不一致）",
         "remedy": "事前共有鍵(PSK)を双方で再設定・再確認してください（1文字でも不一致で失敗します）。"
                   "証明書利用時は有効期限・CA信頼チェーン・サブジェクト名を確認してください。",
         "verify": "PSKは表示されないため再設定して突き合わせるのが確実です。"
                   "証明書は show crypto pki certificates（Cisco）／"
                   "show security pki local-certificate detail（Junos）で有効期限を確認"},
    34: {"label": "SINGLE_PAIR_REQUIRED", "remedy": "トラフィックセレクタを1対1(単一サブネットペア)に絞ってください。",
         "verify": "show crypto ipsec sa（Cisco）"},
    35: {"label": "NO_ADDITIONAL_SAS", "remedy": "追加SA数の上限に達しています。不要なSAを削除してください。",
         "verify": "show crypto ikev2 sa（Cisco）"},
    36: {"label": "INTERNAL_ADDRESS_FAILURE", "remedy": "内部アドレス割当(Config Payload)に失敗しています。アドレスプールを確認してください。",
         "verify": "show crypto ikev2 client（Cisco）"},
    38: {"label": "TS_UNACCEPTABLE（トラフィックセレクタ/Proxy IDのサブネット不一致）",
         "remedy": "Phase2で許可する送信元/宛先サブネット（ACL/トラフィックセレクタ）の範囲を"
                   "対向と完全に一致させてください。",
         "verify": "show crypto ipsec sa（Cisco, local/remote ident網掛け部を確認）／"
                   "show security ipsec security-associations detail（Junos, local/remote selector確認）"},
    43: {"label": "TEMPORARY_FAILURE（一時的な失敗：リソース枯渇等）",
         "remedy": "機器のリソース逼迫が疑われます。CPU/メモリ使用率と同時接続SA数を確認してください。",
         "verify": "show processes cpu／show crypto ikev2 sa summary（Cisco）"},
    44: {"label": "CHILD_SA_NOT_FOUND", "remedy": "参照先のChild SAが既に削除されています。再ネゴシエーションで解消することが多いです。",
         "verify": "show crypto ikev2 sa（Cisco）"},
}


def _find_ike_notify_error(body: bytes, first_type: int, version: int) -> dict | None:
    """
    ISAKMPヘッダ直後のペイロード連鎖からNotify/Notification(v1:11 / v2:41)を探し、
    エラーコードがあれば{"label","remedy","verify"}を返す
    （成功時の情報Notifyや未知コードはNoneのまま無視）。
    """
    notify_type = 11 if version == 1 else 41
    off, cur = 0, first_type
    try:
        while cur != 0 and off + 4 <= len(body):
            nxt = body[off]
            p_len = int.from_bytes(body[off + 2:off + 4], "big")
            if p_len < 4 or off + p_len > len(body):
                return None
            if cur == notify_type:
                nbody = body[off + 4:off + p_len]
                if version == 2 and len(nbody) >= 4:
                    code = int.from_bytes(nbody[2:4], "big")
                elif version == 1 and len(nbody) >= 8:
                    code = int.from_bytes(nbody[6:8], "big")
                else:
                    code = None
                return _IKE_NOTIFY_ERRORS.get(code)
            off += p_len
            cur = nxt
    except Exception:
        return None
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
        "tcp_receiver_pressure": [], "tcp_path_congestion": [],
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
        "suggested_lang": "ja",
        "region_hint": {},
        "threat_intel_hits": [],
        "industrial_alerts": [], "industrial_summary": {},
        "quic_sessions": [],
        "geo_alerts": [], "geo_summary": {},
        "ssh_handshakes": [],
        "ospf_issues": [],
        "ip_fragments": [],
        "http_errors": [],    "http_summary": {},
        "tls_sessions": [],   "tls_alerts": [],
        "ai_service_sessions": [],
        "tls_summary": {"sessions": 0, "unique_sites": 0, "fatal_alerts": 0,
                        "deprecated_tls": 0},
        "tls_handshakes": [], "tls_handshake_summary": {},
        "ipsec": {"ike_sas": [], "esp_flows": [], "summary": {}, "known_issues": []},
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
    # TCPウィンドウ制御の原因切り分け用
    # rwnd(受信ウィンドウ)の縮小トレンド: 受信側NIC/CPU/アプリの処理遅延を示す早期兆候
    # （0に達する前の"じわじわ縮小"を捉える。scale係数は接続内で一定のため比率比較で十分）
    win_trend: dict[tuple, dict] = {}
    # 重複ACKバースト: 経路上のパケットロス/再送(cwnd自主規制)を示す兆候
    dup_ack: dict[tuple, dict] = {}
    # 振る舞い検知用
    horiz_scan: dict[tuple, set]     = defaultdict(set)   # (src, dport) -> {dst,...} 横展開/ラテラルムーブメント
    conn_times: dict[tuple, list]    = defaultdict(list)  # (src, dst, dport) -> [ts,...] ビーコニング
    accessed_domains: dict[str, dict] = {}               # domain -> {clients:set, count, via:set} アクセス先ドメイン
    outbound_bytes: dict[tuple, int] = defaultdict(int)  # (src, dst) -> 送信バイト数 大容量エクスフィル用
    modbus_ops: dict[tuple, dict] = {}                   # (src,dst) -> {read, write, write_fc:set}
    quic_conns: dict[tuple, dict] = {}                   # (src,dst) -> {count, versions:set, initial:bool}
    # GeoIP: 監視対象国(CN/KP/HK/MO)の外部IP出現を集約
    # ip -> {"as_src": bool, "as_dst": bool, "peers": set, "packets": int}
    geo_seen: dict[str, dict] = {}

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
    # TLSフローの継続時間追跡（AIサービス宛の長時間接続＝張りっぱなし検知用）
    tls_flow_duration: dict[tuple, dict] = {}
    # TLSハンドシェイク状態: ck -> {client_hello,server_hello,cert,server_ccs,
    #   client_ccs,app_data,fatal_alert,alert_desc,sni,version,client,server,port,ts}
    tls_hs: dict[tuple, dict] = {}
    # IPsec: IKE SA(初期化SPI) -> 状態 / ESP・AHフロー
    ike_sas: dict[str, dict] = {}
    esp_flows: dict[tuple, dict] = {}   # (src,dst) -> {"proto","count"}
    # OSPF: router_id -> {area, hello_interval, dead_interval, auth_type, priority, ts}
    ospf_routers: dict[str, dict] = {}

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

                # GeoIP: 外部（非プライベート）IPを送信元・宛先別に記録
                if not _is_private_ip(src):
                    _g = geo_seen.setdefault(src, {"as_src": False, "as_dst": False,
                                                   "peers": set(), "packets": 0})
                    _g["as_src"] = True; _g["packets"] += 1; _g["peers"].add(dst)
                if not _is_private_ip(dst):
                    _g = geo_seen.setdefault(dst, {"as_src": False, "as_dst": False,
                                                   "peers": set(), "packets": 0})
                    _g["as_dst"] = True; _g["packets"] += 1; _g["peers"].add(src)

                # IP フラグメント検出
                is_mf      = bool(ip.off & dpkt.ip.IP_MF)
                frag_offset = ip.off & dpkt.ip.IP_OFFMASK  # 8-byte units
                if is_mf or frag_offset > 0:
                    ip_frag_count[(src, dst, ip.p)] += 1

                # ── IPsec ESP(50)/AH(51): トンネル確立後の暗号化通信 ──
                if ip.p in (50, 51):
                    _ek = (src, dst)
                    _ef = esp_flows.setdefault(_ek, {"proto": "ESP" if ip.p == 50 else "AH",
                                                     "count": 0, "first_ts": ts, "last_ts": ts})
                    _ef["count"] += 1
                    _ef["last_ts"] = ts

                # ── OSPF(89): Hello間隔/エリア/認証方式の不一致検知 ──
                # （Helloのタイマー値・エリアIDは認証有無に関わらず平文で読める）
                if ip.p == 89:
                    try:
                        _oh = _parse_ospf_hello(bytes(ip.data))
                    except Exception:
                        _oh = None
                    if _oh:
                        ospf_routers[_oh["router_id"]] = {**_oh, "ts": _ts_str(ts)}

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

                    # ── rwnd(受信ウィンドウ)縮小トレンド: 受信側NIC/CPU逼迫の早期兆候 ──
                    # (0に達する前の"じわじわ縮小"。scale係数は接続内で一定なので比率で比較)
                    if not is_syn and not is_rst:
                        _wk = (src, dst, sport, dport)
                        _wt = win_trend.setdefault(_wk, {"first_win": tcp.win, "min_win": tcp.win,
                                                         "samples": 0, "low_count": 0})
                        _wt["samples"] += 1
                        if tcp.win < _wt["min_win"]:
                            _wt["min_win"] = tcp.win
                        if _wt["first_win"] > 500 and tcp.win < _wt["first_win"] * 0.2:
                            _wt["low_count"] += 1

                    # ── 重複ACKバースト: 経路上のパケットロス/再送(cwnd自主規制)の兆候 ──
                    if is_ack and data_len == 0 and not is_syn and not is_rst:
                        _dk = (src, dst, sport, dport)
                        _da = dup_ack.setdefault(_dk, {"last_ack": None, "run": 0, "bursts": 0})
                        if _da["last_ack"] == tcp.ack:
                            _da["run"] += 1
                            if _da["run"] == 3:   # 3重複ACK = fast retransmitトリガー相当
                                _da["bursts"] += 1
                        else:
                            _da["last_ack"] = tcp.ack
                            _da["run"] = 0

                    # ── 産業プロトコル: Modbus TCP（ポート502） ──
                    if data_len >= 8 and (dport == MODBUS_PORT or sport == MODBUS_PORT):
                        try:
                            _mb = bytes(tcp.data)
                            _proto_id = struct.unpack("!H", _mb[2:4])[0]
                            _fc = _mb[7]  # MBAP(7バイト) の次がファンクションコード
                            if _proto_id == 0 and (_fc in _MODBUS_READ_FC or _fc in _MODBUS_WRITE_FC):
                                _mk = (src, dst)
                                _e = modbus_ops.setdefault(_mk, {"read": 0, "write": 0, "write_fc": set()})
                                if _fc in _MODBUS_WRITE_FC:
                                    _e["write"] += 1
                                    _e["write_fc"].add(_MODBUS_WRITE_FC[_fc])
                                else:
                                    _e["read"] += 1
                        except Exception:
                            pass

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

                            # 継続時間追跡（長時間接続＝張りっぱなし検知用）
                            _dur = tls_flow_duration.setdefault(ck, {
                                "first_ts": ts, "last_ts": ts, "bytes": 0, "packets": 0})
                            _dur["last_ts"]  = ts
                            _dur["bytes"]   += len(payload_b)
                            _dur["packets"] += 1

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

                            # ── TLSハンドシェイク(鍵交換)の成否追跡 ──
                            _hs = tls_hs.setdefault(ck, {
                                "client": src if dport in TLS_PORTS else dst,
                                "server": dst if dport in TLS_PORTS else src,
                                "port":   dport if dport in TLS_PORTS else sport,
                                "client_hello": False, "server_hello": False, "cert": False,
                                "server_ccs": False, "client_ccs": False, "app_data": False,
                                "fatal_alert": False, "alert_desc": "", "version": "", "ts": _ts_str(ts),
                                "cipher_suite": None, "cert_der": None})
                            _to_server = dport in TLS_PORTS   # クライアント→サーバ方向か
                            for _ct, _ht, _rv, _rec in _iter_tls_records(payload_b):
                                if _ct == 22 and _ht == 1:
                                    _hs["client_hello"] = True
                                elif _ct == 22 and _ht == 2:
                                    _hs["server_hello"] = True
                                    if _rv in TLS_VERSIONS:
                                        _hs["version"] = TLS_VERSIONS[_rv]
                                    _sh = _parse_tls_server_hello(_rec)
                                    if _sh:
                                        _hs["cipher_suite"] = _sh["cipher_suite"]
                                elif _ct == 22 and _ht == 11:
                                    _hs["cert"] = True
                                    if _hs["cert_der"] is None:
                                        _cder = _parse_tls_certificate(_rec)
                                        if _cder:
                                            _hs["cert_der"] = _cder
                                elif _ct == 20:   # ChangeCipherSpec
                                    if _to_server:
                                        _hs["client_ccs"] = True
                                    else:
                                        _hs["server_ccs"] = True
                                elif _ct == 23:   # ApplicationData（暗号化完了後）
                                    _hs["app_data"] = True
                                elif _ct == 21 and alert and alert["level"] == "fatal":
                                    _hs["fatal_alert"] = True
                                    _hs["alert_desc"] = alert["desc"]
                            if ch and ch.get("sni"):
                                _hs["sni"] = ch["sni"]

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

                    # ── IPsec IKE(鍵交換): UDP 500 / 4500(NAT-T) ──
                    if udp.dport in (500, 4500) or udp.sport in (500, 4500):
                        _ikp = _parse_ike_header(bytes(udp.data),
                                                 on_4500=(udp.dport == 4500 or udp.sport == 4500))
                        if _ikp:
                            _sa = ike_sas.setdefault(_ikp["ispi"], {
                                "version": _ikp["version"], "initiator": src, "responder": dst,
                                "exchanges": set(), "v2_init_req": False, "v2_init_resp": False,
                                "v2_auth_req": False, "v2_auth_resp": False,
                                "v1_quick": 0, "v1_phase1": 0, "informational_del": False,
                                "ts": _ts_str(ts), "crypto": None, "weak_crypto": [],
                                "notify_error": None, "informational_ts": None})
                            _ex = _ikp["exchange"]
                            _sa["exchanges"].add(_ex)
                            if _ikp["version"] == 2:
                                if _ex == 34:
                                    _sa["v2_init_resp" if _ikp["is_response"] else "v2_init_req"] = True
                                elif _ex == 35:
                                    _sa["v2_auth_resp" if _ikp["is_response"] else "v2_auth_req"] = True
                                elif _ex == 37 and _sa["informational_ts"] is None:
                                    _sa["informational_ts"] = ts
                            else:  # IKEv1
                                if _ex in (2, 4):
                                    _sa["v1_phase1"] += 1
                                elif _ex == 32:
                                    _sa["v1_quick"] += 1
                            # SA(Security Association)ペイロードから暗号アルゴリズム/DHグループを抽出
                            # （提案は交換の最初のメッセージに載るため、未取得の場合のみ試みる）
                            if _sa["crypto"] is None:
                                _sa_body = _find_ike_sa_body(
                                    _ikp["body"], _ikp["next_payload"], _ikp["version"])
                                if _sa_body:
                                    _crypto = _parse_ike_sa_payload(_sa_body, _ikp["version"])
                                    if _crypto["encr"] or _crypto["dh_group"]:
                                        _sa["crypto"] = _crypto
                                        _sa["weak_crypto"] = _crypto["weak"]
                            # Notify/Notificationのエラーコード（提案不一致・認証失敗等の断定情報）
                            if _sa["notify_error"] is None:
                                _nerr = _find_ike_notify_error(
                                    _ikp["body"], _ikp["next_payload"], _ikp["version"])
                                if _nerr:
                                    _sa["notify_error"] = _nerr

                    # ── QUIC / HTTP3 検出（UDP 443 等・Long Headerで判定） ──
                    if udp.dport in QUIC_PORTS or udp.sport in QUIC_PORTS:
                        _qd = bytes(udp.data)
                        if len(_qd) >= 5 and (_qd[0] & 0x80):  # Long Header (bit0x80)
                            _ver = struct.unpack("!I", _qd[1:5])[0]
                            _qk = (src, dst)
                            _qe = quic_conns.setdefault(_qk, {"count": 0, "versions": set(), "initial": False})
                            _qe["count"] += 1
                            if _ver != 0:
                                _qe["versions"].add(f"0x{_ver:08x}")
                            # Long Header Packet Type: bits 0x30。00=Initial
                            if (_qd[0] & 0x30) == 0x00:
                                _qe["initial"] = True

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

    # ── TCPウィンドウ制御の原因切り分け ──────────────────
    # ①受信側(rwnd)要因: NIC/CPU/アプリの処理遅延で受信ウィンドウがじわじわ縮小
    for (src, dst, sp, dp), wt in win_trend.items():
        if wt["first_win"] <= 500 or wt["samples"] < 5:
            continue
        _shrink_ratio = wt["min_win"] / wt["first_win"]
        if _shrink_ratio <= 0.2 and wt["low_count"] >= 3:
            _hit_zero = zero_win_count.get((src, dst, sp, dp), 0)
            result["tcp_receiver_pressure"].append({
                "src": src, "dst": dst, "src_port": sp, "dst_port": dp,
                "first_win": wt["first_win"], "min_win": wt["min_win"],
                "shrink_pct": round(_shrink_ratio * 100, 1),
                "low_count": wt["low_count"], "samples": wt["samples"],
                "hit_zero": _hit_zero > 0, "zero_count": _hit_zero,
                "detail": f"{src} の受信ウィンドウが初期値の{round(_shrink_ratio*100,1)}%まで縮小"
                         f"（{wt['low_count']}/{wt['samples']}サンプルで低下）"
                         + (f"、ゼロウィンドウ{_hit_zero}回に到達" if _hit_zero else "（0には未到達）")
                         + f" — {src}側のNIC/CPU/アプリ処理遅延によるバッファ逼迫の可能性",
                "remedy": f"{src} 側のNIC性能・CPU使用率・受信バッファ設定"
                         "（ソケットバッファサイズ、オフロード設定等）を確認してください。",
            })
    result["tcp_receiver_pressure"].sort(key=lambda x: x["shrink_pct"])

    # ②送信側(cwnd)要因: 重複ACKバースト = 経路上のパケットロス/再送(自主規制)の兆候
    for (acker, sender, asp, adp), da in dup_ack.items():
        if da["bursts"] < 1:
            continue
        _retrans_key = (sender, acker, adp, asp)   # データ送信方向(sender→acker)の再送カウント
        _retrans_n = tcp_retrans_count.get(_retrans_key, 0)
        result["tcp_path_congestion"].append({
            "acker": acker, "sender": sender, "acker_port": asp, "sender_port": adp,
            "dup_ack_bursts": da["bursts"], "retrans_count": _retrans_n,
            "detail": f"{acker} が {sender} からのデータに対し重複ACKバーストを{da['bursts']}回検出"
                     + (f"（対応する再送{_retrans_n}回と相関あり）" if _retrans_n else "")
                     + " — 経路上のパケットロス/順序入れ替わりにより送信側が自主的に速度を"
                       "絞っている(輻輳制御)可能性",
            "remedy": "経路上の帯域差/輻輳を疑い、両端の中間区間（スイッチ/リンク速度）の"
                     "帯域・エラーカウンタ・QoS設定を確認してください。",
        })
    result["tcp_path_congestion"].sort(key=lambda x: x["dup_ack_bursts"], reverse=True)

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

    # ── 生成AI/LLMサービス宛通信の検知（SNIベース。内容は見えないので宛先の可視化のみ） ──
    for _ck, _info in tls_flow_info.items():
        _sni = _info.get("sni") or ""
        _service = _match_ai_service(_sni)
        if not _service:
            continue
        _d = tls_flow_duration.get(_ck, {})
        _first_ts = _d.get("first_ts", 0)
        _last_ts  = _d.get("last_ts", 0)
        _dur_sec  = round(_last_ts - _first_ts, 1)
        result["ai_service_sessions"].append({
            "service":     _service,
            "sni":         _sni,
            "client":      _ck[0],
            "server":      _ck[1],
            "server_port": _ck[3],
            "first_seen":  _ts_str(_first_ts) if _first_ts else "",
            "last_seen":   _ts_str(_last_ts) if _last_ts else "",
            "duration_sec": _dur_sec,
            "bytes":       _d.get("bytes", 0),
            "packets":     _d.get("packets", 0),
            "long_lived":  _dur_sec >= _AI_SESSION_LONGLIVED_SEC,
        })
    result["ai_service_sessions"].sort(key=lambda x: x["duration_sec"], reverse=True)

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

    # ── 表示言語の自動判定（アクセス先ドメインの地域から） ──
    # 日本を含むアジア圏のドメインが中心なら日本語、明確に非アジア圏なら英語を既定にする。
    _asian = _western = 0
    for _dom in accessed_domains:
        _rg = _tld_region(_dom)
        if _rg == "asian":
            _asian += 1
        elif _rg == "western":
            _western += 1
    if _western > _asian:
        result["suggested_lang"] = "en"
    else:
        # アジア優勢・同数・地域判定不能（汎用TLDのみ）は日本語を既定（日本向けツールのため）
        result["suggested_lang"] = "ja"
    result["region_hint"] = {"asian_domains": _asian, "western_domains": _western}

    # ── 脅威インテリジェンス照合（abuse.ch等の既知C2/マルウェアIP・ドメイン） ──
    try:
        import threat_intel as _ti
        _ti_seen = set()
        for _dom, _info in accessed_domains.items():
            _hit = _ti.check_domain(_dom)
            if _hit and _dom not in _ti_seen:
                _ti_seen.add(_dom)
                result["threat_intel_hits"].append({
                    "type": "domain", "indicator": _dom, "feed": _hit,
                    "clients": sorted(_info["clients"])[:10],
                    "detail": f"既知の悪性ドメイン {_dom} へアクセス（脅威フィード: {_hit}）",
                })
        # 外部宛て通信先IPを照合（データ送信・接続試行の両方の宛先）
        _ext_ips = set()
        for (src, dst) in outbound_bytes:
            if not _is_private_ip(dst):
                _ext_ips.add((src, dst))
        for (src, dst, _dp) in conn_times:
            if not _is_private_ip(dst):
                _ext_ips.add((src, dst))
        for (src, dst) in _ext_ips:
            _hit = _ti.check_ip(dst)
            if _hit and dst not in _ti_seen:
                _ti_seen.add(dst)
                result["threat_intel_hits"].append({
                    "type": "ip", "indicator": dst, "feed": _hit, "src": src,
                    "detail": f"既知の悪性IP {dst} と通信（送信元 {src} / 脅威フィード: {_hit}）",
                })
    except Exception as _ti_err:
        print(f"[threat_intel] 照合スキップ: {_ti_err}")

    # 脅威フィード一致はホストリスクにも加点（既存の host_risk に反映）
    if result["threat_intel_hits"]:
        _risk_map = {h["host"]: h for h in result["host_risk"]}
        for _th in result["threat_intel_hits"]:
            _hosts = _th.get("clients") or ([_th["src"]] if _th.get("src") else [])
            for _h in _hosts:
                if _h in _risk_map:
                    _risk_map[_h]["risk_score"] = min(100, _risk_map[_h]["risk_score"] + 30)
                    if "既知悪性先と通信" not in _risk_map[_h]["factors"]:
                        _risk_map[_h]["factors"].append("既知悪性先と通信")
                else:
                    _new = {"host": _h, "risk_score": 30, "risk_level": "中",
                            "factor_count": 1, "factors": ["既知悪性先と通信"]}
                    result["host_risk"].append(_new)
                    _risk_map[_h] = _new
        for _h in result["host_risk"]:
            _s = _h["risk_score"]
            _h["risk_level"] = "重大" if _s >= 70 else "高" if _s >= 40 else "中" if _s >= 20 else "低"
        result["host_risk"].sort(key=lambda x: x["risk_score"], reverse=True)

    # ── 産業プロトコル(Modbus)の集計・書込コマンド警告 ──
    _mb_read = _mb_write = 0
    for (src, dst), op in modbus_ops.items():
        _mb_read += op["read"]
        _mb_write += op["write"]
        if op["write"] > 0:
            result["industrial_alerts"].append({
                "protocol": "Modbus", "src": src, "dst": dst,
                "read": op["read"], "write": op["write"],
                "write_types": "/".join(sorted(op["write_fc"])),
                "severity": "high",
                "detail": f"{src} → {dst}(Modbus) へ書込コマンド {op['write']}回"
                          f"（{'/'.join(sorted(op['write_fc']))}）"
                          " — 制御系への書込は権限/正当性を要確認",
            })
    if modbus_ops:
        result["industrial_summary"] = {
            "modbus_pairs": len(modbus_ops), "modbus_read": _mb_read, "modbus_write": _mb_write}
    result["industrial_alerts"].sort(key=lambda x: x["write"], reverse=True)

    # ── QUIC/HTTP3 セッション集計 ──
    for (src, dst), q in quic_conns.items():
        result["quic_sessions"].append({
            "src": src, "dst": dst, "packets": q["count"],
            "versions": ",".join(sorted(q["versions"])) or "(不明)",
            "has_initial": q["initial"],
        })
    result["quic_sessions"].sort(key=lambda x: x["packets"], reverse=True)

    # ── GeoIP: 監視対象国(中国/北朝鮮/香港/マカオ)の外部IP検知 ──
    try:
        import geoip as _geo
        _country_counts: dict = {}
        for _ip, _info in geo_seen.items():
            _c = _geo.lookup_country(_ip)
            if not _c:
                continue
            _country_counts[_c] = _country_counts.get(_c, 0) + 1
            # 方向: 送信元として観測=inbound（相手からのアクセス）, 宛先=outbound
            _inbound = _info["as_src"]
            _outbound = _info["as_dst"]
            if _inbound and _outbound:
                _direction = "双方向"
            elif _inbound:
                _direction = "inbound(アクセス元)"
            else:
                _direction = "outbound(通信先)"
            # ブロック提案: CN/HK/MOのグローバルアドレスは方向を問わず遮断を推奨
            # （inbound=送信元遮断、outbound=宛先遮断のいずれも対象）
            _block = _geo.is_block_suggested(_c)
            # 北朝鮮は業務通信が想定されないため常に重大、
            # その他のブロック対象国・inboundは高、outboundのみは中
            if _c == "kp":
                _sev = "critical"
            elif _block or _inbound:
                _sev = "high"
            else:
                _sev = "medium"
            _label = _geo.country_label(_c, "ja")
            _peers = sorted(_info["peers"])[:10]
            _detail = (f"{_label}({_c.upper()})のグローバルアドレス {_ip} を検知"
                       f"（{_direction} / パケット{_info['packets']}）")
            if _block:
                _block_dir = "送信元" if _inbound else "宛先"
                _detail += f" — {_block_dir}ブロックを推奨"
            result["geo_alerts"].append({
                "ip": _ip, "country": _c, "country_label": _label,
                "direction": _direction, "inbound": _inbound, "outbound": _outbound,
                "packets": _info["packets"], "peers": _peers,
                "severity": _sev, "block_suggested": _block, "detail": _detail,
            })
        # 重大度順→パケット数順で並べる
        _sev_rank = {"critical": 0, "high": 1, "medium": 2}
        result["geo_alerts"].sort(
            key=lambda x: (_sev_rank.get(x["severity"], 3), -x["packets"]))
        if _country_counts:
            result["geo_summary"] = {
                "countries": {_geo.country_label(c, "ja"): n
                              for c, n in _country_counts.items()},
                "total_ips": sum(_country_counts.values()),
                "block_suggested": sum(1 for a in result["geo_alerts"]
                                       if a["block_suggested"]),
            }
    except Exception as _geo_err:
        print(f"[geoip] 照合スキップ: {_geo_err}")

    # ── TLSハンドシェイク(鍵交換)の成否判定 ──
    _hs_ok = _hs_fail = _hs_incomplete = 0
    _hs_weak_cipher = _hs_cert_issue = 0
    for _ck, _h in tls_hs.items():
        # 成功: サーバHello + (CCS or ApplicationData) が観測でき、Fatal Alertなし
        if _h["fatal_alert"]:
            _status, _reason = "失敗", f"Fatal Alert: {_h['alert_desc']}"
            _hs_fail += 1
        elif _h["server_hello"] and (_h["server_ccs"] or _h["client_ccs"] or _h["app_data"]):
            _status, _reason = "成功", "鍵交換完了（暗号通信に移行）"
            _hs_ok += 1
        elif _h["client_hello"] and not _h["server_hello"]:
            _status, _reason = "未完了", "ClientHelloに対しServerHelloなし（応答なし/遮断）"
            _hs_incomplete += 1
        elif _h["server_hello"]:
            _status, _reason = "未完了", "ServerHelloまで（CipherSpec変更/完了を確認できず）"
            _hs_incomplete += 1
        else:
            continue   # ハンドシェイクの断片が無いフローは対象外

        # 弱い暗号スイート(前方秘匿性なし/RC4/DES/NULL等)の判定
        _weak_cs = None
        if _h.get("cipher_suite") is not None:
            _wc = _WEAK_CIPHER_SUITES.get(_h["cipher_suite"])
            if _wc:
                _weak_cs = f"{_wc[0]}（{_wc[1]}）"
                _hs_weak_cipher += 1

        # 証明書検証(有効期限・自己署名・ホスト名不一致)
        _cert_check = None
        if _h.get("cert_der"):
            _cc = analyze_tls_certificate(_h["cert_der"], _h.get("sni", ""))
            if _cc["issues"]:
                _cert_check = _cc
                _hs_cert_issue += 1

        result["tls_handshakes"].append({
            "client": _h["client"], "server": _h["server"], "server_port": _h["port"],
            "sni": _h.get("sni", ""), "version": _h.get("version", ""),
            "status": _status, "reason": _reason,
            "client_hello": _h["client_hello"], "server_hello": _h["server_hello"],
            "cert": _h["cert"], "change_cipher_spec": _h["server_ccs"] or _h["client_ccs"],
            "app_data": _h["app_data"],
            "weak_cipher": _weak_cs, "cert_issues": _cert_check["issues"] if _cert_check else [],
        })
    _order = {"失敗": 0, "未完了": 1, "成功": 2}
    result["tls_handshakes"].sort(key=lambda x: _order.get(x["status"], 3))
    if result["tls_handshakes"]:
        result["tls_handshake_summary"] = {
            "total": len(result["tls_handshakes"]),
            "success": _hs_ok, "failed": _hs_fail, "incomplete": _hs_incomplete,
            "weak_cipher": _hs_weak_cipher, "cert_issues": _hs_cert_issue}

    # ── IPsec IKE(鍵交換)の成否判定 ──
    _ike_ok = _ike_fail = 0
    for _spi, _sa in ike_sas.items():
        _remedy = _verify = ""
        if _sa["version"] == 2:
            if _sa["v2_auth_resp"]:
                _status, _reason = "成功", "IKE_SA_INIT→IKE_AUTH応答まで完了（CHILD_SA確立）"
            elif _sa["v2_auth_req"] and not _sa["v2_auth_resp"]:
                _status, _reason = "失敗", "IKE_AUTH要求に応答なし（認証失敗/到達不可の可能性）"
                _remedy = "認証設定(PSK/証明書)を対向と再確認し、UDP4500(NAT-T)の到達性を確認してください。"
                _verify = "show crypto ikev2 sa detail（Cisco）／show security ike security-associations detail（Junos）"
            elif _sa["v2_init_resp"] and not _sa["v2_auth_req"]:
                _status, _reason = "未完了", "IKE_SA_INITのみ（Phase1途中・IKE_AUTH未達）"
                _remedy = "IKE_AUTH以降が到達していません。ACL/FWでUDP4500(NAT-T)が許可されているか確認してください。"
                _verify = "show crypto ikev2 sa（Cisco）"
            elif _sa["v2_init_req"] and not _sa["v2_init_resp"]:
                _status, _reason = "失敗", "IKE_SA_INIT要求に応答なし（相手先未応答）"
                _remedy = "対向未応答です。UDP500/4500の疎通・対向機器の起動状態・中間FWでのブロックを確認してください。"
                _verify = "ping <対向IP>／show crypto ikev2 sa（Cisco）／show security ike security-associations（Junos）"
            else:
                _status, _reason = "未完了", "IKEv2交換が途中で終了"
                _verify = "show crypto ikev2 sa（Cisco）／show security ike security-associations（Junos）"
            _exlist = "/".join(_IKEV2_EXCH.get(e, str(e)) for e in sorted(_sa["exchanges"]))
        else:
            if _sa["v1_quick"] >= 2:
                _status, _reason = "成功", "Quick Mode(Phase2)応答まで完了（IPsec SA確立）"
            elif _sa["v1_quick"] == 1:
                _status, _reason = "未完了", "Quick Mode開始のみ（Phase2応答未確認）"
                _remedy = "Phase2のProxy ID(アクセスリスト/トラフィックセレクタ)・PFS設定を対向と照合してください。"
                _verify = "show crypto ipsec sa（Cisco）"
            elif _sa["v1_phase1"] >= 3:
                _status, _reason = "未完了", "Phase1のみ（Quick Mode/Phase2未達）"
                _remedy = "Phase1(ISAKMP SA)は成立しています。IPsecトランスフォームセット/アクセスリストの設定を確認してください。"
                _verify = "show crypto ipsec transform-set（Cisco）"
            else:
                _status, _reason = "失敗", "Phase1が完了せず（提案不一致/未応答の可能性）"
                _remedy = "ISAKMPポリシー(暗号/ハッシュ/DHグループ/認証方式)の不一致、またはPSK不一致の可能性があります。"
                _verify = "show crypto isakmp policy／show crypto isakmp sa detail（Cisco）"
            _exlist = "/".join(_IKEV1_EXCH.get(e, str(e)) for e in sorted(_sa["exchanges"]))
        # Notify/Notificationのエラーコードがあれば、推定でなく機器からの明示的な
        # 失敗理由として上書きする（例: NO_PROPOSAL_CHOSEN＝暗号/DHグループ不一致）
        _nerr = _sa.get("notify_error")
        if _nerr:
            _status = "失敗"
            _reason = f"ピアから明示的なエラー通知: {_nerr['label']}"
            _remedy = _nerr.get("remedy", "")
            _verify = _nerr.get("verify", "")
        if _status == "成功":
            _ike_ok += 1
        elif _status == "失敗":
            _ike_fail += 1
        _crypto = _sa.get("crypto") or {}
        _weak_list = _sa.get("weak_crypto") or []
        if _weak_list and not _remedy:
            _remedy = "弱い暗号/DHグループが提案されています。AES-GCM＋2048bit以上のMODPまたはECP群への見直しを検討してください。"
            _verify = "show crypto ikev2 proposal（Cisco）／show security ike proposal <name>（Junos）"
        result["ipsec"]["ike_sas"].append({
            "version": f"IKEv{_sa['version']}", "initiator": _sa["initiator"],
            "responder": _sa["responder"], "spi": _spi[:16],
            "exchanges": _exlist, "status": _status, "reason": _reason,
            "encr": _crypto.get("encr"), "dh_group": _crypto.get("dh_group"),
            "auth_method": _crypto.get("auth_method"), "weak_crypto": _weak_list,
            "notify_error": _nerr["label"] if _nerr else None,
            "remedy": _remedy, "verify": _verify})
    result["ipsec"]["ike_sas"].sort(
        key=lambda x: (0 if x["weak_crypto"] else 1, _order.get(x["status"], 3)))
    # ESP/AH(確立後の暗号通信)フロー
    for (_s, _d), _f in esp_flows.items():
        result["ipsec"]["esp_flows"].append(
            {"src": _s, "dst": _d, "proto": _f["proto"], "packets": _f["count"]})
    result["ipsec"]["esp_flows"].sort(key=lambda x: x["packets"], reverse=True)
    if ike_sas or esp_flows:
        result["ipsec"]["summary"] = {
            "ike_total": len(ike_sas), "ike_success": _ike_ok, "ike_failed": _ike_fail,
            "ike_weak_crypto": sum(1 for s in result["ipsec"]["ike_sas"] if s["weak_crypto"]),
            "esp_flows": len(esp_flows),
            "esp_packets": sum(f["count"] for f in esp_flows.values())}

    # ── 既知の類似不具合パターン（Junos 21.2R1リリースノート「未解決の問題」より） ──
    # ネットワークポリシーの都合上ここではJuniper公式サイトへ直接アクセスできないが、
    # ユーザー提示の実際のリリースノート記載内容(PR番号)に基づく既知動作。
    # 断定はできないため「類似パターンの可能性」として提示し、実機のJunosバージョン/
    # 該当PRの適用有無は別途 show version 等で確認するよう案内する。
    for _spi, _sa in ike_sas.items():
        _info_ts = _sa.get("informational_ts")
        if _sa["version"] != 2 or _info_ts is None:
            continue   # INFORMATIONAL交換(37)が無ければ対象外
        _fwd = esp_flows.get((_sa["initiator"], _sa["responder"]))
        _rev = esp_flows.get((_sa["responder"], _sa["initiator"]))
        # INFORMATIONAL交換の後も送信を続けた方向 / それ以前に止まった方向を判定
        _fwd_after = bool(_fwd and _fwd["last_ts"] > _info_ts)
        _rev_after = bool(_rev and _rev["last_ts"] > _info_ts)
        _fwd_before = bool(_fwd and _fwd["first_ts"] < _info_ts)
        _rev_before = bool(_rev and _rev["first_ts"] < _info_ts)
        # 両方向とも切断前にESPが流れており(=トンネルは確立していた)、
        # 切断後は片方向だけが送信を継続している(=もう片方は止まった)場合のみ対象
        if _fwd_before and _rev_before and (_fwd_after != _rev_after):
            _stale_dir = f"{_sa['initiator']}→{_sa['responder']}" if _fwd_after \
                else f"{_sa['responder']}→{_sa['initiator']}"
            result["ipsec"]["known_issues"].append({
                "pattern": "IKE INFORMATIONAL交換後にESPが片方向のみ継続",
                "similar_to": "Junos 21.2R1リリースノート記載の既知動作(PR1432925)に類似",
                "detail": f"INFORMATIONAL交換後、{_stale_dir} 方向のみESP送信が継続し、"
                         "反対方向は停止しています。",
                "note": "ピアがトンネルを切断済みでも、ローカル側に古いIPsec SA/NHTBエントリーが"
                        "残留し送信を続けているケースに類似します。断定はできないため、"
                        "実機で以下を確認してください。",
                "verify": "show security ipsec security-associations（stale/古いSPIが残っていないか）／"
                         "show security ipsec next-hop-tunnels（NHTBエントリーの確認）",
                "remedy": "残留が確認できた場合: clear security ipsec security-associations "
                         "で該当SAをクリアして再ネゴシエーションさせる。頻発する場合はJTACへ"
                         "PR1432925系の既知不具合として問い合わせを検討。",
            })
    # 同一ピア間で短時間に複数回IKEネゴシエーションが発生 = トンネルフラップの可能性
    # (Junos PR1416334類似: 統合型ISSU中にIPsecトンネルがフラップし自動復旧する既知動作)
    _peer_negotiations: dict = {}
    for _spi, _sa in ike_sas.items():
        _pk = tuple(sorted((_sa["initiator"], _sa["responder"])))
        _peer_negotiations.setdefault(_pk, []).append(_sa["ts"])
    for _pk, _tslist in _peer_negotiations.items():
        if len(_tslist) >= 2:
            result["ipsec"]["known_issues"].append({
                "pattern": "同一ピアと短時間に複数回のIKEネゴシエーション",
                "similar_to": "Junos 21.2R1リリースノート記載の既知動作(PR1416334)に類似",
                "detail": f"{_pk[0]}⇔{_pk[1]} で{len(_tslist)}回の独立したIKEネゴシエーションを検出",
                "note": "統合型ISSU(ソフトウェア無停止アップグレード)中はIPsecトンネルが"
                        "一時的にフラップし、ISSU完了後に自動復旧する既知動作があります。"
                        "メンテナンス時間帯と一致するなら一時的な現象として無視して問題ありません。",
                "verify": "show system software（ISSU実施履歴）／show log messages（アップグレード時刻の確認）",
                "remedy": "メンテナンス以外の時間帯で頻発する場合は、別の要因"
                         "（DPDタイムアウト不一致・Phase2ライフタイム非対称等）を疑ってください。",
            })

    # ── SSH鍵交換の成否（TCPストリーム再構成を再利用） ──
    try:
        result["ssh_handshakes"] = analyze_ssh_handshake(data).get("sessions", [])
    except Exception as _ssh_err:
        print(f"[ssh] 解析スキップ: {_ssh_err}")

    # ── OSPF: Hello/Dead タイマー・エリアID・認証方式の不一致検知 ──
    # 隣接(Adjacency)が張れない典型原因。Hello区間のタイマー値・エリアIDは
    # 認証の有無に関わらず平文で読めるため、ここは推測ではなく実測値の突き合わせ。
    _ospf_routers_list = list(ospf_routers.items())
    _ospf_seen_pairs = set()
    for _i in range(len(_ospf_routers_list)):
        _rid1, _r1 = _ospf_routers_list[_i]
        for _j in range(_i + 1, len(_ospf_routers_list)):
            _rid2, _r2 = _ospf_routers_list[_j]
            _pair_key = tuple(sorted((_rid1, _rid2)))
            if _pair_key in _ospf_seen_pairs:
                continue
            _ospf_seen_pairs.add(_pair_key)
            _issues = []
            if _r1["area"] != _r2["area"]:
                _issues.append({
                    "category": "エリアID不一致",
                    "detail": f"エリア{_r1['area']} vs エリア{_r2['area']}",
                    "remedy": "同一リンク上のインターフェースのOSPFエリア番号を一致させてください。",
                    "verify": "show ip ospf interface brief（Cisco）／show ospf interface（Junos）"})
            if _r1["hello_interval"] != _r2["hello_interval"] or _r1["dead_interval"] != _r2["dead_interval"]:
                _issues.append({
                    "category": "Hello/Deadタイマー不一致",
                    "detail": (f"Hello:{_r1['hello_interval']}s/Dead:{_r1['dead_interval']}s vs "
                              f"Hello:{_r2['hello_interval']}s/Dead:{_r2['dead_interval']}s"),
                    "remedy": "両ルータのhello-interval/dead-intervalを一致させてください"
                             "（デフォルトはHello10秒/Dead40秒、既定値と異なる変更が片側だけ入っていないか要確認）。",
                    "verify": "show ip ospf interface <IF>（Cisco）／show ospf interface detail（Junos）"})
            if _r1["auth_type"] != _r2["auth_type"]:
                _issues.append({
                    "category": "認証方式不一致",
                    "detail": f"{_r1['auth_type']} vs {_r2['auth_type']}",
                    "remedy": "認証タイプ(なし/簡易パスワード/MD5等)とキーを双方で一致させてください。",
                    "verify": "show ip ospf interface <IF>（Cisco, 認証行を確認）"})
            for _iss in _issues:
                result["ospf_issues"].append({
                    "router1": _rid1, "router2": _rid2, **_iss})
    result["ospf_issues"].sort(key=lambda x: x["category"])

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


def analyze_wireless(data: bytes) -> dict:
    """
    無線(802.11)キャプチャを解析する。ビーコン(SSID列挙)・deauth攻撃・
    WPAハンドシェイク(EAPOL)取得を検出する。Ethernetキャプチャでは
    is_wireless=False を返す（何もしない）。
    """
    result = {"is_wireless": False, "ssids": [], "deauth": [], "eapol": [], "summary": {}}
    try:
        reader = dpkt.pcap.Reader(io.BytesIO(data))
        dlt = reader.datalink()
    except Exception:
        return result
    # 105=IEEE802_11, 127=IEEE802_11_RADIO(radiotap), 163=AVS
    if dlt not in (105, 127, 163, 119):
        return result
    result["is_wireless"] = True

    ssid_seen = {}
    deauth_count = defaultdict(int)
    eapol_pairs = defaultdict(int)
    beacon_n = deauth_n = eapol_n = 0

    for ts, buf in reader:
        try:
            if dlt in (127, 163):  # radiotap等はヘッダを剥がす
                rt = dpkt.radiotap.Radiotap(buf)
                wlan = rt.data
            else:
                wlan = dpkt.ieee80211.IEEE80211(buf)
            if not isinstance(wlan, dpkt.ieee80211.IEEE80211):
                continue
        except Exception:
            continue
        try:
            if wlan.type == dpkt.ieee80211.MGMT_TYPE:
                if wlan.subtype == dpkt.ieee80211.M_BEACON:
                    beacon_n += 1
                    ssid = ""
                    try:
                        ssid = wlan.ssid.data.decode("utf-8", errors="replace")
                    except Exception:
                        pass
                    bssid = ":".join("%02x" % b for b in wlan.mgmt.bssid) if hasattr(wlan, "mgmt") else "?"
                    if ssid and ssid not in ssid_seen:
                        ssid_seen[ssid] = bssid
                elif wlan.subtype == dpkt.ieee80211.M_DEAUTH:
                    deauth_n += 1
                    try:
                        dst = ":".join("%02x" % b for b in wlan.mgmt.dst)
                    except Exception:
                        dst = "broadcast"
                    deauth_count[dst] += 1
            # EAPOL(WPAハンドシェイク) は data フレームの LLC/SNAP 0x888e
            if b"\x88\x8e" in bytes(buf)[:64]:
                eapol_n += 1
        except Exception:
            continue

    result["ssids"] = [{"ssid": s, "bssid": b} for s, b in ssid_seen.items()]
    for dst, cnt in deauth_count.items():
        if cnt >= 5:
            result["deauth"].append({
                "target": dst, "count": cnt, "severity": "high",
                "detail": f"{dst} 宛のdeauthフレーム {cnt}個 — deauth(切断)攻撃/WPAハンドシェイク奪取の可能性",
            })
    result["deauth"].sort(key=lambda x: x["count"], reverse=True)
    if eapol_n:
        result["eapol"].append({
            "count": eapol_n,
            "detail": f"EAPOL(WPAハンドシェイク)フレーム {eapol_n}個を検出 "
                      "— WPA/WPA2ハンドシェイクの取得（パスワード解析の前段）の可能性",
        })
    result["summary"] = {"beacons": beacon_n, "deauth": deauth_n, "eapol": eapol_n,
                         "ssid_count": len(ssid_seen)}
    return result


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


# SSH Binary Packet Protocol のメッセージコード
_SSH_MSG_DISCONNECT = 1
_SSH_MSG_KEXINIT = 20
_SSH_MSG_NEWKEYS = 21
_SSH_DISCONNECT_REASONS = {
    1: "プロトコルエラー", 2: "プロトコルバージョン不一致", 3: "鍵交換失敗",
    5: "MAC不正", 6: "圧縮エラー", 7: "サービス利用不可",
    11: "接続を正常終了", 14: "接続がタイムアウト", 15: "不正な認証情報",
}


def _iter_ssh_packets(blob: bytes):
    """
    SSH Binary Packet Protocol のメッセージコードを順に返す。
    NEWKEYS以降は暗号化されるため、そこで自然にパース不能となり打ち切られる
    （復号は行わない・鍵交換フェーズの平文区間のみが対象）。
    """
    off, n = 0, len(blob)
    while off + 5 <= n:
        pkt_len = int.from_bytes(blob[off:off + 4], "big")
        if pkt_len < 1 or pkt_len > 262144 or off + 4 + pkt_len > n:
            return
        pad_len = blob[off + 4]
        if pad_len >= pkt_len:
            return
        if pkt_len - pad_len - 1 < 1:
            return
        yield blob[off + 5]
        off += 4 + pkt_len


def analyze_ssh_handshake(data: bytes) -> dict:
    """
    SSHの鍵交換(KEX)の成否を判定する。バナー交換後のBinary Packet Protocolを
    走査し、KEXINIT(往復)・NEWKEYS(往復)・DISCONNECTを検出する。
    NEWKEYS到達＝鍵交換完了（以降は暗号化されパース対象外になる）。
    戻り値: {"sessions": [{"client","server","server_port","client_banner",
             "server_banner","status","reason"}]}
    """
    result = {"sessions": []}
    try:
        streams = get_tcp_streams(data)
    except Exception:
        return result
    for s in streams:
        if s["src_port"] != 22 and s["dst_port"] != 22:
            continue
        c2s, s2c = s["client_to_server"], s["server_to_client"]
        banner_c = c2s[:255].split(b"\r\n")[0] if c2s[:4] == b"SSH-" else b""
        banner_s = s2c[:255].split(b"\r\n")[0] if s2c[:4] == b"SSH-" else b""
        if not banner_c and not banner_s:
            continue
        c_off = len(banner_c) + 2 if banner_c else 0
        s_off = len(banner_s) + 2 if banner_s else 0
        c_msgs = list(_iter_ssh_packets(c2s[c_off:]))
        s_msgs = list(_iter_ssh_packets(s2c[s_off:]))
        c_kexinit, s_kexinit = _SSH_MSG_KEXINIT in c_msgs, _SSH_MSG_KEXINIT in s_msgs
        c_newkeys, s_newkeys = _SSH_MSG_NEWKEYS in c_msgs, _SSH_MSG_NEWKEYS in s_msgs
        disconnected = _SSH_MSG_DISCONNECT in c_msgs or _SSH_MSG_DISCONNECT in s_msgs
        if c_newkeys and s_newkeys:
            status, reason = "成功", "双方でNEWKEYSを確認（鍵交換完了、以降は暗号化通信）"
        elif disconnected:
            status, reason = "失敗", "SSH_MSG_DISCONNECTを検出（鍵交換中に切断）"
        elif c_kexinit and s_kexinit:
            status, reason = "未完了", "KEXINITは往復したがNEWKEYSを確認できず"
        elif c_kexinit or s_kexinit:
            status, reason = "未完了", "KEXINITが片方向のみ（応答なし）"
        else:
            status, reason = "未完了", "バナー交換のみ（KEXINIT未確認）"
        result["sessions"].append({
            "client": s["src"] if banner_c else s["dst"],
            "server": s["dst"] if banner_c else s["src"],
            "server_port": s["dst_port"] if banner_c else s["src_port"],
            "client_banner": banner_c.decode("ascii", errors="replace"),
            "server_banner": banner_s.decode("ascii", errors="replace"),
            "status": status, "reason": reason,
        })
    _order = {"失敗": 0, "未完了": 1, "成功": 2}
    result["sessions"].sort(key=lambda x: _order.get(x["status"], 3))
    return result


# 既知のファイルシグネチャ(マジックバイト)。CTFのpcap問題で頻出する
# 「HTTP/FTP等の通信に隠されたファイル」の抽出（ファイルカービング）用。
_FILE_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"PK\x03\x04", "zip"),          # ZIP / Office(docx/xlsx/pptx) / jar / apk 等
    (b"%PDF-", "pdf"),
    (b"\x7fELF", "elf"),
    (b"MZ", "exe"),                  # Windows PE(EXE/DLL)
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"Rar!\x1a\x07\x01\x00", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b\x08", "gz"),         # gzip
    (b"BZh", "bz2"),                 # bzip2
    (b"\xfd7zXZ\x00", "xz"),         # xz
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),  # 旧Office(doc/xls/ppt), MSI 等
    (b"SQLite format 3\x00", "sqlite"),
    (b"ustar", "tar"),              # tar（実際はオフセット257だが簡易検出）
]

# ZIPベースのため中身を再帰展開する拡張子（Officeもzip）
_ZIP_LIKE_EXTS = {"zip", "docx", "xlsx", "pptx", "jar", "apk"}
# カービング/再帰展開の安全上限（解凍爆弾対策）
_CARVE_MAX_TOTAL = 64 * 1024 * 1024   # 展開合計の上限 64MB
_CARVE_MAX_MEMBER = 16 * 1024 * 1024  # 1エントリの上限 16MB
_CARVE_MAX_DEPTH = 3                   # 再帰の最大深さ


def _carve_length(data: bytes, offset: int, ext: str) -> int | None:
    """シグネチャ位置から正確なファイル終端を求める（求まらなければNone）。"""
    try:
        if ext == "png":
            idx = data.find(b"IEND\xae\x42\x60\x82", offset)
            return (idx + 8 - offset) if idx != -1 else None
        if ext == "jpg":
            idx = data.find(b"\xff\xd9", offset + 2)
            return (idx + 2 - offset) if idx != -1 else None
        if ext == "gif":
            idx = data.find(b"\x00\x3b", offset)      # GIFトレーラ
            return (idx + 2 - offset) if idx != -1 else None
        if ext == "pdf":
            idx = data.rfind(b"%%EOF")                # 最後の%%EOFまで
            if idx != -1 and idx >= offset:
                end = idx + 5
                # 末尾の改行も含める
                while end < len(data) and data[end:end + 1] in (b"\r", b"\n"):
                    end += 1
                return end - offset
            return None
        if ext in ("zip",) or ext in _ZIP_LIKE_EXTS:
            # EOCD(End Of Central Directory)候補を全て集め、末尾側から
            # 実際にzipとして開けるものを採用（ネストzipの内側EOCDで誤って
            # 途中截断しないよう、最外周を選ぶ）。
            import zipfile
            eocds, p = [], data.find(b"PK\x05\x06", offset)
            while p != -1:
                eocds.append(p)
                p = data.find(b"PK\x05\x06", p + 4)
            for eocd in reversed(eocds):
                if eocd + 22 > len(data):
                    continue
                clen = int.from_bytes(data[eocd + 20:eocd + 22], "little")
                end = eocd + 22 + clen
                try:
                    zipfile.ZipFile(io.BytesIO(data[offset:end])).infolist()
                    return end - offset
                except Exception:
                    continue
            return None
    except Exception:
        return None
    return None


def find_embedded_files(stream_bytes: bytes) -> list:
    """
    再構成したTCPストリームから既知のファイルシグネチャを検出し、
    可能なら正確な終端まで（不可なら次のシグネチャ位置または末尾まで）を
    候補として切り出す（ファイルカービング）。
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
    covered_until = -1   # 既にカービング済みファイルの終端（内部シグネチャの誤検出を抑止）
    for i, h in enumerate(hits):
        if h["offset"] < covered_until:
            continue  # 直前に切り出したファイルの内部 → スキップ
        next_off = len(stream_bytes)
        for j in range(i + 1, len(hits)):
            if hits[j]["offset"] > h["offset"]:
                next_off = hits[j]["offset"]
                break
        # まず正確な長さを試み、無ければ次シグネチャ（or末尾）までで代替
        exact = _carve_length(stream_bytes, h["offset"], h["ext"])
        if exact and exact > 0:
            end = h["offset"] + exact
        else:
            end = next_off
        chunk = stream_bytes[h["offset"]:end]
        if len(chunk) < 8:
            continue
        # 正確な長さが取れたものだけ「内部シグネチャ抑止」の範囲とする
        if exact:
            covered_until = end
        files.append({"ext": h["ext"], "offset": h["offset"], "size": len(chunk),
                      "data": chunk, "exact": bool(exact)})
    return files


def extract_archive_contents(data: bytes, ext: str = "zip", _depth: int = 0,
                             _budget: list | None = None) -> list:
    """
    ZIP/Office(docx等)アーカイブを展開し、各エントリを走査してflag/Base64や
    さらに内部のアーカイブ・埋め込みファイルを再帰的に取り出す。
    解凍爆弾対策として合計/単体サイズ・深さに上限を設ける。
    戻り値: [{"path", "size", "ctf_hits", "is_archive", "children":[...], "data"?}]
    """
    import zipfile
    if _budget is None:
        _budget = [_CARVE_MAX_TOTAL]
    if _depth > _CARVE_MAX_DEPTH or _budget[0] <= 0:
        return []
    entries = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return []
    for info in zf.infolist():
        if info.is_dir():
            continue
        if _budget[0] <= 0:
            break
        # 解凍爆弾対策: 宣言サイズ・実読込量を制限
        if info.file_size > _CARVE_MAX_MEMBER:
            entries.append({"path": info.filename, "size": info.file_size,
                            "ctf_hits": [], "is_archive": False, "children": [],
                            "note": "サイズ上限超のためスキップ"})
            continue
        try:
            with zf.open(info) as fp:
                member = fp.read(min(info.file_size + 1, _CARVE_MAX_MEMBER))
        except Exception:
            continue
        _budget[0] -= len(member)
        ctf = scan_ctf_indicators(member)
        is_arc = member[:4] == b"PK\x03\x04"
        children = []
        if is_arc:
            children = extract_archive_contents(member, "zip", _depth + 1, _budget)
        else:
            # ZIP以外の埋め込みファイル（画像/PDF等）も内部に隠れていることがある
            for _ef in find_embedded_files(member):
                if _ef["offset"] == 0 and _ef["size"] == len(member):
                    continue  # メンバー自身は除外
                children.append({"path": f"(埋め込み).{_ef['ext']}", "size": _ef["size"],
                                 "ctf_hits": scan_ctf_indicators(_ef["data"]),
                                 "is_archive": False, "children": [], "data": _ef["data"]})
        entries.append({"path": info.filename, "size": info.file_size,
                        "ctf_hits": ctf, "is_archive": is_arc, "children": children,
                        "data": member})
    return entries


# ══════════════════════════════════════════════════════════════════
#  画像フォレンジック（CTF: 画像に隠されたflag/ファイルの検出）
# ══════════════════════════════════════════════════════════════════
_IMAGE_EXTS = {"png", "jpg", "jpeg", "gif"}


def _extract_strings(data: bytes, min_len: int = 5) -> list:
    """バイナリから印字可能なASCII文字列を抽出する（stringsコマンド相当）。"""
    result, cur = [], []
    for b in data[:2_000_000]:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                result.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        result.append("".join(cur))
    return result


def extract_lsb_stego(data: bytes) -> list:
    """
    画像のLSB(最下位ビット)ステガノグラフィを抽出し、flag/印字可能文字列を探す。
    Pillowで画像を開き、RGB各チャネルのLSBを行優先で連結してバイト列を作る
    （最も一般的な埋め込み方式）。CTFの画像ステガノ問題向け。
    戻り値: 検出したflag/文字列のリスト。
    """
    hits = []
    try:
        from PIL import Image
    except Exception:
        return hits
    try:
        img = Image.open(io.BytesIO(data)).convert("RGB")
        w, h = img.size
        if w * h > 4_000_000:  # 過大な画像は処理量を抑える
            img = img.crop((0, 0, min(w, 2000), min(h, 2000)))
        px = list(img.getdata())
    except Exception:
        return hits
    # 複数の一般的な抽出順を試す（R,G,B全て / Rのみ）
    for label, channels in (("RGB-LSB", (0, 1, 2)), ("R-LSB", (0,))):
        bits = []
        for pixel in px:
            for ch in channels:
                bits.append(pixel[ch] & 1)
                if len(bits) >= 8 * 4000:  # 先頭 約4KB 分だけ復元
                    break
            if len(bits) >= 8 * 4000:
                break
        # ビット列をバイト化
        out = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for b in bits[i:i + 8]:
                byte = (byte << 1) | b
            out.append(byte)
        raw = bytes(out)
        for hh in scan_ctf_indicators(raw):
            if hh["type"] == "flag_pattern" and hh["text"] not in [x["text"] for x in hits]:
                hits.append({"method": label, **hh})
        # 印字可能な先頭文字列も（flag以外のヒント）
        for s in _extract_strings(raw, 8)[:3]:
            if "flag" in s.lower() or "ctf" in s.lower():
                if s not in [x.get("text") for x in hits]:
                    hits.append({"method": label, "type": "string", "text": s[:100], "decoded": ""})
    return hits


_JPEG_MARKER_NAMES = {
    0xE0: "APP0(JFIF)", 0xE1: "APP1(EXIF/XMP)", 0xE2: "APP2", 0xEC: "APP12",
    0xED: "APP13(Photoshop)", 0xEE: "APP14(Adobe)", 0xFE: "COM(コメント)",
    0xDB: "DQT(量子化表)", 0xC0: "SOF0", 0xC2: "SOF2", 0xC4: "DHT(ハフマン表)",
    0xDA: "SOS(スキャン開始)", 0xD8: "SOI", 0xD9: "EOI",
}


def analyze_jpeg_segments(data: bytes) -> dict:
    """
    JPEGのマーカーセグメントを走査し、CTFで隠し場所に使われやすい
    COM(コメント)・APPn(EXIF/XMP/ICC等)・サムネイル・複数EOI(隠し画像)を
    取り出して flag/Base64 を検査する。JPEGはDCT非可逆のため画素LSBは効かず、
    こうしたメタ領域・付加データが主要な隠し場所になる。
    戻り値: {"segments":[...], "flag_hits":[...], "exif":{}, "thumbnail":bytes|None,
             "extra_eoi": int}
    """
    out = {"segments": [], "flag_hits": [], "exif": {}, "thumbnail": None, "extra_eoi": 0}
    if not data or data[:2] != b"\xff\xd8":
        return out
    n = len(data)
    i = 2
    seen_flags = set()
    def _scan(blob, where):
        for h in scan_ctf_indicators(blob):
            key = (h["type"], h["text"])
            if key not in seen_flags:
                seen_flags.add(key)
                out["flag_hits"].append({**h, "where": where})
        # 印字可能な短い文字列でflag/ctfを含むもの
        for s in _extract_strings(blob, 6):
            if ("flag" in s.lower() or "ctf" in s.lower()) and ("flag", s) not in seen_flags:
                seen_flags.add(("flag", s))
                out["flag_hits"].append({"type": "string", "text": s[:100],
                                          "decoded": "", "where": where})
    while i < n - 1:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        # スタンドアロンマーカー（長さ無し）
        if marker in (0xD8, 0xD9, 0x01) or 0xD0 <= marker <= 0xD7 or marker == 0xFF:
            if marker == 0xD9:  # EOI
                # EOI以降に追記/2枚目画像が続くか
                rest = data[i + 2:]
                if rest.strip(b"\x00"):
                    out["extra_eoi"] += 1
                    _scan(rest[:65536], "EOI以降(追記/隠し画像)")
                break
            i += 2
            continue
        if i + 4 > n:
            break
        seg_len = int.from_bytes(data[i + 2:i + 4], "big")
        if seg_len < 2:
            break
        payload = data[i + 4:i + 2 + seg_len]
        name = _JPEG_MARKER_NAMES.get(marker, f"FF{marker:02X}")
        # COM/APPn は隠し場所として重要 → 中身を記録・走査
        if marker == 0xFE or 0xE0 <= marker <= 0xEF:
            out["segments"].append({"marker": name, "offset": i, "size": len(payload)})
            _scan(payload, name)
        if marker == 0xDA:   # SOS 以降はエントロピー符号化データ → セグメント走査終了
            # SOS後のスキャンデータ内の次EOIまでを飛ばし、末尾はEOI処理に任せる
            i = data.find(b"\xff\xd9", i)
            if i == -1:
                break
            continue
        i += 2 + seg_len
    # EXIF/サムネイルは Pillow で構造的に取得（あれば）
    try:
        from PIL import Image
        im = Image.open(io.BytesIO(data))
        exif = im.getexif()
        if exif:
            for tag_id, val in exif.items():
                try:
                    from PIL.ExifTags import TAGS
                    tag = TAGS.get(tag_id, str(tag_id))
                except Exception:
                    tag = str(tag_id)
                sval = str(val)[:200]
                out["exif"][str(tag)] = sval
                _scan(sval.encode("utf-8", errors="ignore"), f"EXIF:{tag}")
        # サムネイル（EXIF内の縮小画像に別データが仕込まれることがある）
        thumb = exif.get_ifd(0x8769).get(0x0201) if hasattr(exif, "get_ifd") else None
        if thumb:
            out["thumbnail"] = None  # オフセット情報のみ、実体抽出は割愛
    except Exception:
        pass
    return out


def analyze_image_forensics(ext: str, data: bytes) -> dict:
    """
    抽出した画像に対しCTF頻出の隠し手口を検査する:
      ① 末尾追記データ（画像の終端マーカー以降のデータ）
      ② ポリグロット/埋め込みファイル（画像内のZIP等）
      ③ メタデータ/文字列内の flag / Base64
      ④ LSBステガノグラフィ（ピクセルに隠されたデータ）
      ⑤ JPEGマーカーセグメント（COM/APPn/EXIF・複数EOI）※JPEG時のみ
    戻り値: {"appended_data", "embedded_files", "string_hits", "lsb_stego", "jpeg"}
    """
    result = {"appended_data": None, "embedded_files": [], "string_hits": [],
              "lsb_stego": [], "jpeg": None}
    if not data:
        return result
    ext = (ext or "").lower()

    # ① 末尾追記データ（終端マーカー以降）
    end_off = None
    if ext == "png":
        idx = data.rfind(b"IEND\xae\x42\x60\x82")  # IEND チャンク型+固定CRC
        if idx != -1:
            end_off = idx + 8
    elif ext in ("jpg", "jpeg"):
        idx = data.rfind(b"\xff\xd9")               # JPEG EOI マーカー
        if idx != -1:
            end_off = idx + 2
    elif ext == "gif":
        idx = data.rfind(b"\x00\x3b")               # GIF トレーラ（0x3B）
        if idx != -1:
            end_off = idx + 2
    if end_off is not None and 0 < end_off < len(data):
        appended = data[end_off:]
        if len(appended) >= 4:
            result["appended_data"] = {
                "offset": end_off, "size": len(appended), "data": appended,
                "preview": appended[:100].decode("latin-1", errors="replace"),
                "ctf_hits": scan_ctf_indicators(appended),
            }

    # ② ポリグロット/埋め込みファイル（オフセット0の画像本体以外・同種は除外）
    for f in find_embedded_files(data):
        if f["offset"] > 0 and f["ext"] != ext:
            result["embedded_files"].append(
                {"ext": f["ext"], "offset": f["offset"], "size": f["size"], "data": f["data"]})

    # ③ メタデータ/文字列内の flag / Base64
    _seen = set()
    for s in _extract_strings(data, 6):
        for h in scan_ctf_indicators(s.encode("latin-1", errors="ignore")):
            if h["text"] not in _seen:
                _seen.add(h["text"])
                result["string_hits"].append(h)

    # ④ LSBステガノグラフィ（PNG/GIF等の可逆画像で有効。JPEGは非可逆のため弱い）
    if ext in ("png", "gif", "bmp"):
        result["lsb_stego"] = extract_lsb_stego(data)

    # ⑤ JPEG: マーカーセグメント(COM/APPn/EXIF)・複数EOIを検査
    #    JPEGは画素LSBが効かないため、メタ領域・付加データが主要な隠し場所。
    if ext in ("jpg", "jpeg"):
        _jseg = analyze_jpeg_segments(data)
        if _jseg["flag_hits"] or _jseg["segments"] or _jseg["exif"] or _jseg["extra_eoi"]:
            result["jpeg"] = _jseg
    return result


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


def _printable_preview(s: str, max_len: int = 120) -> str:
    """latin-1文字列を表示用に整形（非表示文字は「.」に）。"""
    out = []
    for ch in s[:max_len]:
        o = ord(ch)
        out.append(ch if 32 <= o < 127 else ".")
    return "".join(out)


def grep_pcap(data: bytes, pattern: str, mode: str = "text",
              case_sensitive: bool = False, scope: str = "packet",
              max_matches: int = 500) -> dict:
    """
    パケットの中身を grep する（本格版）。
      mode  : "text"(部分一致) / "regex"(正規表現) / "hex"(16進バイト列 例 'deadbeef')
      scope : "packet"(パケット単位) / "stream"(TCPストリーム再構成後・跨ぎ検索)
    戻り値: {"matches":[...], "count", "truncated", "error"}
      match: {timestamp,protocol,src,dst,sport,dport,offset,match_text,preview}
    バイナリ安全のため全ペイロードを latin-1(1バイト=1文字) として扱う。
    """
    result = {"matches": [], "count": 0, "truncated": False, "error": None}
    if not pattern:
        result["error"] = "検索パターンが空です。"
        return result

    # パターン→正規表現(latin-1文字列上で検索)を構築
    try:
        if mode == "hex":
            cleaned = re.sub(r"[\s0x,\\x]", "", pattern, flags=re.I)
            if len(cleaned) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned or "x"):
                result["error"] = "16進パターンが不正です（例: deadbeef / 90 90 90）。"
                return result
            needle = re.escape(bytes.fromhex(cleaned).decode("latin-1"))
        elif mode == "regex":
            needle = pattern.encode("utf-8").decode("latin-1")
        else:  # text
            needle = re.escape(pattern.encode("utf-8").decode("latin-1"))
        flags = 0 if case_sensitive else re.IGNORECASE
        rx = re.compile(needle, flags | re.DOTALL)
    except re.error as e:
        result["error"] = f"正規表現エラー: {e}"
        return result
    except Exception as e:
        result["error"] = f"パターン構築エラー: {e}"
        return result

    def _search(hay_bytes, meta):
        hay = hay_bytes.decode("latin-1")
        for m in rx.finditer(hay):
            if result["count"] >= max_matches:
                result["truncated"] = True
                return False
            s, e = m.start(), m.end()
            ctx = hay[max(0, s - 30):s] + "《" + hay[s:e] + "》" + hay[e:e + 30]
            result["matches"].append({
                **meta, "offset": s,
                "match_text": _printable_preview(m.group(), 60),
                "preview": _printable_preview(ctx, 160),
            })
            result["count"] += 1
        return True

    # ── ストリーム再構成後を検索（セグメント跨ぎもヒット） ──
    if scope == "stream":
        try:
            streams = get_tcp_streams(data)
        except Exception as e:
            result["error"] = f"ストリーム再構成エラー: {e}"
            return result
        for s in streams:
            for direction, blob in (("→", s["client_to_server"]), ("←", s["server_to_client"])):
                if not blob:
                    continue
                meta = {"timestamp": s.get("start_ts", ""), "protocol": "TCP",
                        "src": s["src"] if direction == "→" else s["dst"],
                        "dst": s["dst"] if direction == "→" else s["src"],
                        "sport": s["src_port"] if direction == "→" else s["dst_port"],
                        "dport": s["dst_port"] if direction == "→" else s["src_port"]}
                if not _search(blob, meta):
                    return result
        return result

    # ── パケット単位で検索 ──
    try:
        reader, _ = _open_capture(data)
    except Exception as e:
        result["error"] = f"読み込みエラー: {e}"
        return result
    for ts, raw_pkt in reader:
        if result["count"] >= max_matches:
            result["truncated"] = True
            break
        try:
            eth = dpkt.ethernet.Ethernet(raw_pkt)
        except Exception:
            continue
        src = dst = "?"; sport = dport = 0; proto = ""; payload = b""
        if isinstance(eth.data, dpkt.ip.IP):
            pip = eth.data; src = _ip_str(pip.src); dst = _ip_str(pip.dst)
            if isinstance(pip.data, dpkt.tcp.TCP):
                proto = "TCP"; sport = pip.data.sport; dport = pip.data.dport
                payload = bytes(pip.data.data)
            elif isinstance(pip.data, dpkt.udp.UDP):
                proto = "UDP"; sport = pip.data.sport; dport = pip.data.dport
                payload = bytes(pip.data.data)
            else:
                proto = PROTO_NAMES.get(pip.p, f"IP/{pip.p}")
                payload = bytes(pip.data) if pip.data else b""
        else:
            payload = bytes(raw_pkt)
        if not payload:
            continue
        meta = {"timestamp": _ts_str(ts), "protocol": proto,
                "src": src, "dst": dst, "sport": sport, "dport": dport}
        if not _search(payload, meta):
            break
    return result
