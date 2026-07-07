"""
Snort / Suricata ルール取り込みツール（ET Open / Snort Community 対応）。

無料の IDS/IPS ルールセット（Emerging Threats Open、Snort Community Rules 等）を
本ツールの ips_signatures.json 形式に変換して取り込む。フル互換ではなく、
content / pcre / msg / classtype / sid / reference を抽出する実用サブセット。

使い方:
  python ips_rule_import.py <file.rules>        # ファイルから取り込み
  python ips_rule_import.py <URL>               # URLから取得して取り込み
  → ips_signatures_imported.json に保存（pcap_analyzer が起動時に自動マージ）

注意: 取り込んだシグネチャはヒューリスティック変換のため誤検知もあり得ます。
各ルールの content/pcre を単純化して正規表現化しています。
"""
import json
import re
import sys
from pathlib import Path

_OUT_PATH = Path(__file__).parent / "ips_signatures_imported.json"

# Snort classtype → 重大度マッピング
_CLASSTYPE_SEV = {
    "attempted-admin": "critical", "successful-admin": "critical",
    "trojan-activity": "critical", "shellcode-detect": "critical",
    "attempted-user": "high", "successful-user": "high",
    "web-application-attack": "high", "attempted-dos": "high",
    "policy-violation": "medium", "bad-unknown": "medium",
    "attempted-recon": "medium", "network-scan": "medium",
    "misc-activity": "low", "not-suspicious": "low",
}

_CONTENT_RE = re.compile(r'content:\s*"((?:[^"\\]|\\.)*)"', re.IGNORECASE)
_PCRE_RE    = re.compile(r'pcre:\s*"(.*?)"(?:\s*;|\s*\))', re.IGNORECASE)
_MSG_RE     = re.compile(r'msg:\s*"((?:[^"\\]|\\.)*)"', re.IGNORECASE)
_CLASS_RE   = re.compile(r'classtype:\s*([a-z0-9\-]+)', re.IGNORECASE)
_SID_RE     = re.compile(r'sid:\s*(\d+)', re.IGNORECASE)
_REF_RE     = re.compile(r'reference:\s*([^;]+)', re.IGNORECASE)


def _content_to_regex(content: str) -> str:
    """
    Snortのcontent文字列を正規表現(文字列)に変換する。
    |XX XX| はhexバイト、それ以外はリテラル（正規表現メタ文字はエスケープ）。
    """
    out = []
    i = 0
    while i < len(content):
        c = content[i]
        if c == "|":
            end = content.find("|", i + 1)
            if end == -1:
                break
            hexpart = content[i + 1:end].split()
            for h in hexpart:
                try:
                    out.append("\\x%02x" % int(h, 16))
                except ValueError:
                    pass
            i = end + 1
        else:
            # Snortのエスケープ \" \\ \| を戻す
            if c == "\\" and i + 1 < len(content):
                c = content[i + 1]
                i += 1
            out.append(re.escape(c))
            i += 1
    return "".join(out)


def _pcre_to_pattern(pcre: str) -> tuple:
    """Snortのpcre "/pattern/flags" を (pattern, ignorecase) に分解する。"""
    m = re.match(r'^\s*/(.*)/([a-zA-Z]*)\s*$', pcre)
    if not m:
        return None, False
    return m.group(1), ("i" in m.group(2))


def parse_rule(line: str) -> dict | None:
    """1本のSnort/Suricataルールをシグネチャ辞書へ変換する。対象外はNone。"""
    line = line.strip()
    if not line or line.startswith("#") or "(" not in line:
        return None
    msg_m = _MSG_RE.search(line)
    if not msg_m:
        return None
    msg = msg_m.group(1)

    ignorecase = "nocase" in line.lower()
    pattern = None
    # content（複数あれば .* で連結。順序は出現順）
    contents = [_content_to_regex(c) for c in _CONTENT_RE.findall(line)]
    contents = [c for c in contents if c]
    pcre_m = _PCRE_RE.search(line)
    if contents:
        pattern = ".{0,300}?".join(contents) if len(contents) > 1 else contents[0]
    elif pcre_m:
        pat, pcre_ic = _pcre_to_pattern(pcre_m.group(1))
        if not pat:
            return None
        pattern = pat
        ignorecase = ignorecase or pcre_ic
    else:
        return None  # content も pcre も無いルールは対象外

    if ignorecase and not pattern.startswith("(?i)"):
        pattern = "(?i)" + pattern

    classtype = (_CLASS_RE.search(line) or [None, "bad-unknown"])
    classtype = classtype.group(1).lower() if hasattr(classtype, "group") else "bad-unknown"
    sev = _CLASSTYPE_SEV.get(classtype, "medium")
    sid = _SID_RE.search(line)
    sid = sid.group(1) if sid else "0"
    ref = _REF_RE.search(line)
    ref = ref.group(1).strip() if ref else ""

    # 正規表現として妥当かを検証
    try:
        re.compile(pattern.encode("utf-8"))
    except Exception:
        return None

    return {
        "id": f"IMPORT-SID-{sid}",
        "category": msg[:80],
        "severity": sev,
        "binary": bool(re.search(r"\\x", pattern)) and "(?i)" not in pattern,
        "pattern": pattern,
        "cve": _extract_cve(msg + " " + ref),
        "description": f"取り込みルール(sid={sid}, classtype={classtype})",
        "recommended_action": "該当ルールの参照情報を確認し、通信元/宛先を調査。",
        "reference": ref,
        "source": "imported",
    }


_CVE_RE = re.compile(r"CVE[-\s]?(\d{4})[-\s]?(\d{4,7})", re.IGNORECASE)


def _extract_cve(text: str) -> str:
    m = _CVE_RE.search(text or "")
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else ""


def import_rules_text(text: str) -> list:
    """ルール本文（複数行）を取り込み、シグネチャ辞書のリストを返す。"""
    sigs, seen = [], set()
    for line in text.splitlines():
        s = parse_rule(line)
        if s and s["id"] not in seen:
            seen.add(s["id"])
            sigs.append(s)
    return sigs


def save_imported(sigs: list, path: Path = _OUT_PATH) -> None:
    doc = {
        "_comment": "Snort/Suricata ルールから取り込んだIPSシグネチャ。"
                    "pcap_analyzer が builtin(ips_signatures.json) とマージして読み込む。",
        "version": "imported",
        "signatures": sigs,
    }
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")


def fetch_and_import(url: str, timeout: int = 60) -> list:
    """URLからルールを取得して取り込む（ネットワーク到達時のみ）。"""
    import requests
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return import_rules_text(resp.text)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    src = sys.argv[1]
    if src.startswith("http://") or src.startswith("https://"):
        sigs = fetch_and_import(src)
    else:
        sigs = import_rules_text(Path(src).read_text(encoding="utf-8", errors="ignore"))
    save_imported(sigs)
    print(f"{len(sigs)} 件のシグネチャを取り込み、{_OUT_PATH.name} に保存しました。")
    try:
        import pcap_analyzer
        print("合計シグネチャ:", pcap_analyzer.reload_ips_signatures())
    except Exception:
        pass
