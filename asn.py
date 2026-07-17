"""
簡易ASN/クラウド・ISP判定モジュール。

主要クラウド/ISP（AWS・Google Cloud・Microsoft Azure・Cloudflare・
Oracle Cloud・DigitalOcean・GitHub・Linode/Akamai）の公開IPv4割り当て
レンジ（CIDR）を asn_db/*.cidr から読み込み、任意のIPがどの事業者に
属するかを高速に判定する。geoip.py（国別判定）と対をなし、
「どの国か」に加えて「どのクラウド/ISPか」まで分かるようにする。

データは各社の公開レンジをミラーしたGitHubリポジトリ（lord-alfred/ipranges）
由来で、リポジトリ内 asn_db/ に同梱している。ネットワーク到達時は
fetch_ranges() で最新のレンジを再取得できる（geoip.py と同じ運用）。

判定は各CIDRを [開始整数, 終了整数] 区間に展開し、開始でソートした配列に対する
二分探索（bisect）で O(log N) で行う。
"""
import bisect
import ipaddress
from pathlib import Path

_DIR = Path(__file__).parent / "asn_db"

# 事業者キー -> 表示名（日本語 / 英語）
ORG_NAMES = {
    "aws":          ("Amazon AWS", "Amazon AWS"),
    "azure":        ("Microsoft Azure", "Microsoft Azure"),
    "gcp":          ("Google Cloud", "Google Cloud"),
    "cloudflare":   ("Cloudflare", "Cloudflare"),
    "oci":          ("Oracle Cloud", "Oracle Cloud"),
    "digitalocean": ("DigitalOcean", "DigitalOcean"),
    "github":       ("GitHub", "GitHub"),
    "linode":       ("Linode(Akamai)", "Linode(Akamai)"),
}

# fetch_ranges() が取得する公開レンジのミラー元
_ZONE_URLS = {
    "aws":          "https://raw.githubusercontent.com/lord-alfred/ipranges/main/amazon/ipv4.txt",
    "azure":        "https://raw.githubusercontent.com/lord-alfred/ipranges/main/microsoft/ipv4.txt",
    "gcp":          "https://raw.githubusercontent.com/lord-alfred/ipranges/main/google/ipv4.txt",
    "cloudflare":   "https://raw.githubusercontent.com/lord-alfred/ipranges/main/cloudflare/ipv4.txt",
    "oci":          "https://raw.githubusercontent.com/lord-alfred/ipranges/main/oracle/ipv4.txt",
    "digitalocean": "https://raw.githubusercontent.com/lord-alfred/ipranges/main/digitalocean/ipv4.txt",
    "github":       "https://raw.githubusercontent.com/lord-alfred/ipranges/main/github/ipv4.txt",
    "linode":       "https://raw.githubusercontent.com/lord-alfred/ipranges/main/linode/ipv4.txt",
}

# ソート済み区間表: [(start_int, end_int, org), ...]（startで昇順）
_RANGES: list = []
_STARTS: list = []   # bisect 用に start_int だけ抜き出した配列
_LOADED = False


def _load(directory: Path = _DIR) -> list:
    """asn_db/*.cidr を読み込み、[(start, end, org), ...] をstart昇順で返す。"""
    ranges = []
    try:
        files = sorted(directory.glob("*.cidr"))
    except Exception:
        files = []
    for f in files:
        org = f.stem.lower()
        try:
            for raw in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                except ValueError:
                    continue
                if net.version != 4:
                    continue
                ranges.append((int(net.network_address), int(net.broadcast_address), org))
        except Exception as e:
            print(f"[asn] {f.name} 読み込みエラー: {e}")
    ranges.sort(key=lambda r: r[0])
    return ranges


def _ensure_loaded():
    global _RANGES, _STARTS, _LOADED
    if not _LOADED:
        _RANGES = _load()
        _STARTS = [r[0] for r in _RANGES]
        _LOADED = True


def reload_ranges() -> int:
    """レンジを再読み込みする。読み込んだCIDR数を返す。"""
    global _RANGES, _STARTS, _LOADED
    _RANGES = _load()
    _STARTS = [r[0] for r in _RANGES]
    _LOADED = True
    return len(_RANGES)


def lookup_org(ip: str) -> str | None:
    """IPが既知クラウド/ISPのレンジに含まれれば事業者キー(aws/azure/gcp等)を返す。"""
    _ensure_loaded()
    if not _RANGES:
        return None
    try:
        val = int(ipaddress.ip_address(ip))
    except ValueError:
        return None
    # start <= val となる最右の区間を二分探索
    idx = bisect.bisect_right(_STARTS, val) - 1
    if idx < 0:
        return None
    start, end, org = _RANGES[idx]
    if start <= val <= end:
        return org
    return None


def org_label(org: str, lang: str = "ja") -> str:
    """事業者キーを表示名に変換。"""
    names = ORG_NAMES.get(org)
    if not names:
        return org
    return names[1] if lang == "en" else names[0]


def stats() -> dict:
    """事業者別のCIDR件数を返す。"""
    _ensure_loaded()
    counts: dict = {}
    for _s, _e, org in _RANGES:
        counts[org] = counts.get(org, 0) + 1
    return counts


def fetch_ranges(save: bool = True, timeout: int = 30) -> dict:
    """
    各社公開レンジのミラーを取得して asn_db/<org>.cidr に保存する。
    ネットワーク到達時のみ動作。戻り値: {org: 件数 or エラー}。
    """
    import requests
    _DIR.mkdir(exist_ok=True)
    result = {}
    for org, url in _ZONE_URLS.items():
        try:
            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
            if save:
                (_DIR / f"{org}.cidr").write_text(resp.text, encoding="utf-8")
            result[org] = sum(1 for l in resp.text.splitlines()
                              if l.strip() and not l.startswith("#"))
        except Exception as e:
            result[org] = f"エラー: {e}"
    reload_ranges()
    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "fetch":
        print(fetch_ranges())
    elif len(sys.argv) > 2 and sys.argv[1] == "lookup":
        ip = sys.argv[2]
        o = lookup_org(ip)
        print(f"{ip} -> {org_label(o) if o else '(対象外)'} ({o})")
    else:
        print("読み込み済みCIDR:", stats())
