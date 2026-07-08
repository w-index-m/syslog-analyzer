"""
簡易 GeoIP（国別IP判定）モジュール。

中国(CN)・北朝鮮(KP)・香港(HK)・マカオ(MO)など、監視対象国の
IPv4 割り当てレンジ（CIDR）を geoip/*.cidr から読み込み、任意のIPが
どの国に属するかを高速に判定する。

データは RIR（APNIC等）由来の集約済み割り当てレンジ（ipverse/rir-ip）を
リポジトリ内 geoip/ に同梱しており、GitHubを正として各デプロイは pull で
最新を取得する（シグネチャ/脅威フィードと同じ運用）。ネットワーク到達時は
fetch_zones() で最新のレンジを再取得できる。

判定は各CIDRを [開始整数, 終了整数] 区間に展開し、開始でソートした配列に対する
二分探索（bisect）で O(log N) で行う。
"""
import bisect
import ipaddress
from pathlib import Path

_DIR = Path(__file__).parent / "geoip"

# 監視対象国コード -> 表示名（日本語 / 英語）
COUNTRY_NAMES = {
    "cn": ("中国", "China"),
    "kp": ("北朝鮮", "North Korea"),
    "hk": ("香港", "Hong Kong"),
    "mo": ("マカオ", "Macau"),
}

# 送信元がこの国のグローバルアドレスの場合、ブロックを提案する対象
# （北朝鮮は通常業務通信が想定されないため常に高リスクだが、
#   ユーザー要望によりブロック提案は中国・香港・マカオを対象とする）
BLOCK_SUGGEST_COUNTRIES = {"cn", "hk", "mo"}

# fetch_zones() が取得する RIR 由来の集約レンジ
_ZONE_URLS = {
    c: f"https://raw.githubusercontent.com/ipverse/rir-ip/master/country/{c}/ipv4-aggregated.txt"
    for c in COUNTRY_NAMES
}

# ソート済み区間表: [(start_int, end_int, country), ...]（startで昇順）
_RANGES: list = []
_STARTS: list = []   # bisect 用に start_int だけ抜き出した配列
_LOADED = False


def _load(directory: Path = _DIR) -> list:
    """geoip/*.cidr を読み込み、[(start, end, country), ...] をstart昇順で返す。"""
    ranges = []
    try:
        files = sorted(directory.glob("*.cidr"))
    except Exception:
        files = []
    for f in files:
        country = f.stem.lower()
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
                ranges.append((int(net.network_address), int(net.broadcast_address), country))
        except Exception as e:
            print(f"[geoip] {f.name} 読み込みエラー: {e}")
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


def lookup_country(ip: str) -> str | None:
    """IPが監視対象国のレンジに含まれれば国コード(cn/kp/hk/mo)を返す。"""
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
    start, end, country = _RANGES[idx]
    if start <= val <= end:
        return country
    return None


def country_label(country: str, lang: str = "ja") -> str:
    """国コードを表示名に変換。"""
    names = COUNTRY_NAMES.get(country)
    if not names:
        return country.upper()
    return names[1] if lang == "en" else names[0]


def is_block_suggested(country: str) -> bool:
    """その国が送信元ブロック提案の対象か。"""
    return country in BLOCK_SUGGEST_COUNTRIES


def stats() -> dict:
    """国別のCIDR件数を返す。"""
    _ensure_loaded()
    counts: dict = {}
    for _s, _e, c in _RANGES:
        counts[c] = counts.get(c, 0) + 1
    return counts


def fetch_zones(save: bool = True, timeout: int = 30) -> dict:
    """
    RIR由来の国別レンジを取得して geoip/<c>.cidr に保存する。
    ネットワーク到達時のみ動作。戻り値: {country: 件数 or エラー}。
    """
    import requests
    _DIR.mkdir(exist_ok=True)
    result = {}
    for c, url in _ZONE_URLS.items():
        try:
            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
            if save:
                (_DIR / f"{c}.cidr").write_text(resp.text, encoding="utf-8")
            result[c] = sum(1 for l in resp.text.splitlines()
                            if l.strip() and not l.startswith("#"))
        except Exception as e:
            result[c] = f"エラー: {e}"
    reload_ranges()
    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "fetch":
        print(fetch_zones())
    elif len(sys.argv) > 2 and sys.argv[1] == "lookup":
        ip = sys.argv[2]
        c = lookup_country(ip)
        print(f"{ip} -> {country_label(c) if c else '(対象外)'} ({c})")
    else:
        print("読み込み済みCIDR:", stats())
