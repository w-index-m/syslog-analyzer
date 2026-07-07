"""
脅威インテリジェンス（abuse.ch 等の無料フィード）モジュール。

既知の C2 / マルウェア配布 IP・ドメインのブロックリストを読み込み、
pcap内の通信先(IP/ドメイン)が一致するかを照合する。

シグネチャ(ips_signatures.json)と同様、リストはリポジトリ内の
threat_intel/ ディレクトリで一元管理する（GitHubを正とし、各デプロイは
pullで最新を取得）。fetch_feeds() で abuse.ch 等の実フィードを取得して
threat_intel/downloaded_*.txt に保存できる（ネットワーク到達時のみ）。

対応フィード（fetch_feeds）:
  - Feodo Tracker (abuse.ch): 既知ボットネットC2のIP
  - URLhaus (abuse.ch): 既知マルウェア配布URLのホスト
"""
import os
import re
from pathlib import Path

_DIR = Path(__file__).parent / "threat_intel"

# fetch_feeds() が取得する無料フィード（abuse.ch）
_FEEDS = {
    "feodo_c2_ip": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "urlhaus_host": "https://urlhaus.abuse.ch/downloads/text_online/",
}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _parse_line(line: str):
    """1行から IP または ドメインを取り出す（コメント/空行/URLにも対応）。"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # URLhaus等はURL形式のこともあるためホスト部を抽出
    if "://" in line:
        line = line.split("://", 1)[1]
    line = line.split("/", 1)[0].split(":", 1)[0].strip().lower()
    return line or None


def load_indicators(directory: Path = _DIR) -> dict:
    """
    threat_intel/ 内の全 .txt を読み込み、{ips:set, domains:set, sources:dict} を返す。
    sources は indicator -> 由来ファイル名（表示用）。
    """
    ips, domains, sources = set(), set(), {}
    try:
        files = sorted(directory.glob("*.txt"))
    except Exception:
        files = []
    for f in files:
        try:
            for raw in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                ind = _parse_line(raw)
                if not ind:
                    continue
                if _IP_RE.match(ind):
                    ips.add(ind)
                elif "." in ind:
                    domains.add(ind)
                sources.setdefault(ind, f.name)
        except Exception as e:
            print(f"[threat_intel] {f.name} 読み込みエラー: {e}")
    return {"ips": ips, "domains": domains, "sources": sources}


# モジュール読み込み時に一度ロード（reload_indicators で更新可）
_INDICATORS = load_indicators()


def reload_indicators() -> int:
    """脅威インテリジェンスを再読み込みする。IP+ドメインの総数を返す。"""
    global _INDICATORS
    _INDICATORS = load_indicators()
    return len(_INDICATORS["ips"]) + len(_INDICATORS["domains"])


def check_ip(ip: str) -> str | None:
    """IPが既知の悪性リストにあれば由来ファイル名を返す。"""
    if ip in _INDICATORS["ips"]:
        return _INDICATORS["sources"].get(ip, "threat_intel")
    return None


def check_domain(domain: str) -> str | None:
    """ドメイン（またはその親ドメイン）が既知の悪性リストにあれば由来を返す。"""
    d = (domain or "").lower().rstrip(".")
    if not d:
        return None
    labels = d.split(".")
    # 完全一致 or 親ドメイン一致（sub.evil.example も evil.example で一致）
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        if cand in _INDICATORS["domains"]:
            return _INDICATORS["sources"].get(cand, "threat_intel")
    return None


def stats() -> dict:
    return {"ip_count": len(_INDICATORS["ips"]), "domain_count": len(_INDICATORS["domains"])}


def fetch_feeds(save: bool = True, timeout: int = 30) -> dict:
    """
    abuse.ch 等の無料フィードを取得して threat_intel/downloaded_*.txt に保存する。
    ネットワーク到達時のみ動作。戻り値: {feed: 取得件数 or エラー}。
    """
    import requests
    _DIR.mkdir(exist_ok=True)
    result = {}
    for name, url in _FEEDS.items():
        try:
            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
            lines = [l for l in resp.text.splitlines() if _parse_line(l)]
            if save:
                (_DIR / f"downloaded_{name}.txt").write_text(
                    f"# {url} から取得\n" + "\n".join(lines), encoding="utf-8")
            result[name] = len(lines)
        except Exception as e:
            result[name] = f"エラー: {e}"
    reload_indicators()
    return result


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "fetch":
        print(fetch_feeds())
    else:
        print("読み込み済み:", stats())
