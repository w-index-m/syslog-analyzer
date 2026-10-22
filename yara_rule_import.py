"""
YARAルール取り込みツール。

無料で公開されているYARAルール（Yara-Rules/rules、elastic/protections-artifacts 等）を
yara_rules/imported/ に保存する。yara_rules_engine.py が起動時に builtin.yar と
自動マージして読み込む。

使い方:
  python yara_rule_import.py <file.yar>        # ローカルファイルから取り込み
  python yara_rule_import.py <URL>             # URLから取得して取り込み（.yar/.yaraのraw URL）

注意: 取り込むルールのライセンス条件は各リポジトリの定めに従ってください
（多くはMIT/CC等ですが、再配布条件は個別に確認が必要です）。
"""
import sys
from pathlib import Path

_IMPORTED_DIR = Path(__file__).parent / "yara_rules" / "imported"


def _safe_name(url_or_path: str) -> str:
    name = url_or_path.rstrip("/").rsplit("/", 1)[-1]
    if not name.endswith((".yar", ".yara")):
        name += ".yar"
    return name


def import_from_file(path: str) -> Path:
    src = Path(path)
    text = src.read_text(encoding="utf-8", errors="ignore")
    return _save(src.name, text)


def import_from_url(url: str, timeout: int = 30) -> Path:
    import requests
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return _save(_safe_name(url), resp.text)


def _save(name: str, text: str) -> Path:
    _IMPORTED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = _IMPORTED_DIR / name
    out_path.write_text(text, encoding="utf-8")
    return out_path


def validate_and_reload() -> dict:
    """取り込んだルール一式が実際にコンパイル可能かを検証し、結果を返す。"""
    import yara_rules_engine as yre
    return yre.reload_rules()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    src = sys.argv[1]
    if src.startswith("http://") or src.startswith("https://"):
        out = import_from_url(src)
    else:
        out = import_from_file(src)
    print(f"保存しました: {out}")
    result = validate_and_reload()
    if result["error"]:
        print(f"⚠️ コンパイルエラー: {result['error']}")
    else:
        print(f"コンパイル成功。ルール総数: {result['count']}")
