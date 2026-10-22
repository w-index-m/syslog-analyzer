"""
YARAルールスキャンモジュール。

yara-python（任意インストール）を使い、メール添付ファイルや抽出済みファイルを
コミュニティ標準のYARAルールと照合する。yara-pythonが未インストールの環境でも
他機能に影響しないよう、全操作をベストエフォート（失敗時は空リストを返す）で行う。

ルールは2種類を読み込む:
  - yara_rules/builtin.yar          … このリポジトリに同梱の手書きルール
  - yara_rules/imported/*.yar(.yara) … yara_rule_import.py で取り込んだ外部ルール
    （.gitignore対象。Yara-Rules/rules 等、各自のライセンス条件に従って取得すること）
"""
from pathlib import Path

_DIR = Path(__file__).parent / "yara_rules"
_IMPORTED_DIR = _DIR / "imported"

_compiled = None
_compile_error = ""
_rule_count = 0


def _collect_rule_files() -> dict:
    """{namespace: filepath} の形でYARAルールファイル一覧を返す（yara.compile用）。"""
    files = {}
    for p in sorted(_DIR.glob("*.yar")) + sorted(_DIR.glob("*.yara")):
        files[f"builtin_{p.stem}"] = str(p)
    if _IMPORTED_DIR.exists():
        for p in sorted(_IMPORTED_DIR.glob("*.yar")) + sorted(_IMPORTED_DIR.glob("*.yara")):
            files[f"imported_{p.stem}"] = str(p)
    return files


def reload_rules() -> dict:
    """ルールを(再)コンパイルする。{"count": コンパイル成功ルール数, "error": エラー文言(あれば)} を返す。"""
    global _compiled, _compile_error, _rule_count
    try:
        import yara
    except ImportError:
        _compiled, _compile_error, _rule_count = None, "yara-pythonが未インストールです（pip install yara-python）", 0
        return {"count": 0, "error": _compile_error}

    files = _collect_rule_files()
    if not files:
        _compiled, _compile_error, _rule_count = None, "", 0
        return {"count": 0, "error": ""}
    try:
        _compiled = yara.compile(filepaths=files)
        # ルール数はソースファイルを簡易カウント（厳密な本数はyara-pythonのAPIでは取得しづらいため目安）
        _rule_count = sum(1 for _ in _compiled)
        _compile_error = ""
    except Exception as e:
        _compiled, _compile_error, _rule_count = None, str(e), 0
    return {"count": _rule_count, "error": _compile_error}


def is_available() -> bool:
    if _compiled is None and _compile_error == "":
        reload_rules()
    return _compiled is not None


def scan_yara(data: bytes, timeout: int = 5) -> list:
    """
    バイト列をYARAルールと照合する。
    戻り値: [{"rule", "severity", "description", "tags"}, ...]（未インストール/未コンパイル時は空リスト）
    """
    if not data:
        return []
    if _compiled is None and _compile_error == "":
        reload_rules()
    if _compiled is None:
        return []
    try:
        matches = _compiled.match(data=data, timeout=timeout)
    except Exception:
        return []
    out = []
    for m in matches:
        meta = dict(m.meta) if hasattr(m, "meta") else {}
        out.append({
            "rule": m.rule,
            "namespace": getattr(m, "namespace", ""),
            "severity": meta.get("severity", "medium"),
            "description": meta.get("description", ""),
            "reference": meta.get("reference", ""),
            "tags": list(m.tags) if hasattr(m, "tags") else [],
        })
    return out


def stats() -> dict:
    files = _collect_rule_files()
    return {"rule_files": len(files), "compiled": _compiled is not None, "error": _compile_error}


# モジュール読み込み時に一度コンパイルしておく（ips_signatures/threat_intelと同じ方針）
reload_rules()
