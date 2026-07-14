#!/usr/bin/env python3
"""
朝の全スクリプトチェック。

以下を順番に検証する（すべて読み取り専用・副作用なし）:
  1. 構文チェック   - リポジトリ直下の全 .py ファイルが py_compile を通るか
  2. テストスイート - test_analysis.py (pytest) が全件パスするか
  3. IPSシグネチャ  - ips_signatures.json / ips_signatures_imported.json が
                      正しいJSONで、各パターンが実際の読み込みと同じ
                      encode("utf-8") 経由で re.compile できるか

実行:  python3 check_all.py
終了コード: 全チェック合格時 0 / いずれか失敗時 1
"""
import json
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).parent
SIGNATURE_FILES = ["ips_signatures.json", "ips_signatures_imported.json"]


class Result:
    def __init__(self, name):
        self.name = name
        self.ok = True
        self.detail = ""
        self.elapsed = 0.0


def check_syntax() -> Result:
    r = Result("構文チェック")
    t0 = time.time()
    py_files = sorted(REPO_ROOT.glob("*.py"))
    failures = []
    for f in py_files:
        proc = subprocess.run(
            [sys.executable, "-m", "py_compile", str(f)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            failures.append((f.name, proc.stderr.strip().splitlines()[-1] if proc.stderr else "不明なエラー"))
    r.elapsed = time.time() - t0
    if failures:
        r.ok = False
        r.detail = "\n".join(f"  - {name}: {err}" for name, err in failures)
    else:
        r.detail = f"{len(py_files)}/{len(py_files)} ファイルOK"
    return r


def check_tests() -> Result:
    r = Result("テストスイート")
    t0 = time.time()
    test_file = REPO_ROOT / "test_analysis.py"
    if not test_file.exists():
        r.ok = False
        r.detail = "test_analysis.py が見つかりません"
        r.elapsed = time.time() - t0
        return r
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", str(test_file)],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    r.elapsed = time.time() - t0
    last_line = next((ln for ln in reversed(proc.stdout.strip().splitlines()) if ln.strip()), "")
    if proc.returncode != 0:
        r.ok = False
        tail = "\n".join(proc.stdout.strip().splitlines()[-15:])
        r.detail = f"{last_line}\n{tail}"
    else:
        r.detail = last_line
    return r


def check_ips_signatures() -> Result:
    r = Result("IPSシグネチャ")
    t0 = time.time()
    problems = []
    checked_any = False
    total_sigs = 0
    for fname in SIGNATURE_FILES:
        path = REPO_ROOT / fname
        if not path.exists():
            continue
        checked_any = True
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            problems.append(f"{fname}: JSON解析エラー: {e}")
            continue
        sigs = doc.get("signatures", [])
        total_sigs += len(sigs)
        for sig in sigs:
            sig_id = sig.get("id", "?")
            pattern = sig.get("pattern", "")
            try:
                re.compile(pattern.encode("utf-8"))
            except Exception as e:
                problems.append(f"{fname}: シグネチャ「{sig_id}」のパターン不正: {e}")
    r.elapsed = time.time() - t0
    if not checked_any:
        r.ok = False
        r.detail = "シグネチャファイルが見つかりません"
    elif problems:
        r.ok = False
        r.detail = "\n".join(f"  - {p}" for p in problems)
    else:
        r.detail = f"{total_sigs}件のシグネチャすべて正常"
    return r


def print_result(r: Result):
    status = "PASS" if r.ok else "FAIL"
    print(f"[{status}] {r.name:<14} {r.detail.splitlines()[0]:<40} ({r.elapsed:.1f}s)")
    if not r.ok:
        for line in r.detail.splitlines()[1:]:
            print(line)


def main():
    t0 = time.time()
    results = [check_syntax(), check_tests(), check_ips_signatures()]
    print("=" * 70)
    for r in results:
        print_result(r)
    elapsed = time.time() - t0
    passed = sum(1 for r in results if r.ok)
    print("-" * 70)
    overall = "PASS" if passed == len(results) else "FAIL"
    print(f"結果: {overall}  ({passed}/{len(results)} チェック合格, {elapsed:.1f}s)")
    print("=" * 70)
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
