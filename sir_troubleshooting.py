"""
富士通/エフサステクノロジーズ Si-R G シリーズ エラー番号別 対処分類

出典: Si-R G シリーズ トラブルシューティング (P3NK-6952-07Z0 / 2026年6月版)
      付録A「エラー番号別の対処一覧」

`show logging error` で表示される `error code [XXXXXXXX]`（16進8桁）を、
必要な対処カテゴリ（装置交換／環境確認／USB確認／再起動）に分類する。

パターン中の `*` は 16進の 0〜f 1桁を表す（例: b4**1003 は b4?? 1003）。
"""
import re

# ── カテゴリ定義 ─────────────────────────────────────────────
CATEGORY_INFO = {
    "replace": {
        "label": "装置交換が必要",
        "action": "弊社の技術員または認定技術員へ連絡し、装置交換を依頼してください。",
        "severity": "CRITICAL",
    },
    "environment": {
        "label": "設置環境（温度）の確認が必要",
        "action": "装置が設置されている環境の温度を確認してください（過熱の疑い）。",
        "severity": "ERROR",
    },
    "usb": {
        "label": "USB デバイスの確認・交換が必要",
        "action": "接続している USB デバイスを確認・交換してください。",
        "severity": "ERROR",
    },
    "reboot": {
        "label": "再起動が必要",
        "action": "装置を再起動してください。再発する場合は技術員へ連絡してください。",
        "severity": "ERROR",
    },
}

# ── エラー番号一覧（トラブルシューティング 付録A.2 の原文） ──
_REPLACE = (
    "84000051,85020000,85020001,85030000,85030001,85030003,85030004,85030010,85030011,"
    "85030020,85030021,85030022,850c0010,850c0011,850c0012,850c0013,850c0015,850d0001,"
    "85130000,85ff0001,85ff0002,"
    "b4**1003,b4**1006,b4**2006,b4**2046,b4**2056,b4**2066,b4**2076,b4**2086,b4**2096,"
    "b4**20a6,b4**20b6,b4**20c6,b4**20d6,b4**20e6,b4**20f6,b4**a000,b4**a001,b4**a002,"
    "b4**c08*,b4**c00*,b4**c100,b4**c101,b4**e000,b4**e001,"
    "c5000001,c5000002,c5000003,c5000004,c5000010,c5010001,c5010002,c5010003,c5010004,"
    "c5010010,c5020001,c5020002,c5020003,c5020004,c5020010,c5000101,c5000102,c5000103,"
    "c5000104,c5000105,c5010101,c5010102,c5010103,c5010104,c5010105,c5020101,c5020102,"
    "c5020103,c5020104,c5020105,c5000106,c5000120,c5000121,c5000200,c5000201,c5010106,"
    "c5010120,c5010121,c5010200,c5010201,c5020106,c5020120,c5020121,c5020200,c5020201,"
    "c5f00001,c8**1002,c8**1004,c8**2003,c8**2004,c8**2005,c8**2006,c8**4001,c8**5001,"
    "c8**5002,c8**5003,d5000001"
)
_ENVIRONMENT = "85010000,85010001"
_USB = "c5000900,c5010900,c5000502"
_REBOOT = (
    "00000000,00000001,00000002,00000003,00000011,00000012,00000021,00000022,00000023,"
    "00000024,00000025,00000026,00000027,00000028,00000029,0000002a,0000002b,0000002c,"
    "0000002d,00000031,00000032,00000038,00000039,0000003a,0000003b,0000003c,00000040,"
    "00000041,00000042,00000043,00000044,00000050,00000051,00000052,00000053,00000054,"
    "00000055,00000056,00000057,00000058,00000059,0000005a,00000060,00000061,00000062,"
    "00000063,00000064,00000070,00000071,00000072,00000073,00000080,00000081,00000090,"
    "000000a0,000000a1,000000a2,000000a3,000000b0,000000c0,000000c1,000000c2,000000c3,"
    "01000001,01000002,01000003,01000004,00100000,00100001,00100002,00100003,00110000,"
    "00120000,00130000,00140000,00140001,00150000,00150001,00160000,00200000,00200001,"
    "00200002,00200003,00210000,00220000,00230000,00230001,00230002,"
    "84000041,8500****,a7**0cb0,b4**1000,b4**1001,b4**1002,b4**1004,b4**1005,b4**2000,"
    "b4**2001,b4**2002,b4**2003,b4**2004,b4**2005,b4**4006,b4**5000,b4**5001,b4**5002,"
    "b4**6001,b4**6004,b4**6005,b4**7000,b4**7001,b4**7002,b4**8000,c8**1001,c8**1003,"
    "c8**1005,c8**2001,c8**2002,c8**2007,c8**7000"
)


def _pat_to_regex(pat: str) -> re.Pattern:
    """'*' を 16進1桁ワイルドカードに変換して正規表現化。"""
    return re.compile("^" + pat.replace("*", "[0-9a-f]") + "$", re.IGNORECASE)


_CATEGORY_PATTERNS = {}
for _cat, _csv in (("replace", _REPLACE), ("environment", _ENVIRONMENT),
                   ("usb", _USB), ("reboot", _REBOOT)):
    _CATEGORY_PATTERNS[_cat] = [_pat_to_regex(p.strip()) for p in _csv.split(",") if p.strip()]


def _in_a7_range(code: str) -> bool:
    """a7**0101〜a7**0caf（装置交換）の範囲判定。"""
    m = re.fullmatch(r"a7[0-9a-f]{2}([0-9a-f]{4})", code, re.IGNORECASE)
    if not m:
        return False
    return 0x0101 <= int(m.group(1), 16) <= 0x0caf


def classify_error_code(code: str) -> dict | None:
    """
    Si-R エラーコード（16進8桁）を対処カテゴリに分類する。
    戻り値: {code, category, label, action, severity} または None（未知）
    """
    if not code:
        return None
    code = code.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{8}", code):
        return None

    # a7** 範囲（装置交換）を優先判定
    if _in_a7_range(code):
        cat = "replace"
    else:
        cat = None
        for c, pats in _CATEGORY_PATTERNS.items():
            if any(p.match(code) for p in pats):
                cat = c
                break
    if not cat:
        return None

    info = CATEGORY_INFO[cat]
    return {
        "code": code,
        "category": cat,
        "label": info["label"],
        "action": info["action"],
        "severity": info["severity"],
    }


# メッセージ本文から error code を抽出（例: "error code [85010001]"）
ERROR_CODE_RE = re.compile(r"error[_ ]?code\s*[\[=:]\s*([0-9a-fA-F]{8})", re.IGNORECASE)


def extract_and_classify(message: str) -> dict | None:
    """メッセージ本文中の error code を抽出して分類する。"""
    m = ERROR_CODE_RE.search(message or "")
    if not m:
        return None
    return classify_error_code(m.group(1))


if __name__ == "__main__":
    # 自己テスト（トラブルシューティング付録A.2 の代表例）
    samples = [
        ("85010001", "environment"),   # 温度
        ("85020000", "replace"),       # 装置交換
        ("c5000900", "usb"),           # USB
        ("00000041", "reboot"),        # 再起動
        ("b4ab1003", "replace"),       # b4**1003 装置交換
        ("b4ab1000", "reboot"),        # b4**1000 再起動
        ("a7550500", "replace"),       # a7**0101〜0caf 範囲内 装置交換
        ("a7550d00", None),            # 範囲外
        ("ffffffff", None),            # 未定義
    ]
    ok = 0
    for code, expect in samples:
        r = classify_error_code(code)
        got = r["category"] if r else None
        status = "OK" if got == expect else "NG"
        ok += got == expect
        print(f"[{status}] {code} -> {got} (expect {expect})")
    print(f"--- {ok}/{len(samples)} ---")
