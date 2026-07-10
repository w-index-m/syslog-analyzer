"""
LLM送信前DLP（データ漏洩防止）

外部LLM API（Claude/Gemini/Groq/Ollama）へ送信するプロンプトに、企業機密が
含まれる可能性のある文字列（機器のパスワード・IPsec事前共有鍵・SNMP
コミュニティ名・ルーティング認証キー・APIキー・秘密鍵・クレジットカード
番号）が含まれていないかを検出し、送信前にマスクする。

このアプリは "show running-config" の貼り付けや機器コンフィグの取り込みを
扱うため、コンフィグ行に埋め込まれた平文の鍵・パスワードがそのままLLMへの
プロンプトに混入するリスクが実際にある。ネットワーク機器のログには数値列
（バイトカウンタ・タイムスタンプ等）が大量に含まれるため、汎用的な「数字の
並び」検出はクレジットカード番号のような桁数・Luhnチェックを併用し、
誤検知でログ分析結果が壊れないようにしている。
"""
import re

# (カテゴリ名, パターン) — 各パターンはマッチ全体の先頭に「非秘密部分」を
# 残したい場合は group(1) を残し、group(2) 以降を秘密値として扱う。
_ALREADY_MASKED = r'(?!\[REDACTED)'

_SECRET_PATTERNS = [
    ("cisco_username_password", re.compile(
        r'(username\s+\S+\s+password\s+\d+\s+)' + _ALREADY_MASKED + r'(\S+)', re.IGNORECASE)),
    ("cisco_enable_secret", re.compile(
        r'(enable\s+secret\s+\d+\s+)' + _ALREADY_MASKED + r'(\S+)', re.IGNORECASE)),
    ("cisco_line_password", re.compile(
        r'(\bpassword\s+\d+\s+)' + _ALREADY_MASKED + r'(\S+)', re.IGNORECASE)),
    ("ipsec_pre_shared_key", re.compile(
        r'(pre-shared-key\s+(?:ascii-text\s+)?["\']?)' + _ALREADY_MASKED + r'([^\s"\']{3,})', re.IGNORECASE)),
    ("routing_auth_key", re.compile(
        r'((?:authentication-key|key-string)\s+["\']?)' + _ALREADY_MASKED + r'([^\s"\';]{3,})', re.IGNORECASE)),
    ("snmp_community", re.compile(
        r'((?:snmp-server\s+community|set\s+snmp\s+community)\s+)' + _ALREADY_MASKED + r'(\S+)', re.IGNORECASE)),
    ("aws_access_key", re.compile(r'()\b((?:AKIA|ASIA)[0-9A-Z]{16})\b')),
    ("generic_api_key", re.compile(
        r'()\b((?:sk|pk|api|token|bearer)[-_][A-Za-z0-9]{16,})\b', re.IGNORECASE)),
    ("private_key_block", re.compile(
        r'()(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?'
        r'-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)')),
]

# クレジットカード番号らしき桁数の数字列（区切りに半角空白/ハイフンを許容）。
# Luhnチェックで実在しうる番号のみをマスク対象とし、バイトカウンタ等の
# 単なる長い数字列を誤ってマスクしないようにする。
_CC_CANDIDATE = re.compile(r'(?<!\d)(?:\d[ -]?){13,19}(?!\d)')


def _luhn_valid(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0 and total > 0


def sanitize(text: str) -> tuple[str, list[dict]]:
    """
    LLMへ送信する直前のテキストから機密情報らしき文字列をマスクする。
    戻り値: (マスク済みテキスト, 検出内訳 [{"category": str, "count": int}, ...])
    """
    if not text:
        return text, []

    counts: dict[str, int] = {}

    def _mask(m: re.Match, category: str) -> str:
        counts[category] = counts.get(category, 0) + 1
        return f"{m.group(1)}[REDACTED:{category}]"

    result = text
    for category, pattern in _SECRET_PATTERNS:
        result = pattern.sub(lambda m, c=category: _mask(m, c), result)

    def _mask_cc(m: re.Match) -> str:
        raw = re.sub(r'[ -]', '', m.group(0))
        if 13 <= len(raw) <= 19 and _luhn_valid(raw):
            counts["credit_card"] = counts.get("credit_card", 0) + 1
            return "[REDACTED:credit_card]"
        return m.group(0)

    result = _CC_CANDIDATE.sub(_mask_cc, result)

    findings = [{"category": k, "count": v} for k, v in sorted(counts.items())]
    return result, findings
