"""
既知の主要生成AI/LLMサービスのホスト名判定。

pcap解析（TLS SNIベースの宛先検知、内容は見えない）と、mitmproxyベースの
検証用TLS復号プロトタイプ（ai_tls_inspector_prototype.py、内容が見える）の
両方で同じ判定ロジックを共用する。
"""

AI_SERVICE_SNI_SUFFIXES = {
    "anthropic.com":            "Anthropic (Claude API)",
    "claude.ai":                "Claude.ai (Web/Chat)",
    "openai.com":               "OpenAI (ChatGPT/API)",
    "chatgpt.com":              "ChatGPT (Web)",
    "generativelanguage.googleapis.com": "Google (Gemini API)",
    "aistudio.google.com":      "Google AI Studio",
    "gemini.google.com":        "Gemini (Web)",
    "bard.google.com":          "Google Bard/Gemini (Web)",
    "groq.com":                 "Groq API",
    "api.mistral.ai":           "Mistral AI API",
    "cohere.com":               "Cohere API",
    "cohere.ai":                "Cohere API",
    "perplexity.ai":            "Perplexity AI",
    "x.ai":                     "xAI (Grok)",
    "copilot.microsoft.com":    "Microsoft Copilot",
    "huggingface.co":           "Hugging Face",
}

# セッション継続時間がこれを超えたら「長時間接続（張りっぱなしの可能性）」とみなす
AI_SESSION_LONGLIVED_SEC = 1800   # 30分


def match_ai_service(hostname: str) -> str:
    """ホスト名（SNIまたはHTTP Host）を既知の生成AI/LLMサービスと照合する。"""
    if not hostname:
        return ""
    s = hostname.lower().rstrip(".")
    for suffix, label in AI_SERVICE_SNI_SUFFIXES.items():
        if s == suffix or s.endswith("." + suffix):
            return label
    return ""
