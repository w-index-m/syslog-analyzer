"""
【検証用プロトタイプ】TLS復号による生成AIサービス宛通信の内容確認ツール

mitmproxyを使い、既知の生成AI/LLMサービス（Anthropic/OpenAI/Google/Groq等）宛の
HTTPSリクエストを復号し、送信内容（プロンプト等）を確認できるかを技術検証する。
dlp.py の DLP マスク処理も適用し、DLPが「復号後の平文」に対して正しく機能する
ことも合わせて確認できる。

重要 - 必ず読むこと:
  - これは技術検証専用です。自分が管理する端末で、自分の通信に対してのみ
    実行してください。他人の通信を無断で復号することは通信の秘密を侵害します。
  - 社内で本格運用するには、就業規則・労使協定・事前周知等の社内手続きが
    別途必須です（このスクリプト単体では代替できません）。
  - 証明書ピニングをしているアプリ・サイトは復号できず接続エラーになります
    （多くのネイティブアプリがこれを行っています。ブラウザ経由が確認しやすい）。

セットアップ:
  1. pip install mitmproxy
  2. mitmdump -s ai_tls_inspector_prototype.py
     （デフォルトで 127.0.0.1:8080 で待受を開始する）
  3. ブラウザ/OSのプロキシ設定を 127.0.0.1:8080 に向ける
  4. ブラウザで http://mitm.it/ を開き、OS/ブラウザに応じたCA証明書を
     ダウンロード・信頼済み認証局として追加する
     （証明書は ~/.mitmproxy/mitmproxy-ca-cert.pem にも生成されている）
  5. 上記完了後、ブラウザで claude.ai 等にアクセスして送信すると、
     このプロセスのコンソールに検知結果が表示される

終了したら、ブラウザ/OSのプロキシ設定を元に戻し、追加したCA証明書の
信頼設定も削除することを推奨する（検証用の一時的な信頼設定のため）。
"""
from mitmproxy import http

import ai_service_domains
import dlp

_DLP_CATEGORY_JA = {
    "cisco_username_password": "Cisco username password",
    "cisco_enable_secret":     "Cisco enable secret",
    "cisco_line_password":     "Cisco line password",
    "ipsec_pre_shared_key":    "IPsec事前共有鍵",
    "routing_auth_key":        "ルーティング認証キー",
    "snmp_community":          "SNMPコミュニティ名",
    "aws_access_key":          "AWSアクセスキー",
    "generic_api_key":         "APIキー/トークン",
    "private_key_block":       "秘密鍵(PEM)",
    "credit_card":             "クレジットカード番号",
}


class AITrafficInspector:
    """既知の生成AI/LLMサービス宛リクエストを検知し、本文をDLPマスクした上で表示する。"""

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        service = ai_service_domains.match_ai_service(host)
        if not service:
            return

        try:
            body = flow.request.get_text(strict=False) or ""
        except Exception:
            body = "(本文をテキストとして取得できませんでした)"

        redacted, findings = dlp.sanitize(body)

        print("\n" + "=" * 60)
        print(f"[AI通信検知] {service}")
        print(f"  接続先URL : {flow.request.pretty_url}")
        print(f"  メソッド  : {flow.request.method}")
        if findings:
            _detail = " / ".join(
                f"{_DLP_CATEGORY_JA.get(f['category'], f['category'])}×{f['count']}"
                for f in findings
            )
            print(f"  ⚠️ DLP検出: {_detail}")
        print(f"  本文（DLPマスク後・先頭500文字）:\n{redacted[:500]}")
        print("=" * 60)


addons = [AITrafficInspector()]
