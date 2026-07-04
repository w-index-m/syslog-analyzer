import os
import json
import requests

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OLLAMA_BASE_URL   = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL      = os.environ.get("OLLAMA_MODEL", "llama3")
GEMINI_API_KEY    = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL      = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
GROQ_API_KEY      = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL        = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

SYSTEM_PROMPT = """あなたはネットワーク機器のsyslogを解析する専門エンジニアです。
以下のsyslogメッセージを日本語でわかりやすく説明してください。

機器のコンフィグ情報（インターフェース・ルーティング設定）が提供されている場合は、
それを「正常な構成」として参照し、今回のイベントがその構成に対して
本当に異常なのか、構成上問題ない範囲なのかを判断してください。
例：BGPネイバーが1つダウンしても、コンフィグ上に複数のネイバーが定義されていれば
冗長構成があるため影響は限定的、といった判断をしてください。

回答は必ずJSON形式で以下の構造にしてください：
{
  "summary": "一言で何が起きたか（30文字以内）",
  "detail": "詳細な説明（何が起きたか、なぜ起きたか）",
  "impact": "ネットワークへの影響（なし/軽微/中程度/重大）",
  "action": "推奨される対応アクション",
  "telemetry_note": "テレメトリ観点での注目ポイント（この事象が継続/増加する場合の意味）",
  "config_context_note": "コンフィグ情報を参照した場合の判断根拠（コンフィグ情報がない場合は空文字)"
}

JSONのみ返してください。マークダウンの```は不要です。"""

def _build_user_prompt(parsed: dict, raw: str, config_context: str = "") -> str:
    base = f"""
ベンダー: {parsed.get('vendor', '不明')}
ホスト名: {parsed.get('hostname', '不明')}
ファシリティ: {parsed.get('facility', '')}
重要度: {parsed.get('severity', '')}
プロセス/ニーモニック: {parsed.get('process', '')}
メッセージ: {parsed.get('message', raw)}
タグ: {', '.join(parsed.get('tags', []))}
RAWログ: {raw[:300]}
"""
    if config_context:
        base += f"""

────────── 機器のコンフィグ情報（正常構成として参照） ──────────
{config_context[:3000]}
────────────────────────────────────────────
"""
    return base

def analyze_with_claude(parsed: dict, raw: str, config_context: str = "") -> tuple[str, str]:
    """Claude APIで解析。戻り値: (説明JSON文字列, モデル名)"""
    if not ANTHROPIC_API_KEY:
        return "", ""
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            },
            json={
                "model": "claude-sonnet-4-6",
                "max_tokens": 800,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": _build_user_prompt(parsed, raw, config_context)}]
            },
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        text = data["content"][0]["text"].strip()
        # JSON整形
        text = text.replace("```json", "").replace("```", "").strip()
        return text, "claude-sonnet-4-6"
    except Exception as e:
        print(f"[Claude API error] {e}")
        return "", ""

def analyze_with_ollama(parsed: dict, raw: str, config_context: str = "") -> tuple[str, str]:
    """Ollamaローカルで解析。戻り値: (説明JSON文字列, モデル名)"""
    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": _build_user_prompt(parsed, raw, config_context)}
                ],
                "stream": False,
                "options": {"temperature": 0.2}
            },
            timeout=60
        )
        resp.raise_for_status()
        text = resp.json()["message"]["content"].strip()
        text = text.replace("```json", "").replace("```", "").strip()
        return text, f"ollama/{OLLAMA_MODEL}"
    except Exception as e:
        print(f"[Ollama error] {e}")
        return "", ""

def check_ollama_available() -> bool:
    try:
        r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3)
        return r.status_code == 200
    except:
        return False

def list_ollama_models() -> list:
    """Ollama に導入済みのモデル名一覧を返す（未起動時は空）。"""
    try:
        r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=3)
        if r.status_code == 200:
            return [m.get("name", "") for m in r.json().get("models", []) if m.get("name")]
    except Exception:
        pass
    return []


def pull_ollama_model(name: str, progress_cb=None) -> tuple[bool, str]:
    """
    Ollama にモデルをダウンロード（pull）する。
    progress_cb(status:str, pct:float|None) が渡されれば進捗を通知。
    戻り値: (成功したか, メッセージ)
    """
    import json as _json
    name = (name or "").strip()
    if not name:
        return False, "モデル名を指定してください。"
    try:
        with requests.post(f"{OLLAMA_BASE_URL}/api/pull",
                           json={"name": name, "stream": True},
                           stream=True, timeout=3600) as r:
            if r.status_code != 200:
                return False, f"pull 失敗 (HTTP {r.status_code}): {r.text[:200]}"
            last_status = ""
            for line in r.iter_lines():
                if not line:
                    continue
                try:
                    ev = _json.loads(line.decode("utf-8"))
                except Exception:
                    continue
                if ev.get("error"):
                    return False, f"エラー: {ev['error']}"
                status = ev.get("status", "")
                last_status = status
                pct = None
                if ev.get("total"):
                    pct = min(1.0, ev.get("completed", 0) / ev["total"])
                if progress_cb:
                    progress_cb(status, pct)
                if status == "success":
                    return True, f"'{name}' の取得が完了しました。"
            # ストリーム終了（success 明示が無くてもエラーが無ければ成功扱い）
            return True, f"'{name}' の取得が完了しました（{last_status}）。"
    except Exception as e:
        return False, f"pull 通信エラー: {e}"

def check_claude_available() -> bool:
    return bool(ANTHROPIC_API_KEY)

def check_gemini_available() -> bool:
    return bool(GEMINI_API_KEY)

def check_groq_available() -> bool:
    return bool(GROQ_API_KEY)


# ── 共通 raw caller ──────────────────────────────────────────────

def _call_gemini_raw(system: str, user: str, max_tokens: int = 800) -> tuple[str, str]:
    if not GEMINI_API_KEY:
        return "", ""
    try:
        resp = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent",
            params={"key": GEMINI_API_KEY},
            json={
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"parts": [{"text": user}]}],
                "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.2},
            },
            timeout=30,
        )
        resp.raise_for_status()
        text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        return text.replace("```json", "").replace("```", "").strip(), f"gemini/{GEMINI_MODEL}"
    except Exception as e:
        print(f"[Gemini error] {e}")
        return "", ""


def _call_groq_raw(system: str, user: str, max_tokens: int = 800) -> tuple[str, str]:
    if not GROQ_API_KEY:
        return "", ""
    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}",
                     "Content-Type": "application/json"},
            json={
                "model": GROQ_MODEL,
                "messages": [{"role": "system", "content": system},
                             {"role": "user",   "content": user}],
                "max_tokens": max_tokens,
                "temperature": 0.2,
            },
            timeout=30,
        )
        resp.raise_for_status()
        text = resp.json()["choices"][0]["message"]["content"].strip()
        return text.replace("```json", "").replace("```", "").strip(), f"groq/{GROQ_MODEL}"
    except Exception as e:
        print(f"[Groq error] {e}")
        return "", ""

def analyze_with_gemini(parsed: dict, raw: str, config_context: str = "") -> tuple[str, str]:
    return _call_gemini_raw(SYSTEM_PROMPT, _build_user_prompt(parsed, raw, config_context))

def analyze_with_groq(parsed: dict, raw: str, config_context: str = "") -> tuple[str, str]:
    return _call_groq_raw(SYSTEM_PROMPT, _build_user_prompt(parsed, raw, config_context))


LAST_LLM_ERROR = ""  # 直近のLLM呼び出し失敗理由（UI表示用）


def ask_llm(system: str, user: str, mode: str = "auto", max_tokens: int = 1000) -> tuple[str, str]:
    """
    汎用LLM呼び出し。どのタブからでも使えるシンプルなインターフェース。
    戻り値: (テキスト, モデル名)  失敗時は ("", "")
    """
    globals()["LAST_LLM_ERROR"] = ""

    def _claude():
        if not ANTHROPIC_API_KEY:
            return "", ""
        try:
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": ANTHROPIC_API_KEY,
                         "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": "claude-sonnet-4-6", "max_tokens": max_tokens,
                      "system": system,
                      "messages": [{"role": "user", "content": user}]},
                timeout=45,
            )
            resp.raise_for_status()
            return resp.json()["content"][0]["text"].strip(), "claude-sonnet-4-6"
        except Exception as e:
            print(f"[ask_llm:Claude] {e}"); return "", ""

    def _ollama():
        try:
            resp = requests.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={"model": OLLAMA_MODEL,
                      "messages": [{"role": "system", "content": system},
                                   {"role": "user",   "content": user}],
                      "stream": False, "options": {"temperature": 0.2}},
                timeout=180,
            )
            if resp.status_code == 404 or "not found" in (resp.text or "").lower():
                # モデル未導入が最頻の原因
                globals()["LAST_LLM_ERROR"] = (
                    f"Ollamaにモデル '{OLLAMA_MODEL}' が見つかりません。"
                    f"`ollama pull {OLLAMA_MODEL}` で取得するか、"
                    f"サイドバーで導入済みモデルを選択してください。")
                print(f"[ask_llm:Ollama] model not found: {OLLAMA_MODEL}")
                return "", ""
            resp.raise_for_status()
            return resp.json()["message"]["content"].strip(), f"ollama/{OLLAMA_MODEL}"
        except Exception as e:
            globals()["LAST_LLM_ERROR"] = f"Ollama接続エラー: {e}"
            print(f"[ask_llm:Ollama] {e}"); return "", ""

    def _gemini():
        return _call_gemini_raw(system, user, max_tokens)

    def _groq():
        return _call_groq_raw(system, user, max_tokens)

    providers = {"claude": _claude, "gemini": _gemini, "groq": _groq, "ollama": _ollama}
    if mode in providers:
        return providers[mode]()
    for fn in (_claude, _gemini, _groq, _ollama):
        text, model = fn()
        if text:
            return text, model
    return "", ""

def analyze(parsed: dict, raw: str, mode: str = "auto", config_context: str = "") -> tuple[str, str]:
    """
    mode: "auto"   = Claude → Gemini → Groq → Ollama の順に試行
          "claude" = Claude のみ
          "gemini" = Gemini のみ
          "groq"   = Groq のみ
          "ollama" = Ollama のみ（完全ローカル）
          "none"   = AI解析なし
    """
    if mode == "none":
        return "", "なし"

    _providers = {
        "claude": lambda: analyze_with_claude(parsed, raw, config_context),
        "gemini": lambda: analyze_with_gemini(parsed, raw, config_context),
        "groq":   lambda: analyze_with_groq(parsed, raw, config_context),
        "ollama": lambda: analyze_with_ollama(parsed, raw, config_context),
    }

    if mode in _providers:
        explanation, model = _providers[mode]()
    else:  # auto
        explanation, model = "", ""
        for key in ("claude", "gemini", "groq", "ollama"):
            explanation, model = _providers[key]()
            if explanation:
                break

    if not explanation:
        explanation = json.dumps(_rule_based_explain(parsed), ensure_ascii=False)
        model = "ルールベース"

    return explanation, model


# ═══════════════════════════════════════════════════
# LLM-as-a-Judge: AI解析結果の品質チェック
# ═══════════════════════════════════════════════════

JUDGE_SYSTEM_PROMPT = """あなたはネットワークsyslog解析AIの「出力品質」を審査する専門レビュアーです。
これから提示する「元のログ情報」と「AIが生成した解析結果」を比較し、
以下のルーブリック（評価基準）に基づいて厳格に採点してください。

────────── 評価ルーブリック ──────────

1. 正確性 (accuracy) — 0〜10点
   - 重要度(impact)判定がログの内容・重要度に対して適切か
   - 過大評価（軽微な事象を"重大"とする）や過小評価（重大な事象を"なし"とする）がないか

2. 整合性 (consistency) — 0〜10点
   - コンフィグ情報が提供されている場合、それと矛盾する記述がないか
   - 例：コンフィグに存在しないインターフェースやプロトコルに言及していないか
   - コンフィグがない場合は「言及なしで一貫しているか」を見る（10点扱い可）

3. 完全性 (completeness) — 0〜10点
   - summary/detail/impact/action/telemetry_note が全て意味のある内容で埋まっているか
   - 空欄や「不明」「N/A」のような実質的に無意味な内容がないか

4. 実用性 (actionability) — 0〜10点
   - action（推奨対応）が実際の運用者にとって具体的で実行可能か
   - 「確認してください」のような曖昧な表現だけで終わっていないか

────────── 出力形式 ──────────

回答は必ず以下のJSON形式のみで返してください。マークダウンの```は不要です：
{
  "accuracy_score": 0-10の整数,
  "consistency_score": 0-10の整数,
  "completeness_score": 0-10の整数,
  "actionability_score": 0-10の整数,
  "total_score": 4項目の合計(0-40),
  "grade": "A" or "B" or "C" or "D",
  "issues": ["検出された具体的な問題点のリスト。問題なければ空配列"],
  "judge_comment": "総合的な所見を1〜2文で"
}

採点基準: total_score 36-40=A, 28-35=B, 18-27=C, 0-17=D
"""

def _build_judge_prompt(parsed: dict, raw: str, ai_explanation: str, config_context: str = "") -> str:
    prompt = f"""
────────── 元のログ情報 ──────────
ベンダー: {parsed.get('vendor', '不明')}
ホスト名: {parsed.get('hostname', '不明')}
重要度(パーサー判定): {parsed.get('severity', '')}
メッセージ: {parsed.get('message', raw)}
タグ: {', '.join(parsed.get('tags', []))}
"""
    if config_context:
        prompt += f"""
────────── 提供されたコンフィグ情報 ──────────
{config_context[:2000]}
"""
    else:
        prompt += "\n（コンフィグ情報は提供されていません）\n"

    prompt += f"""
────────── AIが生成した解析結果（審査対象） ──────────
{ai_explanation}
────────────────────────────────────────
"""
    return prompt


def judge_with_claude(parsed: dict, raw: str, ai_explanation: str,
                      config_context: str = "") -> dict | None:
    if not ANTHROPIC_API_KEY:
        return None
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            },
            json={
                "model": "claude-sonnet-4-6",
                "max_tokens": 600,
                "system": JUDGE_SYSTEM_PROMPT,
                "messages": [{"role": "user",
                             "content": _build_judge_prompt(parsed, raw, ai_explanation, config_context)}]
            },
            timeout=30
        )
        resp.raise_for_status()
        text = resp.json()["content"][0]["text"].strip()
        text = text.replace("```json", "").replace("```", "").strip()
        result = json.loads(text)
        result["judge_model"] = "claude-sonnet-4-6"
        return result
    except Exception as e:
        print(f"[Judge:Claude error] {e}")
        return None


def judge_with_ollama(parsed: dict, raw: str, ai_explanation: str,
                      config_context: str = "") -> dict | None:
    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "messages": [
                    {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                    {"role": "user",
                     "content": _build_judge_prompt(parsed, raw, ai_explanation, config_context)}
                ],
                "stream": False,
                "options": {"temperature": 0.0}
            },
            timeout=60
        )
        resp.raise_for_status()
        text = resp.json()["message"]["content"].strip()
        text = text.replace("```json", "").replace("```", "").strip()
        result = json.loads(text)
        result["judge_model"] = f"ollama/{OLLAMA_MODEL}"
        return result
    except Exception as e:
        print(f"[Judge:Ollama error] {e}")
        return None


def _rule_based_judge(parsed: dict, ai_explanation: str) -> dict:
    """LLMが使えない場合のルールベース簡易品質チェック"""
    issues = []
    try:
        data = json.loads(ai_explanation)
    except Exception:
        return {
            "accuracy_score": 0, "consistency_score": 0,
            "completeness_score": 0, "actionability_score": 0,
            "total_score": 0, "grade": "D",
            "issues": ["AI解析結果がJSON形式として解析できませんでした"],
            "judge_comment": "解析結果の形式に問題があります",
            "judge_model": "ルールベース"
        }

    completeness = 10
    for field in ["summary", "detail", "impact", "action", "telemetry_note"]:
        val = data.get(field, "")
        if not val or val in ("不明", "N/A", "なし", ""):
            completeness -= 2
            issues.append(f"'{field}' フィールドが空または無意味です")
    completeness = max(0, completeness)

    actionability = 10
    vague_phrases = ["確認してください", "様子を見てください", "注意してください"]
    action_text = data.get("action", "")
    if any(p == action_text.strip() for p in vague_phrases) or len(action_text) < 5:
        actionability = 3
        issues.append("対応アクションが具体性に欠けます")

    accuracy = 7  # ルールベースでは判定不可のため中間値
    consistency = 7

    total = accuracy + consistency + completeness + actionability
    grade = "A" if total >= 36 else "B" if total >= 28 else "C" if total >= 18 else "D"

    return {
        "accuracy_score": accuracy, "consistency_score": consistency,
        "completeness_score": completeness, "actionability_score": actionability,
        "total_score": total, "grade": grade,
        "issues": issues if issues else [],
        "judge_comment": "ルールベースの簡易チェックです。LLMによる詳細な品質評価ではありません。",
        "judge_model": "ルールベース"
    }


def judge_with_gemini(parsed: dict, raw: str, ai_explanation: str,
                      config_context: str = "") -> dict | None:
    text, model = _call_gemini_raw(
        JUDGE_SYSTEM_PROMPT,
        _build_judge_prompt(parsed, raw, ai_explanation, config_context),
        max_tokens=600,
    )
    if not text:
        return None
    try:
        result = json.loads(text)
        result["judge_model"] = model
        return result
    except Exception:
        return None


def judge_with_groq(parsed: dict, raw: str, ai_explanation: str,
                    config_context: str = "") -> dict | None:
    text, model = _call_groq_raw(
        JUDGE_SYSTEM_PROMPT,
        _build_judge_prompt(parsed, raw, ai_explanation, config_context),
        max_tokens=600,
    )
    if not text:
        return None
    try:
        result = json.loads(text)
        result["judge_model"] = model
        return result
    except Exception:
        return None


def judge_quality(parsed: dict, raw: str, ai_explanation: str, mode: str = "auto",
                  config_context: str = "") -> dict:
    """AI解析結果の品質を LLM-as-a-Judge で評価する"""
    if mode == "none" or not ai_explanation:
        return _rule_based_judge(parsed, ai_explanation)

    _providers = {
        "claude": lambda: judge_with_claude(parsed, raw, ai_explanation, config_context),
        "gemini": lambda: judge_with_gemini(parsed, raw, ai_explanation, config_context),
        "groq":   lambda: judge_with_groq(parsed, raw, ai_explanation, config_context),
        "ollama": lambda: judge_with_ollama(parsed, raw, ai_explanation, config_context),
    }

    if mode in _providers:
        result = _providers[mode]()
    else:  # auto
        result = None
        for key in ("claude", "gemini", "groq", "ollama"):
            result = _providers[key]()
            if result:
                break

    return result or _rule_based_judge(parsed, ai_explanation)

def _rule_based_explain(parsed: dict) -> dict:
    """LLMが使えない場合のルールベース解説"""
    severity = parsed.get("severity", "INFO")
    message = parsed.get("message", "")
    vendor = parsed.get("vendor", "")
    tags = parsed.get("tags", [])

    impact_map = {
        "EMERGENCY": "重大", "ALERT": "重大", "CRITICAL": "重大",
        "ERROR": "中程度", "WARNING": "軽微",
        "NOTICE": "なし", "INFO": "なし", "DEBUG": "なし"
    }

    return {
        "summary": f"{vendor} から {severity} レベルのログ",
        "detail": message[:200],
        "impact": impact_map.get(severity, "不明"),
        "action": "ERROR以上の場合は機器の状態を確認してください" if severity in ("ERROR","CRITICAL","ALERT","EMERGENCY") else "通常監視を継続",
        "telemetry_note": "このイベントが短時間に多発する場合は障害の前兆の可能性があります",
        "config_context_note": ""
    }


# ═══════════════════════════════════════════════════
# ネットワーク健全性のLLM相関分析
# ═══════════════════════════════════════════════════

HEALTH_SYSTEM_PROMPT = """あなたはネットワーク機器の健全性を診断する上級ネットワークエンジニアです。
提供される機器のメトリクス（CPU、メモリ、スループット、破棄、ブロードキャスト、エラー等）と
直近のsyslogイベントを総合的に分析し、機器の健全性を診断してください。

特に重要なのは「指標間の因果関係（相関）」の推定です。例：
- ブロードキャスト急増 → CPU負荷上昇 → 破棄増加 → ルーティングプロトコル不安定
  という連鎖がある場合、根本原因はブロードキャストストームであり、
  CPUやルーティングの問題はその「結果」であると見抜いてください。
- スループットが期待値より極端に低い場合、物理障害・ネゴシエーション不一致・
  上位回線の問題などを推定してください。

バラバラの数値を個別に述べるのではなく、「何が根本原因で、何がその結果か」という
ストーリーとして診断することが最も重要です。

回答は必ず以下のJSON形式のみで返してください。マークダウンの```は不要：
{
  "diagnosis": "総合診断（この機器は今健全か、何が起きているか）",
  "root_cause": "推定される根本原因（相関を踏まえて。問題がなければ'特になし'）",
  "causal_chain": ["原因から結果への連鎖をステップで。例: ['ブロードキャスト急増', 'CPU上昇', '破棄増加']。なければ空配列"],
  "throughput_assessment": "スループットの評価（期待通り出ているか、低い場合の推定原因）",
  "priority_action": "今すぐ取るべき最優先アクション（なければ'通常監視を継続'）",
  "risk_if_ignored": "放置した場合のリスク"
}
"""

def _build_health_prompt(device_health: dict, recent_logs: list, config_context: str = "") -> str:
    metrics = device_health.get("metrics", {})
    throughput = device_health.get("throughput", [])
    issues = device_health.get("issues", [])

    prompt = f"""
────────── 機器情報 ──────────
IPアドレス: {device_health.get('source_ip', '不明')}
ホスト名: {device_health.get('hostname', '不明')}
算出ヘルススコア: {device_health.get('health_score', '?')}/100 (ステータス: {device_health.get('status', '?')})

────────── システムメトリクス ──────────
"""
    for k, v in metrics.items():
        prompt += f"  {k}: {v}\n"

    prompt += "\n────────── インターフェース別スループット・品質 ──────────\n"
    for tp in throughput[:10]:
        prompt += f"""  IF {tp.get('if_index','?')} (状態:{tp.get('oper_status','?')}):
    受信={_fmt_bps(tp.get('in_bps'))} 送信={_fmt_bps(tp.get('out_bps'))} 帯域使用率={tp.get('bandwidth_util_pct','?')}%
    ブロードキャスト={tp.get('broadcast_pct','?')}% 破棄={tp.get('discard_pct','?')}% エラー={tp.get('error_pct','?')}%
"""

    if issues:
        prompt += "\n────────── 自動検出された問題 ──────────\n"
        for iss in issues:
            prompt += f"  [{iss.get('level','')}] {iss.get('category','')}: {iss.get('msg','')}\n"

    if recent_logs:
        prompt += "\n────────── 直近のsyslogイベント（最大10件） ──────────\n"
        for log in recent_logs[:10]:
            prompt += f"  [{log.get('severity','')}] {log.get('process','')}: {log.get('message','')[:120]}\n"

    if config_context:
        prompt += f"\n────────── コンフィグ情報 ──────────\n{config_context[:1500]}\n"

    return prompt

def _fmt_bps(bps):
    if bps is None:
        return "?"
    if bps >= 1e9:
        return f"{bps/1e9:.2f}Gbps"
    if bps >= 1e6:
        return f"{bps/1e6:.2f}Mbps"
    if bps >= 1e3:
        return f"{bps/1e3:.2f}Kbps"
    return f"{bps}bps"

def diagnose_health_with_claude(device_health, recent_logs, config_context=""):
    if not ANTHROPIC_API_KEY:
        return None
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": ANTHROPIC_API_KEY,
                     "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": "claude-sonnet-4-6", "max_tokens": 1000,
                  "system": HEALTH_SYSTEM_PROMPT,
                  "messages": [{"role": "user",
                               "content": _build_health_prompt(device_health, recent_logs, config_context)}]},
            timeout=40
        )
        resp.raise_for_status()
        text = resp.json()["content"][0]["text"].strip()
        text = text.replace("```json", "").replace("```", "").strip()
        result = json.loads(text)
        result["diagnosis_model"] = "claude-sonnet-4-6"
        return result
    except Exception as e:
        print(f"[Health diagnosis:Claude error] {e}")
        return None

def diagnose_health_with_ollama(device_health, recent_logs, config_context=""):
    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={"model": OLLAMA_MODEL,
                  "messages": [{"role": "system", "content": HEALTH_SYSTEM_PROMPT},
                               {"role": "user",
                                "content": _build_health_prompt(device_health, recent_logs, config_context)}],
                  "stream": False, "options": {"temperature": 0.1}},
            timeout=90
        )
        resp.raise_for_status()
        text = resp.json()["message"]["content"].strip()
        text = text.replace("```json", "").replace("```", "").strip()
        result = json.loads(text)
        result["diagnosis_model"] = f"ollama/{OLLAMA_MODEL}"
        return result
    except Exception as e:
        print(f"[Health diagnosis:Ollama error] {e}")
        return None

def diagnose_health_with_gemini(device_health, recent_logs, config_context=""):
    text, model = _call_gemini_raw(
        HEALTH_SYSTEM_PROMPT,
        _build_health_prompt(device_health, recent_logs, config_context),
        max_tokens=1000,
    )
    if not text:
        return None
    try:
        result = json.loads(text)
        result["diagnosis_model"] = model
        return result
    except Exception:
        return None


def diagnose_health_with_groq(device_health, recent_logs, config_context=""):
    text, model = _call_groq_raw(
        HEALTH_SYSTEM_PROMPT,
        _build_health_prompt(device_health, recent_logs, config_context),
        max_tokens=1000,
    )
    if not text:
        return None
    try:
        result = json.loads(text)
        result["diagnosis_model"] = model
        return result
    except Exception:
        return None


def diagnose_health(device_health, recent_logs, mode="auto", config_context=""):
    """機器の健全性をLLMで総合診断する"""
    if mode == "none":
        return _rule_based_health_diagnosis(device_health)

    _providers = {
        "claude": lambda: diagnose_health_with_claude(device_health, recent_logs, config_context),
        "gemini": lambda: diagnose_health_with_gemini(device_health, recent_logs, config_context),
        "groq":   lambda: diagnose_health_with_groq(device_health, recent_logs, config_context),
        "ollama": lambda: diagnose_health_with_ollama(device_health, recent_logs, config_context),
    }

    if mode in _providers:
        result = _providers[mode]()
    else:  # auto
        result = None
        for key in ("claude", "gemini", "groq", "ollama"):
            result = _providers[key]()
            if result:
                break

    return result or _rule_based_health_diagnosis(device_health)

ICMP_REDIRECT_SYSTEM_PROMPT = """あなたはネットワークエンジニアです。
ICMP redirectが大量発生している機器について、提供されたデータ（SNMPカウンタ・syslog・ルーティング情報）を総合的に分析し、
根本原因と対処法を日本語で回答してください。

必ず以下のJSON形式で返してください（マークダウンの```不要）:
{
  "root_cause": "根本原因の推定（具体的に）",
  "causal_chain": ["原因A", "→ 結果B", "→ 結果C"],
  "affected_destinations": ["影響を受けている宛先IPリスト"],
  "routing_issue": "ルーティング設定上の問題点",
  "priority_action": "最優先で実施すべき対処",
  "additional_checks": ["追加確認事項1", "追加確認事項2"],
  "risk_if_ignored": "放置した場合のリスク",
  "diagnosis_model": ""
}"""


def _build_icmp_redirect_prompt(ip: str, snmp_data: list, redirect_logs: list, routing_summary: str) -> str:
    log_lines = "\n".join(
        f"  [{l.get('received_at','')[:19]}] {l.get('message','')[:200]}"
        for l in redirect_logs[:20]
    )
    snmp_lines = "\n".join(
        f"  {s.get('oid_name','')}: 累積={s.get('value','')}, 増分={s.get('diff','不明')}/poll, アラート={s.get('alert_level','')}"
        for s in snmp_data
    )
    return f"""
対象機器IP: {ip}

【SNMPカウンタ（ICMP-MIB）】
{snmp_lines or "データなし"}

【関連syslogメッセージ（直近20件）】
{log_lines or "syslogなし"}

【機器のルーティング情報（コンフィグより）】
{routing_summary[:2000] if routing_summary else "コンフィグ未登録"}
"""


def diagnose_icmp_redirect(ip: str, snmp_data: list, redirect_logs: list,
                           routing_summary: str = "", mode: str = "auto") -> dict:
    """ICMP redirect大量発生の根本原因をLLMで診断する"""
    prompt = _build_icmp_redirect_prompt(ip, snmp_data, redirect_logs, routing_summary)

    def _call_claude():
        if not ANTHROPIC_API_KEY:
            return None
        try:
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": ANTHROPIC_API_KEY,
                         "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={"model": "claude-sonnet-4-6", "max_tokens": 1000,
                      "system": ICMP_REDIRECT_SYSTEM_PROMPT,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=40
            )
            resp.raise_for_status()
            text = resp.json()["content"][0]["text"].strip().replace("```json","").replace("```","").strip()
            result = json.loads(text)
            result["diagnosis_model"] = "claude-sonnet-4-6"
            return result
        except Exception as e:
            print(f"[ICMP redirect diagnosis:Claude] {e}")
            return None

    def _call_ollama():
        try:
            resp = requests.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={"model": OLLAMA_MODEL,
                      "messages": [{"role": "system", "content": ICMP_REDIRECT_SYSTEM_PROMPT},
                                   {"role": "user", "content": prompt}],
                      "stream": False, "options": {"temperature": 0.1}},
                timeout=90
            )
            resp.raise_for_status()
            text = resp.json()["message"]["content"].strip().replace("```json","").replace("```","").strip()
            result = json.loads(text)
            result["diagnosis_model"] = f"ollama/{OLLAMA_MODEL}"
            return result
        except Exception as e:
            print(f"[ICMP redirect diagnosis:Ollama] {e}")
            return None

    def _call_gemini():
        text, model = _call_gemini_raw(ICMP_REDIRECT_SYSTEM_PROMPT, prompt, max_tokens=1000)
        if not text:
            return None
        try:
            r = json.loads(text)
            r["diagnosis_model"] = model
            return r
        except Exception:
            return None

    def _call_groq():
        text, model = _call_groq_raw(ICMP_REDIRECT_SYSTEM_PROMPT, prompt, max_tokens=1000)
        if not text:
            return None
        try:
            r = json.loads(text)
            r["diagnosis_model"] = model
            return r
        except Exception:
            return None

    _icmp_providers = {
        "claude": _call_claude, "gemini": _call_gemini,
        "groq": _call_groq,    "ollama": _call_ollama,
    }
    result = None
    if mode in _icmp_providers:
        result = _icmp_providers[mode]()
    else:  # auto
        for key in ("claude", "gemini", "groq", "ollama"):
            result = _icmp_providers[key]()
            if result:
                break
    if not result:
        # ルールベースフォールバック
        result = {
            "root_cause": "ルーティング設定の不整合（デフォルトGW誤設定またはスタティックルート欠落）が疑われます",
            "causal_chain": ["ホストが最適でないGWへパケット送信", "→ ルーターがICMP redirectを送信", "→ ホストが誘導先へ再送"],
            "affected_destinations": [],
            "routing_issue": "コンフィグ情報と実際のルーティングテーブルの確認が必要",
            "priority_action": "show ip redirects / show ip route で実際のルーティングを確認し、不要なICMP redirectを無効化（no ip redirects）",
            "additional_checks": ["デフォルトゲートウェイの設定確認", "スタティックルートの過不足確認"],
            "risk_if_ignored": "帯域の無駄遣い・レイテンシ増加・ルーティングループの可能性",
            "diagnosis_model": "ルールベース"
        }
    return result


def _rule_based_health_diagnosis(device_health):
    issues = device_health.get("issues", [])
    critical = [i for i in issues if i.get("level") == "critical"]
    status = device_health.get("status", "unknown")
    if status == "healthy":
        diagnosis = "機器は健全な状態です。主要指標に問題は検出されていません。"
        root_cause = "特になし"
    elif critical:
        cats = ", ".join(set(i.get("category","") for i in critical))
        diagnosis = f"重大な問題が検出されています（{cats}）。早急な確認が必要です。"
        root_cause = critical[0].get("msg", "不明")
    else:
        diagnosis = "軽微な注意事項があります。経過観察を推奨します。"
        root_cause = issues[0].get("msg", "不明") if issues else "特になし"
    return {
        "diagnosis": diagnosis,
        "root_cause": root_cause,
        "causal_chain": [],
        "throughput_assessment": "ルールベース診断のため詳細分析は省略",
        "priority_action": "criticalな問題から順に確認してください" if critical else "通常監視を継続",
        "risk_if_ignored": "問題が継続・悪化する可能性があります",
        "diagnosis_model": "ルールベース"
    }


# ─────────────────────────────────────────
# pcap 総合 AI 診断
# ─────────────────────────────────────────

_PCAP_SYSTEM_PROMPT = """あなたはパケットキャプチャ（pcap）を分析するネットワークエンジニアです。
提供されるpcap解析サマリーを読み、ネットワーク上の問題を日本語で診断してください。

必ずJSON形式で以下の構造で返してください:
{
  "overall_health": "正常|要注意|問題あり|重大",
  "summary": "全体状況を2〜3文で要約",
  "top_issues": [
    {
      "category": "問題カテゴリ（TCP/DNS/DHCP/VoIP/TLS/HTTP/ICMPなど）",
      "severity": "高|中|低",
      "description": "何が問題か",
      "root_cause": "推定される原因",
      "action": "推奨する対応"
    }
  ],
  "positive_findings": ["問題のなかった点・正常な点"],
  "priority_action": "最優先で行うべき対応",
  "diagnosis_model": ""
}

JSONのみ返してください。```は不要です。"""


def _build_pcap_prompt(pcap_result: dict) -> str:
    r = pcap_result
    icmp_types   = ", ".join(i["name"] + "(" + str(i["count"]) + "件)" for i in r.get("icmp_summary", []))
    dhcp_types   = ", ".join(str(k) + ":" + str(v) for k, v in r.get("dhcp_summary", {}).items())
    http_status  = ", ".join(str(i["status_code"]) + ":" + str(i["count"]) + "件" for i in r.get("http_summary", []))
    dns_s        = r.get("dns_summary", {})
    tls_s        = r.get("tls_summary", {})

    lines = [
        f"キャプチャ期間: {r.get('capture_start','')} 〜 {r.get('capture_end','')}",
        f"総パケット数: {r.get('total_packets', 0):,}",
        "",
        "【ICMP】",
        f"  redirect検出: {len(r.get('icmp_redirects', []))} 件",
        f"  タイプ別: {icmp_types}",
        "",
        "【TCP】",
        f"  問題フロー: {len(r.get('tcp_issues', []))} 件",
        f"  再送多発: {len(r.get('tcp_retransmissions', []))} フロー",
        f"  SYN未応答（接続失敗）: {len(r.get('tcp_syn_no_synack', []))} フロー",
        f"  ゼロウィンドウ: {len(r.get('tcp_zero_window', []))} フロー",
    ]
    if r.get("tcp_issues"):
        for i in r["tcp_issues"][:5]:
            lines.append("    - " + i.get("type","") + " " + i.get("src","") + "→" + i.get("dst","") + " : " + i.get("description","")[:80])

    lines += [
        "",
        "【DNS】",
        f"  クエリ: {dns_s.get('queries',0)} / レスポンス: {dns_s.get('responses',0)}",
        f"  NXDOMAIN: {dns_s.get('nxdomain',0)} / SERVFAIL: {dns_s.get('servfail',0)}",
        f"  応答遅延: {dns_s.get('slow',0)} 件",
    ]
    if r.get("dns_issues"):
        for i in r["dns_issues"][:5]:
            lines.append("    - [" + i.get("type","") + "] " + i.get("name","") + " " + i.get("detail","")[:60])

    lines += [
        "",
        "【DHCP】",
        f"  メッセージタイプ別: {dhcp_types}",
        f"  問題: {len(r.get('dhcp_issues', []))} 件",
    ]
    for i in r.get("dhcp_issues", [])[:3]:
        lines.append("    - [" + i.get("event","") + "] " + i.get("issue","")[:80])

    lines += [
        "",
        "【HTTP】",
        f"  ステータス別: {http_status}",
        f"  4xx/5xxエラー: {len(r.get('http_errors', []))} 件",
    ]
    for e in r.get("http_errors", [])[:3]:
        lines.append(f"    - {e.get('method','')} {e.get('host','')} → HTTP {e.get('status_code','')}")

    lines += [
        "",
        "【TLS/HTTPS】",
        f"  接続数: {tls_s.get('sessions',0)} / ユニークサイト: {tls_s.get('unique_sites',0)}",
        f"  Fatal Alert: {tls_s.get('fatal_alerts',0)} 件",
        f"  非推奨TLS（1.0/1.1）: {tls_s.get('deprecated_tls',0)} 件",
    ]
    for a in r.get("tls_alerts", [])[:3]:
        lines.append(f"    - [{a.get('alert_type','')}] {a.get('src','')}→{a.get('dst','')} : {a.get('description','')[:60]}")

    lines += [
        "",
        "【IPフラグメント】",
        f"  フラグメント発生フロー: {len(r.get('ip_fragments', []))} 件",
    ]
    for f in r.get("ip_fragments", [])[:3]:
        lines.append(f"    - {f.get('src','')}→{f.get('dst','')} {f.get('fragment_count',0)}パケット : {f.get('description','')[:60]}")

    lines += [
        "",
        "【ARP】",
        f"  異常（スプーフィング疑い）: {len(r.get('arp_anomalies', []))} 件",
    ]

    # VoIP
    vc = r.get("voip_stream_count", 0)
    if vc > 0:
        lines += [
            "",
            "【VoIP/RTP】",
            f"  ストリーム数: {vc} / 平均MOS: {r.get('voip_avg_mos', 0)} / 品質不良: {r.get('voip_poor_streams', 0)} ストリーム",
        ]
        for s in r.get("voip_streams", [])[:3]:
            lines.append(f"    - {s.get('src_ip','')}→{s.get('dst_ip','')} MOS={s.get('mos','')} "
                         f"ジッター={s.get('jitter_ms','')}ms ロス={s.get('loss_pct','')}%")

    return "\n".join(lines)


def diagnose_pcap(pcap_result: dict, mode: str = "auto") -> dict:
    """
    pcap解析結果を LLM に投げて総合診断を返す。
    戻り値の構造:
        overall_health, summary, top_issues[], positive_findings[],
        priority_action, diagnosis_model
    """
    prompt = _build_pcap_prompt(pcap_result)

    def _parse(text: str, model: str) -> dict | None:
        try:
            r = json.loads(text)
            r["diagnosis_model"] = model
            return r
        except Exception:
            return None

    def _call_claude():
        if not ANTHROPIC_API_KEY:
            return None
        try:
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": ANTHROPIC_API_KEY,
                         "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": "claude-sonnet-4-6", "max_tokens": 1500,
                      "system": _PCAP_SYSTEM_PROMPT,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=45,
            )
            resp.raise_for_status()
            text = resp.json()["content"][0]["text"].strip().replace("```json","").replace("```","").strip()
            return _parse(text, "claude-sonnet-4-6")
        except Exception as e:
            print(f"[pcap diag:Claude] {e}")
            return None

    def _call_ollama():
        try:
            resp = requests.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={"model": OLLAMA_MODEL,
                      "messages": [{"role": "system", "content": _PCAP_SYSTEM_PROMPT},
                                   {"role": "user",   "content": prompt}],
                      "stream": False, "options": {"temperature": 0.1}},
                timeout=120,
            )
            resp.raise_for_status()
            text = resp.json()["message"]["content"].strip().replace("```json","").replace("```","").strip()
            return _parse(text, f"ollama/{OLLAMA_MODEL}")
        except Exception as e:
            print(f"[pcap diag:Ollama] {e}")
            return None

    def _call_gemini():
        text, model = _call_gemini_raw(_PCAP_SYSTEM_PROMPT, prompt, max_tokens=1500)
        return _parse(text, model) if text else None

    def _call_groq():
        text, model = _call_groq_raw(_PCAP_SYSTEM_PROMPT, prompt, max_tokens=1500)
        return _parse(text, model) if text else None

    providers = {"claude": _call_claude, "gemini": _call_gemini,
                 "groq": _call_groq, "ollama": _call_ollama}

    if mode in providers:
        result = providers[mode]()
    else:
        result = None
        for fn in (_call_claude, _call_gemini, _call_groq, _call_ollama):
            result = fn()
            if result:
                break

    if not result:
        # ルールベースフォールバック
        issues = []
        if len(pcap_result.get("tcp_issues", [])) >= 3:
            issues.append("TCP問題多発")
        if pcap_result.get("dns_summary", {}).get("nxdomain", 0) > 5:
            issues.append("DNS NXDOMAIN多発")
        if pcap_result.get("dhcp_issues"):
            issues.append("DHCP異常")
        if pcap_result.get("tls_summary", {}).get("fatal_alerts", 0) > 0:
            issues.append("TLS Fatal Alert")
        if pcap_result.get("voip_poor_streams", 0) > 0:
            issues.append(f"VoIP品質不良 MOS={pcap_result.get('voip_avg_mos', 0)}")
        health = "重大" if len(issues) >= 3 else "問題あり" if issues else "正常"
        result = {
            "overall_health": health,
            "summary": f"ルールベース診断。検出問題: {', '.join(issues) or 'なし'}",
            "top_issues": [{"category": i, "severity": "中", "description": i,
                            "root_cause": "詳細はLLM診断で確認", "action": "各セクション参照"} for i in issues],
            "positive_findings": [],
            "priority_action": issues[0] if issues else "問題なし",
            "diagnosis_model": "ルールベース",
        }
    return result
