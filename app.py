import streamlit as st
import threading
import time
import json
from datetime import datetime
import pandas as pd

import db
import analyzer
import notifier
import syslog_server
import snmp_trap_server
import snmp_poller
import prtg_view
import health_engine as he
import vendor_recommendations as vendor_rec
from parsers import parse_syslog

# ─────────────────────────────────────────
# ユーザー設定の永続化（APIキー・モデル等をローカル保存）
#   git pull / clean / 再クローン / 再起動をしても再入力不要にする。
#   保存先: ホームディレクトリ配下（リポジトリの外なので git 操作の影響を受けない）
#     Windows: C:\Users\<user>\.syslog_analyzer\settings.json
#     ※旧: リポジトリ直下 user_settings.json（あれば移行のため読み込む）
# ─────────────────────────────────────────
import os as _os
_SETTINGS_DIR = _os.path.join(_os.path.expanduser("~"), ".syslog_analyzer")
_SETTINGS_PATH = _os.path.join(_SETTINGS_DIR, "settings.json")
# 旧保存先（リポジトリ内）。存在すれば移行用に読む。
_LEGACY_SETTINGS_PATH = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "user_settings.json")

def _load_user_settings():
    for _p in (_SETTINGS_PATH, _LEGACY_SETTINGS_PATH):
        try:
            with open(_p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            continue
    return {}

def _save_user_settings(data: dict):
    try:
        _os.makedirs(_SETTINGS_DIR, exist_ok=True)   # ~/.syslog_analyzer を作成
        cur = _load_user_settings()
        cur.update({k: v for k, v in data.items() if v is not None})
        with open(_SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(cur, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"[settings] save error: {e}")
        return False

def _get_secret_api_keys() -> dict:
    """Streamlit Cloud の Settings→Secrets からAPIキーを読む（設定されていれば優先）。"""
    keys = {}
    try:
        for k in ("GEMINI_API_KEY", "GROQ_API_KEY", "ANTHROPIC_API_KEY"):
            if k in st.secrets:
                keys[k] = str(st.secrets[k])
    except Exception:
        pass
    return keys


def _get_secret_slack_settings() -> dict:
    """Streamlit Cloud の Settings→Secrets からSlack通知設定を読む（設定されていれば優先）。"""
    out = {}
    try:
        if "SLACK_WEBHOOK_URL" in st.secrets:
            out["SLACK_WEBHOOK_URL"] = str(st.secrets["SLACK_WEBHOOK_URL"])
        if "SLACK_NOTIFY_ENABLED" in st.secrets:
            out["SLACK_NOTIFY_ENABLED"] = str(st.secrets["SLACK_NOTIFY_ENABLED"])
    except Exception:
        pass
    return out


def _apply_saved_settings_once():
    """起動時に一度だけ、保存済み設定を analyzer / os.environ に反映する。"""
    if st.session_state.get("_settings_loaded"):
        return
    st.session_state["_settings_loaded"] = True
    s = _load_user_settings()
    s.update(_get_secret_api_keys())  # st.secrets(Streamlit Cloud)があればローカル保存より優先
    s.update(_get_secret_slack_settings())
    if s.get("GEMINI_API_KEY"):
        _os.environ["GEMINI_API_KEY"] = s["GEMINI_API_KEY"]
        analyzer.GEMINI_API_KEY = s["GEMINI_API_KEY"]
    if s.get("GROQ_API_KEY"):
        _os.environ["GROQ_API_KEY"] = s["GROQ_API_KEY"]
        analyzer.GROQ_API_KEY = s["GROQ_API_KEY"]
    if s.get("ANTHROPIC_API_KEY"):
        _os.environ["ANTHROPIC_API_KEY"] = s["ANTHROPIC_API_KEY"]
        analyzer.ANTHROPIC_API_KEY = s["ANTHROPIC_API_KEY"]
    if s.get("OLLAMA_MODEL"):
        _os.environ["OLLAMA_MODEL"] = s["OLLAMA_MODEL"]
        analyzer.OLLAMA_MODEL = s["OLLAMA_MODEL"]
    if s.get("SLACK_WEBHOOK_URL"):
        _os.environ["SLACK_WEBHOOK_URL"] = s["SLACK_WEBHOOK_URL"]
    if s.get("SLACK_NOTIFY_ENABLED"):
        _os.environ["SLACK_NOTIFY_ENABLED"] = s["SLACK_NOTIFY_ENABLED"]
    if s.get("llm_mode"):
        st.session_state["llm_mode"] = s["llm_mode"]

def _is_cloud_mode() -> bool:
    """
    Streamlit Community Cloud 等のクラウド公開環境かを判定する。
    クラウドでは syslog/SNMP/NetFlow の受信(ポート待受・機器到達)ができないため、
    それらの機能を隠す判断に使う。
    優先: 環境変数 DEPLOY_MODE(cloud/local) > 自動判定。
    """
    dm = _os.environ.get("DEPLOY_MODE", "").strip().lower()
    if dm in ("cloud", "server", "hosted"):
        return True
    if dm in ("local", "onprem", "on-prem"):
        return False
    # 自動判定: Streamlit Community Cloud の特徴的なパス/ユーザ
    try:
        if _os.path.exists("/mount/src"):        # Cloud はリポジトリを /mount/src にマウント
            return True
        if _os.environ.get("HOME", "").rstrip("/").endswith("appuser"):
            return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────
# クラウド公開版だけの「主要クラウド/通信キャリアへの疎通状況」表示
#   実機ping/SNMPが使えないクラウド環境向けに、このアプリのサーバーから
#   主要クラウド事業者・国内キャリアの公開サイトへHTTP応答時間を計測して見せる。
#   ※あくまで「このサーバー1拠点から見た」参考値であり、利用者ごとの体感速度や
#     「世の中全体の回線混雑状況」を代表するものではない。
# ─────────────────────────────────────────
_CLOUD_LATENCY_TARGETS = [
    ("AWS",          "https://aws.amazon.com"),
    ("Azure",        "https://azure.microsoft.com"),
    ("Google Cloud", "https://cloud.google.com"),
    ("NTTドコモ",     "https://www.nttdocomo.co.jp"),
    ("au (KDDI)",    "https://www.au.com"),
    ("ソフトバンク",   "https://www.softbank.jp"),
]

@st.cache_data(ttl=60, show_spinner=False)
def _measure_cloud_latency() -> list:
    """主要クラウド/キャリアへのHTTP応答時間を計測する（1分キャッシュ・全訪問者で共有）。"""
    import app_probe as _probe
    results = []
    for name, url in _CLOUD_LATENCY_TARGETS:
        r = _probe.probe_http(url, timeout=5)
        results.append({"name": name, "url": url, **r})
    return results

# ─────────────────────────────────────────
# クラウド公開時のアップロード制限（管理者ログインで解除）
#   管理者ID/パスワードは Streamlit Cloud の secrets.toml（[ADMIN_ID]/[ADMIN_PASSWORD]）
#   またはローカル環境変数 ADMIN_ID / ADMIN_PASSWORD で設定する（リポジトリには含めない）。
# ─────────────────────────────────────────
MAX_UPLOAD_MB_GUEST = 5

def _get_admin_credentials() -> tuple:
    try:
        admin_id = str(st.secrets.get("ADMIN_ID", ""))
        admin_pw = str(st.secrets.get("ADMIN_PASSWORD", ""))
        if admin_id or admin_pw:
            return admin_id, admin_pw
    except Exception:
        pass
    return _os.environ.get("ADMIN_ID", ""), _os.environ.get("ADMIN_PASSWORD", "")

def _is_admin_authenticated() -> bool:
    return bool(st.session_state.get("_admin_authenticated", False))

def _check_upload_size_ok(file_obj, cloud_mode: bool) -> bool:
    """クラウド公開時、管理者未ログインならアップロードサイズを制限する。"""
    if not cloud_mode or _is_admin_authenticated():
        return True
    size = len(file_obj.getvalue())
    if size > MAX_UPLOAD_MB_GUEST * 1024 * 1024:
        st.error(
            f"⚠️ ゲスト利用時のアップロード上限は {MAX_UPLOAD_MB_GUEST}MB です"
            f"（このファイル: {size/1024/1024:.1f}MB）。"
            "サイドバーの「🔒 管理者ログイン」からログインすると上限が解除されます。"
        )
        return False
    return True

def _show_table_top_n(df, csv_name: str, dl_key: str, limit: int = 20):
    """
    件数が多くなりうる表を上位N件だけ表示し、全件はCSVダウンロードで提供する。
    df は表示用に列名変更済み・ソート済みのものを渡すこと。
    """
    if len(df) > limit:
        st.caption(f"{len(df)}件あるため、上位{limit}件のみ表示します（全件はCSVでダウンロードできます）。")
        st.dataframe(df.head(limit), use_container_width=True, hide_index=True)
        st.download_button(
            "📥 全件をCSVでダウンロード",
            data=df.to_csv(index=False).encode("utf-8-sig"),
            file_name=csv_name,
            mime="text/csv",
            key=dl_key,
        )
    else:
        st.dataframe(df, use_container_width=True, hide_index=True)


def _render_pcap_ai_diagnosis(res: dict, key_prefix: str = "main"):
    """
    pcap解析結果に対する「🤖 AI診断実行」ボタンとレポート表示。
    pcapの取得経路（アップロード/SCP/EPC等）によらず、全ページで同一の
    ボタン・診断ロジック（analyzer.diagnose_pcap）を使うための共通部品。
    key_prefix は同一画面に複数配置してもキーが衝突しないようにするため。
    """
    st.markdown("---")
    _llm_ok = (analyzer.check_claude_available() or analyzer.check_gemini_available()
               or analyzer.check_groq_available() or analyzer.check_ollama_available())
    _ai_col1, _ai_col2 = st.columns([5, 1])
    _ai_col1.markdown("### 🤖 pcap 総合 AI 診断")
    _ai_col1.caption("TCP / DNS / DHCP / HTTP / TLS / VoIP / ICMP / ARP の全解析結果を LLM に投げて根本原因を推定します。")
    _lang = res.get("suggested_lang", "ja")
    _rh = res.get("region_hint", {})
    _ai_col1.caption(
        f"🌐 出力言語: **{'日本語' if _lang == 'ja' else 'English'}**"
        f"（アクセス先ドメインの地域から自動判定 / アジア圏{_rh.get('asian_domains',0)}・"
        f"非アジア圏{_rh.get('western_domains',0)}）")
    with _ai_col2:
        _pcap_ai_btn = st.button("🤖 AI診断実行", key=f"pcap_ai_diag_{key_prefix}",
                                 disabled=not _llm_ok, use_container_width=True,
                                 type="primary")
    if not _llm_ok:
        st.caption("AI診断を使うにはサイドバーの「🔑 APIキー設定」でClaude / Gemini / Groqのいずれかを設定してください。")

    _diag_state_key = f"_pcap_diag_{key_prefix}"
    if _pcap_ai_btn:
        with st.spinner("LLM がpcap解析結果を総合分析中..."):
            st.session_state[_diag_state_key] = analyzer.diagnose_pcap(
                res, st.session_state.get("llm_mode", "auto"))

    _pcap_diag = st.session_state.get(_diag_state_key)
    if _pcap_diag:
        _health = _pcap_diag.get("overall_health", "")
        _health_color = {"正常": "🟢", "要注意": "🟡", "問題あり": "🟠", "重大": "🔴"}.get(_health, "⚪")
        st.markdown(f"**総合評価: {_health_color} {_health}**")
        st.markdown(f"{_pcap_diag.get('summary','')}")

        _issues = _pcap_diag.get("top_issues", [])
        if _issues:
            st.markdown("**検出された問題（優先順）:**")
            for _iss in _issues:
                _sev = _iss.get("severity", "")
                _sev_icon = {"高": "🔴", "中": "🟡", "低": "🟢"}.get(_sev, "⚪")
                with st.expander(f"{_sev_icon} [{_iss.get('category','')}] {_iss.get('description','')}"):
                    st.markdown(f"**原因推定:** {_iss.get('root_cause','')}")
                    st.markdown(f"**推奨対応:** {_iss.get('action','')}")

        if _pcap_diag.get("positive_findings"):
            st.markdown("**✅ 問題なし:** " + " / ".join(_pcap_diag["positive_findings"]))
        st.info(f"**🚨 最優先対応:** {_pcap_diag.get('priority_action','')}")
        st.caption(f"診断モデル: {_pcap_diag.get('diagnosis_model','')} | "
                   f"LLMモード: {st.session_state.get('llm_mode','auto')}")

    # ── エージェント診断（Claude tool use、ID/session深掘りMVP） ──
    if analyzer.check_claude_available() and res.get("session_id_correlations"):
        st.markdown("")
        _ag_col1, _ag_col2 = st.columns([5, 1])
        _ag_col1.markdown("**🕵️ エージェント診断（Claude, ID/session深掘り）**")
        _ag_col1.caption("通常診断と異なり、LLMが自分でID/session突き合わせの詳細（タイムライン等）を"
                         "ツール呼び出しで取得してから診断します（Claude APIのみ対応・MVP）。")
        with _ag_col2:
            _agentic_btn = st.button("🕵️ 実行", key=f"pcap_agentic_{key_prefix}",
                                      use_container_width=True)
        _agentic_state_key = f"_pcap_agentic_{key_prefix}"
        if _agentic_btn:
            with st.spinner("Claudeがツール呼び出しで深掘りしながら分析中..."):
                st.session_state[_agentic_state_key] = analyzer.diagnose_pcap_agentic(res)

        _agentic_diag = st.session_state.get(_agentic_state_key)
        if _agentic_diag:
            if _agentic_diag.get("tool_calls_made"):
                st.caption("🔍 深掘りしたID値: " + ", ".join(_agentic_diag["tool_calls_made"]))
            _ah = _agentic_diag.get("overall_health", "")
            _ahc = {"正常": "🟢", "要注意": "🟡", "問題あり": "🟠", "重大": "🔴"}.get(_ah, "⚪")
            st.markdown(f"**総合評価: {_ahc} {_ah}**")
            st.markdown(_agentic_diag.get("summary", ""))
            for _iss in _agentic_diag.get("top_issues", []):
                _sev_icon = {"高": "🔴", "中": "🟡", "低": "🟢"}.get(_iss.get("severity", ""), "⚪")
                with st.expander(f"{_sev_icon} [{_iss.get('category','')}] {_iss.get('description','')}"):
                    st.markdown(f"**原因推定:** {_iss.get('root_cause','')}")
                    st.markdown(f"**推奨対応:** {_iss.get('action','')}")
            st.info(f"**🚨 最優先対応:** {_agentic_diag.get('priority_action','')}")
            st.caption(f"診断モデル: {_agentic_diag.get('diagnosis_model','')}")
        elif _agentic_btn:
            st.error("エージェント診断に失敗しました（応答形式エラー等）。通常のAI診断をご利用ください。")

    # ── 複数Ollamaモデルによる多面解析（ローカル限定） ──
    # クラウドAPIと違いOllamaは呼び出し課金・レート制限がないため、
    # 導入済みモデルが複数あれば同じデータを全モデルに投げて比較する価値がある。
    if analyzer.check_ollama_available():
        _installed_models = analyzer.list_ollama_models()
        if len(_installed_models) >= 2:
            with st.expander("🔬 複数のOllamaモデルで多面解析（無料・ローカルのみ）"):
                st.caption("導入済みのOllamaモデルに同じデータを投げて、診断結果を比較します。"
                           "ローカル実行のためクラウドAPIのクオータは消費しません。")
                _sel_models = st.multiselect(
                    "比較するモデルを選択", _installed_models,
                    default=_installed_models[:2], key=f"ollama_multi_sel_{key_prefix}")
                if st.button("▶ 選択したモデルで比較解析", key=f"ollama_multi_run_{key_prefix}",
                             disabled=not _sel_models, use_container_width=True):
                    _multi_results = {}
                    _progress = st.progress(0.0)
                    for _mi, _mname in enumerate(_sel_models):
                        with st.spinner(f"{_mname} で分析中... ({_mi+1}/{len(_sel_models)})"):
                            _multi_results[_mname] = analyzer.diagnose_pcap_with_ollama_model(res, _mname)
                        _progress.progress((_mi + 1) / len(_sel_models))
                    st.session_state[f"_pcap_ollama_multi_{key_prefix}"] = _multi_results

                _multi_results = st.session_state.get(f"_pcap_ollama_multi_{key_prefix}")
                if _multi_results:
                    _model_tabs = st.tabs(list(_multi_results.keys()))
                    for _mtab, (_mname, _mres) in zip(_model_tabs, _multi_results.items()):
                        with _mtab:
                            if not _mres:
                                st.error("このモデルでは診断結果を取得できませんでした（応答形式エラー・タイムアウト等）。")
                                continue
                            _mhealth = _mres.get("overall_health", "")
                            _mcolor = {"正常": "🟢", "要注意": "🟡", "問題あり": "🟠", "重大": "🔴"}.get(_mhealth, "⚪")
                            st.markdown(f"**総合評価: {_mcolor} {_mhealth}**")
                            st.markdown(_mres.get("summary", ""))
                            for _iss in _mres.get("top_issues", []):
                                _sev_icon = {"高": "🔴", "中": "🟡", "低": "🟢"}.get(_iss.get("severity", ""), "⚪")
                                st.markdown(f"- {_sev_icon} [{_iss.get('category','')}] {_iss.get('description','')}")
                            st.caption(f"🚨 最優先対応: {_mres.get('priority_action','')}")


def _render_icmp_redirect_diagnosis_result(result: dict):
    """analyzer.diagnose_icmp_redirect / diagnose_icmp_redirect_agentic の結果表示（共通部品）。"""
    if not result:
        return
    if result.get("tool_calls_made"):
        st.caption("🔍 確認したルート: " + ", ".join(result["tool_calls_made"]))
    st.markdown(f"**🎯 根本原因:** {result.get('root_cause','')}")
    if result.get("causal_chain"):
        st.markdown("**🔗 因果連鎖:** " + " → ".join(result["causal_chain"]))
    if result.get("routing_issue"):
        st.markdown(f"**⚙️ ルーティング問題:** {result.get('routing_issue','')}")
    st.markdown(f"**🚨 最優先対処:** {result.get('priority_action','')}")
    if result.get("additional_checks"):
        st.markdown("**📋 追加確認事項:**")
        for c in result["additional_checks"]:
            st.markdown(f"  - {c}")
    st.markdown(f"**⚠️ 放置リスク:** {result.get('risk_if_ignored','')}")
    st.caption(f"診断モデル: {result.get('diagnosis_model','')}")

# ─────────────────────────────────────────
# ページ設定
# ─────────────────────────────────────────
st.set_page_config(
    page_title="Syslog AI アナライザー",
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────
# CSS
# ─────────────────────────────────────────
st.markdown("""
<style>
  .main { background: #f0f2f6; color: #1f2937; }
  .stApp { background: #f0f2f6; }
  .metric-card {
    background: #ffffff; border: 1px solid #d0d7de;
    border-radius: 8px; padding: 16px; text-align: center;
    box-shadow: 0 1px 3px rgba(16,24,40,0.06);
  }
  .severity-EMERGENCY, .severity-ALERT, .severity-CRITICAL {
    color: #dc2626; font-weight: bold;
  }
  .severity-ERROR   { color: #ea580c; font-weight: bold; }
  .severity-WARNING { color: #b45309; }
  .severity-NOTICE  { color: #2563eb; }
  .severity-INFO    { color: #16a34a; }
  .severity-DEBUG   { color: #64748b; }
  .log-card {
    background: #ffffff; border: 1px solid #e5e9ef; border-left: 3px solid #d0d7de;
    border-radius: 6px; padding: 12px; margin-bottom: 8px;
    font-family: 'JetBrains Mono', monospace; font-size: 12px;
    box-shadow: 0 1px 2px rgba(16,24,40,0.05);
  }
  .tag-chip {
    display: inline-block; background: #e9edf2;
    border: 1px solid #d0d7de; border-radius: 12px;
    padding: 2px 8px; margin: 2px; font-size: 11px; color: #6b7280;
  }
  .ai-explanation {
    background: #eff6ff; border: 1px solid #2563eb;
    border-radius: 6px; padding: 12px; margin-top: 8px;
    font-size: 13px;
  }
  .telemetry-note {
    background: #ecfdf3; border: 1px solid #16a34a;
    border-radius: 6px; padding: 8px; margin-top: 6px;
    font-size: 12px; color: #16a34a;
  }
  div[data-testid="stMetricValue"] { font-size: 2rem; }

  /* タブが多いとき横に見切れないよう複数行に折り返す */
  div[data-baseweb="tab-list"] {
    flex-wrap: wrap !important;
    row-gap: 4px;
  }
  /* タブ内テキストの折り返しを防ぎ、ラベルを見やすく */
  button[data-baseweb="tab"] {
    white-space: nowrap;
  }
  button[data-baseweb="tab"] > div[data-testid="stMarkdownContainer"] p {
    font-size: 0.9rem;
  }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────
# DB初期化
# ─────────────────────────────────────────
db.init_db()

# ─────────────────────────────────────────
# Session State 初期化
# ─────────────────────────────────────────
if "server_started" not in st.session_state:
    st.session_state.server_started = False
if "snmp_trap_started" not in st.session_state:
    st.session_state.snmp_trap_started = False
if "snmp_poller_started" not in st.session_state:
    st.session_state.snmp_poller_started = False
if "netflow_started" not in st.session_state:
    st.session_state.netflow_started = False
if "auto_analyze" not in st.session_state:
    st.session_state.auto_analyze = True
if "judge_enabled" not in st.session_state:
    st.session_state.judge_enabled = False
if "llm_mode" not in st.session_state:
    st.session_state.llm_mode = "auto"
# 保存済みのAPIキー・モデル・モードを起動時に一度だけ反映（再入力不要にする）
_apply_saved_settings_once()
if "syslog_port" not in st.session_state:
    st.session_state.syslog_port = 5140
if "snmp_trap_port" not in st.session_state:
    st.session_state.snmp_trap_port = 16200
if "last_log_count" not in st.session_state:
    st.session_state.last_log_count = 0

# ─────────────────────────────────────────
# サイドバー
# ─────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛰️ Syslog AI アナライザー")
    st.markdown("---")

    # クラウド公開環境では受信系(syslog/SNMP/NetFlow)は使えないため隠す
    _cloud_mode = _is_cloud_mode()
    if _cloud_mode:
        st.info("☁️ クラウド公開モード\n\n"
                "この環境では **syslog / SNMP / NetFlow の受信機能は利用できません**（ポート待受・機器到達不可）ため非表示です。\n\n"
                "✅ 利用可能: **show log 解析・パケット(pcap)解析・LLM解析・各種ビューア**")

        st.markdown("### 🔒 管理者ログイン")
        if _is_admin_authenticated():
            st.success("✅ 管理者ログイン中（アップロード上限なし）")
            if st.button("ログアウト", key="_admin_logout_btn", use_container_width=True):
                st.session_state["_admin_authenticated"] = False
                st.rerun()
        else:
            st.caption(f"ゲスト利用時のファイルアップロード上限: {MAX_UPLOAD_MB_GUEST}MB")
            with st.form("_admin_login_form"):
                _admin_id_in = st.text_input("管理者ID")
                _admin_pw_in = st.text_input("パスワード", type="password")
                _admin_login_submitted = st.form_submit_button("ログイン")
            if _admin_login_submitted:
                _real_id, _real_pw = _get_admin_credentials()
                if _real_pw and _admin_id_in == _real_id and _admin_pw_in == _real_pw:
                    st.session_state["_admin_authenticated"] = True
                    st.success("ログインしました")
                    st.rerun()
                else:
                    st.error("IDまたはパスワードが違います")
    else:
        # サーバー制御
        st.markdown("### 📡 syslog受信サーバー")
        port = st.number_input("UDPポート番号", min_value=514, max_value=65535,
                                value=st.session_state.syslog_port, step=1)
        st.caption("514はroot権限が必要。5140推奨（要機器側設定）")
    
        col1, col2 = st.columns(2)
        with col1:
            if st.button("▶ 起動", use_container_width=True,
                         disabled=st.session_state.server_started):
                srv = syslog_server.get_server(port=int(port))
                srv.start()
                if srv.running:
                    st.session_state.server_started = True
                    st.session_state.syslog_port = int(port)
                    st.success(f"UDP {port} で受信中")
                else:
                    st.error(srv.error or "起動失敗")
        with col2:
            if st.button("⏹ 停止", use_container_width=True,
                         disabled=not st.session_state.server_started):
                srv = syslog_server.get_server()
                srv.stop()
                st.session_state.server_started = False
                st.info("停止しました")
    
        if st.session_state.server_started:
            st.success(f"✅ UDP {st.session_state.syslog_port} 受信中")
        else:
            st.warning("⏸ 停止中")
    
        st.markdown("---")
    
        # SNMP Trap サーバー制御
        st.markdown("### 📡 SNMP Trap サーバー")
        snmp_port = st.number_input("Trap受信ポート", min_value=162, max_value=65535,
                                     value=st.session_state.snmp_trap_port, step=1)
        st.caption("162はroot権限が必要。16200推奨")
    
        snmp_communities = st.text_input("コミュニティ名（カンマ区切り）", value="public,private")
    
        col3, col4 = st.columns(2)
        with col3:
            if st.button("▶ Trap起動", use_container_width=True,
                         disabled=st.session_state.snmp_trap_started):
                communities = [c.strip() for c in snmp_communities.split(",")]
                srv = snmp_trap_server.get_snmp_server(port=int(snmp_port), communities=communities)
                srv.start()
                if srv.running:
                    st.session_state.snmp_trap_started = True
                    st.session_state.snmp_trap_port = int(snmp_port)
                    st.success(f"UDP {snmp_port} Trap受信中")
                else:
                    st.error(srv.error or "起動失敗")
        with col4:
            if st.button("⏹ Trap停止", use_container_width=True,
                         disabled=not st.session_state.snmp_trap_started):
                snmp_trap_server.get_snmp_server().stop()
                st.session_state.snmp_trap_started = False
                st.info("停止しました")
    
        if st.session_state.snmp_trap_started:
            st.success(f"✅ UDP {st.session_state.snmp_trap_port} Trap受信中")
        else:
            st.warning("⏸ Trap停止中")
    
        # SNMPポーラー制御
        st.markdown("**SNMPポーリング（定期収集）**")
        col5, col6 = st.columns(2)
        with col5:
            if st.button("▶ Poller起動", use_container_width=True,
                         disabled=st.session_state.snmp_poller_started):
                snmp_poller.start_poller()
                st.session_state.snmp_poller_started = True
                st.success("ポーラー起動")
        with col6:
            if st.button("⏹ Poller停止", use_container_width=True,
                         disabled=not st.session_state.snmp_poller_started):
                snmp_poller.stop_poller()
                st.session_state.snmp_poller_started = False
                st.info("停止")
    
        # NetFlow 制御
        st.markdown("**🌊 NetFlow v5 受信**")
        import netflow_collector as _nfc
        nf_port = st.number_input("NetFlow ポート", min_value=1024, max_value=65535,
                                   value=9995, key="netflow_port_input")
        col7, col8 = st.columns(2)
        with col7:
            if st.button("▶ NetFlow起動", use_container_width=True,
                         disabled=st.session_state.netflow_started):
                srv = _nfc.get_server(port=int(nf_port))
                srv.start()
                if srv.running:
                    st.session_state.netflow_started = True
                    st.success(f"UDP {nf_port} 受信中")
                else:
                    st.error(srv.error or "起動失敗")
        with col8:
            if st.button("⏹ NetFlow停止", use_container_width=True,
                         disabled=not st.session_state.netflow_started):
                _nfc.get_server().stop()
                st.session_state.netflow_started = False
                st.info("停止")
        if st.session_state.netflow_started:
            st.success(f"✅ UDP {nf_port} NetFlow受信中")
        else:
            st.warning("⏸ NetFlow停止中")

    st.markdown("---")
    st.markdown("### 🤖 AI解析エンジン")
    _sidebar_cloud = _is_cloud_mode()
    claude_ok = analyzer.check_claude_available()
    gemini_ok = analyzer.check_gemini_available()
    groq_ok   = analyzer.check_groq_available()

    if _sidebar_cloud:
        # クラウド環境では localhost の Ollama には到達できないため、
        # 自動起動の試行やステータス表示・起動ボタンを一切出さない
        ollama_ok = False
    else:
        # アプリ起動時に Ollama が未起動なら一度だけ自動起動を試みる
        if not st.session_state.get("_ollama_autostart_tried"):
            st.session_state["_ollama_autostart_tried"] = True
            if not analyzer.check_ollama_available():
                _ok, _msg = analyzer.start_ollama(wait_sec=8)
                if _ok:
                    st.toast("🏠 Ollama を自動起動しました")
        ollama_ok = analyzer.check_ollama_available()

    st.markdown(f"{'✅' if claude_ok else '❌'} Claude API "
                f"({'APIキーあり' if claude_ok else 'ANTHROPIC_API_KEY未設定'})")
    st.markdown(f"{'✅' if gemini_ok else '❌'} Gemini "
                f"({'APIキーあり' if gemini_ok else 'GEMINI_API_KEY未設定'})")
    st.markdown(f"{'✅' if groq_ok else '❌'} Groq "
                f"({'APIキーあり' if groq_ok else 'GROQ_API_KEY未設定'})")
    if not _sidebar_cloud:
        st.markdown(f"{'✅' if ollama_ok else '❌'} Ollama "
                    f"({'接続OK' if ollama_ok else 'localhost:11434 未起動'})")
        if not ollama_ok:
            if st.button("▶ Ollama を起動する", key="start_ollama_btn", use_container_width=True):
                with st.spinner("Ollama を起動中…"):
                    _ok, _msg = analyzer.start_ollama(wait_sec=10)
                (st.success if _ok else st.error)(_msg)
                if _ok:
                    st.rerun()
    else:
        st.caption("☁️ クラウド環境のため Ollama（ローカルLLM）は利用できません。"
                   "Gemini / Groq をご利用ください。")

    with st.expander("🔑 APIキー設定", expanded=not (claude_ok or gemini_ok or groq_ok)):
        import os
        if _is_cloud_mode():
            # クラウド公開環境では全訪問者が同じサーバープロセス（同じos.environ）を
            # 共有するため、アプリ内の入力欄にキーを持たせるのは危険（誰でも閲覧できてしまう）。
            # Streamlit Cloud の Settings→Secrets を正とし、アプリ側では編集UIを出さない。
            st.info("☁️ クラウド公開環境ではAPIキーをアプリ内から設定しません。\n\n"
                    "Streamlit Cloudの管理画面 → 対象アプリの **Settings → Secrets** で\n"
                    "`GEMINI_API_KEY` / `GROQ_API_KEY` を設定してください"
                    "（保存すると自動的に反映されます）。")
            st.caption("この方式なら訪問者にキーの値が見えることはありません。")
        else:
            _gk = st.text_input("Gemini API Key", type="password",
                                 value=os.environ.get("GEMINI_API_KEY",""),
                                 help="Google AI Studio (aistudio.google.com) で無料取得")
            _rk = st.text_input("Groq API Key", type="password",
                                 value=os.environ.get("GROQ_API_KEY",""),
                                 help="console.groq.com で無料取得")
            _c_apply, _c_clear = st.columns(2)
            if _c_apply.button("適用して保存", key="apply_api_keys", use_container_width=True):
                if _gk:
                    os.environ["GEMINI_API_KEY"] = _gk
                    analyzer.GEMINI_API_KEY = _gk
                if _rk:
                    os.environ["GROQ_API_KEY"] = _rk
                    analyzer.GROQ_API_KEY = _rk
                # ローカルに保存（次回起動・git pull後も再入力不要）
                _save_user_settings({"GEMINI_API_KEY": _gk or None, "GROQ_API_KEY": _rk or None})
                st.success("APIキーを保存しました（次回以降は自動で読み込まれます）")
                st.rerun()
            if _c_clear.button("保存キーを削除", key="clear_api_keys", use_container_width=True):
                _save_user_settings({"GEMINI_API_KEY": "", "GROQ_API_KEY": ""})
                os.environ.pop("GEMINI_API_KEY", None); analyzer.GEMINI_API_KEY = ""
                os.environ.pop("GROQ_API_KEY", None);   analyzer.GROQ_API_KEY = ""
                st.info("保存したキーを削除しました")
                st.rerun()
            st.caption(f"💾 保存先: {_SETTINGS_PATH}（この端末内のみ・git操作の影響を受けません）")

    with st.expander("🔔 Slack通知設定", expanded=False):
        if _is_cloud_mode():
            # APIキーと同じ理由（全訪問者が同じos.environを共有）で、
            # Webhook URLもアプリ内の編集UIには出さず、Streamlit Cloud の Secrets を正とする。
            st.info("☁️ クラウド公開環境ではWebhook URLをアプリ内から設定しません。\n\n"
                    "Streamlit Cloudの管理画面 → 対象アプリの **Settings → Secrets** で\n"
                    "`SLACK_WEBHOOK_URL` と `SLACK_NOTIFY_ENABLED`（`\"1\"`で有効）を設定してください"
                    "（保存すると自動的に反映されます）。")
            st.caption("この方式ならWebhook URLの値が訪問者に見えることはありません。")
            if _is_admin_authenticated():
                if st.button("🧪 テスト送信", key="slack_test_send_cloud", use_container_width=True):
                    _ok, _err = notifier.send_slack_message(
                        "🔔 [テスト通知] Syslog AI Analyzerからのテスト送信です。")
                    (st.success("Slackへ送信しました") if _ok else st.error(_err))
        else:
            _wh = st.text_input("Slack Webhook URL", type="password",
                                 value=_os.environ.get("SLACK_WEBHOOK_URL", ""),
                                 help="Slackアプリの「Incoming Webhook」で発行したURLを貼り付け")
            _en = st.checkbox("危険水準(critical)アラートをSlackに通知する",
                               value=_os.environ.get("SLACK_NOTIFY_ENABLED", "") == "1",
                               key="slack_notify_enabled_cb")
            _c_apply, _c_clear = st.columns(2)
            if _c_apply.button("適用して保存", key="apply_slack_settings", use_container_width=True):
                if _wh:
                    _os.environ["SLACK_WEBHOOK_URL"] = _wh
                _os.environ["SLACK_NOTIFY_ENABLED"] = "1" if _en else "0"
                _save_user_settings({"SLACK_WEBHOOK_URL": _wh or None,
                                      "SLACK_NOTIFY_ENABLED": "1" if _en else "0"})
                st.success("Slack通知設定を保存しました（次回以降は自動で読み込まれます）")
                st.rerun()
            if _c_clear.button("保存URLを削除", key="clear_slack_settings", use_container_width=True):
                _save_user_settings({"SLACK_WEBHOOK_URL": "", "SLACK_NOTIFY_ENABLED": "0"})
                _os.environ.pop("SLACK_WEBHOOK_URL", None)
                _os.environ["SLACK_NOTIFY_ENABLED"] = "0"
                st.info("保存したWebhook URLを削除しました")
                st.rerun()
            if st.button("🧪 テスト送信", key="slack_test_send", use_container_width=True):
                _test_url = _wh or _os.environ.get("SLACK_WEBHOOK_URL", "")
                if not _test_url:
                    st.warning("先にWebhook URLを入力してください。")
                else:
                    _ok, _err = notifier.send_slack_message(
                        "🔔 [テスト通知] Syslog AI Analyzerからのテスト送信です。", webhook_url=_test_url)
                    (st.success("Slackへ送信しました") if _ok else st.error(_err))
            st.caption(f"💾 保存先: {_SETTINGS_PATH}（この端末内のみ・git操作の影響を受けません）")
            st.caption("有効化すると、SNMP監視でCPU/メモリ等が危険水準(critical)を超えた際に自動通知されます"
                       "（同じ項目が継続して危険な間は最短30分間隔で再通知）。")

    if _sidebar_cloud:
        # クラウドでは Ollama 到達不可のため選択肢から除外し、自動の説明も合わせる
        _mode_opts = [
            ("auto",   "🔄 自動 (Gemini→Groq→Claude)"),
            ("gemini", "✨ Gemini（無料枠あり）"),
            ("groq",   "⚡ Groq（無料枠あり・高速）"),
            ("claude", "☁️  Claude APIのみ"),
            ("none",   "⛔ AI解析なし（高速）"),
        ]
    else:
        _mode_opts = [
            ("auto",   "🔄 自動 (Claude→Gemini→Groq→Ollama)"),
            ("gemini", "✨ Gemini（無料枠あり）"),
            ("groq",   "⚡ Groq（無料枠あり・高速）"),
            ("claude", "☁️  Claude APIのみ"),
            ("ollama", "🏠 Ollamaのみ（完全ローカル）"),
            ("none",   "⛔ AI解析なし（高速）"),
        ]
    _saved_mode = st.session_state.get("llm_mode", "auto")
    if _sidebar_cloud and _saved_mode == "ollama":
        _saved_mode = "auto"  # クラウドで保存済みモードがollamaなら自動に読み替え
    _mode_idx = next((i for i, o in enumerate(_mode_opts) if o[0] == _saved_mode), 0)
    llm_mode = st.selectbox("解析モード", _mode_opts,
                            format_func=lambda x: x[1], index=_mode_idx)
    if llm_mode[0] != st.session_state.get("llm_mode"):
        _save_user_settings({"llm_mode": llm_mode[0]})  # 選んだモードを記憶
    st.session_state.llm_mode = llm_mode[0]

    if ollama_ok:
        import os
        _installed = analyzer.list_ollama_models()
        _cur_model = os.environ.get("OLLAMA_MODEL", analyzer.OLLAMA_MODEL)
        if _installed:
            # 導入済みモデルから選択（現在値が一覧に無ければ先頭を既定に）
            _idx = _installed.index(_cur_model) if _cur_model in _installed else 0
            _sel_model = st.selectbox("Ollamaモデル（導入済み）", _installed, index=_idx,
                                      help="ローカルにpull済みのモデルから選択")
        else:
            _sel_model = st.text_input("Ollamaモデル名", value=_cur_model,
                                       help="例: gemma3 / llama3 / qwen2.5 など")
        # 選択したモデルを analyzer に反映（これが無いと既定のllama3のまま失敗する）
        if _sel_model and _sel_model != analyzer.OLLAMA_MODEL:
            analyzer.OLLAMA_MODEL = _sel_model
            os.environ["OLLAMA_MODEL"] = _sel_model
            _save_user_settings({"OLLAMA_MODEL": _sel_model})  # モデル選択を記憶
        st.caption(f"使用モデル: **{analyzer.OLLAMA_MODEL}**"
                   + ("" if _installed else "（未導入なら下でモデルを取得してください）"))

        # ── アプリ内でモデルを取得(pull) ──
        with st.expander("📥 モデルを取得（pull）"):
            _pull_name = st.text_input("取得するモデル名", value="gemma3",
                                       key="ollama_pull_name",
                                       help="例: gemma3 / llama3 / qwen2.5 / elyza/llama3-jp")
            if st.button("📥 取得を開始", key="ollama_pull_btn"):
                _pbar = st.progress(0.0, text="準備中…")
                def _cb(status, pct):
                    _pbar.progress(pct if pct is not None else 0.0,
                                   text=f"{status}" + (f" {pct*100:.0f}%" if pct else ""))
                with st.spinner(f"'{_pull_name}' を取得中…（数GB・数分かかります）"):
                    _ok, _msg = analyzer.pull_ollama_model(_pull_name, _cb)
                if _ok:
                    _pbar.progress(1.0, text="完了")
                    st.success(_msg)
                    analyzer.OLLAMA_MODEL = _pull_name
                    os.environ["OLLAMA_MODEL"] = _pull_name
                    st.rerun()
                else:
                    st.error(_msg)

        # ── pcap解析専用モデルを作成（Modelfileにシステムプロンプトを焼き込み） ──
        with st.expander("🏗️ pcap解析専用モデルを作成（packet-analyst）"):
            st.caption("導入済みモデルをベースに、pcap解析用のシステムプロンプトを焼き込んだ"
                       "専用モデルを作成します（重み調整の本格的なファインチューニングではなく、"
                       "Ollama Modelfileによる軽量版）。作成後は他のモデルと同様に選択して使えます。")
            if _installed:
                _base_model_sel = st.selectbox("ベースモデル", _installed, key="packet_analyst_base")
            else:
                _base_model_sel = st.text_input("ベースモデル名", value="gemma3", key="packet_analyst_base_txt")
            _target_name = st.text_input("作成するモデル名", value="packet-analyst", key="packet_analyst_name")
            if st.button("🏗️ 専用モデルを作成", key="packet_analyst_create_btn", use_container_width=True):
                with st.spinner(f"'{_target_name}' を作成中…"):
                    _pa_ok, _pa_msg = analyzer.create_packet_analyst_model(_base_model_sel, _target_name)
                (st.success if _pa_ok else st.error)(_pa_msg)
                if _pa_ok:
                    st.rerun()
    else:
        # Ollama 自体が起動していない場合の案内（モデル取得もできない）
        st.caption("💡 完全ローカルで使うには Ollama を起動してください（https://ollama.com）。"
                   "起動後、ここで gemma3 等のモデルを取得・選択できます。")

    st.session_state.auto_analyze = st.checkbox("受信ログを自動AI解析", value=True)
    st.session_state.judge_enabled = st.checkbox(
        "🧑‍⚖️ AI解析結果の品質チェック（Judge）を実行",
        value=False,
        help="一次解析の結果を別のLLM呼び出しで審査します。Claude APIの呼び出し回数が2倍になります。"
    )

    st.markdown("---")

    # ─── デモシミュレーター ─────────────────────
    st.markdown("### 🎮 デモシミュレーター（実機不要）")
    st.caption("実機なしで全機能をテストできるデモデータを生成します。")
    import demo_simulator as _demo_sim
    _demo_scenario = st.selectbox(
        "シナリオ選択",
        list(_demo_sim.SCENARIOS.keys()),
        format_func=lambda k: _demo_sim.SCENARIOS[k],
        key="demo_scenario_sel",
    )
    if st.button("▶ データ生成", key="demo_run", use_container_width=True):
        with st.spinner("シミュレーションデータ生成中..."):
            _demo_result = _demo_sim.run_scenario(_demo_scenario)
        st.session_state["_demo_result"]    = _demo_result
        st.session_state["_demo_pcap_key"]  = f"demo_{_demo_scenario}"
        # pcap を解析して pcap タブで使えるようにする
        if _demo_result.get("pcap_bytes"):
            import pcap_analyzer as _pa_demo
            _demo_pcap_res   = _pa_demo.analyze_pcap(_demo_result["pcap_bytes"])
            _demo_pcap_convs = _pa_demo.get_conversations(_demo_result["pcap_bytes"])
            _demo_pcap_tlk   = _pa_demo.get_top_talkers(_demo_result["pcap_bytes"])
            _demo_pcap_streams = _pa_demo.get_tcp_streams(_demo_result["pcap_bytes"])
            st.session_state["_pcap_key"]     = f"demo_{_demo_scenario}"
            st.session_state["_pcap_res"]     = _demo_pcap_res
            st.session_state["_pcap_convs"]   = _demo_pcap_convs
            st.session_state["_pcap_talkers"] = _demo_pcap_tlk
            st.session_state["_pcap_streams"] = _demo_pcap_streams
            st.session_state["_pcap_bytes"]   = _demo_result["pcap_bytes"]
        st.success(
            f"生成完了 — syslog: {_demo_result['syslog_count']}件 | "
            f"NetFlow: {_demo_result['flow_count']}件 | "
            f"pcap: {len(_demo_result.get('pcap_bytes') or b'')/1024:.1f} KB"
        )
        st.rerun()

    _demo_r = st.session_state.get("_demo_result")
    if _demo_r:
        st.caption(f"最終実行: {_demo_r['scenario']} シナリオ")
        if _demo_r.get("pcap_bytes"):
            st.info("📦 生成したpcapは「📦 パケット解析」タブで**ダウンロード不要でそのまま解析済み**です。")
            st.download_button(
                "💾 demo.pcap をダウンロード（任意）",
                data=_demo_r["pcap_bytes"],
                file_name=f"demo_{_demo_r['scenario']}.pcap",
                mime="application/octet-stream",
                use_container_width=True,
            )

    st.markdown("---")

    # テストログ投入
    st.markdown("### 🧪 テストログ投入")
    test_vendor = st.selectbox("ベンダー", [
        "Cisco IOS/IOS-XE", "Cisco NX-OS", "富士通 Si-R",
        "富士通 IPCOM", "富士通 SR-S", "F5 BIG-IP LTM", "Palo Alto",
        "APRESIA", "RHEL/Linux", "Windows"
    ])
    if st.button("📨 テストログ送信", use_container_width=True):
        _inject_test_log(test_vendor)
        st.success("投入しました")

    st.markdown("---")

    # show logging 貼り付け取り込み
    st.markdown("### 📋 show logging 貼り付け")
    st.caption("機器の `show logging` / `show logging syslog` 出力を貼り付けて一括取り込み")
    _sl_src = st.text_input("送信元IP/ホスト（任意）", value="pasted-device",
                            key="show_log_src",
                            help="貼り付けたログの送信元として記録されます")
    _sl_text = st.text_area("ここに show logging 出力を貼り付け", height=160,
                            key="show_log_text",
                            placeholder="*Jul  3 10:00:01.123: %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down\n"
                                        "*Jul  3 10:00:02.456: %LINEPROTO-5-UPDOWN: Line protocol on Gi1/0/1, down")
    if st.button("🔍 解析して取り込み", use_container_width=True, key="show_log_ingest"):
        if _sl_text.strip():
            _sl_res = _ingest_show_logging(_sl_text, _sl_src.strip() or "pasted-device")
            if _sl_res["total"]:
                _vb = " / ".join(f"{k}:{v}" for k, v in _sl_res["by_vendor"].items())
                st.success(f"✅ {_sl_res['total']}件取り込み（除外{_sl_res['skipped']}行）\n\n{_vb}")
                st.caption("「📊 ログ一括 AI 分析」タブでまとめて評価できます")
            else:
                st.warning(f"取り込めるログ行がありませんでした（除外{_sl_res['skipped']}行）")
        else:
            st.error("show logging の出力を貼り付けてください")

    st.markdown("---")

    # ログクリア
    if st.button("🗑️ 全ログ削除", use_container_width=True):
        db.clear_logs()
        st.success("クリアしました")

    st.markdown("---")
    st.caption("v1.0 | Cisco/NX-OS/Si-R/IPCOM/SR-S/F5 BIG-IP/PaloAlto/APRESIA/RHEL/Windows対応")

# ─────────────────────────────────────────
# show log解析タブ用のサンプル（ベンダー別・貼り付け形式）
#   pcapの「デモシミュレーター」に相当する、show系コマンド貼り付けの実例集。
#   それぞれ show_analyzer.py のベンダー別異常検知が実際に反応する内容にしてある。
# ─────────────────────────────────────────
SHOWLOG_SAMPLES = {
    "Cisco IOS/IOS-XE": """Switch#show logging
Jul  4 09:58:12.101: %SYS-2-MALLOCFAIL: Memory allocation of 65536 bytes failed
Jul  4 09:59:03.552: %SYS-3-CPUHOG: Task ran for 3204ms, process = IP Input
Jul  4 10:00:39.701: %SYS-5-RESTART: System restarted --
Jul  4 10:01:27.694: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
Jul  4 10:01:28.011: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down
Switch#show running-config
hostname Switch
interface GigabitEthernet0/1
 description Uplink-to-Core
 no ip address
 shutdown
interface Vlan1
 ip address 192.168.1.10 255.255.255.0
Switch#show interface status
Port      Name               Status       Vlan       Duplex  Speed Type
Gi0/1     Uplink-to-Core     notconnect   1          auto    auto  10/100/1000BaseTX
Gi0/2                        connected    1          a-full  a-1000 10/100/1000BaseTX
Switch#""",

    "F5 BIG-IP": """[root@bigip1:Standby:Not In Sync] ~ # tmsh show ltm pool
Ltm::Pool: pool_web01
Status
Availability   : available
State          : enabled
Reason         : The pool has no enabled members. 0 of 2 members available

Ltm::Pool Member: 10.0.0.11:80
  Session       : monitor-enabled
  State         : down

Ltm::Pool Member: 10.0.0.12:80
  Session       : monitor-enabled
  State         : down
[root@bigip1:Standby:Not In Sync] ~ # tmsh show sys ha-status
HA status
  This device        : Standby
  Peer device        : Active
  Config sync status : Not In Sync
[root@bigip1:Standby:Not In Sync] ~ #""",

    "Palo Alto": """admin@PA-FW> show system info
hostname: PA-FW01
model: PA-820
sw-version: 10.2.3
admin@PA-FW> show high-availability state

Local Information:
    Mode: Active-Passive
    State: suspended
    Reason: Suspended by user

Peer Information:
    State: active
admin@PA-FW> show session info
num-active: 195000
num-max: 200000
num-tcp: 120000
num-udp: 60000
admin@PA-FW> request license info
Feature: Threat Prevention
Description: Threat Prevention License
Expires: 2026-01-01
Expired: yes
admin@PA-FW>""",

    "富士通 Si-R": """SiR-G210#show logging
Jul  4 09:50:12 SiR-G210 protocol: ether 1 1 link down
Jul  4 09:50:15 SiR-G210 isakmp: DPD watching host is down. [203.0.113.1]
Jul  4 09:52:30 SiR-G210 bgpd: 10.0.0.1 recv NOTIFICATION 6/2 (Cease/Administrative Shutdown)
Jul  4 09:55:02 SiR-G210 init: error code [85020000]
Jul  4 09:56:40 SiR-G210 cmodemctl: [WWAN1] PIN code error. modem0 (PUK required)
SiR-G210#""",
}

# ─────────────────────────────────────────
# テストログ定義
# ─────────────────────────────────────────
TEST_LOGS = {
    "Cisco IOS/IOS-XE": [
        ("<189>Jun 30 10:00:01 catalyst01 %LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down", "192.168.1.1"),
        ("<190>Jun 30 10:01:00 catalyst01 %SYS-5-CONFIG_I: Configured from console by admin on vty0", "192.168.1.1"),
        ("<187>Jun 30 10:02:00 catalyst01 %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gi1/0/2 from LOADING to FULL", "192.168.1.1"),
    ],
    "Cisco NX-OS": [
        ("<163>2024 Jun 30 10:00:00 JST nexus01 %ETH_PORT_CHANNEL-5-FOP_CHANGED: port-channel5: first operational port changed from Ethernet1/1 to Ethernet1/2", "192.168.1.2"),
        ("<131>2024 Jun 30 10:01:00 JST nexus01 %VPC-3-VPC_PEER_KEEP_ALIVE_RECV_FAIL: In domain 10, vPC peer keep-alive receive has failed", "192.168.1.2"),
    ],
    "富士通 Si-R": [
        # Si-R G12x/G21x メッセージ集の実メッセージ形式に準拠
        ("<22>Jun 30 10:00:00 SiR-G210 protocol: ether 1 1 link up", "192.168.1.3"),
        ("<19>Jun 30 10:01:00 SiR-G210 protocol: ether 1 3 link down", "192.168.1.3"),
        ("<22>Jun 30 10:02:00 SiR-G210 protocol: [line0] ch1 disconnected by peer", "192.168.1.3"),
        ("<163>Jun 30 10:03:00 SiR-G210 isakmp: DPD watching host is down. [203.0.113.1]", "192.168.1.3"),
        ("<163>Jun 30 10:04:00 SiR-G210 bgpd: 10.0.0.1 recv NOTIFICATION 6/2 (Cease/Administrative Shutdown)", "192.168.1.3"),
        ("<163>Jun 30 10:05:00 SiR-G210 nsm: vrrp master router down detection. lan0 vrid1 [192.168.1.1] #3", "192.168.1.3"),
        ("<165>Jun 30 10:06:00 SiR-G210 cmodemctl: [WWAN1] PIN code error. modem0 (PUK required)", "192.168.1.3"),
        ("<165>Jun 30 10:07:00 SiR-G210 sshlogin: failed login admin on ssh 1 from 203.0.113.100", "192.168.1.3"),
    ],
    "富士通 IPCOM": [
        ("<165>Jun 30 10:00:00 ipcom-ex01 ipf[1234]: [DENY] TCP 192.168.100.50:54321->10.0.0.1:22", "192.168.1.7"),
        ("<166>Jun 30 10:01:00 ipcom-ex01 ifmgr[100]: IF GigabitEthernet0 link down", "192.168.1.7"),
        ("<165>Jun 30 10:02:00 ipcom-ex01 iked[200]: INFO IKE SA established peer=203.0.113.1", "192.168.1.7"),
        ("<163>Jun 30 10:03:00 ipcom-ex01 bgpd[300]: BGP neighbor 10.0.0.2 Down: Hold Timer Expired", "192.168.1.7"),
        ("<165>Jun 30 10:04:00 ipcom-ex01 natd[400]: NAT session table full, dropping new connection", "192.168.1.7"),
    ],
    "富士通 SR-S": [
        ("<134>Jun 30 10:00:00 sw-srs01 l2loopd: Configuration Testing Protocol detects a loop in port 5 and port 6", "192.168.1.8"),
        ("<134>Jun 30 10:01:00 sw-srs01 l2loopd: Configuration Testing Protocol blocked port 5", "192.168.1.8"),
        ("<134>Jun 30 10:02:00 sw-srs01 protocol: ether 3 link down", "192.168.1.8"),
        ("<134>Jun 30 10:03:00 sw-srs01 mstpd: Topology Change detected", "192.168.1.8"),
        ("<134>Jun 30 10:04:00 sw-srs01 protocol: MAC learning entry moved from ether 1 to ether 2 [00:11:22:33:44:55 vid=10]", "192.168.1.8"),
        ("<134>Jun 30 10:05:00 sw-srs01 telnetd: failed login guest on telnet from 192.168.1.100", "192.168.1.8"),
    ],
    "F5 BIG-IP LTM": [
        ("<133>Jun 30 10:00:00 bigip1 tmm[1234]: 01010028:4: Pool /Common/web_pool member /Common/10.0.0.11:80 monitor status down.", "192.168.1.20"),
        ("<134>Jun 30 10:01:00 bigip1 tmm1[1234]: 01010221:5: Pool /Common/web_pool member /Common/10.0.0.11:80 monitor status up.", "192.168.1.20"),
        ("<131>Jun 30 10:02:00 bigip1 tmm[1234]: 01010025:3: Pool /Common/web_pool now has no members available.", "192.168.1.20"),
        ("<134>Jun 30 10:03:00 bigip1 tmm[1234]: 01340011:5: HA process failover: going standby.", "192.168.1.20"),
        ("<133>Jun 30 10:04:00 bigip1 tmm[1234]: 01260009:4: SSL handshake failed / certificate expired for virtual /Common/vs_https.", "192.168.1.20"),
        ("<131>Jun 30 10:05:00 bigip1 mcpd[1000]: 010719xx:3: Configuration sync failed: device group mismatch.", "192.168.1.20"),
    ],
    "Palo Alto": [
        ("<14>Jun 30 10:00:00 PA-FW01 1,2026/06/30 10:00:00,001801000001,THREAT,vulnerability,2049,2026/06/30 10:00:00,203.0.113.9,10.0.0.5,,,allow-web,,,web-browsing,vsys1,untrust,trust,ae1,ae2,log-forward,,critical,,drop,,SQL Injection Attempt", "192.168.1.30"),
        ("<14>Jun 30 10:01:00 PA-FW01 1,2026/06/30 10:01:00,001801000001,TRAFFIC,end,2049,,,10.0.0.5,203.0.113.1,,,allow-web,,,ssl,vsys1,trust,untrust,,,,allow", "192.168.1.30"),
        ("<14>Jun 30 10:02:00 PA-FW01 1,2026/06/30 10:02:00,001801000001,TRAFFIC,deny,2049,,,10.0.0.9,8.8.8.8,,,block-dns,,,dns,vsys1,trust,untrust,,,,deny", "192.168.1.30"),
        ("<14>Jun 30 10:03:00 PA-FW01 1,2026/06/30 10:03:00,001801000001,SYSTEM,general,0,,,,,,,high,HA1 link down, peer suspended", "192.168.1.30"),
        ("<14>Jun 30 10:04:00 PA-FW01 1,2026/06/30 10:04:00,001801000001,CONFIG,0,0,,,,admin,commit,committed,succeeded", "192.168.1.30"),
        ("<14>Jun 30 10:05:00 PA-FW01 1,2026/06/30 10:05:00,001801000001,SYSTEM,general,0,,,,,,,medium,Threat Prevention license expired", "192.168.1.30"),
    ],
    "APRESIA": [
        ("<131>Jun 30 10:00:00 apresia01 LINK_DOWN: Port 1/0/3 link down", "192.168.1.4"),
        ("<134>Jun 30 10:01:00 apresia01 LOOP_DETECT: Loop detected on Port 1/0/5 - port blocked", "192.168.1.4"),
        ("<134>Jun 30 10:02:00 apresia01 STP: Topology change detected on Port 1/0/2", "192.168.1.4"),
    ],
    "RHEL/Linux": [
        ("<38>Jun 30 10:00:00 rhel-server01 sshd[12345]: Failed password for invalid user admin from 203.0.113.100 port 55234 ssh2", "192.168.1.5"),
        ("<85>Jun 30 10:01:00 rhel-server01 sudo[23456]: user01 : TTY=pts/0 ; PWD=/home/user01 ; USER=root ; COMMAND=/bin/systemctl restart httpd", "192.168.1.5"),
        ("<30>Jun 30 10:02:00 rhel-server01 kernel: Out of memory: Kill process 9876 (java) score 890 or sacrifice child", "192.168.1.5"),
    ],
    "Windows": [
        ("<14>Jun 30 10:00:00 WIN-SERVER01 MSWinEventLog[Security]: EventID=4625 Logon Type=3 User=Administrator Source=203.0.113.200", "192.168.1.6"),
        ("<14>Jun 30 10:01:00 WIN-SERVER01 MSWinEventLog[Security]: EventID=4740 Account=testuser Caller=WIN-DC01", "192.168.1.6"),
        ("<14>Jun 30 10:02:00 WIN-SERVER01 MSWinEventLog[System]: EventID=7034 ServiceName=MyService", "192.168.1.6"),
    ],
}

def _get_config_context(ip: str) -> str:
    """登録済みコンフィグから該当IPのインターフェース/ルーティング概要を取得"""
    cfg = db.get_device_config(ip)
    if not cfg:
        return ""
    parts = []
    if cfg.get("interfaces_summary"):
        parts.append("【インターフェース構成】\n" + cfg["interfaces_summary"])
    if cfg.get("routing_summary"):
        parts.append("【ルーティング構成】\n" + cfg["routing_summary"])
    if cfg.get("notes"):
        parts.append("【補足メモ】\n" + cfg["notes"])
    return "\n\n".join(parts)

# ── show logging 出力を一括取り込み ──────────────────────────
import re as _re_ingest

# 先頭のシーケンス番号（例 "000123: "）を除去
_SHOW_LOG_SEQ_RE = _re_ingest.compile(r"^\s*\d{1,6}:\s+")

# ノイズ行（show logging のステータス/バナー/プロンプト/コマンドエコー）→ 取り込まない
_SHOW_LOG_NOISE_RE = _re_ingest.compile(
    r"^(?:"
    r".*[#>]\s*(?:sh(?:ow)?)\s+logg|"                 # コマンドエコー "Switch#show logging"
    r"\s*\S+[#>]\s*$|"                                 # プロンプトのみ "Switch#"
    r"\s*(?:syslog logging|console logging|monitor logging|buffer logging|"
    r"exception logging|count and timestamp|persistent logging|trap logging|"
    r"file logging|logging source-interface|logging to|logging exception|"
    r"logging message counter|logging for|log buffer\s*\(|origin-id|esm:|"
    r"no active filter|no inactive filter|active filter modules|"
    r"filtering disabled|no (?:in)?active message discriminator|"
    r"message discriminator|copyright \(c\)|compiled |cisco ios software|"
    r"technical support:|system image file|rom:\s|bootldr:|"
    r"\s*members?\s|\d+ messages? (?:logged|dropped|rate-limited))"
    r")", _re_ingest.IGNORECASE)

# 実ログ行らしさの判定（ホワイトリスト）
_MNEMONIC_RE = _re_ingest.compile(r"%[A-Za-z0-9_]+-\d+-[A-Za-z0-9_]+")
_TS_CISCO_RE = _re_ingest.compile(r"^\*?\s*\w{3}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}")
_TS_ISO_RE   = _re_ingest.compile(r"^\d{4}[-/]\d{1,2}[-/]\d{1,2}[ T]\d{1,2}:\d{2}")
_PRI_RE      = _re_ingest.compile(r"^<\d{1,3}>")
# 富士通 show logging syslog 形式（date host machine : process: ...）
_FJ_PROC_RE  = _re_ingest.compile(r"\b[a-z][\w\-]*:\s")


def _looks_like_log(line: str) -> bool:
    """実際のログ行（イベント）らしいか。ステータス/バナー行を除外する。"""
    if _MNEMONIC_RE.search(line):      # Cisco %FAC-N-MNEM
        return True
    if _PRI_RE.match(line):            # syslog PRI <NNN>
        return True
    if _TS_CISCO_RE.match(line):       # "Jul  4 00:54:39" / "*Mar 1 00:00:18"
        return True
    if _TS_ISO_RE.match(line):         # "2026/07/03 10:00:00"（富士通等）
        return True
    return False


def _ingest_show_logging(text: str, source_ip: str) -> dict:
    """
    `show logging` / `show logging syslog` の貼り付け出力を1行ずつ解析し DB 取り込み。
    ステータス行・バナー・プロンプト・コマンドエコーは自動除外し、実ログ行のみ取り込む。
    戻り値: {"total", "skipped", "by_vendor"}
    """
    total = 0
    skipped = 0
    by_vendor: dict[str, int] = {}
    ids: list = []
    for raw_line in (text or "").splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue
        # 先頭シーケンス番号を除去
        line = _SHOW_LOG_SEQ_RE.sub("", line).strip()
        if not line:
            continue
        # ノイズ行は除外
        if _SHOW_LOG_NOISE_RE.search(line):
            skipped += 1
            continue
        # 実ログ行に見えないものは除外（未分類ゴミの取り込み防止）
        if not _looks_like_log(line):
            skipped += 1
            continue
        try:
            parsed = parse_syslog(line, source_ip)
            _new_id = db.insert_log(source_ip, line, parsed)
            if _new_id:
                ids.append(_new_id)
            v = parsed.get("vendor", "不明")
            by_vendor[v] = by_vendor.get(v, 0) + 1
            total += 1
        except Exception:
            skipped += 1
    return {"total": total, "skipped": skipped, "by_vendor": by_vendor, "ids": ids}


# ── show logging の LLM 詳細解析（config / interface status 相関対応） ──
def _llm_analyze_show_log(logs: list, mode: str,
                          config_text: str = "", intf_text: str = "",
                          extra_text: str = "") -> tuple[str, str]:
    """
    取り込んだログ一覧に加え、show running-config / show interface status /
    その他のshow出力(routing/cpu/counters等) を突き合わせて総合解析する。
    ルーティング・ICMP redirect・CPU/メモリ・ブロードキャスト/マルチキャストも観点に含む。
    戻り値: (レポート本文, モデル名)
    """
    import json as _json
    lines = []
    vendors_present = set()
    for lg in logs[:200]:
        tags = lg.get("tags")
        if isinstance(tags, str):
            try:
                tags = _json.loads(tags)
            except Exception:
                tags = []
        tagstr = ",".join(t for t in (tags or [])
                          if not t.startswith(("src:", "loop_port", "from:", "to:", "mac:")))
        v = lg.get("vendor", "")
        if v:
            vendors_present.add(v)
        lines.append(f"[{lg.get('severity','INFO')}] {v} "
                     f"{lg.get('message','')}  <{tagstr}>")
    ctx = "\n".join(lines) if lines else "(ログなし)"

    # ベンダー別の重点確認事項（検出されたベンダーのみ追加）
    _vendor_checks = []
    if any("F5" in v or "BIG-IP" in v for v in vendors_present):
        _vendor_checks.append(
            "・F5 BIG-IP: プールメンバーの監視状態(down/available)と可用数、仮想サーバの状態、"
            "HA(冗長化)の同期状況(In Sync/Not In Sync)とActive/Standby、SSL証明書の有効期限、"
            "TMMメモリ/CPU使用率、コネクション数の急増を重点的に確認する。")
    if any("Palo Alto" in v for v in vendors_present):
        _vendor_checks.append(
            "・Palo Alto: 脅威(THREAT)ログのseverityとaction(drop/reset=防御成功、alertのみ=通過中で要確認)、"
            "HA状態(suspended/non-functional/sync)、ライセンス/サブスクリプション期限、"
            "セッション使用率、GlobalProtect接続状況、ポリシーでの拒否/許可傾向を重点的に確認する。")
    if any("Cisco" in v for v in vendors_present):
        _vendor_checks.append(
            "・Cisco: インターフェースのリンク状態とエラーカウンタ、STP(トポロジ変更/ループ検知/BPDU異常)、"
            "OSPF/BGP/HSRP/VRRP等の隣接・冗長状態、CPU/メモリ使用率、ライセンスレベル、"
            "セキュリティ(ACL拒否ログ/認証失敗/ポートセキュリティ違反/err-disable)を重点的に確認する。")
    vendor_check_block = ("\n" + "\n".join(_vendor_checks) + "\n") if _vendor_checks else ""

    # 長すぎる config / interface は切り詰め（トークン節約）
    def _clip(s, n):
        s = (s or "").strip()
        return s if len(s) <= n else s[:n] + "\n…(以下省略)"
    cfg = _clip(config_text, 6000)
    intf = _clip(intf_text, 3000)
    extra = _clip(extra_text, 5000)

    system = (
        "あなたは Cisco / 富士通などのネットワーク機器に精通した運用エンジニアです。"
        "同一機器から採取した show logging・show running-config・show interface status を"
        "相互に突き合わせ、事実に基づいて日本語で報告します。\n"
        "【厳守事項】\n"
        "1. ログ・設定・状態に実在する記述だけを根拠にする。書かれていない事象を作らない（ハルシネーション禁止）。\n"
        "2. 「確定（出力から読み取れる）」と「推測」を必ず分けて書く。推測には『推測:』と付ける。\n"
        "3. 各指摘には該当するログ行・設定行・ポート名を引用する。\n"
        "4. 以下の既知の正常挙動を誤って障害/バグと判定しない:\n"
        "   ・%SYS-5-RESTART は通常の再起動通知でクラッシュではない\n"
        "   ・%PNP-* は未設定機のゼロタッチ(PnP)動作。PnPサーバ不在時の alarm は想定内\n"
        "   ・'administratively down' は shutdown 設定によるもので障害ではない\n"
        "   ・notconnect はケーブル未接続、'Not Present' は SFP等モジュール未実装\n"
        "   ・F5: 'monitor status up' への遷移は正常復旧。意図したメンテナンス中のmemberダウンは想定内\n"
        "   ・Palo Alto: action=allow のTRAFFICログは正常通信。THREATでaction=dropは防御成功（障害ではない）\n"
    )
    user = (
        "同一機器の以下の出力を突き合わせて解析してください。次の構成で回答します。\n\n"
        "1. 【全体サマリ】機種・役割・設定状況・接続状況を3行以内で\n"
        "2. 【確定事象】ログ/設定/状態から事実として読み取れること（該当行を引用）\n"
        "3. 【バグ/不具合の有無】クラッシュ/メモリ/watchdog/再起動異常などの兆候。無ければ『不具合の兆候なし』と明記\n"
        "4. 【ルーティング】OSPF/BGP/EIGRP/RIP等の隣接・経路・再配布の異常、"
        "経路フラップやルーティングテーブルの問題（該当ログ/設定を引用。無ければ『言及なし』）\n"
        "5. 【ICMP Redirect / 三角ルーティング】ICMP redirect の送受信や、"
        "非効率な経路（同一セグメントへの折り返し）の兆候（無ければ『兆候なし』）\n"
        "6. 【CPU / メモリ / 温度】高CPU・メモリ枯渇・高温などリソース逼迫の兆候\n"
        "7. 【ブロードキャスト/マルチキャスト】ブロードキャスト/マルチキャスト過多、"
        "ストーム、IGMP/PIM関連、ループ由来のフレーム氾濫の兆候（該当を引用。無ければ『兆候なし』）\n"
        "8. 【エラー/破棄/インターフェース品質】入出力エラー・破棄・デュプレックス不一致・CRC等\n"
        "9. 【設定・運用上の問題】未設定・セキュリティ・ライセンス・冗長性など（該当箇所を引用）\n"
        "10.【ログと設定の相関】ログの事象を設定/状態で説明できるか（例: Vlan down ↔ interface Vlan1 shutdown）\n"
        "11.【推奨アクション】優先度順に、実行コマンド（show系の追加確認コマンド含む）付きで\n"
        f"{vendor_check_block}"
        "※各項目、提供データに該当が無ければ『該当データなし』と明記し、想像で埋めないこと。\n"
        "※show ip route / show processes cpu / show interfaces counters / "
        "tmsh show ltm pool / show high-availability state 等が貼られていれば併せて解析すること。\n\n"
        f"────── show logging（解析済み {len(lines)}件）──────\n{ctx}\n\n"
        f"────── show running-config ──────\n{cfg if cfg else '(未提供)'}\n\n"
        f"────── show interface status ──────\n{intf if intf else '(未提供)'}\n\n"
        f"────── その他の show 出力（routing/cpu/counters 等）──────\n{extra if extra else '(未提供)'}\n"
    )
    return analyzer.ask_llm(system, user, mode, max_tokens=3500)


def _llm_analyze_prtg(devices: list, latest_metrics: list, alerts: list,
                      label_map: dict, mode: str,
                      running_configs: dict | None = None) -> tuple[str, str]:
    """
    MRTG風ダッシュボードの現況（デバイス状態・最新センサー値・超過アラート）を
    LLMに渡し、総合的な健全性診断レポートを生成する。
    running_configs: {ip: config_text} が渡された場合、show running-config も
    踏まえたコンフィグ是正点の指摘を追加で行う。
    戻り値: (レポート本文, モデル名)
    """
    # デバイス状態
    dev_lines = []
    for d in devices:
        dev_lines.append(f"- {d.get('hostname') or d.get('ip')} ({d.get('ip')}): "
                         f"状態={d.get('last_status','unknown')} 最終ポーリング={d.get('last_polled','-')}")
    dev_ctx = "\n".join(dev_lines) if dev_lines else "(登録デバイスなし)"

    # 最新センサー値（(ip, oid_name) ごとに最新1件）
    seen = set()
    sensor_lines = []
    for m in latest_metrics:
        key = (m.get("source_ip"), m.get("oid_name"))
        if key in seen:
            continue
        seen.add(key)
        name = prtg_view.metric_label(m.get("oid_name"), label_map)
        sensor_lines.append(f"- [{m.get('alert_level','none')}] {m.get('hostname') or m.get('source_ip')} "
                            f"{name} = {m.get('value','-')} {m.get('unit','')}")
    sensor_ctx = "\n".join(sensor_lines[:150]) if sensor_lines else "(センサーデータなし)"

    # しきい値超過アラート
    alert_lines = []
    for a in alerts:
        name = prtg_view.metric_label(a.get("oid_name"), label_map)
        alert_lines.append(f"- [{a.get('alert_level','')}] {a.get('hostname') or a.get('source_ip')} "
                           f"{name} = {a.get('value','-')} {a.get('unit','')} ({a.get('recorded_at','')})")
    alert_ctx = "\n".join(alert_lines) if alert_lines else "(しきい値超過なし)"

    # show running-config（SNMP/CISCO-CONFIG-COPY-MIB経由で取得済みのもの）
    cfg_blocks = []
    for _ip, _cfg in (running_configs or {}).items():
        _host = next((d.get("hostname") for d in devices if d.get("ip") == _ip), None) or _ip
        cfg_blocks.append(f"### {_host} ({_ip}) の running-config\n```\n{_cfg[:8000]}\n```")
    cfg_ctx = "\n\n".join(cfg_blocks) if cfg_blocks else ""

    system = (
        "あなたはネットワーク運用監視(PRTG/Zabbix等)に精通した運用エンジニアです。"
        "SNMPポーリングで収集したデバイス状態・センサー値・アラートを分析し、"
        "日本語で事実ベースの診断を行います。"
        "提供データに無いことは推測せず「データなし」と明記してください。"
    )
    sections = (
        "1. 【全体サマリ】監視対象デバイス数・状態・全体的な健全性を3行以内で。"
        "down/エラー/しきい値超過アラートが1件もない場合は、先頭に"
        "「🚀 現在異常はありません。順調に稼働しています」のように、"
        "一目で安心できる前向きな一言を日本語で添えてください。\n"
        "2. 【デバイス状態】down/エラーの機器があれば個別に指摘\n"
        "3. 【リソース逼迫】CPU/メモリ/温度/セッション数など高負荷の兆候（しきい値超過を優先）\n"
        "4. 【トラフィック/帯域】帯域使用率が高いインターフェースや異常なエラーカウント\n"
        "5. 【重大アラート】しきい値超過(critical/warning)の内容と考えられる原因\n"
        "6. 【推奨アクション】優先度順に、確認すべきコマンドや対処\n"
    )
    if cfg_ctx:
        sections += (
            "7. 【コンフィグ是正点】show running-configの内容を確認し、"
            "セキュリティ・冗長性・運用上のベストプラクティスに照らして是正すべき点を指摘してください"
            "（例: 未使用ACL/インターフェースの放置、暗号化されていないパスワード、"
            "VTYへのACL未設定、NTP/ロギング未設定、デフォルトのSNMPコミュニティ名 等）。"
            "問題が無ければ「特に是正すべき点はありません」と明記してください。\n"
        )
    user = (
        "以下はネットワーク監視ダッシュボードの現在の状態です。次の構成で診断してください。\n\n"
        f"{sections}\n"
        f"────── 登録デバイス ({len(devices)}台) ──────\n{dev_ctx}\n\n"
        f"────── 最新センサー値 ──────\n{sensor_ctx}\n\n"
        f"────── しきい値超過アラート ──────\n{alert_ctx}\n"
        + (f"\n────── show running-config ──────\n{cfg_ctx}\n" if cfg_ctx else "")
    )
    return analyzer.ask_llm(system, user, mode, max_tokens=3000 if cfg_ctx else 2500)


def _scoped_showlog_logs() -> list:
    """
    show log解析タブの解析対象ログを返す。
    直近に貼り付けたログID集合があればそれだけに絞る（過去ログの混入防止）。
    """
    ids = st.session_state.get("_showlog_ids")
    alllogs = db.get_logs(limit=500)
    if ids:
        return [l for l in alllogs if l.get("id") in ids]
    return alllogs[:200]


def _inject_test_log(vendor: str):
    logs = TEST_LOGS.get(vendor, [])
    for raw, src_ip in logs:
        parsed = parse_syslog(raw, src_ip)
        explanation, model = "", ""
        if st.session_state.auto_analyze and st.session_state.llm_mode != "none":
            config_ctx = _get_config_context(src_ip)
            explanation, model = analyzer.analyze(parsed, raw, st.session_state.llm_mode, config_ctx)
        log_id = db.insert_log(src_ip, raw, parsed, explanation, model)
        if st.session_state.judge_enabled and explanation:
            config_ctx = _get_config_context(src_ip)
            judge_result = analyzer.judge_quality(
                parsed, raw, explanation, st.session_state.llm_mode, config_ctx)
            db.update_judge_result(log_id, judge_result, judge_result.get("judge_model",""))

# ─────────────────────────────────────────
# キューからDB保存（バックグラウンド処理）
# ─────────────────────────────────────────
def _process_queue():
    import queue as Q
    # syslogキュー処理
    q = syslog_server.log_queue
    processed = 0
    while processed < 20:
        try:
            item = q.get_nowait()
            src_ip = item["source_ip"]
            raw    = item["raw"]
            parsed = item["parsed"]
            explanation, model = "", ""
            if st.session_state.auto_analyze and st.session_state.llm_mode != "none":
                config_ctx = _get_config_context(src_ip)
                explanation, model = analyzer.analyze(
                    parsed, raw, st.session_state.llm_mode, config_ctx)
            log_id = db.insert_log(src_ip, raw, parsed, explanation, model)
            if st.session_state.judge_enabled and explanation:
                config_ctx = _get_config_context(src_ip)
                judge_result = analyzer.judge_quality(
                    parsed, raw, explanation, st.session_state.llm_mode, config_ctx)
                db.update_judge_result(log_id, judge_result, judge_result.get("judge_model",""))
            processed += 1
        except Exception:
            break

    # SNMP Trapキュー処理
    tq = snmp_trap_server.trap_queue
    processed = 0
    while processed < 20:
        try:
            item = tq.get_nowait()
            src_ip = item["source_ip"]
            raw    = item["raw"]
            parsed = item["parsed"]
            explanation, model = "", ""
            if st.session_state.auto_analyze and st.session_state.llm_mode != "none":
                config_ctx = _get_config_context(src_ip)
                explanation, model = analyzer.analyze(
                    parsed, raw, st.session_state.llm_mode, config_ctx)
            log_id = db.insert_log(src_ip, raw, parsed, explanation, model)
            if st.session_state.judge_enabled and explanation:
                config_ctx = _get_config_context(src_ip)
                judge_result = analyzer.judge_quality(
                    parsed, raw, explanation, st.session_state.llm_mode, config_ctx)
                db.update_judge_result(log_id, judge_result, judge_result.get("judge_model",""))
            processed += 1
        except Exception:
            break

_process_queue()

# ─────────────────────────────────────────
# メインUI
# ─────────────────────────────────────────
(tab_health, tab1, tab_showlog, tab_prtg, tab2, tab3, tab4, tab5,
 tab_netflow, tab_pcap, tab_topo, tab_probe) = st.tabs([
    "📊 品質ルーブリック", "📋 ログビューア", "📥 show log解析", "📟 MRTG風",
    "📊 テレメトリダッシュボード", "📡 SNMPモニター", "🗂️ 機器コンフィグ",
    "📖 セットアップガイド", "🌊 NetFlow", "📦 パケット解析",
    "🗺️ トポロジー", "⏱️ 応答時間"
])

# ═══════════════════════════════════════════
# TAB: 品質ルーブリック（メイン画面）
# ═══════════════════════════════════════════
with tab_health:
    st.markdown("## 🩺 ネットワーク品質ルーブリック（品質評価）")

    overall = he.get_network_overall_health()

    if overall["overall_score"] is None:
        st.info("まだ品質データがありません。「📡 SNMPモニター」タブでデバイスを登録し、"
                "下の「品質チェック実行」ボタンを押すか、SNMPポーラーを起動してください。")
    else:
        score = overall["overall_score"]
        score_color = "#16a34a" if score >= 85 else "#b45309" if score >= 60 else "#dc2626"
        status_label = "正常" if score >= 85 else "注意" if score >= 60 else "異常"

        col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
        with col1:
            st.markdown(f"""
<div style="background:#ffffff; border:2px solid {score_color}; border-radius:12px; padding:20px; text-align:center;">
  <div style="color:#6b7280; font-size:13px;">ネットワーク総合健全度</div>
  <div style="color:{score_color}; font-size:48px; font-weight:bold; line-height:1.2;">{score}<span style="font-size:20px;">/100</span></div>
  <div style="color:{score_color}; font-size:16px; font-weight:bold;">{status_label}</div>
</div>
""", unsafe_allow_html=True)
        with col2:
            st.metric("🟢 正常", overall["healthy"])
        with col3:
            st.metric("🟡 注意", overall["warning"])
        with col4:
            st.metric("🔴 異常", overall["critical"])

    st.markdown("---")

    col_run1, col_run2 = st.columns([2, 1])
    with col_run1:
        st.markdown("### 機器別品質ステータス")
    with col_run2:
        run_llm = st.checkbox("LLM診断を含める", value=False,
                              help="各機器をLLMが総合診断します（時間とAPI呼び出しが増えます）")
        if st.button("🤖 品質チェック実行", use_container_width=True, type="primary"):
            devices = snmp_poller.get_devices()
            if not devices:
                st.warning("SNMPデバイスが登録されていません。SNMPモニタータブで登録してください。")
            else:
                prog = st.progress(0)
                llm_mode = st.session_state.llm_mode if run_llm else "none"
                for idx, dev in enumerate(devices):
                    with st.spinner(f"{dev['ip']} をチェック中..."):
                        try:
                            snmp_poller.poll_device_health(
                                dev["ip"], dev.get("community","public"),
                                dev.get("version","v2c"), dev.get("port",161),
                                llm_mode=llm_mode
                            )
                        except Exception as e:
                            st.error(f"{dev['ip']}: {e}")
                    prog.progress((idx+1)/len(devices))
                st.success("品質チェック完了")
                st.rerun()

    st.caption("💡 CPU・メモリ・温度は即時取得。スループット・破棄・ブロードキャスト率は2回目以降のチェックで差分計算されます（初回は基準値の取得のみ）。")

    devices_health = he.get_latest_health_all()
    if devices_health:
        for dh in devices_health:
            dh_score = dh["health_score"]
            dh_color = "#16a34a" if dh_score >= 85 else "#b45309" if dh_score >= 60 else "#dc2626"
            dh_icon = "🟢" if dh_score >= 85 else "🟡" if dh_score >= 60 else "🔴"
            metrics = dh.get("metrics", {})
            issues = dh.get("issues", [])

            with st.expander(f"{dh_icon} {dh['hostname']} ({dh['source_ip']}) — {dh_score}/100", expanded=(dh_score < 60)):
                mcols = st.columns(5)
                with mcols[0]:
                    cpu = metrics.get("cpu_5min")
                    st.metric("CPU(5分)", f"{cpu}%" if cpu is not None else "—")
                with mcols[1]:
                    mem = metrics.get("memory_used_pct")
                    st.metric("メモリ", f"{mem}%" if mem is not None else "—")
                with mcols[2]:
                    temp = metrics.get("temperature_celsius")
                    st.metric("温度", f"{temp}℃" if temp is not None else "—")
                with mcols[3]:
                    st.metric("検出問題数", len(issues))
                with mcols[4]:
                    st.metric("最終チェック", dh["recorded_at"][11:19])

                if issues:
                    st.markdown("**検出された問題:**")
                    for iss in issues:
                        lv_color = "#dc2626" if iss["level"] == "critical" else "#b45309"
                        st.markdown(
                            f"<div style='color:{lv_color}; font-size:13px;'>"
                            f"● [{iss['category']}] {iss['msg']}</div>",
                            unsafe_allow_html=True
                        )
                else:
                    st.success("問題は検出されていません")

                diag = dh.get("llm_diagnosis")
                if diag:
                    st.markdown("---")
                    st.markdown(f"**🤖 LLM総合診断** ({diag.get('diagnosis_model','')})")
                    st.markdown(f"**診断:** {diag.get('diagnosis','')}")
                    if diag.get("root_cause") and diag["root_cause"] != "特になし":
                        st.markdown(f"**🎯 根本原因:** {diag['root_cause']}")
                    chain = diag.get("causal_chain", [])
                    if chain:
                        st.markdown("**🔗 因果連鎖:** " + " → ".join(chain))
                    if diag.get("throughput_assessment"):
                        st.markdown(f"**📊 スループット評価:** {diag['throughput_assessment']}")
                    if diag.get("priority_action"):
                        st.info(f"**⚡ 最優先アクション:** {diag['priority_action']}")
                    if diag.get("risk_if_ignored"):
                        st.warning(f"**⚠️ 放置リスク:** {diag['risk_if_ignored']}")

                # ── エージェント診断（Claude tool use、メトリクス推移深掘りMVP） ──
                if analyzer.check_claude_available():
                    _hdev_ip = dh["source_ip"]
                    if st.button("🕵️ エージェント診断（メトリクス推移を深掘り）",
                                 key=f"health_agentic_{_hdev_ip}", use_container_width=True):
                        with st.spinner("Claudeがメトリクス推移を確認しながら分析中..."):
                            _recent_logs = db.get_logs(limit=10, source_ip=_hdev_ip)
                            st.session_state[f"_health_agentic_{_hdev_ip}"] = \
                                analyzer.diagnose_health_agentic(dh, _recent_logs)

                    _hdiag = st.session_state.get(f"_health_agentic_{_hdev_ip}")
                    if _hdiag:
                        if _hdiag.get("tool_calls_made"):
                            st.caption("🔍 確認したメトリクス: " + ", ".join(_hdiag["tool_calls_made"]))
                        st.markdown(f"**診断:** {_hdiag.get('diagnosis','')}")
                        if _hdiag.get("root_cause") and _hdiag["root_cause"] != "特になし":
                            st.markdown(f"**🎯 根本原因:** {_hdiag['root_cause']}")
                        if _hdiag.get("priority_action"):
                            st.info(f"**⚡ 最優先アクション:** {_hdiag['priority_action']}")

                trend = he.get_health_trend(dh["source_ip"], hours=6)
                if len(trend) >= 2:
                    df_trend = pd.DataFrame(trend)
                    df_trend["time"] = df_trend["recorded_at"].str[11:16]
                    st.line_chart(df_trend.set_index("time")["health_score"])

    st.markdown("---")
    with st.expander("📖 品質スコアの算出基準"):
        st.markdown("""
**100点満点からの減点方式**

| 項目 | 注意（減点） | 危険（減点） |
|------|------------|------------|
| CPU使用率(5分) | 60%以上（-10） | 80%以上（-25） |
| メモリ使用率 | 75%以上（-8） | 90%以上（-20） |
| 帯域使用率 | 70%以上（-5） | 90%以上（-12） |
| ブロードキャスト率 | 5%以上（-6） | 20%以上（-15） |
| パケット破棄率 | 0.1%以上（-5） | 1%以上（-12） |
| 入力エラー率 | 0.01%以上（-4） | 0.1%以上（-10） |
| 筐体温度 | 60℃以上（-8） | 75℃以上（-20） |
| インターフェースダウン | — | -15 |

**ステータス判定:** 85点以上=🟢正常 / 60〜84点=🟡注意 / 60点未満=🔴異常

**Cisco系の相関分析:**
ブロードキャスト急増 → CPU上昇 → 破棄増加 → ルーティング不安定、という連鎖を
LLM診断が「根本原因はブロードキャストストーム」と推定します。
温度上昇が続く場合は冷却障害・ファン停止の疑いで、CPU/メモリ性能低下の前兆となることがあります。
        """)

# ═══════════════════════════════════════════
# TAB1: ログビューア
# ═══════════════════════════════════════════
with tab1:
    st.markdown("## 📋 受信ログ一覧")

    st.caption("💡 機器の `show logging` 出力を貼り付けて解析したいときは、上部の "
               "「📥 show log解析」タブをご利用ください。")

    # フィルター
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        f_vendor = st.selectbox("ベンダー", ["すべて", "Cisco IOS/IOS-XE", "Cisco NX-OS",
                                              "富士通 Si-R", "富士通 IPCOM", "富士通 SR-S",
                                              "F5 BIG-IP LTM", "Palo Alto",
                                              "APRESIA ApresiaLight",
                                              "RHEL/Linux", "Windows", "Generic/不明"])
    with col2:
        f_severity = st.selectbox("重要度", ["すべて", "EMERGENCY", "ALERT", "CRITICAL",
                                              "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"])
    with col3:
        f_ip = st.text_input("送信元IP", placeholder="例: 192.168.1.1")
    with col4:
        f_limit = st.number_input("表示件数", min_value=10, max_value=500, value=50, step=10)

    logs = db.get_logs(
        limit=int(f_limit),
        source_ip=f_ip if f_ip else None,
        severity=f_severity if f_severity != "すべて" else None,
        vendor=f_vendor if f_vendor != "すべて" else None
    )

    # 自動更新
    auto_refresh = st.checkbox("🔄 5秒ごとに自動更新", value=False)
    if auto_refresh:
        time.sleep(5)
        st.rerun()

    st.caption(f"表示中: {len(logs)} 件")

    if not logs:
        st.info("ログがありません。サーバーを起動してネットワーク機器からsyslogを送信するか、テストログを投入してください。")
    else:
        for log in logs:
            sev = log.get("severity", "INFO")
            vendor = log.get("vendor", "")
            hostname = log.get("hostname", "")
            process = log.get("process", "")
            message = log.get("message", "")
            received = log.get("received_at", "")[:19].replace("T", " ")
            src_ip = log.get("source_ip", "")
            tags = json.loads(log.get("tags") or "[]")
            ai_text = log.get("ai_explanation", "")
            ai_model = log.get("ai_model", "")
            judge_text = log.get("judge_result", "")
            judge_model = log.get("judge_model", "")

            sev_color = {
                "EMERGENCY": "#dc2626", "ALERT": "#dc2626", "CRITICAL": "#dc2626",
                "ERROR": "#ea580c", "WARNING": "#b45309",
                "NOTICE": "#2563eb", "INFO": "#16a34a", "DEBUG": "#64748b"
            }.get(sev, "#64748b")

            border_color = sev_color if sev in ("EMERGENCY","ALERT","CRITICAL","ERROR") else "#d0d7de"

            with st.container():
                st.markdown(f"""
<div class="log-card" style="border-left-color:{border_color}">
  <div style="display:flex; justify-content:space-between; align-items:center;">
    <span style="color:{sev_color}; font-weight:bold;">◉ {sev}</span>
    <span style="color:#6b7280; font-size:11px;">{received} | {src_ip}</span>
  </div>
  <div style="color:#1f2937; margin:4px 0;">
    <span style="color:#0891b2;">[{vendor}]</span>
    <span style="color:#92400e;"> {hostname}</span>
    <span style="color:#9333ea;"> {process}</span>
  </div>
  <div style="color:#1f2937; margin:4px 0; word-break:break-all;">{message[:300]}</div>
  <div>{"".join(f'<span class="tag-chip">{t}</span>' for t in tags)}</div>
</div>
""", unsafe_allow_html=True)

                # AI解析結果表示
                if ai_text:
                    try:
                        ai_data = json.loads(ai_text)
                        impact_color = {
                            "重大": "#dc2626", "中程度": "#ea580c",
                            "軽微": "#b45309", "なし": "#16a34a"
                        }.get(ai_data.get("impact",""), "#64748b")
                        config_note = ai_data.get('config_context_note', '')
                        config_note_html = f'''
<div class="telemetry-note" style="background:#f3eefd; border-color:#7c3aed; color:#7c3aed;">
  🗂️ コンフィグ参照: {config_note}
</div>''' if config_note else ''
                        st.markdown(f"""
<div class="ai-explanation">
  <div style="color:#2563eb; font-size:11px; margin-bottom:4px;">
    🤖 AI解析 ({ai_model})
  </div>
  <div style="font-weight:bold; color:#111827;">
    📌 {ai_data.get('summary','')}
  </div>
  <div style="margin:4px 0; color:#1f2937;">{ai_data.get('detail','')}</div>
  <div>
    影響度: <span style="color:{impact_color}; font-weight:bold;">{ai_data.get('impact','')}</span>
    &nbsp;|&nbsp;
    対応: {ai_data.get('action','')}
  </div>
</div>
<div class="telemetry-note">
  📡 テレメトリ観点: {ai_data.get('telemetry_note','')}
</div>
{config_note_html}
""", unsafe_allow_html=True)
                    except Exception:
                        if ai_text:
                            st.markdown(f'<div class="ai-explanation">🤖 {ai_text}</div>',
                                       unsafe_allow_html=True)
                elif st.session_state.llm_mode != "none":
                    col_a, col_b = st.columns([1, 4])
                    with col_a:
                        if st.button("🤖 AI解析", key=f"analyze_{log['id']}",
                                    type="primary", use_container_width=True):
                            with st.spinner("解析中..."):
                                raw = log.get("raw","")
                                from parsers import parse_syslog as ps
                                parsed = ps(raw, log.get("source_ip",""))
                                config_ctx = _get_config_context(log.get("source_ip",""))
                                expl, model = analyzer.analyze(
                                    parsed, raw, st.session_state.llm_mode, config_ctx)
                                db.update_ai_explanation(log["id"], expl, model)
                            st.rerun()

                st.markdown("<hr style='border-color:#e9edf2; margin:8px 0;'>", unsafe_allow_html=True)

    # ── Splunk風 一括ログ LLM 分析 ──────────────────────────────
    if logs:
        st.markdown("---")
        st.markdown("### 📊 ログ一括 AI 分析（Splunk 風）")
        st.caption(
            "現在フィルター中のログをまとめてLLMに渡し、全体的な傾向・根本原因・優先対応をサマリーします。"
        )
        _batch_llm_ok = (analyzer.check_claude_available() or analyzer.check_gemini_available()
                         or analyzer.check_groq_available() or analyzer.check_ollama_available())
        _batch_col1, _batch_col2 = st.columns([3, 1])
        with _batch_col1:
            _batch_max = st.slider("分析対象ログ上限", 10, 200, 50, step=10,
                                   key="batch_llm_limit",
                                   help="多いほど精度が上がりますが LLM への入力トークンが増えます")
        with _batch_col2:
            _batch_btn = st.button("🤖 一括 AI 分析", key="batch_llm_run",
                                   disabled=not _batch_llm_ok,
                                   use_container_width=True, type="primary")
        if not _batch_llm_ok:
            st.caption("一括 AI 分析はサイドバーの「🔑 APIキー設定」でいずれかのLLMを設定してから使用してください。")

        if _batch_btn:
            _batch_logs = logs[:_batch_max]
            _batch_lines = []
            for _bl in _batch_logs:
                _bsev  = _bl.get("severity", "INFO")
                _bhost = _bl.get("hostname", "") or _bl.get("source_ip", "")
                _bmsg  = (_bl.get("message", "") or "")[:200]
                _bts   = (_bl.get("received_at", "") or "")[:19].replace("T", " ")
                _batch_lines.append(f"[{_bts}] {_bsev} {_bhost}: {_bmsg}")
            _batch_text = "\n".join(_batch_lines)
            _batch_ctx = (
                f"対象期間のログ {len(_batch_logs)} 件:\n\n{_batch_text}\n\n"
                f"フィルター条件: ベンダー={f_vendor}, 重要度={f_severity}, IP={f_ip or '全て'}"
            )
            with st.spinner("LLM が全ログをまとめて分析中..."):
                _batch_ai_text, _batch_ai_model = analyzer.ask_llm(
                    "あなたはネットワーク運用の専門家です。"
                    "提供されたネットワーク機器のsyslogログ一覧を分析し、以下を日本語で回答してください:\n"
                    "1. 全体的な状況サマリー（2〜3文）\n"
                    "2. 検出された重大/重要な問題点（箇条書き）\n"
                    "3. 根本原因の推定\n"
                    "4. 最優先の対応策\n"
                    "5. 今後のモニタリングポイント",
                    _batch_ctx,
                    st.session_state.get("llm_mode", "auto"),
                    max_tokens=1500,
                )
            st.session_state["_batch_ai"] = (_batch_ai_text, _batch_ai_model, len(_batch_logs))

        _batch_cached = st.session_state.get("_batch_ai")
        if _batch_cached and _batch_cached[0]:
            with st.expander(
                f"🤖 一括分析結果（{_batch_cached[1]}）— {_batch_cached[2]} 件のログを分析",
                expanded=True
            ):
                st.markdown(_batch_cached[0])

    # ── データダウンロード ───────────────────────────────────────
    st.markdown("---")
    st.markdown("### 💾 データダウンロード")
    _dl_c1, _dl_c2, _dl_c3 = st.columns(3)

    # CSV ダウンロード
    with _dl_c1:
        if logs:
            import io as _io_dl
            _csv_rows = []
            for _lr in logs:
                _csv_rows.append({
                    "受信時刻":    (_lr.get("received_at") or "")[:19].replace("T"," "),
                    "送信元IP":    _lr.get("source_ip",""),
                    "ホスト名":    _lr.get("hostname",""),
                    "ベンダー":    _lr.get("vendor",""),
                    "重要度":      _lr.get("severity",""),
                    "プロセス":    _lr.get("process",""),
                    "メッセージ":  _lr.get("message",""),
                    "AI解析":      _lr.get("ai_explanation",""),
                })
            import csv as _csv_mod
            _csv_buf = _io_dl.StringIO()
            _csv_wr  = _csv_mod.DictWriter(_csv_buf, fieldnames=list(_csv_rows[0].keys()))
            _csv_wr.writeheader()
            _csv_wr.writerows(_csv_rows)
            st.download_button(
                "📄 ログ一覧を CSV でダウンロード",
                data=_csv_buf.getvalue().encode("utf-8-sig"),
                file_name=f"syslog_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )
        else:
            st.caption("ログがないのでダウンロードできません")

    # SQLite DB ダウンロード
    with _dl_c2:
        import db as _db_dl
        _db_path = _db_dl.DB_PATH
        if _db_path.exists():
            with open(_db_path, "rb") as _f_db:
                _db_bytes = _f_db.read()
            st.download_button(
                "🗄️ SQLite DB をダウンロード",
                data=_db_bytes,
                file_name=f"syslog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db",
                mime="application/octet-stream",
                use_container_width=True,
                help="Windowsでも DB Browser for SQLite で開けます"
            )
        else:
            st.caption("DB ファイルが見つかりません")

    # JSON ダウンロード
    with _dl_c3:
        if logs:
            _json_data = json.dumps(
                [{k: v for k, v in _lr.items() if k != "id"} for _lr in logs],
                ensure_ascii=False, indent=2, default=str
            )
            st.download_button(
                "📋 ログ一覧を JSON でダウンロード",
                data=_json_data.encode("utf-8"),
                file_name=f"syslog_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
            )
        else:
            st.caption("ログがないのでダウンロードできません")

# ═══════════════════════════════════════════
# TAB: show log 解析（貼り付け一括取り込み）
# ═══════════════════════════════════════════
with tab_showlog:
    st.markdown("## 📥 show コマンド貼り付け解析")
    st.markdown(
        "機器で採取した **show 系コマンドをまとめて貼り付け**てください。"
        "`show logging` / `show running-config` / `show interface status` / "
        "`show version` などを自動でセクション分割し、"
        "**ログ解析＋設定・ポート状態の異常性チェック**を行います。"
    )

    # ── ファイルをドラッグ＆ドロップでも解析可能に ─────────────
    # .pcap/.pcapng/.cap は自動でパケット解析タブへ誘導、
    # syslog/txt/log/cfg/conf はテキストとして読み込みここで解析する。
    if _is_cloud_mode() and not _is_admin_authenticated():
        st.caption(f"🔒 ゲスト利用時のアップロード上限: {MAX_UPLOAD_MB_GUEST}MB（管理者ログインで解除）")
    _up_file = st.file_uploader(
        "📎 ファイルをドラッグ＆ドロップ（syslog/show出力のテキスト、pcap/pcapng、zip/gz圧縮も可）",
        type=["txt", "log", "cfg", "conf", "syslog", "pcap", "pcapng", "cap", "zip", "gz"],
        key="show_log_file_upload",
        help="テキストファイルはそのまま下の欄に読み込みます。pcap系は自動でパケット解析します。"
             "zip/gzで圧縮したものは自動解凍します（zip内のsyslog/pcapを自動選択）。",
    )
    if _up_file is not None and _check_upload_size_ok(_up_file, _is_cloud_mode()):
        _up_bytes = _up_file.getvalue()
        _up_name = _up_file.name.lower()

        # zip/gz 圧縮なら自動解凍。pcap優先で探し、無ければテキスト(ログ)として展開
        if _up_name.endswith((".zip", ".gz")) or _up_bytes[:4] == b"PK\x03\x04" or _up_bytes[:2] == b"\x1f\x8b":
            _sdec = pcap_analyzer.decompress_upload(_up_bytes, _up_file.name, prefer="pcap")
            if not _sdec["extracted"]:
                _sdec = pcap_analyzer.decompress_upload(_up_bytes, _up_file.name, prefer="log")
            if _sdec["extracted"]:
                _up_bytes = _sdec["data"]
                _up_name = _sdec["name"].lower()
                st.info(f"🗜️ 圧縮ファイルを自動解凍しました（{_sdec['source']}）→ `{_sdec['name']}`")
        # 拡張子で判別できない場合はマジックバイトでpcapを判定
        _is_pcap_upload = _up_name.endswith((".pcap", ".pcapng", ".cap")) or \
            pcap_analyzer._looks_like_pcap(_up_bytes)
        if _is_pcap_upload:
            # pcap系はここでそのまま解析（パケット解析タブと同じエンジン）
            st.info(f"📦 pcapファイルを検出しました: {_up_file.name}（{len(_up_bytes):,} bytes）")
            if st.button("📦 このpcapを解析する", key="show_log_pcap_analyze"):
                import pcap_analyzer as _pa_up
                with st.spinner("pcap を解析中…"):
                    _pcap_res = _pa_up.analyze_pcap(_up_bytes)
                st.session_state["_showlog_pcap_result"] = _pcap_res
                st.session_state["_showlog_pcap_name"] = _up_file.name
            _pres = st.session_state.get("_showlog_pcap_result")
            if _pres and st.session_state.get("_showlog_pcap_name") == _up_file.name:
                st.success(f"✅ 解析完了: 総パケット数 {_pres.get('total_packets', 0)}")
                _pc1, _pc2, _pc3, _pc4 = st.columns(4)
                _pc1.metric("ICMP Redirect", len(_pres.get("icmp_redirects", [])))
                _pc2.metric("TCP問題", len(_pres.get("tcp_issues", [])))
                _pc3.metric("VoIPストリーム", len(_pres.get("voip_streams", [])))
                _pc4.metric("DNS異常", len(_pres.get("dns_issues", [])))
                st.caption("詳細な内訳は「📦 パケット解析」タブと同じデータです。"
                           "そちらのタブでも同じファイルをアップロードすると全項目を確認できます。")
        else:
            # テキスト系はそのまま下の貼り付け欄に読み込む
            try:
                _up_text = _up_bytes.decode("utf-8")
            except UnicodeDecodeError:
                _up_text = _up_bytes.decode("shift_jis", errors="replace")
            if st.session_state.get("_showlog_last_upload") != _up_file.name:
                st.session_state["show_log_text_tab"] = _up_text
                st.session_state["_showlog_last_upload"] = _up_file.name
                st.success(f"📄 {_up_file.name} を読み込みました（下の欄に反映済み）")
                st.rerun()

    # ── サンプルを読み込む（実機が無くても各ベンダーの挙動を試せる） ──
    with st.expander("📋 サンプルを読み込む（実機が無くてもお試しいただけます）"):
        _spl_col1, _spl_col2 = st.columns([3, 1])
        with _spl_col1:
            _spl_vendor = st.selectbox("ベンダー", list(SHOWLOG_SAMPLES.keys()),
                                       key="showlog_sample_vendor")
        with _spl_col2:
            st.write("")
            st.write("")
            if st.button("📋 読み込む", key="showlog_sample_load", use_container_width=True):
                st.session_state["show_log_text_tab"] = SHOWLOG_SAMPLES[_spl_vendor]
                st.success(f"{_spl_vendor} のサンプルを読み込みました（下の欄に反映済み）")
                st.rerun()

    _sc1, _sc2 = st.columns([3, 1])
    with _sc1:
        _sl_text_tab = st.text_area(
            "ここに show 系コマンドの出力をまとめて貼り付け（またはファイルをドラッグ）",
            height=340, key="show_log_text_tab",
            placeholder=(
                "Switch#show logging\n"
                "Jul  4 00:54:39.701: %SYS-5-RESTART: System restarted --\n"
                "Jul  4 00:55:27.694: %LINK-5-CHANGED: Interface Vlan1, changed state to administratively down\n"
                "Switch#show running-config\n"
                "hostname Switch\n"
                "interface Vlan1\n no ip address\n shutdown\n"
                "Switch#show interface status\n"
                "Gi0/1   notconnect  1  auto auto 10/100/1000BaseTX\n"
                "Switch#"
            ),
        )
    with _sc2:
        _sl_src_tab = st.text_input("送信元IP/ホスト", value="pasted-device",
                                    key="show_log_src_tab",
                                    help="貼り付けたログの送信元として記録されます")
        _sl_go_tab = st.button("🤖 解析（取り込み＋異常＋LLM）", use_container_width=True,
                               key="show_log_ingest_tab", type="primary")
        _sl_auto_llm = st.checkbox("解析時にLLMまで自動実行", value=True,
                                   key="show_log_auto_llm",
                                   help="ボタン1回で取り込み・異常チェック・LLM詳細解析まで実行します")
        st.caption("show logging はDB取り込み、config/interface は異常性チェック・相関解析に使用します。")

    if _sl_go_tab:
        if _sl_text_tab.strip():
            import show_analyzer as _sa
            _secs = _sa.split_sections(_sl_text_tab)
            _chk = _sa.check_anomalies(_secs)
            # logging セクションを DB 取り込み
            _r = {"total": 0, "skipped": 0, "by_vendor": {}}
            if _chk["logging_body"]:
                _r = _ingest_show_logging(_chk["logging_body"],
                                          _sl_src_tab.strip() or "pasted-device")
            # config / interface を LLM 相関解析用に保持
            st.session_state["showlog_cfg"] = _chk["config_body"]
            st.session_state["showlog_intf"] = _chk["intf_body"]
            st.session_state["showlog_extra"] = _chk.get("extra_body", "")
            st.session_state["_show_anomalies"] = _chk["anomalies"]
            # 今回貼り付けた分だけを解析対象にする（過去ログの混入防止）
            st.session_state["_showlog_ids"] = set(_r.get("ids", []))
            # セクション内訳
            _kind_label = {"logging": "show logging", "config": "running-config",
                           "intf_status": "interface status", "intf_brief": "ip int brief",
                           "interfaces": "interfaces", "version": "version",
                           "cdp": "cdp", "cpu": "cpu", "other": "その他"}
            _sec_summary = " / ".join(
                f"{_kind_label.get(s['kind'], s['kind'])}"
                for s in _secs) or "（区切りなし＝logging扱い）"
            st.success(
                f"✅ {len(_secs)} セクションを認識: {_sec_summary}\n\n"
                f"ログ取り込み {_r['total']} 件（除外 {_r['skipped']} 行）／"
                f"異常検出 {len(_chk['anomalies'])} 件")
            if _r["by_vendor"]:
                _vcols = st.columns(max(1, len(_r["by_vendor"])))
                for _i, (_v, _c) in enumerate(_r["by_vendor"].items()):
                    _vcols[_i].metric(_v, f"{_c} 件")
            # 新しい取り込みバッチなので、LLM 自動解析を未実行状態にリセット
            st.session_state["_showlog_llm_done_ids"] = None
        else:
            st.error("show コマンドの出力を貼り付けてください")

    # ── 🩺 健全性スコア（ネットワーク品質ルーブリック） ──────────
    _anoms = st.session_state.get("_show_anomalies")
    if _anoms is not None:
        import show_analyzer as _sa2
        import bug_analyzer as _bug2
        _qlogs = _scoped_showlog_logs()
        _qbug = _bug2.analyze_batch(_qlogs) if _qlogs else {"counts": {"bug": 0, "ops": 0}}
        _q = _sa2.quality_score(_anoms, _qbug["counts"].get("bug", 0),
                                _qbug["counts"].get("ops", 0))
        _grade_color = {"A": "#16a34a", "B": "#65a30d", "C": "#b45309",
                        "D": "#ea580c", "E": "#dc2626"}.get(_q["grade"], "#6b7280")
        st.markdown("### 🩺 健全性スコア（品質ルーブリック）")
        _qc1, _qc2 = st.columns([1, 2])
        with _qc1:
            st.markdown(
                f"<div class='metric-card' style='border:2px solid {_grade_color};'>"
                f"<div style='font-size:14px;color:#6b7280;'>総合評価</div>"
                f"<div style='font-size:52px;font-weight:bold;color:{_grade_color};line-height:1;'>"
                f"{_q['grade']}</div>"
                f"<div style='font-size:28px;font-weight:bold;color:#374151;'>{_q['score']}<span style='font-size:14px;'>/100</span></div>"
                f"<div style='font-size:12px;color:{_grade_color};margin-top:4px;'>{_q['label']}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )
        with _qc2:
            st.markdown("**評価の内訳（減点根拠）**")
            if _q["deductions"]:
                for _d in _q["deductions"]:
                    st.markdown(f"<div style='font-size:13px;color:#6b7280;'>・{_d}</div>",
                                unsafe_allow_html=True)
            else:
                st.markdown("<div style='color:#16a34a;'>減点なし（良好）</div>",
                            unsafe_allow_html=True)
            st.caption("採点基準: ERROR以上 -20〜-30 / WARNING -8 / NOTICE -3 / バグ疑い -25（各件数×）")

    # ── 🚨 異常性チェック（config / interface / license） ────────
    if _anoms is not None:
        st.markdown("### 🚨 異常性チェック（設定・ポート状態）")
        if _anoms:
            _sev_color = {"EMERGENCY": "#dc2626", "ALERT": "#dc2626", "CRITICAL": "#dc2626",
                          "ERROR": "#dc2626", "WARNING": "#b45309", "NOTICE": "#2563eb"}
            _crit = sum(1 for a in _anoms if a["severity"] in ("ERROR", "CRITICAL", "ALERT", "EMERGENCY"))
            _warn = sum(1 for a in _anoms if a["severity"] == "WARNING")
            st.caption(f"🔴 要対処 {_crit} 件 / 🟠 注意 {_warn} 件 / その他 {len(_anoms)-_crit-_warn} 件")
            for _a in _anoms:
                _col = _sev_color.get(_a["severity"], "#6b7280")
                _remedy_html = ""
                if _a.get("remedy"):
                    _remedy_html = (f"<br><span style='color:#16a34a;font-size:12px;'>"
                                    f"✅ 対処: {_a['remedy']}</span>")
                st.markdown(
                    f"<div class='log-card' style='border-left:3px solid {_col};'>"
                    f"<span style='color:{_col};font-weight:bold;'>[{_a['severity']}] {_a['category']}</span> "
                    f"{_a['detail']}<br>"
                    f"<span style='color:#6b7280;font-size:12px;'>根拠: {_a['evidence']}</span>"
                    f"{_remedy_html}"
                    f"</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.success("設定・ポート状態に目立った異常はありませんでした。")

    # ── 🐛 バグ判定解析（各ログに判定バッジを付けて表示） ──────
    st.markdown("### 🐛 バグ判定（各ログを色分け）")
    st.markdown(
        "<div style='font-size:13px;color:#6b7280;margin-bottom:6px;'>"
        "各ログを次の3つに自動分類します：&nbsp;"
        "<span style='background:#fde8e8;color:#dc2626;padding:1px 8px;border-radius:10px;'>🐛 バグ疑い</span>&nbsp;"
        "<span style='background:#fef3e2;color:#b45309;padding:1px 8px;border-radius:10px;'>⚙️ 運用・設定</span>&nbsp;"
        "<span style='background:#e8f0fe;color:#2563eb;padding:1px 8px;border-radius:10px;'>✅ 情報</span>"
        "</div>",
        unsafe_allow_html=True,
    )
    _bug_recent = _scoped_showlog_logs()
    if _bug_recent:
        import bug_analyzer as _bug
        import json as _json_bd
        # 各ログを判定＋メッセージで重複除去
        _seen = set()
        _judged = []
        for _lg in _bug_recent:
            _msg = _lg.get("message", "")
            _key = (_lg.get("vendor", ""), _msg)
            if _key in _seen:
                continue
            _seen.add(_key)
            _tags = _lg.get("tags")
            if isinstance(_tags, str):
                try:
                    _tags = _json_bd.loads(_tags)
                except Exception:
                    _tags = []
            _res = _bug.analyze_bug({"message": _msg, "tags": _tags,
                                     "severity": _lg.get("severity", "")},
                                    _lg.get("raw", _msg))
            _judged.append((_lg, _res))
        _bc = {"bug": 0, "ops": 0, "info": 0}
        for _, _res in _judged:
            _bc[_res["verdict"]] += 1
        _m1, _m2, _m3 = st.columns(3)
        _m1.metric("🐛 バグ疑い", f"{_bc['bug']} 件")
        _m2.metric("⚙️ 運用・設定", f"{_bc['ops']} 件")
        _m3.metric("✅ 情報", f"{_bc['info']} 件")
        if _bc["bug"]:
            st.error(f"🐛 バグ疑いが {_bc['bug']} 件あります。最優先で調査してください。")
        else:
            st.success("🐛 バグ疑いは検出されませんでした（下記は運用・設定/情報レベルです）。")

        _style = {
            "bug":  ("#dc2626", "🐛 バグ疑い"),
            "ops":  ("#b45309", "⚙️ 運用・設定"),
            "info": ("#2563eb", "✅ 情報"),
        }

        def _render_card(_lg, _res):
            _v = _res["verdict"]
            _col, _badge = _style[_v]
            _sev = _lg.get("severity", "INFO")
            _reason = ""
            if _v in ("bug", "ops"):
                _conf = {"high": "🔴高", "medium": "🟠中", "low": "🟡低"}.get(_res.get("confidence"), "")
                _reason = (f"<br><span style='color:{_col};font-size:12px;'>"
                           f"▶ 判定理由: {_res['category']} — {_res['reason']} {_conf}</span>")
            # 日本語の意味/アドバイスを付記（何を示すログか分かるように）
            _adv = _bug.explain_log(_lg.get("message", ""))
            _adv_html = ""
            if _adv:
                _adv_html = (f"<br><span style='color:#0f766e;font-size:12px;'>"
                             f"💬 意味: {_adv}</span>")
            st.markdown(
                f"<div class='log-card' style='border-left:4px solid {_col};'>"
                f"<span style='background:{_col};color:#fff;padding:1px 8px;border-radius:10px;"
                f"font-size:11px;font-weight:bold;'>{_badge}</span> "
                f"<span class='severity-{_sev}'>[{_sev}]</span> "
                f"<b>{_lg.get('vendor','')}</b> "
                f"<span style='color:#6b7280;font-size:12px;'>{_lg.get('hostname','')}</span><br>"
                f"<span style='color:#374151;'>{_lg.get('message','')}</span>"
                f"{_reason}"
                f"{_adv_html}"
                f"</div>",
                unsafe_allow_html=True,
            )

        # バグ→運用は常時表示（要対処）。情報は折りたたみ（クラッター防止）
        _actionable = [(l, r) for l, r in _judged if r["verdict"] in ("bug", "ops")]
        _infos = [(l, r) for l, r in _judged if r["verdict"] == "info"]
        _actionable.sort(key=lambda x: 0 if x[1]["verdict"] == "bug" else 1)
        if _actionable:
            st.markdown("**要確認（バグ・運用/設定）**")
            for _lg, _res in _actionable[:40]:
                _render_card(_lg, _res)
        else:
            st.caption("要対処（バグ・運用/設定）のログはありません。")
        if _infos:
            with st.expander(f"✅ 情報レベルのログ {len(_infos)} 件（クリックで表示）"):
                for _lg, _res in _infos[:60]:
                    _render_card(_lg, _res)
    else:
        st.caption("ログを取り込むとバグ判定結果を表示します。")

    # ── 🤖 LLM による詳細解析（config / interface status 相関） ──
    st.markdown("### 🤖 LLM 詳細解析（設定・ポート状態と相関）")
    # 使用エンジンの状態を明示（使えるか一目で分かるように）
    _mode_now2 = st.session_state.get("llm_mode", "auto")
    _eng_ok, _eng_name = analyzer.active_llm_engine(_mode_now2)
    if _eng_ok:
        st.markdown(
            f"<div style='display:inline-block;background:#ecfdf3;border:1px solid #16a34a;"
            f"border-radius:12px;padding:2px 12px;color:#166534;font-size:13px;'>"
            f"🟢 LLM 使用可能: <b>{_eng_name}</b></div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"<div style='display:inline-block;background:#fef2f2;border:1px solid #dc2626;"
            f"border-radius:12px;padding:2px 12px;color:#991b1b;font-size:13px;'>"
            f"🔴 LLM 使用不可: <b>{_eng_name}</b>（下の案内を参照）</div>",
            unsafe_allow_html=True,
        )
    _has_cfg = bool(st.session_state.get("showlog_cfg", "").strip())
    _has_intf = bool(st.session_state.get("showlog_intf", "").strip())
    _ctx_parts = []
    if _has_cfg:
        _ctx_parts.append("running-config")
    if _has_intf:
        _ctx_parts.append("interface status")
    if _ctx_parts:
        st.caption(f"上で貼り付けた **{' / '.join(_ctx_parts)}** も相関材料として解析に含めます。")
    else:
        st.caption("上の貼り付けに show running-config / show interface status も含めると、"
                   "ログと設定・ポート状態を突き合わせた総合診断ができます。")
    _llm_ok = (analyzer.check_claude_available() or analyzer.check_gemini_available()
               or analyzer.check_groq_available() or analyzer.check_ollama_available())
    _mode_sel = st.session_state.get("llm_mode", "auto")
    if not _llm_ok:
        st.warning(
            "🔑 **LLM APIキーが未設定のため AI 詳細解析が使えません。**\n\n"
            "サイドバーの「🔑 APIキー設定」で、無料枠のある **Gemini** または **Groq** の "
            "キーを1つ入れて「適用」すると、この機能が有効になります。\n"
            "- Gemini: https://aistudio.google.com （無料）\n"
            "- Groq: https://console.groq.com （無料・高速）"
        )
    elif _mode_sel == "none":
        st.info("解析モードが「⛔ AI解析なし」になっています。サイドバーで Gemini/Groq/auto に切り替えてください。")
    else:
        # 今回の貼り付けバッチ識別子。新しいバッチにまだレポートが無ければ自動実行。
        _cur_ids = frozenset(st.session_state.get("_showlog_ids") or [])
        _done_ids = st.session_state.get("_showlog_llm_done_ids")
        _auto_on = st.session_state.get("show_log_auto_llm", True)

        def _run_showlog_llm():
            _ll = _scoped_showlog_logs()
            if not _ll:
                st.warning("解析対象のログがありません。先に show ログを取り込んでください。")
                return
            with st.spinner("🤖 LLM が show logging・config・ルーティング/CPU/ポート状態を突き合わせて解析中…"):
                _rep, _mdl = _llm_analyze_show_log(
                    _ll, _mode_sel,
                    config_text=st.session_state.get("showlog_cfg", ""),
                    intf_text=st.session_state.get("showlog_intf", ""),
                    extra_text=st.session_state.get("showlog_extra", ""))
            if _rep:
                st.session_state["_showlog_llm_report"] = _rep
                st.session_state["_showlog_llm_model"] = _mdl
                st.session_state["_showlog_llm_done_ids"] = _cur_ids
            else:
                _err = getattr(analyzer, "LAST_LLM_ERROR", "") or "APIキー設定・ネットワークをご確認ください。"
                st.error(f"LLM 解析に失敗しました。{_err}")

        # 自動実行: 新しい取り込みバッチがあり、まだ解析していなければ即実行（バッチ毎に1回）
        if _auto_on and _cur_ids and _cur_ids != _done_ids:
            st.session_state["_showlog_llm_done_ids"] = _cur_ids  # 二重実行防止(先にマーク)
            st.caption("🤖 取り込み後、自動でLLM詳細解析を実行しました。")
            _run_showlog_llm()
        # 手動再実行ボタン（やり直したいとき）
        if st.button("🤖 LLM で再解析する", key="showlog_llm",
                     use_container_width=True, type="primary"):
            _run_showlog_llm()
    if st.session_state.get("_showlog_llm_report"):
        st.markdown(
            f"<div class='ai-explanation'>{st.session_state['_showlog_llm_report']}</div>",
            unsafe_allow_html=True,
        )
        st.caption(f"モデル: {st.session_state.get('_showlog_llm_model','')}")

    # 直近の取り込みログをその場でプレビュー表示
    st.markdown("### 🔎 解析結果（直近の取り込みログ）")
    _recent = db.get_logs(limit=30)
    if _recent:
        import json as _json_sl
        for _lg in _recent:
            _tags = _json_sl.loads(_lg.get("tags") or "[]")
            _sev = _lg.get("severity", "INFO")
            _chips = " ".join(
                f"<span class='tag-chip'>{_t}</span>" for _t in _tags[:8]
            )
            st.markdown(
                f"<div class='log-card'>"
                f"<span class='severity-{_sev}'>[{_sev}]</span> "
                f"<b>{_lg.get('vendor','')}</b> "
                f"<span style='color:#6b7280;'>{_lg.get('hostname','')}</span><br>"
                f"{_lg.get('message','')}<br>{_chips}"
                f"</div>",
                unsafe_allow_html=True,
            )
    else:
        st.caption("まだ取り込まれたログがありません。上に show logging を貼り付けて実行してください。")

# ═══════════════════════════════════════════
# TAB: MRTG 風ダッシュボード
# ═══════════════════════════════════════════
with tab_prtg:
    import prtg_view as _prtg
    st.markdown("## 📟 MRTG 風モニタリングダッシュボード")
    st.caption("SNMPポーリングの結果を、速度計ゲージ・信号機センサー・トラフィックグラフで可視化します。")

    # ── ⚙️ SNMP 設定（このタブから直接：デバイス登録＋ポーラー起動） ──
    _prtg_cloud = _is_cloud_mode()
    with st.expander("⚙️ SNMP 設定（デバイス登録・ポーリング開始）", expanded=not snmp_poller.get_devices()):
        if _prtg_cloud:
            st.warning("☁️ クラウド公開モードでは SNMP ポーリング(機器到達)は利用できません。"
                       "ローカル(社内)環境で実行してください。")
        _pc1, _pc2, _pc3, _pc4 = st.columns([2, 1.5, 1, 1])
        with _pc1:
            _pd_ip = st.text_input("IPアドレス", placeholder="192.168.1.1", key="prtg_add_ip")
        with _pc2:
            _pd_comm = st.text_input("コミュニティ", value="public", key="prtg_add_comm")
        with _pc3:
            _pd_ver = st.selectbox("バージョン", ["v2c", "v1"], key="prtg_add_ver")
        with _pc4:
            _pd_int = st.number_input("間隔(秒)", value=60, min_value=10, max_value=3600, key="prtg_add_int")
        _pb0, _pb1, _pb2, _pb3 = st.columns(4)
        if _pb0.button("🔍 SNMP Walk 探索", use_container_width=True, key="prtg_walk",
                       disabled=_prtg_cloud):
            if _pd_ip.strip():
                with st.spinner(f"{_pd_ip} を SNMP Walk で探索中…"):
                    _dres = snmp_poller.discover_device(
                        _pd_ip.strip(), _pd_comm.strip() or "public", _pd_ver)
                    _dres["_ip"] = _pd_ip.strip()
                    st.session_state["_prtg_discover"] = _dres
            else:
                st.error("IPアドレスを入力してください")
        if _pb1.button("➕ デバイス追加", use_container_width=True, key="prtg_add_dev",
                       disabled=_prtg_cloud):
            if _pd_ip.strip():
                snmp_poller.add_device(_pd_ip.strip(), _pd_comm.strip() or "public", _pd_ver, 161, int(_pd_int))
                st.success(f"{_pd_ip} を登録しました")
                st.rerun()
            else:
                st.error("IPアドレスを入力してください")
        # 探索結果の表示
        _disc = st.session_state.get("_prtg_discover")
        if _disc:
            if _disc.get("reachable"):
                _sys = _disc["system"]
                st.success(f"✅ 応答あり: **{_sys.get('sysName','(名前なし)')}**")
                st.caption(f"sysDescr: {(_sys.get('sysDescr','') or '')[:120]}")
                _ifs = _disc.get("interfaces", [])
                if _ifs:
                    st.caption(f"インターフェース {len(_ifs)} 個を検出（up={sum(1 for i in _ifs if i['status']=='up')}）。"
                               "監視したいIFを選んで登録すると、自動でトラフィック/使用率を収集します。")
                    # 検出IFから監視対象を選択（手動OID入力は不要）
                    _disc_ip = _disc.get("_ip") or _pd_ip.strip()
                    _opt_labels = {f"[{i['index']}] {i['name']} ({i['status']})": i for i in _ifs}
                    # 既に監視中のIFを既定選択に
                    _already = {m["ifindex"]: m for m in snmp_poller.get_monitored_interfaces(_disc_ip)}
                    _default = [lbl for lbl, i in _opt_labels.items() if str(i["index"]) in _already]
                    # st.form で囲み、選択の度の全画面再描画（重いダッシュボード込み）を防止
                    with st.form("prtg_if_select_form"):
                        _sel_ifs = st.multiselect("監視対象インターフェース", list(_opt_labels.keys()),
                                                  default=_default, key="prtg_sel_ifs")
                        _submitted = st.form_submit_button("✅ 選択したIFを監視登録", type="primary")
                    if _submitted:
                        _chosen = [{"index": _opt_labels[l]["index"], "name": _opt_labels[l]["name"]}
                                   for l in _sel_ifs]
                        # デバイス未登録なら合わせて登録
                        if _disc_ip and _disc_ip not in [d["ip"] for d in snmp_poller.get_devices()]:
                            snmp_poller.add_device(_disc_ip, _pd_comm.strip() or "public", _pd_ver, 161, int(_pd_int))
                        snmp_poller.set_monitored_interfaces(_disc_ip, _chosen)
                        st.success(f"{len(_chosen)} 個のインターフェースを監視登録しました。"
                                   "ポーリング開始でトラフィック収集が始まります。")
                        st.rerun()
            else:
                st.error(f"❌ {_disc.get('error','応答なし')}")
        if not st.session_state.get("snmp_poller_started"):
            if _pb2.button("▶ ポーリング開始", use_container_width=True, type="primary",
                           key="prtg_poll_start", disabled=_prtg_cloud):
                snmp_poller.start_poller()
                st.session_state.snmp_poller_started = True
                st.success("ポーリングを開始しました（数十秒後にゲージ・グラフが出ます）")
                st.rerun()
        else:
            if _pb2.button("⏹ ポーリング停止", use_container_width=True, key="prtg_poll_stop"):
                snmp_poller.stop_poller()
                st.session_state.snmp_poller_started = False
                st.info("ポーリングを停止しました")
                st.rerun()
        _pb3.button("🔄 表示を更新", use_container_width=True, key="prtg_refresh")
        # 登録済みデバイスの簡易一覧＋削除
        _reg = snmp_poller.get_devices()
        if _reg:
            st.caption(f"登録済み {len(_reg)} 台 / ポーリング: "
                       + ("🟢 実行中" if st.session_state.get("snmp_poller_started") else "⏸ 停止中"))
            for _rd in _reg:
                _rc1, _rc2 = st.columns([5, 1])
                _rc1.markdown(f"・**{_rd.get('hostname') or _rd.get('ip')}** ({_rd.get('ip')}) "
                              f"— {_rd.get('community')}/{_rd.get('version')} 状態:{_rd.get('last_status','-')}")
                if _rc2.button("削除", key=f"prtg_del_{_rd.get('ip')}"):
                    snmp_poller.remove_device(_rd.get("ip"))
                    st.rerun()

    _devices = snmp_poller.get_devices()
    _latest = snmp_poller.get_latest_metrics(limit=300)
    _alerts = snmp_poller.get_alert_metrics()
    _label_map = {}
    for _k, _v in {**snmp_poller.THRESHOLDS, **snmp_poller.COUNTER_OIDS}.items():
        _label_map[_k] = _v.get("label", _k)
    _label_map.update(snmp_poller.DISPLAY_LABELS)
    # ベンダー固有MIB(Cisco/PaloAlto/F5)のラベルも表示に反映
    try:
        _label_map.update(snmp_poller.vendor_metric_labels())
    except Exception:
        pass

    if not _devices and not _latest:
        st.info("まだSNMPデータがありません。上の「⚙️ SNMP 設定」でデバイスを登録し、"
                "「▶ ポーリング開始」を押すと、ここにゲージ・グラフが表示されます。")
    else:
        # ── 📥 show running-config取得（SNMP/CISCO-CONFIG-COPY-MIB・実験的） ──
        _prtg_running_configs = st.session_state.setdefault("_prtg_running_configs", {})
        if not _prtg_cloud and _devices:
            with st.expander("📥 show running-config を取得（SNMP経由・Cisco専用・実験的）"):
                st.caption(
                    "CISCO-CONFIG-COPY-MIB を使い、機器にTFTPでこのホストへ running-config を"
                    "送信させて取得します。SNMPの**書き込み権限(RW)コミュニティ**と、"
                    "このホストでのUDP/69バインド（root権限）が必要です。"
                    "取得した内容はLLM総合診断に「コンフィグ是正点」として組み込まれます。"
                )
                _cfg_dev_opts = {f"{d.get('hostname') or d.get('ip')} ({d.get('ip')})": d.get("ip")
                                 for d in _devices}
                _ccc1, _ccc2 = st.columns(2)
                with _ccc1:
                    _cfg_sel_dev = st.selectbox("対象デバイス", list(_cfg_dev_opts.keys()), key="cfg_copy_dev")
                    _cfg_target_ip = _cfg_dev_opts[_cfg_sel_dev]
                with _ccc2:
                    _cfg_rw_comm = st.text_input("SNMP書き込みコミュニティ(RW)", type="password",
                                                 key="cfg_copy_rw_community")
                _default_local_ip = ""
                try:
                    import cisco_config_copy as _ccc
                    _default_local_ip = _ccc.guess_local_ip_for(_cfg_target_ip)
                except Exception:
                    pass
                _cfg_tftp_ip = st.text_input(
                    "このホストのIP（機器から見えるTFTP宛先アドレス）",
                    value=_default_local_ip, key="cfg_copy_tftp_ip")
                if st.button("📥 running-configを取得する", key="cfg_copy_btn"):
                    if not _cfg_rw_comm or not _cfg_tftp_ip:
                        st.error("書き込みコミュニティとホストIPの両方を入力してください。")
                    else:
                        import cisco_config_copy as _ccc
                        with st.spinner(f"{_cfg_sel_dev} からrunning-configを取得中…（最大30秒）"):
                            _cfg_res = _ccc.fetch_running_config(
                                _cfg_target_ip, _cfg_rw_comm, _cfg_tftp_ip, timeout=30)
                        if _cfg_res["ok"]:
                            _prtg_running_configs[_cfg_target_ip] = _cfg_res["config_text"]
                            st.success(f"✅ 取得成功（{len(_cfg_res['config_text']):,} 文字）")
                        else:
                            st.error(f"取得失敗: {_cfg_res['error']}")
                if _prtg_running_configs:
                    st.caption(f"取得済み: {len(_prtg_running_configs)}台分のrunning-configがLLM診断に含まれます。")
                    for _cip, _ctext in _prtg_running_configs.items():
                        with st.expander(f"プレビュー: {_cip}", expanded=False):
                            st.code(_ctext[:3000], language="text")

        # ── 🤖 LLM 総合診断（最初に表示：まず結論を見せる） ──────
        st.markdown("### 🤖 LLM 総合診断")
        _prtg_llm_ok = (analyzer.check_claude_available() or analyzer.check_gemini_available()
                        or analyzer.check_groq_available() or analyzer.check_ollama_available())
        _prtg_mode = st.session_state.get("llm_mode", "auto")
        if not _prtg_llm_ok:
            st.warning("🔑 LLM APIキーが未設定です。サイドバー「🔑 APIキー設定」でGemini/Groqキーを設定するか、"
                       "Ollamaを起動すると診断できます。")
        elif _prtg_mode == "none":
            st.info("解析モードが「⛔ AI解析なし」です。サイドバーでモードを切り替えてください。")
        else:
            if st.button("🤖 このダッシュボードをLLMで診断する", key="prtg_llm_btn",
                        type="primary", use_container_width=True):
                with st.spinner("🤖 LLM がデバイス状態・センサー値・アラートを分析中…"):
                    _prep, _pmdl = _llm_analyze_prtg(_devices, _latest, _alerts, _label_map, _prtg_mode,
                                                     running_configs=_prtg_running_configs)
                if _prep:
                    st.session_state["_prtg_llm_report"] = _prep
                    st.session_state["_prtg_llm_model"] = _pmdl
                else:
                    st.error("LLM診断に失敗しました。APIキー設定・ネットワークをご確認ください。")
        if st.session_state.get("_prtg_llm_report"):
            st.markdown(
                f"<div class='ai-explanation'>{st.session_state['_prtg_llm_report']}</div>",
                unsafe_allow_html=True,
            )
            st.caption(f"モデル: {st.session_state.get('_prtg_llm_model','')}")
        st.markdown("---")

        # ── ① デバイス状態マップ ──────────────────────────────
        st.markdown("### 🗺️ デバイス状態マップ")
        _dcols = st.columns(max(1, min(4, len(_devices) or 1)))
        for _i, _dev in enumerate(_devices):
            _st = (_dev.get("last_status") or "unknown").lower()
            _dcol = _prtg.status_color("critical" if _st in ("down", "error", "unreachable")
                                       else ("ok" if _st in ("ok", "up", "reachable") else "unknown"))
            _mark = "🟢" if _dcol == "#16a34a" else ("🔴" if _dcol == "#dc2626" else "⚪")
            with _dcols[_i % len(_dcols)]:
                st.markdown(
                    f"<div class='metric-card' style='border-top:4px solid {_dcol};text-align:left;'>"
                    f"<div style='font-size:20px;'>{_mark} <b>{_dev.get('hostname') or _dev.get('ip')}</b></div>"
                    f"<div style='color:#6b7280;font-size:12px;'>{_dev.get('ip')}</div>"
                    f"<div style='color:#6b7280;font-size:12px;'>状態: {_dev.get('last_status','unknown')}</div>"
                    f"<div style='color:#9ca3af;font-size:11px;'>最終: {_dev.get('last_polled','-')}</div>"
                    f"</div>", unsafe_allow_html=True)

        # ── ② 速度計ゲージ（最新値・ゲージ対象の指標） ──────────
        st.markdown("### 🎛️ 速度計ゲージ（最新値）")
        # 各(source_ip, oid_name)の最新値だけ拾う
        _seen_g = set()
        _gauges = []
        for _m in _latest:  # _latest は新しい順
            _key = (_m.get("source_ip"), _m.get("oid_name"))
            if _key in _seen_g:
                continue
            _spec = _prtg.gauge_spec_for(_m.get("oid_name", ""))
            if not _spec:
                continue
            _seen_g.add(_key)
            try:
                _val = float(_m.get("value"))
            except (TypeError, ValueError):
                continue
            _gauges.append((_m.get("hostname") or _m.get("source_ip"), _spec, _val))
        if _gauges:
            _gcols = st.columns(min(4, len(_gauges)))
            for _i, (_host, _spec, _val) in enumerate(_gauges[:12]):
                with _gcols[_i % len(_gcols)]:
                    st.markdown(
                        f"<div style='text-align:center;font-size:12px;color:#6b7280;'>{_host}</div>"
                        + _prtg.svg_gauge(_val, _spec["max"], _spec["label"], _spec["unit"],
                                          _spec["warn"], _spec["crit"]),
                        unsafe_allow_html=True)
        else:
            st.caption("ゲージ対象の指標（CPU/温度など）がまだ収集されていません。")

        # ── ③ センサー一覧（信号機ステータス） ──────────────────
        st.markdown("### 🚦 センサー一覧（信号機ステータス）")
        _seen_s = set()
        _sensors = []
        for _m in _latest:
            _key = (_m.get("source_ip"), _m.get("oid_name"))
            if _key in _seen_s:
                continue
            _seen_s.add(_key)
            _sensors.append(_m)
        if _sensors:
            _scols = st.columns(3)
            for _i, _m in enumerate(_sensors[:30]):
                _lv = (_m.get("alert_level") or "none").lower()
                _col = _prtg.status_color(_lv)
                _dot = "🟢" if _col == "#16a34a" else ("🟡" if _col == "#f59e0b" else ("🔴" if _col == "#dc2626" else "⚪"))
                _name = _prtg.metric_label(_m.get("oid_name"), _label_map)
                with _scols[_i % 3]:
                    st.markdown(
                        f"<div class='log-card' style='border-left:4px solid {_col};padding:8px 12px;'>"
                        f"{_dot} <b>{_name}</b> "
                        f"<span style='color:#6b7280;font-size:11px;'>{_m.get('hostname') or _m.get('source_ip')}</span><br>"
                        f"<span style='font-size:18px;font-weight:bold;color:{_col};'>{_m.get('value','-')}</span> "
                        f"<span style='color:#6b7280;font-size:12px;'>{_m.get('unit','')}</span>"
                        f"</div>", unsafe_allow_html=True)
        else:
            st.caption("センサーデータがまだありません。")

        # ── ④ トラフィックグラフ（時系列） ──────────────────────
        st.markdown("### 📈 トラフィック / 指標グラフ（時系列）")
        if _devices:
            _gc1, _gc2, _gc3 = st.columns([2, 2, 1])
            _dev_opts = {f"{d.get('hostname') or d.get('ip')} ({d.get('ip')})": d.get("ip") for d in _devices}
            _sel_dev = _gc1.selectbox("デバイス", list(_dev_opts.keys()), key="prtg_dev")
            _metric_opts = ["ifInOctets.1", "ifOutOctets.1",
                            "cpmCPUTotal5sec", "cpmCPUTotal1min", "cpmCPUTotal5min",
                            "memory_used_pct", "hrCpuLoad",
                            "ciscoEnvMonTemperatureStatusValue", "ifInErrors.1"]
            _sel_metric = _gc2.selectbox("指標", _metric_opts,
                                         format_func=lambda k: _prtg.metric_label(k, _label_map), key="prtg_metric")
            _hours = _gc3.selectbox("期間", [1, 3, 6, 24], key="prtg_hours",
                                    format_func=lambda h: f"{h}時間")
            # 累積カウンタ(トラフィック等)は時間当たりレートに変換して表示する
            _trend, _trend_unit = snmp_poller.get_metric_trend_display(_dev_opts[_sel_dev], _sel_metric, hours=_hours)
            if _trend:
                import pandas as _pd_prtg
                _df = _pd_prtg.DataFrame(_trend)
                # value を数値化
                _df["value"] = _pd_prtg.to_numeric(_df["value"], errors="coerce")
                if "recorded_at" in _df.columns:
                    _df["recorded_at"] = _pd_prtg.to_datetime(_df["recorded_at"], errors="coerce")
                    _df = _df.dropna(subset=["value"]).set_index("recorded_at")
                st.line_chart(_df["value"], height=260)
                _unit_suffix = f"（{_trend_unit}換算・時間当たり平均）" if _trend_unit else ""
                st.caption(f"{_sel_dev} / {_prtg.metric_label(_sel_metric, _label_map)}{_unit_suffix} — 直近{_hours}時間")
            else:
                st.caption("この指標の時系列データがまだありません（ポーリングを数回実行すると蓄積されます）。")

        # ── ⑤ しきい値アラート ──────────────────────────────────
        st.markdown("### 🚨 しきい値アラート（超過中）")
        if _alerts:
            for _a in _alerts[:30]:
                _lv = (_a.get("alert_level") or "warning").lower()
                _col = _prtg.status_color(_lv)
                _name = _prtg.metric_label(_a.get("oid_name"), _label_map)
                st.markdown(
                    f"<div class='log-card' style='border-left:4px solid {_col};'>"
                    f"<span style='color:{_col};font-weight:bold;'>[{_a.get('alert_level','')}]</span> "
                    f"<b>{_name}</b> = {_a.get('value','-')} {_a.get('unit','')} "
                    f"<span style='color:#6b7280;font-size:12px;'>@ {_a.get('hostname') or _a.get('source_ip')} "
                    f"({_a.get('recorded_at','')})</span>"
                    f"</div>", unsafe_allow_html=True)
        else:
            st.success("現在しきい値を超過しているセンサーはありません。")

        # ── ⑥ 取得した生SNMPデータ（全項目・一覧表） ──────────────
        with st.expander("🔍 SNMPポーリングで取得できた全項目（生データ）", expanded=False):
            st.caption("ゲージ/信号機に出ていない項目も含め、ポーリングで実際に取得できた全OIDの最新値を一覧できます。")
            _seen_raw = set()
            _raw_rows = []
            for _m in _latest:
                _key = (_m.get("source_ip"), _m.get("oid_name"))
                if _key in _seen_raw:
                    continue
                _seen_raw.add(_key)
                _raw_rows.append({
                    "デバイス": _m.get("hostname") or _m.get("source_ip"),
                    "IP": _m.get("source_ip"),
                    "OID名": _m.get("oid_name"),
                    "項目名": _prtg.metric_label(_m.get("oid_name"), _label_map),
                    "値": _m.get("value"),
                    "単位": _m.get("unit") or "",
                    "状態": _m.get("alert_level") or "none",
                    "OID": _m.get("oid"),
                    "取得日時": _m.get("recorded_at"),
                })
            if _raw_rows:
                _df_raw = pd.DataFrame(_raw_rows).sort_values(["デバイス", "OID名"])
                st.dataframe(_df_raw, use_container_width=True, hide_index=True)
                st.caption(f"{len(_raw_rows)} 項目を表示中（直近ポーリング分・最大300件の範囲内）")
            else:
                st.caption("まだデータがありません。ポーリングを開始すると表示されます。")

# ═══════════════════════════════════════════
# TAB2: テレメトリダッシュボード
# ═══════════════════════════════════════════
with tab2:
    st.markdown("## 📊 テレメトリダッシュボード")
    st.caption("テレメトリ = 機器から継続的に収集される観測データ。単発ログではなく「傾向・増減・分布」を見ることで異常を早期検知します。")

    summary = db.get_telemetry_summary()

    # KPIカード
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("総受信ログ数", f"{summary['total']:,}")
    with col2:
        error_count = sum(
            r["total"] for r in summary["by_severity"]
            if r["severity"] in ("ERROR","CRITICAL","ALERT","EMERGENCY")
        )
        st.metric("エラー以上", f"{error_count:,}", delta=None)
    with col3:
        vendor_count = len(summary["by_vendor"])
        st.metric("検出ベンダー数", vendor_count)
    with col4:
        source_count = len(summary["by_source"])
        st.metric("送信元IP数", source_count)

    st.markdown("---")

    col_l, col_r = st.columns(2)

    with col_l:
        st.markdown("### 重要度別分布")
        if summary["by_severity"]:
            df_sev = pd.DataFrame(summary["by_severity"])
            df_sev.columns = ["重要度", "件数"]
            sev_order = ["EMERGENCY","ALERT","CRITICAL","ERROR","WARNING","NOTICE","INFO","DEBUG"]
            df_sev["order"] = df_sev["重要度"].map(
                {s: i for i, s in enumerate(sev_order)}).fillna(99)
            df_sev = df_sev.sort_values("order").drop("order", axis=1)
            st.bar_chart(df_sev.set_index("重要度"))
        else:
            st.info("データなし")

        st.markdown("### ベンダー別分布")
        if summary["by_vendor"]:
            df_v = pd.DataFrame(summary["by_vendor"])
            df_v.columns = ["ベンダー", "件数"]
            st.bar_chart(df_v.set_index("ベンダー"))
        else:
            st.info("データなし")

    with col_r:
        st.markdown("### 送信元IP TOP10")
        if summary["by_source"]:
            df_src = pd.DataFrame(summary["by_source"])
            df_src.columns = ["送信元IP", "件数"]
            st.dataframe(df_src, use_container_width=True, hide_index=True)
        else:
            st.info("データなし")

        st.markdown("### 直近1時間のログ増減トレンド")
        st.caption("📡 テレメトリ観点: 急激なスパイクはネットワーク障害・攻撃の前兆")
        if summary["trend"]:
            df_trend = pd.DataFrame(summary["trend"])
            df_trend.columns = ["時刻", "件数"]
            st.line_chart(df_trend.set_index("時刻"))
        else:
            st.info("直近1時間のデータなし")

    # テレメトリの概念説明
    st.markdown("---")
    with st.expander("📡 テレメトリとは？（ネットワーク文脈での解説）"):
        st.markdown("""
### テレメトリ（Telemetry）とは

**定義:** 離れた場所にある機器の状態・動作を**継続的・自動的**に収集・送信する仕組み。

---

#### syslogとテレメトリの関係

| 観点 | syslog単体 | テレメトリ（syslog活用） |
|------|-----------|----------------------|
| 見方 | 1件1件のイベント | 時系列での傾向・分布 |
| 目的 | 何が起きたか | 何が起きようとしているか |
| 活用 | 障害後の原因調査 | 障害の予兆検知・予防 |

---

#### このダッシュボードでのテレメトリ活用例

- **ログ増減トレンド** → 短時間に急増 = 障害・攻撃の前兆
- **重要度分布** → ERRORが増加傾向 = 機器の劣化・設定問題
- **送信元IP TOP10** → 特定機器からのログ集中 = その機器が問題
- **AI解析のテレメトリ注記** → 「このイベントが多発する場合の意味」を提示

---

#### 将来の拡張イメージ（OpenTelemetry連携）

```
機器 → syslog/SNMP/gRPC → OpenTelemetry Collector
                                   ↓
                    Traces / Metrics / Logs に統合
                                   ↓
                    このダッシュボード（LLM解析）
```
        """)

# ═══════════════════════════════════════════
# TAB3: SNMPモニター
# ═══════════════════════════════════════════
with tab3:
    st.markdown("## 📡 SNMPモニター")
    st.caption("syslog（障害通知）＋ SNMP（定量メトリクス）を組み合わせることで、より精度の高いテレメトリ分析が可能です。")

    snmp_tab1, snmp_tab2 = st.tabs(["🚨 SNMP Trap", "📈 SNMPポーリング"])

    # ── SNMP Trap タブ ──
    with snmp_tab1:
        st.markdown("### 受信済み SNMP Trap")
        st.caption("Trapはsyslogと同じDBに保存されます。ベンダーフィルターで 'SNMP' を選択してください。")

        # Trapログをフィルタして表示
        trap_logs = db.get_logs(limit=100, vendor=None)
        trap_logs = [l for l in trap_logs if "SNMP" in (l.get("vendor") or "")]

        if not trap_logs:
            st.info("SNMP Trapがまだ受信されていません。\nサイドバーでTrapサーバーを起動し、機器側でSNMP Trap送信先を設定してください。")
        else:
            st.caption(f"受信Trap: {len(trap_logs)} 件")
            for log in trap_logs:
                sev = log.get("severity", "INFO")
                sev_color = {
                    "CRITICAL": "#dc2626", "ERROR": "#ea580c",
                    "WARNING": "#b45309", "NOTICE": "#2563eb", "INFO": "#16a34a"
                }.get(sev, "#64748b")
                tags = json.loads(log.get("tags") or "[]")
                st.markdown(f"""
<div class="log-card" style="border-left-color:{sev_color}">
  <span style="color:{sev_color}; font-weight:bold;">◉ {sev}</span>
  <span style="color:#0891b2; margin-left:8px;">{log.get('vendor','')}</span>
  <span style="color:#92400e; margin-left:8px;">{log.get('hostname','')}</span>
  <span style="color:#6b7280; float:right; font-size:11px;">{log.get('received_at','')[:19]}</span>
  <div style="margin-top:6px; color:#1f2937;">{log.get('message','')}</div>
  <div>{"".join(f'<span class="tag-chip">{t}</span>' for t in tags)}</div>
</div>
""", unsafe_allow_html=True)

        st.markdown("---")
        st.markdown("### 機器側 SNMP Trap 設定例")
        with st.expander("設定コマンド一覧"):
            st.code("""
# Cisco IOS/IOS-XE
snmp-server host 192.168.x.x version 2c public
snmp-server enable traps snmp linkdown linkup coldstart
snmp-server enable traps envmon
snmp-server enable traps ospf
snmp-server enable traps bgp

# Cisco NX-OS
snmp-server host 192.168.x.x traps version 2c public
snmp-server enable traps link linkDown
snmp-server enable traps link linkUp

# 富士通 Si-R
snmp host 192.168.x.x community public version 2c
snmp trap enable

# APRESIA ApresiaLight
snmp-server host 192.168.x.x community public
snmp-server trap enable
""", language="bash")

    # ── SNMPポーリング タブ ──
    with snmp_tab2:
        st.markdown("### ポーリング対象デバイス管理")

        # デバイス追加フォーム
        with st.expander("＋ デバイスを追加"):
            c1, c2, c3, c4, c5 = st.columns(5)
            with c1:
                new_ip = st.text_input("IPアドレス", placeholder="192.168.1.1")
            with c2:
                new_comm = st.text_input("コミュニティ", value="public")
            with c3:
                new_ver = st.selectbox("バージョン", ["v2c", "v1"])
            with c4:
                new_port = st.number_input("ポート", value=161, min_value=1, max_value=65535)
            with c5:
                new_interval = st.number_input("間隔(秒)", value=60, min_value=10, max_value=3600)
            if st.button("追加"):
                if new_ip:
                    snmp_poller.add_device(new_ip, new_comm, new_ver, new_port, new_interval)
                    st.success(f"{new_ip} を追加しました")
                    st.rerun()

        # デバイス一覧
        devices = snmp_poller.get_devices()
        if devices:
            st.markdown("#### 登録デバイス")
            df_dev = pd.DataFrame(devices)[["ip","hostname","community","version","interval_sec","last_polled","last_status"]]
            df_dev.columns = ["IP","ホスト名","コミュニティ","バージョン","間隔(秒)","最終ポーリング","状態"]
            st.dataframe(df_dev, use_container_width=True, hide_index=True)

            # 手動ポーリング
            sel_ip = st.selectbox("手動ポーリング対象", [d["ip"] for d in devices])
            poll_c1, poll_c2 = st.columns(2)
            with poll_c1:
                if st.button("▶ 今すぐポーリング（基本メトリクス）"):
                    with st.spinner(f"{sel_ip} にSNMP GETを送信中..."):
                        dev = next((d for d in devices if d["ip"] == sel_ip), {})
                        result = snmp_poller.poll_device(
                            sel_ip, dev.get("community","public"),
                            dev.get("version","v2c"), dev.get("port",161)
                        )
                    if result.get("metrics"):
                        st.success(f"{len(result['metrics'])} 個のOIDを取得しました")
                        st.json(result["metrics"])
                    else:
                        st.error("取得できませんでした（機器の設定・到達性を確認してください）")
            with poll_c2:
                if st.button("🩺 品質チェック（スループット/破棄/CPU）"):
                    with st.spinner(f"{sel_ip} の品質を評価中..."):
                        dev = next((d for d in devices if d["ip"] == sel_ip), {})
                        health = snmp_poller.poll_device_health(
                            sel_ip, dev.get("community","public"),
                            dev.get("version","v2c"), dev.get("port",161),
                            llm_mode="none"
                        )
                    st.success(f"品質スコア: {health['health_score']}/100 ({health['status']})")
                    st.caption("詳細は「📊 品質ルーブリック」タブで確認できます")

            st.markdown("---")
            st.markdown("#### 📍 ルーティングテーブル取得")
            rt_col1, rt_col2 = st.columns([1, 3])
            with rt_col1:
                st.caption("SNMP Walk（MIB: ipRouteTable）")
                if st.button("📍 SNMP で取得", key="fetch_rt"):
                    with st.spinner(f"{sel_ip} のルーティングテーブルをWalk中..."):
                        dev = next((d for d in devices if d["ip"] == sel_ip), {})
                        try:
                            routes = snmp_poller.fetch_routing_table(
                                sel_ip, dev.get("community","public"),
                                dev.get("version","v2c"), dev.get("port",161)
                            )
                            if routes:
                                st.success(f"{len(routes)} 件のルートを取得しました")
                            else:
                                st.warning("ルートが取得できませんでした")
                        except Exception as e:
                            st.error(f"取得エラー: {e}")
                    st.rerun()

                st.caption("RESTCONF（IOS-XE 専用・高速）")
                if st.button("⚡ RESTCONF で取得", key="fetch_rt_restconf"):
                    import restconf_client as rc_ui
                    rc_dev = rc_ui.get_device(sel_ip)
                    if not rc_dev:
                        st.warning("このIPのRESTCONFデバイスが未登録です（下のEPCパネルで登録してください）")
                    else:
                        with st.spinner(f"{sel_ip} にRESTCONFでルーティングテーブルを問い合わせ中..."):
                            client = rc_ui.RestconfClient(
                                sel_ip, rc_dev["username"], rc_dev["password"],
                                rc_dev.get("port", 443), bool(rc_dev.get("verify_ssl"))
                            )
                            rc_routes = client.get_routing_table()
                        if rc_routes:
                            st.success(f"✅ RESTCONF: {len(rc_routes)} 件のルートを取得しました（SNMPより高速）")
                            st.session_state[f"rc_routes_{sel_ip}"] = rc_routes
                        else:
                            st.error("RESTCONF でルートを取得できませんでした（機器設定を確認してください）")

            with rt_col2:
                # RESTCONF 取得結果を優先表示
                rc_routes_key = f"rc_routes_{sel_ip}"
                if rc_routes_key in st.session_state:
                    rc_rt = st.session_state[rc_routes_key]
                    st.caption("📡 RESTCONF 取得結果")
                    df_rc = pd.DataFrame(rc_rt)[["dest","mask","nexthop","proto","metric"]]
                    df_rc.columns = ["宛先","マスク","ネクストホップ","プロトコル","メトリック"]
                    st.dataframe(df_rc, use_container_width=True, hide_index=True)
                else:
                    rt_rows = snmp_poller.get_routing_table(sel_ip)
                    if rt_rows:
                        df_rt = pd.DataFrame(rt_rows)[["dest","mask","nexthop","route_type","proto","fetched_at"]]
                        df_rt.columns = ["宛先","マスク","ネクストホップ","タイプ","プロトコル","取得時刻"]
                        st.dataframe(df_rt, use_container_width=True, hide_index=True)
                    else:
                        st.caption("ルーティングテーブルなし（上のボタンで取得してください）")
        else:
            st.info("デバイスが登録されていません。上のフォームから追加してください。")

        st.markdown("---")
        st.markdown("### 🔀 ICMP Redirect 監視")
        st.caption("ICMP redirectが急増するとルーティング設定の問題・ループ・意図しないトポロジ変化の可能性があります。")
        icmp_rows = snmp_poller.get_icmp_redirect_latest()
        import db as _db
        all_logs = _db.get_logs(limit=500)
        redirect_logs = [l for l in all_logs if "ICMP Redirect" in (l.get("tags") or "")]

        if icmp_rows:
            # ── デバイスごとのカウンタ表示 ──
            for row in icmp_rows:
                label = "受信" if "In" in row["oid_name"] else "送信"
                diff_val = row.get("diff")
                al = row.get("alert_level", "none")
                al_color = "#dc2626" if al == "critical" else "#b45309" if al == "warning" else "#16a34a"
                al_icon  = "🔴" if al == "critical" else "🟡" if al == "warning" else "🟢"
                diff_str = f"+{diff_val}/poll" if diff_val is not None else "初回取得"
                st.markdown(f"""
<div class="log-card" style="border-left-color:{al_color}">
  <span style="color:{al_color}; font-weight:bold;">{al_icon} ICMP Redirect {label}</span>
  <span style="color:#0891b2; margin-left:8px;">{row['source_ip']}</span>
  <span style="color:#6b7280; margin-left:8px; font-size:12px;">累積: {row['value']} | 今回増分: {diff_str}</span>
  <span style="color:#6b7280; float:right; font-size:11px;">{row['recorded_at'][:19]}</span>
</div>
""", unsafe_allow_html=True)

            # ── ② タイムライン可視化 ──
            icmp_ips = list({r["source_ip"] for r in icmp_rows})
            sel_icmp_ip = st.selectbox("タイムライン表示対象IP", icmp_ips, key="icmp_trend_ip")
            trend_data = snmp_poller.get_icmp_redirect_trend(sel_icmp_ip, hours=6)
            if trend_data:
                import pandas as pd
                df_trend = pd.DataFrame(trend_data)
                df_trend["recorded_at"] = pd.to_datetime(df_trend["recorded_at"], format="ISO8601")
                df_trend["value"] = pd.to_numeric(df_trend["value"], errors="coerce")
                df_pivot = df_trend.pivot_table(
                    index="recorded_at", columns="oid_name", values="value"
                ).reset_index().set_index("recorded_at")
                df_pivot.columns = [c.replace("icmpIn","受信redirect ").replace("icmpOut","送信redirect ") for c in df_pivot.columns]
                st.markdown("**📈 ICMP Redirect 累積カウンタ推移（直近6時間）**")
                st.line_chart(df_pivot)
            else:
                st.caption("タイムラインデータなし（2回以上ポーリング後に表示されます）")

            # ── ① redirect先IP・宛先の抽出 ──
            redirect_dest_tags = []
            for rl in redirect_logs:
                tags = rl.get("tags") or []
                if isinstance(tags, str):
                    try:
                        import json as _json
                        tags = _json.loads(tags)
                    except Exception:
                        tags = []
                for t in tags:
                    if t.startswith("redirect_"):
                        redirect_dest_tags.append({
                            "IP": rl.get("source_ip",""),
                            "時刻": rl.get("received_at","")[:19],
                            "種別": t.split(":")[0].replace("redirect_",""),
                            "値": t.split(":",1)[1] if ":" in t else ""
                        })
            if redirect_dest_tags:
                st.markdown("**🎯 syslogから抽出したredirect先情報**")
                st.dataframe(pd.DataFrame(redirect_dest_tags), use_container_width=True, hide_index=True)

            # ── ③ ルーティングテーブル照合 ──
            # 優先順位: RESTCONF（取得済みキャッシュがあれば最優先・高速&高精度） > SNMP Walk > コンフィグ解析
            _rc_routes_icmp = st.session_state.get(f"rc_routes_{sel_icmp_ip}")
            snmp_routes = snmp_poller.get_routing_table(sel_icmp_ip)
            routing_summary = ""
            if _rc_routes_icmp:
                with st.expander(f"🗺️ ルーティングテーブル（RESTCONF取得済み: {len(_rc_routes_icmp)}件）", expanded=True):
                    st.caption("⚡ RESTCONFで取得したルートを使用中（「SNMPモニター」タブの「⚡ RESTCONF で取得」ボタンで更新できます）")
                    df_rc_icmp = pd.DataFrame(_rc_routes_icmp)[["dest","mask","nexthop","proto","metric"]]
                    df_rc_icmp.columns = ["宛先","マスク","ネクストホップ","プロトコル","メトリック"]
                    st.dataframe(df_rc_icmp, use_container_width=True, hide_index=True)
                    if redirect_dest_tags:
                        st.markdown("**宛先IP照合結果:**")
                        dest_ips = [t["値"] for t in redirect_dest_tags if t["種別"] == "dest"]
                        for dip in set(dest_ips[:5]):
                            match = next((r for r in _rc_routes_icmp if r.get("dest") == dip), None)
                            if match:
                                st.markdown(f"- 宛先 `{dip}` → ✅ 一致ルート: `{match['dest']}/{match['mask']}` via `{match['nexthop']}` ({match['proto']})")
                            else:
                                st.markdown(f"- 宛先 `{dip}` → ⚠️ ルーティングテーブルに一致なし（スタティックルート欠落の可能性）")
                routing_summary = "\n".join(
                    f"{r['dest']}/{r['mask']} via {r['nexthop']} ({r['proto']})"
                    for r in _rc_routes_icmp
                )
            elif snmp_routes:
                with st.expander(f"🗺️ ルーティングテーブル（SNMP Walk取得済み: {len(snmp_routes)}件）"):
                    df_rt_icmp = pd.DataFrame(snmp_routes)[["dest","mask","nexthop","route_type","proto","fetched_at"]]
                    df_rt_icmp.columns = ["宛先","マスク","ネクストホップ","タイプ","プロトコル","取得時刻"]
                    st.dataframe(df_rt_icmp, use_container_width=True, hide_index=True)
                    if redirect_dest_tags:
                        st.markdown("**宛先IP照合結果:**")
                        dest_ips = [t["値"] for t in redirect_dest_tags if t["種別"] == "dest"]
                        for dip in set(dest_ips[:5]):
                            match = snmp_poller.route_lookup(sel_icmp_ip, dip)
                            if match:
                                st.markdown(f"- 宛先 `{dip}` → ✅ 一致ルート: `{match['dest']}/{match['mask']}` via `{match['nexthop']}` ({match['proto']})")
                            else:
                                st.markdown(f"- 宛先 `{dip}` → ⚠️ ルーティングテーブルに一致なし（スタティックルート欠落の可能性）")
                routing_summary = "\n".join(
                    f"{r['dest']}/{r['mask']} via {r['nexthop']} ({r['proto']})"
                    for r in snmp_routes
                )
            else:
                cfg = _db.get_device_config(sel_icmp_ip)
                if cfg:
                    routing_summary = cfg.get("routing_summary", "") or cfg.get("interfaces_summary", "")
                    with st.expander("🗺️ 機器のルーティング情報（コンフィグより）"):
                        st.text(routing_summary[:2000] if routing_summary else "ルーティング情報なし")
                        if redirect_dest_tags:
                            dest_ips = [t["値"] for t in redirect_dest_tags if t["種別"] == "dest"]
                            for dip in set(dest_ips[:5]):
                                hit = dip in routing_summary if routing_summary else False
                                st.markdown(f"- 宛先 `{dip}` → {'✅ コンフィグに記載あり' if hit else '⚠️ コンフィグに見当たらない（スタティックルート欠落の可能性）'}")
                else:
                    st.caption("ルーティング照合：SNMPポーリングタブで「📍 ルーティングテーブル取得」を実行するか、「機器コンフィグ」タブにコンフィグを登録してください。")

            # ── ④ EPC 自動トリガー設定・手動制御 ──
            import restconf_client as rc_epc
            with st.expander("📦 EPC（パケットキャプチャ）自動トリガー設定", expanded=False):
                st.caption("ICMP Redirect が急増したとき、Catalyst に自動で `monitor capture` を起動します。")

                epc_dev = rc_epc.get_device(sel_icmp_ip)
                with st.form(f"restconf_form_{sel_icmp_ip}"):
                    st.markdown("**RESTCONF 認証情報**")
                    fc1, fc2 = st.columns(2)
                    with fc1:
                        f_user = st.text_input("ユーザー名", value=epc_dev["username"] if epc_dev else "")
                        f_iface = st.text_input("EPC キャプチャ対象インターフェース",
                                                value=epc_dev.get("epc_interface","") if epc_dev else "",
                                                placeholder="GigabitEthernet1/0/1")
                        f_threshold = st.number_input("自動起動閾値（redirects/poll）",
                                                      min_value=1, max_value=500,
                                                      value=epc_dev.get("epc_threshold",10) if epc_dev else 10)
                    with fc2:
                        f_pass = st.text_input("パスワード", type="password",
                                               value="" if epc_dev else "")
                        f_duration = st.number_input("キャプチャ時間（秒）",
                                                     min_value=10, max_value=3600,
                                                     value=epc_dev.get("epc_duration_sec",60) if epc_dev else 60)
                        f_auto = st.checkbox("ICMP Redirect 急増時に自動起動",
                                             value=bool(epc_dev.get("epc_auto_trigger")) if epc_dev else False)
                    if st.form_submit_button("💾 保存"):
                        if f_user and f_pass:
                            rc_epc.add_device(
                                sel_icmp_ip, f_user, f_pass, 443, False,
                                f_iface, f_auto, f_threshold, f_duration
                            )
                            st.success("✅ RESTCONF デバイス設定を保存しました")
                        else:
                            st.error("ユーザー名とパスワードを入力してください")

                st.markdown("**手動 EPC 操作**")
                epc_cols = st.columns(3)
                is_cap = rc_epc.is_capturing(sel_icmp_ip)
                with epc_cols[0]:
                    if st.button("▶ EPC 開始", key=f"epc_start_{sel_icmp_ip}",
                                 disabled=is_cap or not epc_dev):
                        res = rc_epc.manual_start_epc(sel_icmp_ip)
                        if res["ok"]:
                            st.success(f"✅ キャプチャ開始: {res['capture_name']} ({res['duration_sec']}秒後に自動停止)")
                        else:
                            st.error(res.get("error", "起動失敗"))
                with epc_cols[1]:
                    if st.button("■ EPC 停止＋自動取得", key=f"epc_stop_{sel_icmp_ip}",
                                 disabled=not is_cap):
                        with st.spinner("停止 → flash エクスポート → SCP ダウンロード中..."):
                            res = rc_epc.manual_stop_epc(sel_icmp_ip)
                        if res["ok"]:
                            if res.get("local_path"):
                                st.success(f"✅ 自動取得完了: {res['local_path']}")
                            elif res.get("scp_error"):
                                st.warning(f"flash 保存済み: {res['pcap_flash_path']}\nSCP エラー: {res['scp_error']}")
                        else:
                            st.error(res.get("error", "停止失敗"))
                with epc_cols[2]:
                    cap_status = "🔴 キャプチャ中" if is_cap else "⚫ 待機中"
                    st.metric("EPC 状態", cap_status)

                epc_events = rc_epc.get_epc_events(sel_icmp_ip, limit=10)
                if epc_events:
                    st.markdown("**EPC イベント履歴**")
                    df_epc = pd.DataFrame(epc_events)[["triggered_at","trigger_reason","capture_name","status","pcap_flash_path"]]
                    df_epc.columns = ["日時","トリガー理由","キャプチャ名","状態","pcapパス"]
                    st.dataframe(df_epc, use_container_width=True, hide_index=True)
                else:
                    st.caption("EPC イベント履歴なし")

                st.markdown("---")
                st.markdown("**🤖 自動解析結果**")
                analyses = rc_epc.get_epc_analyses(sel_icmp_ip, limit=5)
                if analyses:
                    latest = analyses[0]
                    st.caption(f"最終解析: {latest['analyzed_at'][:19]}  |  キャプチャ: {latest['capture_name']}")
                    an = latest.get("analysis", {})
                    ac1, ac2, ac3, ac4 = st.columns(4)
                    ac1.metric("総パケット数", an.get("total_packets", 0))
                    ac2.metric("ICMP Redirect", len(an.get("icmp_redirects", [])))
                    ac3.metric("TCP問題", len(an.get("tcp_issues", [])))
                    ac4.metric("DNSエラー", an.get("dns_summary", {}).get("nxdomain", 0))

                    rds = an.get("icmp_redirects", [])
                    if rds:
                        st.markdown(f"**🔀 ICMP Redirect 詳細 ({len(rds)} 件)**")
                        st.dataframe(pd.DataFrame(rds), use_container_width=True, hide_index=True)

                    rip = an.get("rip_packets", [])
                    if rip:
                        with st.expander(f"🗺️ RIP パケット ({len(rip)} 件)"):
                            st.dataframe(pd.DataFrame(rip), use_container_width=True, hide_index=True)

                    arp = an.get("arp_anomalies", [])
                    if arp:
                        with st.expander(f"⚠️ ARP 異常 ({len(arp)} 件)"):
                            st.dataframe(pd.DataFrame(arp), use_container_width=True, hide_index=True)

                    if len(analyses) > 1:
                        with st.expander(f"📜 過去の解析履歴 ({len(analyses)-1} 件)"):
                            for old in analyses[1:]:
                                a2 = old.get("analysis", {})
                                st.markdown(
                                    f"- `{old['analyzed_at'][:19]}` — "
                                    f"pkts={a2.get('total_packets',0)} "
                                    f"redirects={len(a2.get('icmp_redirects',[]))} "
                                    f"TCP問題={len(a2.get('tcp_issues',[]))}"
                                )
                    if st.button("🔄 解析結果を更新", key="refresh_analysis"):
                        st.rerun()
                else:
                    st.info("まだ自動解析結果がありません。EPC が完了すると自動で解析・保存されます。")

                st.markdown("---")
                st.markdown("**📥 手動 pcap ダウンロード＆解析**")
                st.caption("Catalyst の flash から SCP で pcap を取得してそのまま解析します。（IOS-XE 側: `ip scp server enable` が必要）")

                dl_ip   = sel_icmp_ip
                dl_user = epc_dev["username"] if epc_dev else ""
                dl_col1, dl_col2 = st.columns(2)
                with dl_col1:
                    dl_user_in = st.text_input("ユーザー名", value=dl_user, key="dl_user")
                    dl_pass_in = st.text_input("パスワード", type="password", key="dl_pass")
                with dl_col2:
                    # flash にある pcap 一覧を取得するボタン
                    if st.button("🔍 flash の pcap 一覧を取得", key="list_pcap"):
                        if dl_user_in and dl_pass_in:
                            with st.spinner(f"{dl_ip} に SSH 接続中..."):
                                found = rc_epc.list_flash_pcaps(dl_ip, dl_user_in, dl_pass_in)
                            if found:
                                st.session_state[f"flash_pcaps_{dl_ip}"] = found
                                st.success(f"{len(found)} 件の pcap を検出しました")
                            else:
                                st.warning("pcap ファイルが見つかりませんでした（`ip scp server enable` を確認してください）")
                        else:
                            st.error("ユーザー名とパスワードを入力してください")

                    # 一覧から選択 or 手動入力
                    flash_list = st.session_state.get(f"flash_pcaps_{dl_ip}", [])
                    # EPC イベント履歴から flash パスと自動ダウンロード済みパスを収集
                    hist_paths = []
                    for e in epc_events:
                        fp = e.get("pcap_flash_path","")
                        if fp and fp.startswith("flash:"):
                            hist_paths.append(fp)
                        # "downloaded:/path/to/file.pcap" 形式のステータスからも取得
                        st_val = e.get("status","")
                        if st_val.startswith("downloaded:"):
                            hist_paths.append(st_val.split("downloaded:",1)[1])
                    all_options = list(dict.fromkeys(flash_list + hist_paths))  # 重複除去

                    if all_options:
                        dl_file = st.selectbox("ダウンロードするファイル", all_options, key="dl_file_sel")
                    else:
                        dl_file = st.text_input("flash パス（例: flash:/epc_xxx.pcap）", key="dl_file_manual")

                if st.button("⬇ ダウンロードして解析", key="dl_and_analyze", type="primary",
                             disabled=not (dl_user_in and dl_pass_in and dl_file)):
                    with st.spinner(f"SCP でダウンロード中: {dl_ip}:{dl_file}"):
                        pcap_bytes, err = rc_epc.download_pcap_via_scp(
                            dl_ip, dl_user_in, dl_pass_in, dl_file
                        )
                    if pcap_bytes:
                        st.success(f"✅ ダウンロード完了 ({len(pcap_bytes):,} bytes)")
                        with st.spinner("pcap を解析中..."):
                            import pcap_analyzer
                            pcap_result = pcap_analyzer.analyze_pcap(pcap_bytes)
                            pcap_convs   = pcap_analyzer.get_conversations(pcap_bytes)
                            pcap_talkers = pcap_analyzer.get_top_talkers(pcap_bytes)
                            pcap_streams = pcap_analyzer.get_tcp_streams(pcap_bytes)
                        # 「📦 パケット解析」タブと同じセッション状態に格納する。
                        # これにより取得経路（アップロード/SCP/EPC）によらず同じ解析結果表示・
                        # 同じ「🤖 AI診断実行」ボタンが使えるようになる。
                        st.session_state["_pcap_key"]     = f"epc_{dl_ip}_{dl_file}"
                        st.session_state["_pcap_res"]     = pcap_result
                        st.session_state["_pcap_convs"]   = pcap_convs
                        st.session_state["_pcap_talkers"] = pcap_talkers
                        st.session_state["_pcap_streams"] = pcap_streams
                        st.session_state["_pcap_bytes"]   = pcap_bytes

                        # 解析結果を表示
                        st.markdown("#### 📊 pcap 解析結果")
                        sr1, sr2, sr3, sr4 = st.columns(4)
                        sr1.metric("総パケット数", pcap_result.get("total_packets", 0))
                        sr2.metric("ICMP Redirect", len(pcap_result.get("icmp_redirects", [])))
                        sr3.metric("TCP問題フロー", len(pcap_result.get("tcp_issues", [])))
                        sr4.metric("キャプチャ時間", f"{pcap_result.get('capture_duration_sec', 0):.1f}s")

                        redirects = pcap_result.get("icmp_redirects", [])
                        if redirects:
                            st.markdown(f"**🔀 ICMP Redirect ({len(redirects)} 件)**")
                            df_rd = pd.DataFrame(redirects)
                            st.dataframe(df_rd, use_container_width=True, hide_index=True)

                        rip_pkts = pcap_result.get("rip_packets", [])
                        if rip_pkts:
                            st.markdown(f"**🗺️ RIP パケット ({len(rip_pkts)} 件)**")
                            st.dataframe(pd.DataFrame(rip_pkts), use_container_width=True, hide_index=True)

                        arp_issues = pcap_result.get("arp_anomalies", [])
                        if arp_issues:
                            st.markdown(f"**⚠️ ARP 異常 ({len(arp_issues)} 件)**")
                            st.dataframe(pd.DataFrame(arp_issues), use_container_width=True, hide_index=True)

                        # ダウンロードボタン（ローカル保存用）
                        st.download_button(
                            "💾 pcap をローカルに保存",
                            data=pcap_bytes,
                            file_name=dl_file.split("/")[-1],
                            mime="application/octet-stream",
                        )

                        # 全ページ共通の「🤖 AI診断実行」ボタン（詳細な内訳表は「📦 パケット解析」タブ参照）
                        _render_pcap_ai_diagnosis(pcap_result, key_prefix="epc")
                    else:
                        st.error(f"ダウンロード失敗: {err}")

                with st.expander("💡 IOS-XE 側の事前設定（コピペ用）"):
                    st.code("""conf t
 ip http server
 ip http secure-server
 ip http authentication local
 restconf
 ip scp server enable
 username admin privilege 15 secret YourPassword
end""", language="text")

            # ── ⑤ AI自動原因推定 ──
            st.markdown("**🤖 AI自動原因推定**")
            llm_ok = analyzer.check_claude_available() or analyzer.check_gemini_available() or analyzer.check_groq_available() or analyzer.check_ollama_available()
            if llm_ok:
                _icmp_c1, _icmp_c2 = st.columns(2)
                if _icmp_c1.button("🤖 ICMP redirect根本原因をAIで診断", key="icmp_ai_diag",
                                    type="primary", use_container_width=True):
                    with st.spinner("AIがICMP redirect原因を分析中..."):
                        dev_snmp = [r for r in icmp_rows if r["source_ip"] == sel_icmp_ip]
                        dev_logs = [l for l in redirect_logs if l.get("source_ip") == sel_icmp_ip]
                        st.session_state["_icmp_diag_main"] = analyzer.diagnose_icmp_redirect(
                            ip=sel_icmp_ip,
                            snmp_data=dev_snmp,
                            redirect_logs=dev_logs,
                            routing_summary=routing_summary,
                            mode=st.session_state.get("llm_mode", "auto")
                        )
                if analyzer.check_claude_available():
                    if _icmp_c2.button("🕵️ エージェント診断（ルート検索を深掘り）", key="icmp_agentic",
                                        use_container_width=True):
                        with st.spinner("Claudeがルーティングテーブルを検索しながら分析中..."):
                            dev_snmp = [r for r in icmp_rows if r["source_ip"] == sel_icmp_ip]
                            dev_logs = [l for l in redirect_logs if l.get("source_ip") == sel_icmp_ip]
                            st.session_state["_icmp_diag_main"] = analyzer.diagnose_icmp_redirect_agentic(
                                ip=sel_icmp_ip, snmp_data=dev_snmp,
                                redirect_logs=dev_logs, routing_summary=routing_summary,
                            )
                _render_icmp_redirect_diagnosis_result(st.session_state.get("_icmp_diag_main"))
            else:
                st.caption("AI診断を使うにはClaude APIまたはOllamaの設定が必要です")

            # ── 関連syslog一覧 ──
            if redirect_logs:
                with st.expander(f"📋 関連syslogログ ({len(redirect_logs)}件)"):
                    for rl in redirect_logs[:20]:
                        st.markdown(f"- `{rl.get('received_at','')[:19]}` **{rl.get('source_ip','')}** {rl.get('message','')[:120]}")
            else:
                st.caption("syslogでのICMP redirect検出なし（機器側のlogging設定確認を推奨）")
        else:
            st.info("ICMP redirectデータなし。デバイスを登録してポーリングを開始してください。")

        st.markdown("---")
        st.markdown("### 閾値アラート（直近10分）")
        alerts = snmp_poller.get_alert_metrics()
        if alerts:
            for a in alerts:
                level_color = "#dc2626" if a["alert_level"] == "critical" else "#b45309"
                st.markdown(f"""
<div class="log-card" style="border-left-color:{level_color}">
  <span style="color:{level_color}; font-weight:bold;">
    {'🔴 CRITICAL' if a['alert_level']=='critical' else '🟡 WARNING'}
  </span>
  <span style="color:#0891b2; margin-left:8px;">{a['source_ip']}</span>
  <span style="color:#6b7280; margin-left:8px;">{a['oid_name']}</span>
  <span style="color:#92400e; margin-left:8px; font-weight:bold;">{a['value']} {a['unit']}</span>
  <span style="color:#6b7280; float:right; font-size:11px;">{a['recorded_at'][:19]}</span>
</div>
""", unsafe_allow_html=True)
        else:
            st.success("✅ 閾値超過なし")

        st.markdown("---")
        st.markdown("### 収集メトリクス一覧")
        metrics = snmp_poller.get_latest_metrics(limit=50)
        if metrics:
            df_m = pd.DataFrame(metrics)[["recorded_at","source_ip","oid_name","value","unit","alert_level"]]
            df_m.columns = ["取得時刻","送信元IP","OID名","値","単位","アラート"]
            st.dataframe(df_m, use_container_width=True, hide_index=True)
        else:
            st.info("メトリクスがまだ収集されていません")

        st.markdown("---")
        with st.expander("📡 テレメトリ観点：syslog + SNMP の組み合わせ効果"):
            st.markdown("""
| データソース | 得られる情報 | テレメトリでの活用 |
|-------------|-------------|-----------------|
| **syslog** | イベント（何が起きたか） | 障害の「発生」を検知 |
| **SNMP Trap** | 重要イベントの即時通知 | 障害の「発生」を即時検知 |
| **SNMP Polling** | CPU/メモリ/IF統計などの定量値 | 障害の「予兆」を検知 |

**組み合わせ例：**
- CPU使用率が80%超（SNMP Polling） → syslogにOSPFネイバーダウン（syslog）
- → 「CPU高負荷によるルーティングプロトコル不安定」と推定可能

**AI解析への活用：**
SNMPメトリクスのコンテキストをLLMに渡すことで、
syslogの単一イベントでは分からない**根本原因**を推定できます。
            """)

# ═══════════════════════════════════════════
# TAB4: 機器コンフィグ管理
# ═══════════════════════════════════════════
with tab4:
    st.markdown("## 🗂️ 機器コンフィグ管理")
    st.caption("インターフェース・ルーティング設定を事前に登録すると、AI解析時に「構成上正常か」を踏まえた判断ができるようになります。")

    st.markdown("### ＋ コンフィグを登録")
    with st.form("config_upload_form"):
        c1, c2, c3 = st.columns(3)
        with c1:
            cfg_ip = st.text_input("機器のIPアドレス *", placeholder="192.168.1.1")
        with c2:
            cfg_hostname = st.text_input("ホスト名（任意）", placeholder="catalyst01")
        with c3:
            cfg_vendor = st.selectbox("ベンダー", [
                "Cisco IOS/IOS-XE", "Cisco NX-OS", "富士通 Si-R",
                "富士通 IPCOM", "富士通 SR-S",
                "APRESIA", "RHEL/Linux", "Windows", "その他"
            ])

        if _is_cloud_mode() and not _is_admin_authenticated():
            st.caption(f"🔒 ゲスト利用時のアップロード上限: {MAX_UPLOAD_MB_GUEST}MB（管理者ログインで解除）")
        uploaded_cfg = st.file_uploader(
            "コンフィグファイル（.txt / show running-config の出力等）",
            type=["txt", "cfg", "conf", "log"]
        )
        cfg_text_input = st.text_area(
            "またはここに直接貼り付け",
            height=200,
            placeholder="interface GigabitEthernet1/0/1\n description Uplink to Core\n ip address 10.0.0.1 255.255.255.0\n...\nrouter ospf 1\n network 10.0.0.0 0.0.0.255 area 0\n..."
        )
        cfg_notes = st.text_area(
            "補足メモ（任意）",
            placeholder="例: この機器はHAペアのプライマリ。BGPネイバーは3台中1台が冗長構成。"
        )

        submitted = st.form_submit_button("💾 登録/更新")
        if submitted:
            if not cfg_ip:
                st.error("IPアドレスは必須です")
            elif uploaded_cfg is not None and not _check_upload_size_ok(uploaded_cfg, _is_cloud_mode()):
                pass  # エラーメッセージは _check_upload_size_ok 内で表示済み
            else:
                final_text = ""
                if uploaded_cfg is not None:
                    final_text = uploaded_cfg.read().decode("utf-8", errors="replace")
                elif cfg_text_input.strip():
                    final_text = cfg_text_input
                if not final_text:
                    st.error("ファイルアップロードまたはテキスト貼り付けのいずれかが必要です")
                else:
                    db.save_device_config(cfg_ip, final_text, cfg_hostname, cfg_vendor, cfg_notes)
                    st.success(f"{cfg_ip} のコンフィグを登録しました")
                    st.rerun()

    st.markdown("---")
    st.markdown("### 登録済みコンフィグ一覧")

    configs = db.get_all_device_configs()
    if not configs:
        st.info("まだコンフィグが登録されていません。上のフォームから登録してください。")
    else:
        for cfg in configs:
            with st.expander(f"📄 {cfg['ip']} ({cfg.get('hostname') or '無名'}) - {cfg.get('vendor','')}"):
                full_cfg = db.get_device_config(cfg["ip"])
                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown("**📶 抽出されたインターフェース構成**")
                    st.code(full_cfg.get("interfaces_summary","")[:2000] or "（検出されませんでした）",
                            language="text")
                with col_b:
                    st.markdown("**🛣️ 抽出されたルーティング構成**")
                    st.code(full_cfg.get("routing_summary","")[:2000] or "（検出されませんでした）",
                            language="text")
                if full_cfg.get("notes"):
                    st.markdown(f"**📝 補足メモ:** {full_cfg['notes']}")
                st.caption(f"登録日時: {cfg.get('uploaded_at','')[:19]}")
                if st.button("🗑️ このコンフィグを削除", key=f"del_cfg_{cfg['ip']}"):
                    db.delete_device_config(cfg["ip"])
                    st.success("削除しました")
                    st.rerun()

    st.markdown("---")
    with st.expander("📖 コンフィグ登録のしかた（コマンド例）"):
        st.markdown("""
機器にログインし、以下のコマンドの出力結果をコピー＆ペーストするか、
テキストファイルとして保存してアップロードしてください。

```bash
# Cisco IOS/IOS-XE
show running-config

# Cisco NX-OS
show running-config

# 富士通 Si-R
show config

# RHEL/Linux
ip addr show
ip route show
cat /etc/sysconfig/network-scripts/ifcfg-*
```

**ポイント：**
- 全部のコンフィグでなくても構いません（インターフェース・ルーティング部分があれば十分）
- パスワードやシークレットキーが含まれる場合は事前に削除することを推奨します
- 機器が増えてきたら、IPアドレスごとに登録してください（送信元IPで自動的に紐付けられます）
        """)

    st.markdown("---")
    st.markdown("## 📚 ベンダー推奨設定集")
    st.caption("各メーカー公式ドキュメント・ベストプラクティスに基づくsyslog/SNMP設定のテンプレートです。導入時の参考にしてください。")

    vendor_options = vendor_rec.get_all_vendors()
    selected_vendor = st.selectbox("ベンダーを選択", vendor_options, key="vendor_rec_select")

    settings = vendor_rec.get_settings(selected_vendor)
    if settings:
        st.markdown(f"### {settings['category']}")

        rec_tab1, rec_tab2, rec_tab3 = st.tabs(["📜 syslog設定", "📡 SNMP設定", "🔒 セキュリティ注意事項"])

        with rec_tab1:
            st.code(settings["syslog"].strip(), language="bash")
            st.button("📋 コピー用に表示", key=f"copy_syslog_{selected_vendor}",
                      help="コードブロック右上のコピーアイコンからコピーできます")

        with rec_tab2:
            st.code(settings["snmp"].strip(), language="bash")

        with rec_tab3:
            for note in settings["security_notes"]:
                st.markdown(f"- ⚠️ {note}")

        st.caption(f"📖 参照: {settings['reference']}")
        st.warning("⚠️ `${...}` で示された値は必ず環境に応じた独自の文字列に変更してください。デフォルトのコミュニティ名（public/private）の使用は避けてください。")

# ═══════════════════════════════════════════
# TAB5: セットアップガイド
# ═══════════════════════════════════════════
with tab5:
    st.markdown("## 📖 セットアップガイド")

    st.markdown("""
### 必要なもの

- **Python 3.10以上**
- **pip**（Pythonパッケージマネージャー）
- （オプション）**Ollama**（オフライン時のローカルLLM）

---

### 1. インストール手順

```bash
# リポジトリをコピー or ダウンロード後
cd syslog-analyzer

# 依存パッケージをインストール
pip install -r requirements.txt
```

---

### 2. 起動方法

```bash
# Streamlitアプリを起動（これだけでOK）
streamlit run app.py
```

ブラウザで `http://localhost:8501` を開く。

> ⚠️ **ポート514について**
> UDPポート514はLinux/Macでは `root` 権限が必要です。
> サイドバーで **5140** などに変更し、機器側の転送先ポートも合わせてください。

---

### 3. Claude API（任意）

Claude APIは **Claude.aiのProサブスクリプション**では利用できません。
API利用は別途 [Anthropic API](https://console.anthropic.com) の契約が必要です（従量課金）。

```bash
# 環境変数に設定
export ANTHROPIC_API_KEY="sk-ant-..."   # Linux/Mac
set ANTHROPIC_API_KEY=sk-ant-...        # Windows
```

---

### 4. Ollama（完全ローカルLLM）

```bash
# Ollamaをインストール（https://ollama.com）
curl -fsSL https://ollama.com/install.sh | sh   # Linux/Mac
# Windowsはインストーラーを使用

# モデルをダウンロード（日本語対応モデル推奨）
ollama pull llama3          # 汎用（英語中心）
ollama pull gemma3          # Google製、日本語対応良好
ollama pull elyza/llama3-jp # 日本語特化

# Ollamaサービスを起動
ollama serve
```

---

### 5. 機器側のsyslog設定例

#### Cisco IOS/IOS-XE
```
logging host 192.168.x.x transport udp port 5140
logging trap informational
```

#### Cisco NX-OS
```
logging server 192.168.x.x 6 use-vrf management
```

#### 富士通 Si-R
```
syslog host 192.168.x.x
syslog facility local0
```

#### APRESIA ApresiaLight
```
syslog-server 192.168.x.x
```

#### RHEL/Linux (rsyslog)
```bash
# /etc/rsyslog.conf に追記
*.* @192.168.x.x:5140    # UDP
*.* @@192.168.x.x:5140   # TCP
systemctl restart rsyslog
```

#### Windows (NXLog)
```xml
<!-- /etc/nxlog/nxlog.conf 例 -->
<Output syslog_out>
  Module  om_udp
  Host    192.168.x.x
  Port    5140
  Exec    to_syslog_bsd();
</Output>
```

#### Windows (Winlogbeat)
```yaml
# winlogbeat.yml 例
winlogbeat.event_logs:
  - name: Security
  - name: System
  - name: Application

output.logstash:
  # または直接syslog出力プラグインを使用
```
    """)

# ═══════════════════════════════════════════
# TAB: パケット解析（Wireshark pcap/pcapng）
# ═══════════════════════════════════════════
# ═══════════════════════════════════════════
# TAB: NetFlow
# ═══════════════════════════════════════════
with tab_netflow:
    import netflow_collector as _nfc2

    st.markdown("## 🌊 NetFlow フロー解析")
    st.caption("ルーターから送信される NetFlow v5 を受信・集計してトラフィックを可視化します。")

    if not st.session_state.netflow_started:
        st.info("サイドバーから NetFlow サーバーを起動してください。\n\n"
                "**ルーター側の設定例（Cisco IOS-XE）:**\n```\n"
                "ip flow-export version 5\n"
                "ip flow-export destination <このPCのIP> 9995\n"
                "ip flow-cache timeout active 1\n"
                "!\n"
                "interface GigabitEthernet1/0/1\n"
                " ip flow ingress\n"
                " ip flow egress\n```")
    else:
        _nf_hours = st.select_slider(
            "集計期間", options=[1, 3, 6, 12, 24], value=1,
            format_func=lambda x: f"過去 {x} 時間"
        )

        if st.button("🔄 更新", key="nf_refresh"):
            st.rerun()

        _nf_sum = _nfc2.get_summary(_nf_hours)

        # ── 概要メトリクス ──
        st.markdown("### 📊 概要")
        _nc1, _nc2, _nc3, _nc4, _nc5 = st.columns(5)
        _nc1.metric("総フロー数",    f"{_nf_sum['total_flows']:,}")
        _nc2.metric("総バイト数",    f"{_nf_sum['total_bytes']/1024/1024:.1f} MB")
        _nc3.metric("総パケット数",  f"{_nf_sum['total_packets']:,}")
        _nc4.metric("ユニーク送信元", f"{_nf_sum['unique_src']:,}")
        _nc5.metric("エクスポーター", f"{_nf_sum['exporters']:,}")

        # ── タイムライン ──
        _nf_timeline = _nfc2.get_traffic_timeline(_nf_hours)
        if _nf_timeline:
            st.markdown("---")
            st.markdown("### 📈 トラフィックタイムライン")
            df_tl = pd.DataFrame(_nf_timeline)
            df_tl["MB"] = (df_tl["total_bytes"] / 1024 / 1024).round(3)
            st.line_chart(df_tl.set_index("ts")["MB"], height=200)
            st.caption("単位: MB / 集計バケット")

        # ── トップトーカー + プロトコル ──
        st.markdown("---")
        _ta_col, _pr_col = st.columns(2)

        with _ta_col:
            st.markdown("### 📡 トップトーカー（送信元IP）")
            _nf_talkers = _nfc2.get_top_talkers(_nf_hours, limit=15)
            if _nf_talkers:
                df_tk = pd.DataFrame(_nf_talkers)
                df_tk["MB"] = (df_tk["total_bytes"] / 1024 / 1024).round(3)
                st.bar_chart(df_tk.set_index("ip")["MB"].head(10))
                _tk_show = df_tk[["ip", "MB", "total_packets", "flows"]]
                _tk_show.columns = ["IPアドレス", "MB", "パケット数", "フロー数"]
                st.dataframe(_tk_show, use_container_width=True, hide_index=True)
            else:
                st.info("データなし")

        with _pr_col:
            st.markdown("### 🔌 プロトコル分布")
            _nf_protos = _nfc2.get_protocol_stats(_nf_hours)
            if _nf_protos:
                df_pr = pd.DataFrame(_nf_protos)
                df_pr["MB"] = (df_pr["total_bytes"] / 1024 / 1024).round(3)
                st.bar_chart(df_pr.set_index("protocol_name")["MB"])
                _pr_show = df_pr[["protocol_name", "MB", "total_packets", "flows"]]
                _pr_show.columns = ["プロトコル", "MB", "パケット数", "フロー数"]
                st.dataframe(_pr_show, use_container_width=True, hide_index=True)
            else:
                st.info("データなし")

        # ── アプリケーション（ポート別） ──
        _nf_ports = _nfc2.get_port_stats(_nf_hours)
        if _nf_ports:
            st.markdown("---")
            st.markdown("### 🌐 アプリケーション別トラフィック（TCP/UDP 宛先ポート）")
            df_pt = pd.DataFrame(_nf_ports)
            df_pt["MB"] = (df_pt["total_bytes"] / 1024 / 1024).round(3)
            _pt_col1, _pt_col2 = st.columns([2, 1])
            with _pt_col1:
                st.bar_chart(df_pt.set_index("app")["MB"])
            with _pt_col2:
                _pt_show = df_pt[["app", "dst_port", "MB", "flows"]]
                _pt_show.columns = ["アプリ", "ポート", "MB", "フロー"]
                st.dataframe(_pt_show, use_container_width=True, hide_index=True)

        # ── フロー一覧 ──
        st.markdown("---")
        st.markdown("### 📋 フロー一覧（直近500件）")
        _nf_flows = _nfc2.get_recent_flows(_nf_hours, limit=500)
        if _nf_flows:
            df_fl = pd.DataFrame(_nf_flows)
            _fl_cols = ["received_at", "exporter_ip", "src_ip", "dst_ip",
                        "src_port", "dst_port", "proto_name", "app", "packets", "bytes"]
            df_fl = df_fl[_fl_cols].rename(columns={
                "received_at":  "受信時刻", "exporter_ip": "エクスポーター",
                "src_ip":       "送信元IP",  "dst_ip":       "宛先IP",
                "src_port":     "送信元Port","dst_port":     "宛先Port",
                "proto_name":   "プロトコル","app":          "アプリ",
                "packets":      "パケット数","bytes":        "バイト数",
            })
            st.dataframe(df_fl, use_container_width=True, hide_index=True)
        else:
            st.info("まだフローデータがありません。ルーターの flow-export 設定を確認してください。")

        # ── DDoS 検出 ──
        st.markdown("---")
        _ddos_row1, _ddos_row2 = st.columns([4, 1])
        _ddos_row1.markdown("### 🚨 DDoS / 攻撃パターン検出")
        _nf_alerts = _nfc2.get_ddos_alerts(_nf_hours)
        with _ddos_row2:
            _nf_llm_ok = (analyzer.check_claude_available() or analyzer.check_gemini_available()
                          or analyzer.check_groq_available() or analyzer.check_ollama_available())
            if st.button("🤖 AI分析", key="nf_ddos_ai", disabled=not _nf_llm_ok,
                         use_container_width=True, type="primary"):
                _nf_sum2 = _nfc2.get_summary(_nf_hours)
                _nf_ai_ctx = (
                    f"NetFlow集計期間: 過去{_nf_hours}時間\n"
                    f"総フロー: {_nf_sum2['total_flows']:,} / 総バイト: {_nf_sum2['total_bytes']/1024/1024:.1f}MB\n\n"
                    "検出アラート:\n" +
                    "\n".join(f"- [{a['type']}] {a['src_ip']} : {a['detail']}" for a in _nf_alerts)
                    if _nf_alerts else "アラートなし"
                )
                with st.spinner("LLM分析中..."):
                    _nf_ai_text, _nf_ai_model = analyzer.ask_llm(
                        "あなたはネットワークセキュリティの専門家です。"
                        "NetFlowの異常検出結果を日本語で簡潔に解説し、対策を提案してください。",
                        _nf_ai_ctx,
                        st.session_state.get("llm_mode", "auto"),
                    )
                st.session_state["_nf_ddos_ai"] = (_nf_ai_text, _nf_ai_model)

        if "nf_ddos_ai" in [k.split("_")[-1] for k in st.session_state]:
            _nf_ai_res = st.session_state.get("_nf_ddos_ai")
            if _nf_ai_res and _nf_ai_res[0]:
                with st.expander(f"🤖 AI分析結果（{_nf_ai_res[1]}）", expanded=True):
                    st.markdown(_nf_ai_res[0])

        if _nf_alerts:
            _alert_cols = st.columns([1, 2, 3])
            _alert_cols[0].markdown("**種別**")
            _alert_cols[1].markdown("**送信元IP**")
            _alert_cols[2].markdown("**詳細**")
            for _al in _nf_alerts:
                _sev_icon = "🔴" if _al["severity"] == "high" else "🟡"
                _type_map = {
                    "volumetric": "ボリューム攻撃",
                    "port_scan":  "ポートスキャン",
                    "syn_flood":  "SYNフラッド",
                    "icmp_flood": "ICMPフラッド",
                }
                _c1, _c2, _c3 = st.columns([1, 2, 3])
                _c1.markdown(f"{_sev_icon} **{_type_map.get(_al['type'], _al['type'])}**")
                _c2.code(_al["src_ip"])
                _c3.markdown(_al["detail"])
        else:
            st.success("✅ 現在の集計期間で異常なトラフィックパターンは検出されていません。")

        # ── 帯域トレンド（容量計画） ──
        st.markdown("---")
        st.markdown("### 📉 帯域トレンド（容量計画）")
        _nf_trend_days = st.select_slider(
            "表示期間", options=[1, 3, 7, 14, 30], value=7,
            format_func=lambda x: f"過去 {x} 日間", key="nf_trend_days"
        )
        _cap_threshold = st.number_input(
            "容量閾値 (MB/時間)", min_value=0, value=100, step=10, key="nf_cap_thresh"
        )
        _bw_hist = _nfc2.get_bandwidth_history(_nf_trend_days)
        if _bw_hist:
            import pandas as pd
            df_bw = pd.DataFrame(_bw_hist)
            df_bw["MB"] = (df_bw["total_bytes"] / 1024 / 1024).round(2)
            df_bw_idx = df_bw.set_index("hour")[["MB"]]
            if _cap_threshold > 0:
                df_bw_idx["閾値"] = float(_cap_threshold)
            st.line_chart(df_bw_idx, height=220)
            _peak_mb  = df_bw["MB"].max()
            _avg_mb   = df_bw["MB"].mean()
            _over_cnt = int((df_bw["MB"] > _cap_threshold).sum()) if _cap_threshold > 0 else 0
            _bw_c1, _bw_c2, _bw_c3 = st.columns(3)
            _bw_c1.metric("ピーク (MB/h)",   f"{_peak_mb:.1f}")
            _bw_c2.metric("平均 (MB/h)",     f"{_avg_mb:.1f}")
            _bw_c3.metric("閾値超過 (時間数)", f"{_over_cnt}")
        else:
            st.info("帯域トレンドデータがありません（NetFlowデータが蓄積されると表示されます）。")

with tab_pcap:
    import pcap_analyzer
    import restconf_client as _rc

    st.markdown("## 📦 パケット解析（Wireshark pcap/pcapng）")

    # ── 解析済みpcapがあれば最上部で明示（デモ/SCP/EPC/アップロードいずれの経路でも） ──
    _loaded_key = st.session_state.get("_pcap_key", "")
    if st.session_state.get("_pcap_res") and _loaded_key:
        if _loaded_key.startswith("demo_"):
            _src_label = f"🎮 デモシミュレーター（{_loaded_key[5:]} シナリオ）で生成したpcap"
        elif _loaded_key.startswith("_dl_"):
            _src_label = "📡 SCPでダウンロードしたpcap"
        elif _loaded_key.startswith("epc_"):
            _src_label = "📡 EPC（機器キャプチャ）でダウンロードしたpcap"
        else:
            _src_label = "📁 アップロードしたpcap"
        _lc1, _lc2 = st.columns([4, 1])
        _lc1.success(f"✅ {_src_label} を解析済みです。**このページ下部**に結果を表示しています"
                     "（ダウンロード不要でそのまま解析されています）。")
        if _lc2.button("🗑️ クリア", key="pcap_clear_loaded", use_container_width=True):
            for _k in ("_pcap_key", "_pcap_res", "_pcap_convs", "_pcap_talkers", "_pcap_streams"):
                st.session_state.pop(_k, None)
            st.rerun()

    # ══════════════════════════════════════════
    # デバイス登録 & SSH/SCP ダウンロード
    # ══════════════════════════════════════════
    st.markdown("### 📡 デバイスから直接取得（SSH/SCP）")
    st.caption("Catalyst など IOS-XE の flash にある pcap を SCP でダウンロードして自動解析します。（`ip scp server enable` が必要）")

    with st.expander("⚙️ デバイス登録・管理", expanded=False):
        _saved_devs = _rc.get_pcap_devices()
        if _saved_devs:
            st.markdown("**登録済みデバイス**")
            _dev_df = pd.DataFrame(_saved_devs)[["name", "ip", "username", "ssh_port"]]
            _dev_df.columns = ["名前", "IPアドレス", "ユーザー名", "SSHポート"]
            st.dataframe(_dev_df, use_container_width=True, hide_index=True)
            _del_opts = {f"{d['name']} ({d['ip']})": d["id"] for d in _saved_devs}
            _del_sel  = st.selectbox("削除するデバイス", ["（選択）"] + list(_del_opts.keys()),
                                     key="pcap_del_dev")
            if st.button("🗑 削除", key="pcap_del_btn") and _del_sel != "（選択）":
                _rc.remove_pcap_device(_del_opts[_del_sel])
                st.success("削除しました")
                st.rerun()
            st.markdown("---")

        st.markdown("**新規デバイス登録**")
        with st.form("pcap_dev_reg_form"):
            _rd1, _rd2 = st.columns(2)
            with _rd1:
                _reg_name = st.text_input("デバイス名", placeholder="core-sw-01")
                _reg_ip   = st.text_input("IPアドレス", placeholder="192.168.1.1")
                _reg_port = st.number_input("SSHポート", min_value=1, max_value=65535, value=22)
            with _rd2:
                _reg_user = st.text_input("ユーザー名")
                _reg_pass = st.text_input("パスワード", type="password")
            if st.form_submit_button("💾 登録"):
                if _reg_name and _reg_ip and _reg_user and _reg_pass:
                    _rc.add_pcap_device(_reg_name, _reg_ip, _reg_user, _reg_pass, int(_reg_port))
                    st.success(f"✅ {_reg_name} ({_reg_ip}) を登録しました")
                    st.rerun()
                else:
                    st.error("全項目を入力してください")

    # ── ダウンロード & 解析 ──────────────────
    _pcap_devs = _rc.get_pcap_devices()
    if _pcap_devs:
        _dev_labels = {f"{d['name']} ({d['ip']})": d for d in _pcap_devs}
        _sel_label  = st.selectbox("対象デバイス", list(_dev_labels.keys()), key="pcap_dev_sel")
        _sel_dev    = _dev_labels[_sel_label]

        _dl_col1, _dl_col2 = st.columns([1, 2])
        with _dl_col1:
            if st.button("🔍 flash の pcap 一覧を取得", key="pcap_list_btn"):
                with st.spinner(f"{_sel_dev['ip']} に接続中..."):
                    _found = _rc.list_flash_pcaps(
                        _sel_dev["ip"], _sel_dev["username"], _sel_dev["password"]
                    )
                if _found:
                    st.session_state[f"_flash_{_sel_dev['ip']}"] = _found
                    st.success(f"{len(_found)} 件を検出")
                else:
                    st.warning("pcap ファイルが見つかりません")

        with _dl_col2:
            _flash_list = st.session_state.get(f"_flash_{_sel_dev['ip']}", [])
            if _flash_list:
                _dl_file = st.selectbox("ダウンロードするファイル", _flash_list, key="pcap_file_sel")
            else:
                _dl_file = st.text_input("flash パス（例: flash:/epc_cap.pcap）",
                                         key="pcap_file_manual")

        if st.button("⬇ ダウンロード＆解析", key="pcap_dl_btn", type="primary",
                     disabled=not _dl_file):
            with st.spinner(f"SCP ダウンロード中: {_sel_dev['ip']}:{_dl_file}"):
                _dl_bytes, _dl_err = _rc.download_pcap_via_scp(
                    _sel_dev["ip"], _sel_dev["username"],
                    _sel_dev["password"], _dl_file
                )
            if _dl_bytes:
                st.success(f"✅ ダウンロード完了 ({len(_dl_bytes):,} bytes)")
                with st.spinner("解析中..."):
                    _dl_res   = pcap_analyzer.analyze_pcap(_dl_bytes)
                    _dl_convs = pcap_analyzer.get_conversations(_dl_bytes)
                    _dl_tlk   = pcap_analyzer.get_top_talkers(_dl_bytes)
                    _dl_streams = pcap_analyzer.get_tcp_streams(_dl_bytes)
                st.session_state["_pcap_key"]     = f"_dl_{_sel_dev['ip']}_{_dl_file}"
                st.session_state["_pcap_res"]     = _dl_res
                st.session_state["_pcap_convs"]   = _dl_convs
                st.session_state["_pcap_talkers"] = _dl_tlk
                st.session_state["_pcap_streams"] = _dl_streams
                st.session_state["_pcap_bytes"]   = _dl_bytes
                st.download_button(
                    "💾 ローカルに保存", data=_dl_bytes,
                    file_name=_dl_file.split("/")[-1],
                    mime="application/octet-stream",
                )
                st.rerun()
            else:
                st.error(f"ダウンロード失敗: {_dl_err}")
    else:
        st.info("まずデバイスを登録してください（上の「デバイス登録・管理」を開く）")

    st.markdown("---")
    st.markdown("### 📁 ファイルアップロード")
    st.caption("Wireshark でキャプチャしたファイルを直接アップロードします。")
    if _is_cloud_mode() and not _is_admin_authenticated():
        st.caption(f"🔒 ゲスト利用時のアップロード上限: {MAX_UPLOAD_MB_GUEST}MB（管理者ログインで解除）")

    uploaded_pcap = st.file_uploader(
        "pcap / pcapng ファイルをアップロード（zip / gz 圧縮もそのままでOK）",
        type=["pcap", "pcapng", "cap", "zip", "gz"],
        help="Wiresharkの「名前を付けて保存」で保存したファイルのほか、zip/gzで圧縮したものも"
             "自動解凍して解析します。zip内に複数ある場合は pcap/pcapng を自動選択します。"
    )

    if uploaded_pcap is not None and _check_upload_size_ok(uploaded_pcap, _is_cloud_mode()):
        raw_bytes = uploaded_pcap.read()
        _pcap_upname = uploaded_pcap.name

        # zip/gz で圧縮されていれば自動解凍してpcapを取り出す
        _pdec = pcap_analyzer.decompress_upload(raw_bytes, uploaded_pcap.name, prefer="pcap")
        if _pdec["extracted"]:
            raw_bytes = _pdec["data"]
            _pcap_upname = _pdec["name"]
            st.info(f"🗜️ 圧縮ファイルを自動解凍しました（{_pdec['source']}）→ "
                    f"`{_pdec['name']}`（{len(raw_bytes):,} bytes）"
                    + (f" ／ 同梱: {', '.join(_pdec['candidates'][:8])}"
                       if len(_pdec.get('candidates', [])) > 1 else ""))

        # キャッシュ: 同じファイルなら再解析しない
        _pcap_key = f"{_pcap_upname}_{len(raw_bytes)}"
        if st.session_state.get("_pcap_key") != _pcap_key:
            with st.spinner("パケットを解析中..."):
                res      = pcap_analyzer.analyze_pcap(raw_bytes)
                convs    = pcap_analyzer.get_conversations(raw_bytes)
                talkers  = pcap_analyzer.get_top_talkers(raw_bytes)
                streams  = pcap_analyzer.get_tcp_streams(raw_bytes)
            st.session_state["_pcap_key"]     = _pcap_key
            st.session_state["_pcap_res"]     = res
            st.session_state["_pcap_convs"]   = convs
            st.session_state["_pcap_talkers"] = talkers
            st.session_state["_pcap_streams"] = streams
            st.session_state["_pcap_bytes"]   = raw_bytes
        else:
            res     = st.session_state["_pcap_res"]
            convs   = st.session_state["_pcap_convs"]
            talkers = st.session_state["_pcap_talkers"]
            streams = st.session_state.get("_pcap_streams", [])
    elif st.session_state.get("_pcap_res"):
        # SCP/EPCなど、アップロード以外の経路で取得済みのpcap結果があればそちらを使う
        # （取得経路によらず、同じ解析結果表示・同じAI診断ボタンを使うための統一処理）
        res     = st.session_state["_pcap_res"]
        convs   = st.session_state.get("_pcap_convs", [])
        talkers = st.session_state.get("_pcap_talkers", [])
        streams = st.session_state.get("_pcap_streams", [])
    else:
        res = None
        streams = []

    if res is not None:
        if res["error"]:
            st.error(f"解析エラー: {res['error']}")
        else:
            # ── 概要 ───────────────────────────────────
            st.markdown("---")
            st.markdown("### 📊 キャプチャ概要")
            ov_cols = st.columns(4)
            with ov_cols[0]:
                st.metric("総パケット数", f"{res['total_packets']:,}")
            with ov_cols[1]:
                st.metric("TCP問題フロー", len(res["tcp_issues"]),
                          delta="⚠️ 要確認" if res["tcp_issues"] else None)
            with ov_cols[2]:
                _dns_err = res["dns_summary"]["nxdomain"] + res["dns_summary"]["servfail"] + res["dns_summary"]["refused"]
                st.metric("DNSエラー", _dns_err,
                          delta="⚠️ 要確認" if _dns_err else None)
            with ov_cols[3]:
                st.metric("ICMP redirect", len(res["icmp_redirects"]),
                          delta="⚠️ 要確認" if res["icmp_redirects"] else None)
            ov_cols2 = st.columns(4)
            with ov_cols2[0]:
                st.metric("会話フロー数", len(convs))
            with ov_cols2[1]:
                st.metric("ARP異常", len(res["arp_anomalies"]),
                          delta="⚠️ 要確認" if res["arp_anomalies"] else None)
            with ov_cols2[2]:
                st.metric("pcap内syslog", len(res.get("syslog_packets", [])),
                          delta="📋 解析済" if res.get("syslog_packets") else None)
            with ov_cols2[3]:
                st.metric("RIPパケット", len(res["rip_packets"]))
            ov_cols3 = st.columns(4)
            with ov_cols3[0]:
                _http_err_cnt = len(res.get("http_errors", []))
                st.metric("HTTPエラー(4xx/5xx)", _http_err_cnt,
                          delta="⚠️ 要確認" if _http_err_cnt else None)
            with ov_cols3[1]:
                st.metric("TLS Fatal Alert", res.get("tls_summary", {}).get("fatal_alerts", 0),
                          delta="⚠️ 要確認" if res.get("tls_summary", {}).get("fatal_alerts") else None)
            with ov_cols3[2]:
                st.metric("IPフラグメント", len(res.get("ip_fragments", [])),
                          delta="⚠️ MTU問題?" if res.get("ip_fragments") else None)
            with ov_cols3[3]:
                st.metric("DHCP問題", len(res.get("dhcp_issues", [])),
                          delta="⚠️ 要確認" if res.get("dhcp_issues") else None)
            st.caption(f"📅 キャプチャ範囲: {res['capture_start']} 〜 {res['capture_end']}")

            # ── 🛡️ IPS検査（シグネチャ型 + アノマリ型 + 振る舞い型） ──
            _ips_alerts = res.get("ips_alerts", [])
            _behavior_items = (res.get("worm_propagation", []) + res.get("beaconing", [])
                               + res.get("suspicious_destinations", []) + res.get("data_exfil", []))
            _anomaly_items = (res.get("scan_patterns", []) + res.get("dns_tunneling", [])
                              + res.get("icmp_exfil", []))
            _host_risk = res.get("host_risk", [])
            _ti_hits = res.get("threat_intel_hits", [])
            _geo_alerts = res.get("geo_alerts", [])
            if (_ips_alerts or _anomaly_items or _behavior_items or _host_risk
                    or _ti_hits or _geo_alerts):
                st.markdown("---")
                st.markdown("### 🛡️ IPS検査（不正侵入・マルウェアの兆候）")
                st.caption("Catalyst等でミラー/インライン取得したパケットを、IPS/IDS的に検査します。"
                           "**シグネチャ型**（既知攻撃パターン照合）・**アノマリ型**（統計的異常）・"
                           "**振る舞い型**（ワーム拡散/C2/持ち出し等の挙動）・**脅威インテリジェンス**"
                           "（既知C2/マルウェアIP・ドメイン照合）の各面で検査し、"
                           "最後にホスト別のリスクスコアに束ねます。簡易ヒューリスティックのため参考情報として扱ってください。")

                # ── 🌐 脅威インテリジェンス一致（最優先・確度高） ──
                if _ti_hits:
                    st.markdown("**🌐 脅威インテリジェンス一致（既知の悪性IP/ドメイン）**")
                    for _th in _ti_hits:
                        st.error(f"🔴 {_th['detail']}")

                # ── 🌏 地理的検知（中国/北朝鮮/香港/マカオの外部IP） ──
                if _geo_alerts:
                    _geo_sum = res.get("geo_summary", {})
                    _cty = "・".join(f"{k}{v}件" for k, v in _geo_sum.get("countries", {}).items())
                    st.markdown(f"**🌏 監視対象国からの通信を検知（{_cty}）**")
                    st.caption("中国(CN)・北朝鮮(KP)・香港(HK)・マカオ(MO)に割り当てられた"
                               "グローバルIPアドレスとの通信です（RIR由来の国別割当レンジと照合）。"
                               "業務上の想定有無を確認してください。")
                    _geo_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}
                    _block_in, _block_out = set(), set()   # 送信元遮断 / 宛先遮断
                    for _ga in _geo_alerts:
                        _btag = ""
                        if _ga["block_suggested"]:
                            _bdir = "送信元" if _ga["inbound"] else "宛先"
                            _btag = f"　🚫 **{_bdir}ブロック推奨**"
                            if _ga["inbound"]:
                                _block_in.add(_ga["ip"])
                            else:
                                _block_out.add(_ga["ip"])
                        st.markdown(f"- {_geo_icon.get(_ga['severity'],'⚪')} "
                                    f"**{_ga['country_label']}({_ga['country'].upper()})** "
                                    f"`{_ga['ip']}` — {_ga['direction']}"
                                    f"（パケット{_ga['packets']} / 相手: {', '.join(_ga['peers'][:5])}）"
                                    + _btag)
                    if _block_in or _block_out:
                        st.warning("🚫 **ブロック候補（中国/香港/マカオとの通信）**："
                                   "業務上不要であれば境界FW/ACLでの遮断を推奨します。"
                                   "アクセス元(inbound)は送信元遮断、通信先(outbound)は宛先遮断します。")
                        _acl_lines, _ipt_lines, _all_ips = [], [], []
                        for _ip in sorted(_block_in):
                            _acl_lines.append(f"deny ip host {_ip} any")
                            _ipt_lines.append(f"iptables -A INPUT -s {_ip} -j DROP")
                            _all_ips.append(_ip)
                        for _ip in sorted(_block_out):
                            _acl_lines.append(f"deny ip any host {_ip}")
                            _ipt_lines.append(f"iptables -A OUTPUT -d {_ip} -j DROP")
                            _all_ips.append(_ip)
                        _blocktext = "\n".join(sorted(set(_all_ips)))
                        st.code(_blocktext, language="text")
                        with st.expander("🧱 ブロック設定例（ACL / iptables）"):
                            st.caption("Cisco ACL 形式（inbound=送信元遮断 / outbound=宛先遮断）：")
                            st.code("\n".join(_acl_lines), language="text")
                            st.caption("iptables 形式：")
                            st.code("\n".join(_ipt_lines), language="text")
                        st.download_button(
                            "📥 ブロック候補IP一覧をダウンロード", data=_blocktext,
                            file_name="geo_block_candidates.txt", mime="text/plain",
                            key="dl_geo_block")

                # ── ⚠️ ホスト別リスクスコア（相関検知の要約・最上部） ──
                if _host_risk:
                    st.markdown("**⚠️ ホスト別リスクスコア（複数の怪しい挙動を束ねた危険度）**")
                    _lv_icon = {"重大": "🔴", "高": "🟠", "中": "🟡", "低": "🟢"}
                    for _hr in _host_risk[:10]:
                        if _hr["risk_score"] < 20:
                            continue
                        st.markdown(f"{_lv_icon.get(_hr['risk_level'],'⚪')} **{_hr['host']}** — "
                                    f"リスク {_hr['risk_score']}/100（{_hr['risk_level']}）: "
                                    + " + ".join(_hr["factors"]))

                # シグネチャ型（CVE/推奨対応つき・重大度フィルタあり）
                if _ips_alerts:
                    _crit = sum(1 for a in _ips_alerts if a["severity"] == "critical")
                    _high = sum(1 for a in _ips_alerts if a["severity"] == "high")
                    st.markdown(f"**🔴 シグネチャ型検知: {len(_ips_alerts)}件**（重大 {_crit} / 高 {_high}）")
                    # 重大度で絞り込み（ET Open等を取り込むと件数が増えるため）
                    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                    _sev_filter = st.selectbox(
                        "表示する最低重大度", ["すべて", "medium以上", "high以上", "criticalのみ"],
                        key="ips_sev_filter")
                    _sev_max = {"すべて": 3, "medium以上": 2, "high以上": 1, "criticalのみ": 0}[_sev_filter]
                    _ips_view = [a for a in _ips_alerts
                                 if _sev_order.get(a["severity"], 9) <= _sev_max]
                    if not _ips_view:
                        st.caption("この重大度に該当する検知はありません。")
                    _sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
                    if _ips_view:
                        df_ips = pd.DataFrame(_ips_view)
                        df_ips["重大度"] = df_ips["severity"].map(lambda s: f"{_sev_icon.get(s,'⚪')} {s}")
                        _ips_cols = ["重大度", "category", "cve", "protocol", "src", "dst", "dst_port", "count"]
                        df_ips_show = df_ips[_ips_cols].rename(columns={
                            "category": "攻撃カテゴリ", "cve": "CVE", "protocol": "プロトコル",
                            "src": "送信元IP", "dst": "宛先IP", "dst_port": "宛先Port", "count": "回数"})
                        _show_table_top_n(df_ips_show, "ips_signature_alerts.csv", "dl_ips_csv")
                    with st.expander("検知の詳細・推奨対応を見る"):
                        for _a in _ips_view[:20]:
                            st.markdown(f"**{_sev_icon.get(_a['severity'],'⚪')} {_a['category']}** "
                                        f"({_a['src']}→{_a['dst']}:{_a['dst_port']})"
                                        + (f" / {_a['cve']}" if _a.get('cve') else ""))
                            if _a.get("description"):
                                st.caption(f"内容: {_a['description']}")
                            if _a.get("recommended_action"):
                                st.caption(f"推奨対応: {_a['recommended_action']}")
                            if _a.get("reference"):
                                st.caption(f"参考: {_a['reference']}")

                # 振る舞い型
                if _behavior_items:
                    st.markdown("**🦠 振る舞い型検知（ワーム拡散・C2・持ち出し等の挙動）**")
                    for _wp in res.get("worm_propagation", []):
                        st.markdown(f"- 🔴 **ワーム横展開**: {_wp['detail']}")
                    for _bc in res.get("beaconing", []):
                        st.markdown(f"- 🔴 **C2ビーコニング**: {_bc['detail']}")
                    for _de in res.get("data_exfil", []):
                        st.markdown(f"- 🔴 **大容量持ち出し**: {_de['detail']}")
                    for _sd in res.get("suspicious_destinations", []):
                        _ic = "🔴" if _sd["severity"] == "high" else "🟡"
                        st.markdown(f"- {_ic} **怪しい外部アクセス**: {_sd['detail']}")

                # アノマリ型（統計検出）
                if _anomaly_items:
                    st.markdown("**🟠 アノマリ型検知（統計的異常）**")
                    for _sp in res.get("scan_patterns", []):
                        _t = "ポートスキャン" if _sp["type"] == "port_scan" else "DDoS(SYNフラッド)"
                        st.markdown(f"- 🔴 **{_t}**: {_sp['detail']}")
                    for _dt in res.get("dns_tunneling", []):
                        st.markdown(f"- 🔴 **DNSトンネリング**: {_dt['detail']}")
                    for _ie in res.get("icmp_exfil", []):
                        st.markdown(f"- 🔴 **ICMPエクスフィル**: {_ie['detail']}")

            # ── 🏭 産業用プロトコル（Modbus/DNP3 の制御系通信） ──
            _ind_alerts = res.get("industrial_alerts", [])
            _ind_sum = res.get("industrial_summary", {})
            if _ind_alerts or _ind_sum:
                st.markdown("---")
                st.markdown("### 🏭 産業用プロトコル（OT/制御系）")
                if _ind_sum:
                    st.caption(f"Modbus 通信ペア {_ind_sum.get('modbus_pairs',0)} / "
                               f"読取 {_ind_sum.get('modbus_read',0)}回 / "
                               f"書込 {_ind_sum.get('modbus_write',0)}回。"
                               "制御系（PLC等）への**書込コマンド**は物理影響を伴うため、"
                               "正当な操作か・権限があるかを必ず確認してください。")
                for _ia in _ind_alerts:
                    st.markdown(f"- 🟠 **{_ia['protocol']} 書込**: {_ia['detail']}")

            # ── 🌐 QUIC / HTTP3（UDPベースの新しいWeb通信） ──
            _quic = res.get("quic_sessions", [])
            if _quic:
                st.markdown("---")
                st.markdown("### 🌐 QUIC / HTTP3 セッション")
                st.caption("UDP/443等で動作するQUIC（HTTP/3）通信を検出しました。"
                           "暗号化されペイロードは追えませんが、接続先・バージョン・"
                           "Initialパケットの有無から通信の存在を把握できます。")
                _qdf = pd.DataFrame([{
                    "送信元": _q["src"], "宛先": _q["dst"], "パケット数": _q["packets"],
                    "バージョン": _q["versions"],
                    "Initial": "○" if _q["has_initial"] else "",
                } for _q in _quic])
                _show_table_top_n(_qdf, "quic_sessions.csv", "dl_quic_csv")

            # ── 📡 無線 802.11（Wi-Fi）解析 ──
            _wl = {"is_wireless": False}
            _wl_bytes = st.session_state.get("_pcap_bytes")
            try:
                if _wl_bytes and hasattr(pcap_analyzer, "analyze_wireless"):
                    _wl = pcap_analyzer.analyze_wireless(_wl_bytes)
            except Exception as _wl_err:
                _wl = {"is_wireless": False}
                print(f"[app] 無線解析をスキップ: {_wl_err}")
            if _wl.get("is_wireless"):
                st.markdown("---")
                st.markdown("### 📡 無線LAN（802.11 / Wi-Fi）解析")
                st.caption("無線キャプチャ（radiotap/802.11）を検出しました。"
                           "ビーコン(SSID)・認証解除(deauth)攻撃・WPAハンドシェイク(EAPOL)を検査します。")
                _wl_sum = _wl.get("summary", {})
                st.caption(f"ビーコン {_wl_sum.get('beacons',0)} / "
                           f"SSID {_wl_sum.get('ssid_count',0)} / "
                           f"deauth {_wl_sum.get('deauth',0)} / "
                           f"EAPOL {_wl_sum.get('eapol',0)}")
                if _wl.get("ssids"):
                    st.markdown("**検出SSID（アクセスポイント）**: "
                                + ", ".join(f"`{s['ssid']}`" for s in _wl["ssids"][:20]))
                for _da in _wl.get("deauth", []):
                    st.error(f"🔴 **Deauth（認証解除）攻撃の疑い**: {_da['detail']}")
                for _ep in _wl.get("eapol", []):
                    st.info(f"🔑 {_ep['detail']}")

            # ── 📧 メール添付ファイルのウイルスチェック ──────
            # 付加機能のため、万一失敗してもページ全体を落とさないよう防御的に呼ぶ
            # （モジュールのバージョン差異・特殊なMIME等でも安全に無視する）。
            _mail_atts = []
            try:
                if hasattr(pcap_analyzer, "scan_email_attachments"):
                    _mail_atts = pcap_analyzer.scan_email_attachments(streams=streams)
            except Exception as _mail_err:
                _mail_atts = []
                print(f"[app] メール添付チェックをスキップ: {_mail_err}")
            if _mail_atts:
                st.markdown("---")
                st.markdown("### 📧 メール添付ファイルのウイルスチェック")
                st.caption("pcap内のメール通信(SMTP/POP3/IMAP)から添付ファイルを取り出し、"
                           "「一旦開いて」中身を検査した結果です（実行ファイル/危険拡張子/マクロ/"
                           "EICAR/シグネチャ一致）。")
                _sev_icon2 = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
                for _mi, _att in enumerate(_mail_atts):
                    st.markdown(f"{_sev_icon2.get(_att['severity'],'⚪')} **{_att['filename']}** "
                                f"({_att['size']:,} bytes, 件名: {_att['subject'] or '(なし)'}) "
                                f"{_att['src']}→{_att['dst']}")
                    for _v in _att["verdicts"]:
                        st.markdown(f"　- {_sev_icon2.get(_v['severity'],'⚪')} [{_v['type']}] {_v['detail']}")
                    st.download_button("📥 この添付を取り出す（隔離環境で確認）", data=_att["data"],
                                       file_name=_att["filename"], mime="application/octet-stream",
                                       key=f"dl_mail_att_{_mi}")

            # ── pcap 総合 AI 診断（全ページ共通部品） ──────
            _render_pcap_ai_diagnosis(res, key_prefix="main")

            # ── ICMP redirect 詳細 ─────────────────────
            st.markdown("---")
            st.markdown("### 🔀 ICMP Redirect パケット詳細")
            if res["icmp_redirects"]:
                df_red = pd.DataFrame(res["icmp_redirects"])
                df_red["ts"] = pd.to_datetime(df_red["timestamp"], format="ISO8601", errors="coerce")

                # ── 時間あたりの発生数タイムライン ──
                st.markdown("**📈 時間あたりの発生数**")
                capture_sec = (df_red["ts"].max() - df_red["ts"].min()).total_seconds()
                if capture_sec <= 120:
                    freq, freq_label = "5s", "5秒"
                elif capture_sec <= 600:
                    freq, freq_label = "1min", "1分"
                elif capture_sec <= 3600:
                    freq, freq_label = "5min", "5分"
                else:
                    freq, freq_label = "15min", "15分"

                df_timeline = (
                    df_red.set_index("ts")
                    .resample(freq)
                    .size()
                    .reset_index()
                )
                df_timeline.columns = ["時刻", f"redirect数/{freq_label}"]
                df_timeline["時刻"] = df_timeline["時刻"].dt.strftime("%H:%M:%S")
                st.line_chart(df_timeline.set_index("時刻"))
                st.caption(f"集計単位: {freq_label}　最大: {df_timeline.iloc[:,1].max()} パケット/{freq_label}")

                st.markdown("---")

                # ── 送信元ルーター別 ──
                lc1, lc2 = st.columns(2)
                with lc1:
                    st.markdown("**🖥️ Redirectを送ったルーター別 発生数**")
                    router_count = df_red["router_ip"].value_counts().reset_index()
                    router_count.columns = ["ルーターIP", "件数"]
                    st.bar_chart(router_count.set_index("ルーターIP"))

                with lc2:
                    st.markdown("**📨 Redirectを受けたホスト別 発生数**")
                    target_count = df_red["target_ip"].value_counts().reset_index()
                    target_count.columns = ["対象ホストIP", "件数"]
                    st.bar_chart(target_count.set_index("対象ホストIP"))

                # ── redirect先（元パケット宛先・GW）──
                st.markdown("---")
                dc1, dc2 = st.columns(2)
                with dc1:
                    st.markdown("**🎯 redirect元パケット宛先（orig_dst）別**")
                    dest_count = df_red["orig_dst"].value_counts().reset_index()
                    dest_count.columns = ["元パケット宛先IP", "件数"]
                    st.dataframe(dest_count, use_container_width=True, hide_index=True)
                with dc2:
                    st.markdown("**🔀 正しいゲートウェイ（gateway）別**")
                    gw_count = df_red["gateway"].value_counts().reset_index()
                    gw_count.columns = ["ゲートウェイIP", "件数"]
                    st.dataframe(gw_count, use_container_width=True, hide_index=True)

                st.markdown("---")

                # 統計サマリ
                st.markdown("**通信ペア別 redirect 発生回数**")
                pair_count = (
                    df_red.groupby(["router_ip", "target_ip", "gateway", "orig_dst"])
                    .size().reset_index(name="回数")
                    .sort_values("回数", ascending=False)
                )
                pair_count.columns = ["Redirectを送ったルーター", "Redirectを受けたホスト",
                                       "本来のゲートウェイ", "元パケットの宛先", "回数"]
                _show_table_top_n(pair_count, "icmp_redirect_pairs.csv", "dl_icmp_redirect_pairs_csv")

                # syslog との統合表示
                st.markdown("**syslog検出との照合**")
                all_syslog_redirect = [
                    l for l in db.get_logs(limit=500)
                    if "ICMP Redirect" in (l.get("tags") or "")
                ]
                snmp_latest = snmp_poller.get_icmp_redirect_latest()

                col_p, col_s, col_n = st.columns(3)
                with col_p:
                    st.markdown(f"""
<div class="metric-card">
  <div style="color:#6b7280;font-size:12px;">pcapng検出</div>
  <div style="font-size:28px;font-weight:bold;color:#dc2626;">{len(res['icmp_redirects'])}</div>
  <div style="font-size:11px;color:#6b7280;">パケット</div>
</div>""", unsafe_allow_html=True)
                with col_s:
                    st.markdown(f"""
<div class="metric-card">
  <div style="color:#6b7280;font-size:12px;">syslog検出</div>
  <div style="font-size:28px;font-weight:bold;color:#b45309;">{len(all_syslog_redirect)}</div>
  <div style="font-size:11px;color:#6b7280;">ログエントリ</div>
</div>""", unsafe_allow_html=True)
                with col_n:
                    total_snmp = sum(int(r.get("value", 0)) for r in snmp_latest
                                     if "In" in r.get("oid_name", ""))
                    st.markdown(f"""
<div class="metric-card">
  <div style="color:#6b7280;font-size:12px;">SNMP累積カウンタ</div>
  <div style="font-size:28px;font-weight:bold;color:#7c3aed;">{total_snmp:,}</div>
  <div style="font-size:11px;color:#6b7280;">icmpInRedirects</div>
</div>""", unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)

                # 全パケット一覧
                with st.expander(f"📋 全 {len(res['icmp_redirects'])} パケット一覧"):
                    df_show = df_red[["timestamp","router_ip","target_ip",
                                       "gateway","orig_src","orig_dst","orig_proto","code_desc"]]
                    df_show.columns = ["時刻","ルーターIP","対象ホスト",
                                        "正しいGW","元送信元","元宛先","プロトコル","種別"]
                    st.dataframe(df_show, use_container_width=True, hide_index=True)

                # AI統合診断
                st.markdown("---")
                st.markdown("### 🤖 pcap + syslog + SNMP 統合AI診断")
                st.caption("3つのデータソースを統合してICMP redirect の根本原因をAIが推定します。")

                llm_ok = analyzer.check_claude_available() or analyzer.check_gemini_available() or analyzer.check_groq_available() or analyzer.check_ollama_available()
                if llm_ok:
                    def _build_integrated_icmp_context():
                        router_ips = df_red["router_ip"].unique().tolist()
                        sel_router = router_ips[0] if router_ips else ""

                        # routing summary（RESTCONF > SNMP > コンフィグ の優先順）
                        routing_summary = ""
                        _rc_routes_router = st.session_state.get(f"rc_routes_{sel_router}")
                        snmp_routes = snmp_poller.get_routing_table(sel_router)
                        if _rc_routes_router:
                            routing_summary = "\n".join(
                                f"{r['dest']}/{r['mask']} via {r['nexthop']} ({r['proto']})"
                                for r in _rc_routes_router
                            )
                        elif snmp_routes:
                            routing_summary = "\n".join(
                                f"{r['dest']}/{r['mask']} via {r['nexthop']} ({r['proto']})"
                                for r in snmp_routes
                            )
                        else:
                            cfg = db.get_device_config(sel_router)
                            if cfg:
                                routing_summary = cfg.get("routing_summary","") or ""

                        # pcap 情報を補足コンテキストとして追加
                        pcap_ctx = f"""
【pcapng解析結果】
- キャプチャ期間: {res['capture_start']} 〜 {res['capture_end']}
- 総パケット数: {res['total_packets']}
- ICMP redirect検出: {len(res['icmp_redirects'])}パケット
- 主なredirect通信ペア:
"""
                        for _, row in pair_count.head(5).iterrows():
                            pcap_ctx += (f"  {row.iloc[0]} → {row.iloc[1]} "
                                         f"(GW:{row.iloc[2]}, 宛先:{row.iloc[3]}) "
                                         f"{row.iloc[4]}回\n")

                        dev_logs = [l for l in all_syslog_redirect
                                    if l.get("source_ip") == sel_router]
                        return sel_router, routing_summary + "\n" + pcap_ctx, dev_logs

                    _int_c1, _int_c2 = st.columns(2)
                    if _int_c1.button("🤖 統合AI診断を実行", key="pcap_ai_diag",
                                       type="primary", use_container_width=True):
                        sel_router, full_routing_ctx, dev_logs = _build_integrated_icmp_context()
                        with st.spinner("AIが pcap + syslog + SNMP を統合分析中..."):
                            st.session_state["_icmp_diag_integrated"] = analyzer.diagnose_icmp_redirect(
                                ip=sel_router,
                                snmp_data=snmp_latest,
                                redirect_logs=dev_logs,
                                routing_summary=full_routing_ctx,
                                mode=st.session_state.get("llm_mode", "auto")
                            )
                    if analyzer.check_claude_available():
                        if _int_c2.button("🕵️ エージェント診断（ルート検索を深掘り）", key="pcap_icmp_agentic",
                                           use_container_width=True):
                            sel_router, full_routing_ctx, dev_logs = _build_integrated_icmp_context()
                            with st.spinner("Claudeがルーティングテーブルを検索しながら分析中..."):
                                st.session_state["_icmp_diag_integrated"] = analyzer.diagnose_icmp_redirect_agentic(
                                    ip=sel_router, snmp_data=snmp_latest,
                                    redirect_logs=dev_logs, routing_summary=full_routing_ctx,
                                )
                    _render_icmp_redirect_diagnosis_result(st.session_state.get("_icmp_diag_integrated"))
                else:
                    st.caption("AI診断にはClaude APIまたはOllamaの設定が必要です（サイドバー参照）")

            else:
                st.success("✅ ICMP redirectパケットは検出されませんでした")

            # ── pcap内 syslog ──────────────────────────
            syslog_pkts = res.get("syslog_packets", [])
            if syslog_pkts:
                st.markdown("---")
                st.markdown(f"### 📋 pcap内 syslogメッセージ（{len(syslog_pkts)}件）")
                st.caption("キャプチャ内のUDP 514/5140パケットからsyslogを抽出し、既存パーサーで解析しました。")

                sev_color_map = {
                    "EMERGENCY": "#dc2626", "ALERT": "#dc2626", "CRITICAL": "#dc2626",
                    "ERROR": "#ea580c", "WARNING": "#b45309",
                    "NOTICE": "#2563eb", "INFO": "#16a34a", "DEBUG": "#64748b"
                }

                # 重要度サマリ
                from collections import Counter
                sev_counts = Counter(
                    p.get("parsed", {}).get("severity", "UNKNOWN")
                    for p in syslog_pkts
                )
                sc_cols = st.columns(len(sev_counts) or 1)
                for idx, (sev, cnt) in enumerate(sorted(sev_counts.items())):
                    color = sev_color_map.get(sev, "#64748b")
                    with sc_cols[idx % len(sc_cols)]:
                        st.markdown(f"""
<div class="metric-card">
  <div style="color:{color};font-size:12px;font-weight:bold;">{sev}</div>
  <div style="font-size:24px;font-weight:bold;color:{color};">{cnt}</div>
</div>""", unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)

                # ログ一覧
                for pkt in syslog_pkts:
                    parsed = pkt.get("parsed") or {}
                    sev = parsed.get("severity", "INFO")
                    sev_c = sev_color_map.get(sev, "#64748b")
                    vendor  = parsed.get("vendor", "Generic")
                    host    = parsed.get("hostname", pkt["src_ip"])
                    process = parsed.get("process", "")
                    message = parsed.get("message", pkt["raw"])
                    tags    = parsed.get("tags", [])
                    st.markdown(f"""
<div class="log-card" style="border-left-color:{sev_c}">
  <div style="display:flex;justify-content:space-between;align-items:center;">
    <span style="color:{sev_c};font-weight:bold;">◉ {sev}</span>
    <span style="color:#6b7280;font-size:11px;">{pkt['timestamp']} | {pkt['src_ip']}:{pkt['port']}</span>
  </div>
  <div style="color:#1f2937;margin:4px 0;">
    <span style="color:#0891b2;">[{vendor}]</span>
    <span style="color:#92400e;"> {host}</span>
    <span style="color:#9333ea;"> {process}</span>
  </div>
  <div style="color:#1f2937;margin:4px 0;word-break:break-all;">{message[:300]}</div>
  <div>{"".join(f'<span class="tag-chip">{t}</span>' for t in tags)}</div>
</div>
""", unsafe_allow_html=True)

            # ── RIP パケット ───────────────────────────
            if res["rip_packets"]:
                st.markdown("---")
                st.markdown("### 🔄 RIPパケット")
                df_rip = pd.DataFrame(res["rip_packets"])
                df_rip.columns = ["時刻","送信元","宛先","バージョン","コマンド","サイズ(bytes)"]
                st.dataframe(df_rip, use_container_width=True, hide_index=True)
                rip_peers = df_rip["送信元"].unique()
                st.caption(f"RIPネイバー候補: {', '.join(rip_peers)}")

            # ── ARP 異常 ───────────────────────────────
            if res["arp_anomalies"]:
                st.markdown("---")
                st.markdown("### ⚠️ ARP 異常検出")
                df_arp = pd.DataFrame(res["arp_anomalies"])
                df_arp.columns = ["時刻","IPアドレス","旧MACアドレス","新MACアドレス","説明"]
                st.dataframe(df_arp, use_container_width=True, hide_index=True)

            # ── TCP 問題 ───────────────────────────────
            if res["tcp_issues"]:
                st.markdown("---")
                st.markdown("### 🔌 TCP 問題検出")
                _rst_n    = sum(1 for x in res["tcp_issues"] if x.get("type") == "RST多発")
                _retrans_n = sum(1 for x in res["tcp_issues"] if x.get("type") == "再送多発")
                _syn_n    = sum(1 for x in res["tcp_issues"] if x.get("type") == "接続失敗")
                _tc1, _tc2, _tc3 = st.columns(3)
                with _tc1:
                    st.metric("RST多発フロー", _rst_n,
                              delta="⚠️ 接続拒否" if _rst_n else None)
                with _tc2:
                    st.metric("再送多発フロー", _retrans_n,
                              delta="⚠️ 品質低下" if _retrans_n else None)
                with _tc3:
                    st.metric("接続失敗(SYN未応答)", _syn_n,
                              delta="⚠️ サービス停止?" if _syn_n else None)
                # ポートスキャン/DDoS(SYNフラッド)の統計的兆候（LLM診断を待たずに即座に表示）
                for _scan in res.get("scan_patterns", []):
                    if _scan["type"] == "port_scan":
                        st.error(f"🔴 **ポートスキャンを検出**: {_scan['detail']}")
                    elif _scan["type"] == "ddos_synflood":
                        st.error(f"🔴 **DDoS(分散SYNフラッド)を検出**: {_scan['detail']}")
                df_tcp = pd.DataFrame(res["tcp_issues"])
                df_tcp_show = df_tcp[["type", "src", "dst", "src_port", "dst_port", "count", "description"]]
                df_tcp_show.columns = ["種別", "送信元IP", "宛先IP", "送信元Port", "宛先Port", "回数", "説明"]
                df_tcp_show = df_tcp_show.sort_values("回数", ascending=False)
                _show_table_top_n(df_tcp_show, "tcp_issues.csv", "dl_tcp_issues_csv")

            # ── TCP 再送詳細 ─────────────────────────────
            if res.get("tcp_retransmissions"):
                st.markdown("---")
                st.markdown("### 🔁 TCP 再送詳細")
                st.caption("同一シーケンス番号＋サイズのパケットが複数回出現したフロー（輻輳・ロス・遅延の指標）")
                df_rt = pd.DataFrame(res["tcp_retransmissions"])
                df_rt = df_rt[["src", "dst", "src_port", "dst_port", "retrans_count", "description"]]
                df_rt.columns = ["送信元IP", "宛先IP", "送信元Port", "宛先Port", "再送回数", "説明"]
                df_rt = df_rt.sort_values("再送回数", ascending=False)
                _show_table_top_n(df_rt, "tcp_retransmissions.csv", "dl_tcp_retrans_csv")

            # ── SYN 未応答 ──────────────────────────────
            if res.get("tcp_syn_no_synack"):
                st.markdown("---")
                st.markdown("### 🚫 接続失敗（SYN未応答）")
                st.caption("SYNを送ったがSYN-ACKが返ってこなかった通信（サービス停止・ファイアウォール拒否の可能性）")
                df_syn = pd.DataFrame(res["tcp_syn_no_synack"])
                df_syn = df_syn[["src", "dst", "src_port", "dst_port", "syn_at", "wait_sec", "description"]]
                df_syn.columns = ["接続元IP", "接続先IP", "接続元Port", "接続先Port", "SYN送信時刻", "待機(秒)", "説明"]
                df_syn = df_syn.sort_values("待機(秒)", ascending=False)
                _show_table_top_n(df_syn, "tcp_syn_no_synack.csv", "dl_tcp_syn_csv")

            # ── TCP ゼロウィンドウ ──────────────────────
            if res.get("tcp_zero_window"):
                st.markdown("---")
                st.markdown("### 🪟 TCP ゼロウィンドウ")
                st.caption("受信バッファが枯渇して Window=0 を通知したフロー。送信側が停止しスループットが急落します。")
                df_zw = pd.DataFrame(res["tcp_zero_window"])
                df_zw = df_zw[["src", "dst", "src_port", "dst_port", "count", "description"]]
                df_zw.columns = ["Window=0送出IP", "通信相手IP", "送出Port", "相手Port", "発生回数", "説明"]
                st.dataframe(df_zw, use_container_width=True, hide_index=True)

            # ── DNS 解析 ────────────────────────────────
            _dns_sum = res.get("dns_summary", {})
            _dns_issues = res.get("dns_issues", [])
            if _dns_sum.get("queries", 0) > 0 or _dns_issues:
                st.markdown("---")
                st.markdown("### 🌐 DNS 解析")
                st.caption("UDP 53 のクエリ/レスポンスを解析。NXDOMAIN・SERVFAIL・応答遅延を検出します。")
                _dc1, _dc2, _dc3, _dc4, _dc5 = st.columns(5)
                with _dc1:
                    st.metric("DNSクエリ数",   _dns_sum.get("queries", 0))
                with _dc2:
                    st.metric("NXDOMAIN",      _dns_sum.get("nxdomain", 0),
                              delta="⚠️ 名前解決失敗" if _dns_sum.get("nxdomain") else None)
                with _dc3:
                    st.metric("SERVFAIL",      _dns_sum.get("servfail", 0),
                              delta="⚠️ サーバーエラー" if _dns_sum.get("servfail") else None)
                with _dc4:
                    st.metric("REFUSED",       _dns_sum.get("refused", 0),
                              delta="⚠️ ACL拒否?" if _dns_sum.get("refused") else None)
                with _dc5:
                    st.metric("応答遅延(>500ms)", _dns_sum.get("slow", 0),
                              delta="⚠️ 遅延" if _dns_sum.get("slow") else None)
                if _dns_issues:
                    df_dns = pd.DataFrame(_dns_issues)
                    _dns_disp_cols = ["timestamp", "client", "server", "name", "qtype", "rcode", "rtt_ms", "issue"]
                    df_dns = df_dns[_dns_disp_cols].rename(columns={
                        "timestamp": "時刻", "client": "クライアント", "server": "DNSサーバー",
                        "name": "ドメイン名", "qtype": "タイプ", "rcode": "応答コード",
                        "rtt_ms": "RTT(ms)", "issue": "問題",
                    })
                    st.dataframe(df_dns, use_container_width=True, hide_index=True)
                else:
                    st.success("✅ DNS エラー・遅延は検出されませんでした")

            # ── IPフラグメント ──────────────────────────
            _ip_frags = res.get("ip_fragments", [])
            if _ip_frags:
                st.markdown("---")
                st.markdown("### 🧩 IPフラグメント")
                st.caption("フラグメント化されたIPパケットを検出。MTU問題・Path MTU Discovery障害の可能性があります。")
                df_frag = pd.DataFrame(_ip_frags)
                df_frag = df_frag[["src", "dst", "protocol", "fragment_count", "description"]]
                df_frag.columns = ["送信元IP", "宛先IP", "プロトコル", "フラグメント数", "説明"]
                st.dataframe(df_frag, use_container_width=True, hide_index=True)

            # ── プロトコル不明（ID/sessionキーワード検出） ──────
            _unk_hints = res.get("unknown_proto_hints", [])
            if _unk_hints:
                st.markdown("---")
                st.markdown("### ❓ プロトコル不明の通信（ID/session キーワード検出）")
                st.caption("既知のプロトコルとして解析できなかった通信のうち、平文に「id」「session」を"
                           "含む語が見つかったものです。独自プロトコルや認証・セッション管理を行っている"
                           "通信の可能性があるため、手動確認をおすすめします。")
                df_unk = pd.DataFrame(_unk_hints)
                df_unk = df_unk[["protocol", "src", "dst", "src_port", "dst_port",
                                  "count", "keywords", "sample", "description"]]
                df_unk.columns = ["プロトコル", "送信元IP", "宛先IP", "送信元Port", "宛先Port",
                                   "回数", "検出語", "サンプル(先頭120バイト)", "説明"]
                df_unk = df_unk.sort_values("回数", ascending=False)
                _show_table_top_n(df_unk, "unknown_proto_hints.csv", "dl_unknown_proto_csv")

            # ── ID/session値による突き合わせ（複数フローにまたがる出現） ──
            _sid_corr = res.get("session_id_correlations", [])
            if _sid_corr:
                st.markdown("---")
                st.markdown("### 🔗 ID/session値による通信の突き合わせ")
                st.caption("同じID/session値が複数の通信フローにまたがって出現しているものです。"
                           "人手での突き合わせは現実的に困難なため機械的に検出しています。"
                           "送信元IPが複数にまたがる場合はセッションの使い回し・乗っ取りの疑いもあるため要確認です。")
                for _c in _sid_corr:
                    if _c["anomaly_multi_src"]:
                        st.error(f"🔴 **要確認**: {_c['description']}")
                df_sid = pd.DataFrame(_sid_corr)
                df_sid_show = df_sid[["id_value", "total_occurrences", "distinct_flows",
                                       "distinct_src_ips", "description"]]
                df_sid_show.columns = ["ID値", "出現回数", "フロー数", "送信元IP種類数", "説明"]
                _show_table_top_n(df_sid_show, "session_id_correlations.csv", "dl_session_id_csv")

                _sid_options = [c["id_value"] for c in _sid_corr]
                _sel_sid = st.selectbox("内訳を見るID値を選択", _sid_options, key="sel_session_id_corr")
                _sel_c = next((c for c in _sid_corr if c["id_value"] == _sel_sid), None)
                if _sel_c:
                    _sid_c1, _sid_c2 = st.columns(2)
                    with _sid_c1:
                        st.markdown("**フロー別集計**")
                        df_sid_flows = pd.DataFrame(_sel_c["flows"])
                        df_sid_flows.columns = ["プロトコル", "送信元IP", "宛先IP", "送信元Port", "宛先Port", "回数"]
                        st.dataframe(df_sid_flows, use_container_width=True, hide_index=True)
                    with _sid_c2:
                        st.markdown("**出現順（シーケンス）**")
                        st.caption(f"最大間隔: {_sel_c.get('max_gap_sec', 0)}秒")
                        df_sid_tl = pd.DataFrame(_sel_c["timeline"])
                        df_sid_tl.columns = ["時刻", "プロトコル", "送信元IP", "宛先IP",
                                              "送信元Port", "宛先Port", "前回からの間隔(秒)"]
                        st.dataframe(df_sid_tl, use_container_width=True, hide_index=True)

                    # TCPフローであれば、再構成したストリームとして中身を確認できるようにする
                    _sid_tcp_flows = [f for f in _sel_c["flows"] if f["protocol"] == "TCP"]
                    if _sid_tcp_flows and streams:
                        _sid_flow_labels = {
                            f"{f['src']}:{f['src_port']} ⇄ {f['dst']}:{f['dst_port']}": f
                            for f in _sid_tcp_flows
                        }
                        _sid_flow_pick = st.selectbox("ストリームで見るフローを選択",
                                                       list(_sid_flow_labels.keys()),
                                                       key="sid_flow_to_stream")
                        if st.button("🔗 このフローをストリームで見る", key="sid_jump_to_stream"):
                            _pf = _sid_flow_labels[_sid_flow_pick]
                            st.session_state["_stream_jump_flow"] = (_pf["src"], _pf["dst"],
                                                                      _pf["src_port"], _pf["dst_port"])
                            st.rerun()

            # ── 🚩 CTF/フォレンジック機能 ────────────────
            _ctf_hits = res.get("ctf_flag_hits", [])
            _dns_tun = res.get("dns_tunneling", [])
            _icmp_exfil = res.get("icmp_exfil", [])
            if _ctf_hits or streams or _dns_tun or _icmp_exfil:
                st.markdown("---")
                st.markdown("### 🚩 CTF / フォレンジック機能")
                st.caption("ネットワークフォレンジック系CTF問題向け。flag{...}/Base64検出、"
                           "TCPストリーム再構成（Follow TCP Stream）、埋め込みファイル抽出"
                           "（正確なファイル長でカービング／ZIP・Officeは再帰展開）、"
                           "画像ステガノ（PNG/GIF/BMPは画素LSB、JPEGはコメント/EXIF/APPn・複数EOI）、"
                           "DNS/ICMPトンネリング検出、多段エンコード自動デコードができます。"
                           "いずれもヒューリスティックのため、必ず内容を目視確認してください。")

                # DNSトンネリング検出
                if _dns_tun:
                    st.markdown("**🕳️ DNSトンネリング/エクスフィルの兆候**")
                    for _dt in _dns_tun:
                        st.error(f"🔴 {_dt['detail']}")
                    df_dt = pd.DataFrame(_dns_tun)
                    df_dt = df_dt[["domain", "query_count", "avg_subdomain_len", "max_subdomain_len",
                                    "qtypes", "client_count"]]
                    df_dt.columns = ["ベースドメイン", "クエリ数", "平均サブ長", "最大サブ長",
                                      "クエリ型", "クライアント数"]
                    st.dataframe(df_dt, use_container_width=True, hide_index=True)
                    with st.expander("サブドメインのサンプルを見る"):
                        for _dt in _dns_tun:
                            st.markdown(f"**{_dt['domain']}**")
                            for _s in _dt["sample_subdomains"]:
                                _dec = pcap_analyzer.multi_layer_decode(_s)
                                _note = f" → デコード: `{_dec['final'][:60]}`" if _dec["steps"] else ""
                                st.code(_s + _note)

                # ICMPエクスフィル検出
                if _icmp_exfil:
                    st.markdown("**🕳️ ICMPトンネリング/エクスフィルの兆候**")
                    for _ie in _icmp_exfil:
                        st.error(f"🔴 {_ie['detail']}")
                        for _f in _ie["findings"]:
                            _icon = "🚩" if _f["type"] == "flag_pattern" else "🔤"
                            st.success(f"{_icon} {_f['text']}")

                if _ctf_hits:
                    st.markdown("**🚩 検出されたflag候補・Base64候補**")
                    st.caption("Base64候補は自動デコードを試み、印字可能な結果が得られた場合のみ「デコード結果」に表示します。")
                    df_ctf = pd.DataFrame(_ctf_hits)
                    df_ctf = df_ctf[["type", "protocol", "src", "dst", "src_port", "dst_port",
                                      "timestamp", "text", "decoded"]]
                    df_ctf.columns = ["種別", "プロトコル", "送信元IP", "宛先IP",
                                       "送信元Port", "宛先Port", "時刻", "検出文字列", "デコード結果"]
                    df_ctf["種別"] = df_ctf["種別"].map(
                        {"flag_pattern": "🚩 flagパターン", "base64_candidate": "🔤 Base64候補"})
                    _show_table_top_n(df_ctf, "ctf_flag_hits.csv", "dl_ctf_flag_csv")

                if streams:
                    st.markdown("**🔗 TCPストリーム再構成（Follow TCP Stream）**")
                    _stream_labels = {
                        f"#{i} {s['src']}:{s['src_port']} ⇄ {s['dst']}:{s['dst_port']} "
                        f"({s['c2s_bytes']+s['s2c_bytes']}B, {s['packets']}pkt)": s
                        for i, s in enumerate(streams)
                    }
                    _label_list = list(_stream_labels.keys())

                    # IP/ポート番号で直接ストリームを検索（片方向のみ分かっていても検索可能）
                    _sr_c1, _sr_c2, _sr_c3 = st.columns([2, 1, 1])
                    _search_ip = _sr_c1.text_input("IPアドレスで検索(任意)", key="stream_search_ip")
                    _search_port = _sr_c2.text_input("ポート番号で検索(任意)", key="stream_search_port")
                    with _sr_c3:
                        st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
                        if st.button("🔎 検索してジャンプ", key="stream_search_btn", use_container_width=True):
                            _matched = next((
                                s for s in streams
                                if (not _search_ip or _search_ip in (s["src"], s["dst"]))
                                and (not _search_port or _search_port in (str(s["src_port"]), str(s["dst_port"])))
                            ), None)
                            if _matched:
                                st.session_state["_stream_jump_flow"] = (
                                    _matched["src"], _matched["dst"], _matched["src_port"], _matched["dst_port"])
                                st.rerun()
                            else:
                                st.warning("条件に一致するストリームが見つかりませんでした。")

                    _jump = st.session_state.pop("_stream_jump_flow", None)
                    _default_idx = 0
                    if _jump:
                        for _i, (_lbl, _s) in enumerate(_stream_labels.items()):
                            if (_s["src"], _s["dst"], _s["src_port"], _s["dst_port"]) == _jump:
                                _default_idx = _i
                                break
                    _sel_stream_lbl = st.selectbox("ストリームを選択", _label_list,
                                                    index=_default_idx, key="ctf_stream_sel")
                    _sel_stream = _stream_labels[_sel_stream_lbl]
                    _stream_full = _sel_stream["client_to_server"] + _sel_stream["server_to_client"]

                    _st_c1, _st_c2 = st.columns(2)
                    with _st_c1:
                        st.markdown(f"**→ 送信 ({_sel_stream['c2s_bytes']} bytes)**")
                        st.text_area("client_to_server",
                                     _sel_stream["client_to_server"].decode("utf-8", errors="replace"),
                                     height=200, key=f"ctf_stream_c2s_{_sel_stream_lbl}",
                                     label_visibility="collapsed")
                    with _st_c2:
                        st.markdown(f"**← 応答 ({_sel_stream['s2c_bytes']} bytes)**")
                        st.text_area("server_to_client",
                                     _sel_stream["server_to_client"].decode("utf-8", errors="replace"),
                                     height=200, key=f"ctf_stream_s2c_{_sel_stream_lbl}",
                                     label_visibility="collapsed")

                    if st.button("🚩 このストリームでflag/Base64を検索", key="ctf_stream_scan"):
                        _stream_hits = pcap_analyzer.scan_ctf_indicators(_stream_full)
                        if _stream_hits:
                            for _sh in _stream_hits:
                                _icon = "🚩" if _sh["type"] == "flag_pattern" else "🔤"
                                st.success(f"{_icon} {_sh['text']}")
                                if _sh.get("decoded"):
                                    st.markdown(f"　　↳ デコード結果: `{_sh['decoded']}`")
                        else:
                            st.info("このストリームからは検出されませんでした"
                                    "（1パケット単体では見えなくても、ストリーム再構成で見えることがあります）。")

                    _embedded = pcap_analyzer.find_embedded_files(_stream_full)
                    if _embedded:
                        st.markdown(f"**📁 埋め込みファイル候補（{len(_embedded)}件・ベストエフォート抽出）**")
                        _img_exts = {"png", "jpg", "jpeg", "gif"}
                        for _fi, _ef in enumerate(_embedded):
                            _fc1, _fc2 = st.columns([3, 1])
                            _fc1.markdown(f"`.{_ef['ext']}` — オフセット{_ef['offset']} / {_ef['size']} bytes")
                            _fc2.download_button(
                                "📥 ダウンロード", data=_ef["data"],
                                file_name=f"extracted_{_fi}.{_ef['ext']}",
                                mime="application/octet-stream",
                                key=f"dl_embedded_{_fi}_{_sel_stream['src']}_{_sel_stream['src_port']}",
                            )
                            # 画像は末尾追記・ポリグロット・メタデータを深掘り検査
                            if _ef["ext"] in _img_exts:
                                _imgf = pcap_analyzer.analyze_image_forensics(_ef["ext"], _ef["data"])
                                _found = (_imgf["appended_data"] or _imgf["embedded_files"]
                                          or _imgf["string_hits"] or _imgf.get("lsb_stego")
                                          or _imgf.get("jpeg"))
                                if _found:
                                    with _fc1.expander("🔬 画像フォレンジック（隠しデータ検出）", expanded=True):
                                        for _ls in _imgf.get("lsb_stego", []):
                                            st.success(f"🧿 LSBステガノ({_ls['method']}): {_ls['text']}"
                                                       + (f" → `{_ls['decoded']}`" if _ls.get("decoded") else ""))
                                        for _sh in _imgf["string_hits"]:
                                            _ic = "🚩" if _sh["type"] == "flag_pattern" else "🔤"
                                            st.success(f"{_ic} メタデータ/文字列: {_sh['text']}"
                                                       + (f" → `{_sh['decoded']}`" if _sh.get("decoded") else ""))
                                        _ap = _imgf["appended_data"]
                                        if _ap:
                                            st.warning(f"📎 末尾追記データ {_ap['size']}バイト"
                                                       f"（オフセット{_ap['offset']}以降）を検出")
                                            for _sh in _ap["ctf_hits"]:
                                                _ic = "🚩" if _sh["type"] == "flag_pattern" else "🔤"
                                                st.success(f"{_ic} 追記内に: {_sh['text']}"
                                                           + (f" → `{_sh['decoded']}`" if _sh.get("decoded") else ""))
                                            st.download_button(
                                                "📥 末尾追記データを取り出す", data=_ap["data"],
                                                file_name=f"appended_{_fi}.bin",
                                                mime="application/octet-stream",
                                                key=f"dl_appended_{_fi}_{_sel_stream['src']}_{_sel_stream['src_port']}")
                                        for _pj_i, _pj in enumerate(_imgf["embedded_files"]):
                                            st.warning(f"🧬 ポリグロット: 画像内に .{_pj['ext']} を検出"
                                                       f"（オフセット{_pj['offset']} / {_pj['size']}バイト）")
                                            st.download_button(
                                                f"📥 埋め込み.{_pj['ext']}を取り出す", data=_pj["data"],
                                                file_name=f"polyglot_{_fi}_{_pj_i}.{_pj['ext']}",
                                                mime="application/octet-stream",
                                                key=f"dl_poly_{_fi}_{_pj_i}_{_sel_stream['src']}_{_sel_stream['src_port']}")
                                        # JPEG: マーカーセグメント(COM/APPn/EXIF)・複数EOI
                                        _jpg = _imgf.get("jpeg")
                                        if _jpg:
                                            st.caption("🧩 JPEGマーカー解析（コメント/EXIF/APPn・複数EOI）"
                                                       "— JPEGは画素LSBが効かないため、これらのメタ領域が主な隠し場所です。")
                                            for _jh in _jpg["flag_hits"]:
                                                _ic = "🚩" if _jh["type"] == "flag_pattern" else "🔤"
                                                st.success(f"{_ic} [{_jh.get('where','')}] {_jh['text']}"
                                                           + (f" → `{_jh['decoded']}`" if _jh.get("decoded") else ""))
                                            if _jpg.get("extra_eoi"):
                                                st.warning(f"📎 EOI(画像終端)以降にデータを検出"
                                                           f"（隠し画像/追記の可能性 ×{_jpg['extra_eoi']}）")
                                            if _jpg.get("segments"):
                                                st.caption("検出セグメント: "
                                                           + ", ".join(f"{s['marker']}({s['size']}B)"
                                                                       for s in _jpg["segments"][:12]))
                                            if _jpg.get("exif"):
                                                with st.expander("📷 EXIFメタデータ"):
                                                    for _k, _v in list(_jpg["exif"].items())[:30]:
                                                        st.text(f"{_k}: {_v}")

                            # ZIP/Office(docx等)は中身を再帰展開してflagを探索
                            elif _ef["ext"] in {"zip", "docx", "xlsx", "pptx", "jar"}:
                                _arc = pcap_analyzer.extract_archive_contents(_ef["data"], _ef["ext"])
                                if _arc:
                                    with _fc1.expander(f"🗜️ アーカイブ展開（{_ef['ext']}・再帰）", expanded=True):
                                        _acnt = [0]
                                        def _render_arc(_entries, _depth=0, _pfx=""):
                                            for _ai, _e in enumerate(_entries):
                                                _pad = "　" * _depth
                                                _tag = "📦" if _e["is_archive"] else "📄"
                                                st.markdown(f"{_pad}{_tag} `{_e['path']}` "
                                                            f"（{_e['size']:,} bytes）")
                                                for _h in _e["ctf_hits"]:
                                                    _ic = "🚩" if _h["type"] == "flag_pattern" else "🔤"
                                                    st.success(f"{_pad}{_ic} {_h['text']}"
                                                               + (f" → `{_h['decoded']}`" if _h.get("decoded") else ""))
                                                if _e.get("data") is not None and _e["ctf_hits"]:
                                                    st.download_button(
                                                        "📥 このファイルを取り出す", data=_e["data"],
                                                        file_name=_e["path"].replace("/", "_") or f"member_{_acnt[0]}",
                                                        mime="application/octet-stream",
                                                        key=f"dl_arc_{_fi}_{_acnt[0]}_{_sel_stream['src']}_{_sel_stream['src_port']}")
                                                    _acnt[0] += 1
                                                if _e.get("children"):
                                                    _render_arc(_e["children"], _depth + 1)
                                        _render_arc(_arc)

                    st.download_button(
                        "📥 このストリームの生データをダウンロード（送信+応答結合）",
                        data=_stream_full, file_name="tcp_stream.bin",
                        mime="application/octet-stream", key="dl_stream_raw",
                    )

                # 多段エンコード自動デコーダー（手動入力）
                st.markdown("**🔓 多段エンコード自動デコーダー**")
                st.caption("Base64 / Hex / URL / gzip / zlib / ROT13 を自動で数段試し、flagが出るまでデコードします。")
                _ml_input = st.text_area("デコードしたい文字列を貼り付け", height=80, key="ml_decode_input",
                                          placeholder="例: 多段エンコードされた文字列（H4sIA... など）")
                if st.button("🔓 自動デコード", key="ml_decode_btn"):
                    if _ml_input.strip():
                        _ml_res = pcap_analyzer.multi_layer_decode(_ml_input.strip())
                        if _ml_res["steps"]:
                            st.markdown("**デコード手順:** " + " → ".join(s["method"] for s in _ml_res["steps"]))
                            for _si, _st in enumerate(_ml_res["steps"], 1):
                                st.code(f"{_si}. [{_st['method']}] {_st['preview']}")
                        if _ml_res["flag"]:
                            st.success(f"🚩 flag発見: {_ml_res['flag']}")
                        elif _ml_res["steps"]:
                            st.info(f"最終結果: `{_ml_res['final']}`")
                        else:
                            st.warning("デコードできませんでした（対応形式: Base64/Hex/URL/gzip/zlib/ROT13）。")
                    else:
                        st.warning("文字列を入力してください。")

            # ── HTTP 解析 ────────────────────────────────
            _http_errs = res.get("http_errors", [])
            _http_sum  = res.get("http_summary", [])
            if _http_sum or _http_errs:
                st.markdown("---")
                st.markdown("### 🌍 HTTP 応答コード解析")
                st.caption("平文 HTTP レスポンスの応答コードを集計。4xx/5xx エラーを検出します（暗号化されていないHTTP通信のみ）。")
                if _http_sum:
                    df_http_sum = pd.DataFrame(_http_sum)
                    df_http_sum.columns = ["ステータスコード", "件数"]
                    _hc1, _hc2 = st.columns([1, 2])
                    with _hc1:
                        st.dataframe(df_http_sum, use_container_width=True, hide_index=True)
                    with _hc2:
                        st.bar_chart(df_http_sum.set_index("ステータスコード"))
                if _http_errs:
                    st.markdown("**4xx / 5xx エラー一覧**")
                    df_http_err = pd.DataFrame(_http_errs)
                    _http_cols = ["timestamp", "server", "client", "server_port", "status_code", "reason", "category"]
                    df_http_err = df_http_err[_http_cols].rename(columns={
                        "timestamp": "時刻", "server": "サーバーIP", "client": "クライアントIP",
                        "server_port": "Port", "status_code": "ステータス",
                        "reason": "理由", "category": "カテゴリ",
                    })
                    st.dataframe(df_http_err, use_container_width=True, hide_index=True)
                else:
                    st.success("✅ HTTP 4xx/5xx エラーは検出されませんでした")

            # ── TLS / HTTPS 解析 ─────────────────────────
            _tls_sum      = res.get("tls_summary", {})
            _tls_sessions = res.get("tls_sessions", [])
            _tls_alerts   = res.get("tls_alerts", [])
            if _tls_sum.get("sessions", 0) > 0 or _tls_alerts:
                st.markdown("---")
                st.markdown("### 🔒 TLS / HTTPS 解析")
                st.caption(
                    "HTTPS のペイロードは暗号化されており読めませんが、"
                    "SNI（接続先ホスト名）・TLSバージョン・Fatal Alert は平文で送受信されるため取得できます。"
                )
                _tc1, _tc2, _tc3, _tc4 = st.columns(4)
                with _tc1:
                    st.metric("TLSセッション数", _tls_sum.get("sessions", 0))
                with _tc2:
                    st.metric("ユニーク接続先", _tls_sum.get("unique_sites", 0))
                with _tc3:
                    st.metric("Fatal Alert", _tls_sum.get("fatal_alerts", 0),
                              delta="⚠️ 接続エラー" if _tls_sum.get("fatal_alerts") else None)
                with _tc4:
                    st.metric("非推奨TLS(<1.2)", _tls_sum.get("deprecated_tls", 0),
                              delta="⚠️ セキュリティ問題" if _tls_sum.get("deprecated_tls") else None)
                if _tls_sessions:
                    st.markdown("**TLS セッション一覧（SNI付き）**")
                    df_tls = pd.DataFrame(_tls_sessions)
                    _tls_cols = ["timestamp", "client", "server", "server_port", "sni", "tls_version"]
                    df_tls = df_tls[[c for c in _tls_cols if c in df_tls.columns]].rename(columns={
                        "timestamp": "時刻", "client": "クライアントIP", "server": "サーバーIP",
                        "server_port": "Port", "sni": "接続先ホスト名(SNI)", "tls_version": "TLSバージョン",
                    })
                    st.dataframe(df_tls, use_container_width=True, hide_index=True)
                if _tls_alerts:
                    st.markdown("**⚠️ TLS Alert 一覧**")
                    df_ta = pd.DataFrame(_tls_alerts)
                    _ta_cols = ["timestamp", "client", "server", "server_port", "sni", "alert", "issue"]
                    df_ta = df_ta[[c for c in _ta_cols if c in df_ta.columns]].rename(columns={
                        "timestamp": "時刻", "client": "クライアントIP", "server": "サーバーIP",
                        "server_port": "Port", "sni": "接続先ホスト名(SNI)",
                        "alert": "アラート内容", "issue": "問題",
                    })
                    st.dataframe(df_ta, use_container_width=True, hide_index=True)

            # ── DHCP 解析 ────────────────────────────────
            _dhcp_issues = res.get("dhcp_issues", [])
            _dhcp_sum    = res.get("dhcp_summary", {})
            if _dhcp_sum or _dhcp_issues:
                st.markdown("---")
                st.markdown("### 📋 DHCP 解析")
                st.caption("DHCP NAK・DECLINE・DISCOVER未応答などのIPアドレス割り当て問題を検出します。")
                if _dhcp_sum:
                    df_dhcp_sum = pd.DataFrame(
                        [{"メッセージタイプ": k, "件数": v} for k, v in sorted(_dhcp_sum.items())]
                    )
                    st.dataframe(df_dhcp_sum, use_container_width=True, hide_index=True)
                if _dhcp_issues:
                    st.markdown("**⚠️ DHCP 問題検出**")
                    df_dhcp = pd.DataFrame(_dhcp_issues)
                    _dhcp_cols = ["timestamp", "server", "client_mac", "hostname", "event", "detail", "issue"]
                    df_dhcp = df_dhcp[[c for c in _dhcp_cols if c in df_dhcp.columns]].rename(columns={
                        "timestamp": "時刻", "server": "サーバーIP", "client_mac": "クライアントMAC",
                        "hostname": "ホスト名", "event": "イベント", "detail": "詳細", "issue": "問題",
                    })
                    st.dataframe(df_dhcp, use_container_width=True, hide_index=True)
                else:
                    st.success("✅ DHCP 問題は検出されませんでした")

            # ── VoIP/RTP 品質（MOS）─────────────────────
            _voip_streams = res.get("voip_streams", [])
            if _voip_streams or res.get("voip_stream_count", 0) > 0:
                st.markdown("---")
                st.markdown("### 📞 VoIP / RTP 品質（MOS スコア）")
                st.caption("RTP ストリームを検出してジッター・パケットロス・MOS スコアを算出します（G.107 E-model 近似）。")
                _vc1, _vc2, _vc3, _vc4 = st.columns(4)
                _vc1.metric("RTPストリーム数",  res.get("voip_stream_count", 0))
                _vc2.metric("平均MOSスコア",    res.get("voip_avg_mos", 0))
                _vc3.metric("品質不良ストリーム", res.get("voip_poor_streams", 0),
                            delta="⚠️ MOS<3.6" if res.get("voip_poor_streams", 0) > 0 else None)
                _avg_mos = res.get("voip_avg_mos", 0)
                _vc4.metric("品質判定",
                    "最高" if _avg_mos >= 4.3 else
                    "良好" if _avg_mos >= 4.0 else
                    "普通" if _avg_mos >= 3.6 else
                    "やや悪い" if _avg_mos >= 3.1 else "悪い")
                if _voip_streams:
                    df_voip = pd.DataFrame(_voip_streams)
                    _voip_show_cols = ["src_ip", "dst_ip", "ssrc", "codec",
                                       "packets", "duration_s", "jitter_ms", "loss_pct", "mos", "quality"]
                    df_voip = df_voip[[c for c in _voip_show_cols if c in df_voip.columns]].rename(columns={
                        "src_ip": "送信元IP", "dst_ip": "宛先IP", "ssrc": "SSRC",
                        "codec": "コーデック", "packets": "パケット数",
                        "duration_s": "継続(秒)", "jitter_ms": "ジッター(ms)",
                        "loss_pct": "パケットロス%", "mos": "MOS", "quality": "品質",
                    })
                    st.dataframe(df_voip, use_container_width=True, hide_index=True)
                    st.info("💡 MOS 4.0以上=良好 / 3.6以上=普通 / 3.1以上=やや悪い / 3.1未満=悪い（電話品質不可）")

            # ── 会話フロー一覧 ──────────────────────────
            st.markdown("---")
            st.markdown("### 💬 会話フロー一覧")
            st.caption("TCP/UDP の双方向フローを集計（バイト数の多い順）。RTT・スループット付き。")
            if convs:
                _conv_proto = st.selectbox(
                    "プロトコルで絞り込み", ["ALL", "TCP", "UDP"],
                    key="conv_proto_filter"
                )
                _convs_f = convs if _conv_proto == "ALL" else [
                    c for c in convs if c["protocol"] == _conv_proto
                ]
                df_conv = pd.DataFrame(_convs_f)
                _conv_cols = ["protocol", "src_ip", "src_port", "dst_ip", "dst_port",
                              "packets", "bytes", "throughput_kbps", "duration_sec",
                              "rtt_ms", "tcp_state"]
                _conv_cols = [c for c in _conv_cols if c in df_conv.columns]
                df_conv = df_conv[_conv_cols].rename(columns={
                    "protocol": "プロトコル", "src_ip": "送信元IP",
                    "src_port": "送信元Port", "dst_ip": "宛先IP",
                    "dst_port": "宛先Port", "packets": "パケット数",
                    "bytes": "バイト数", "throughput_kbps": "スループット(KB/s)",
                    "duration_sec": "継続(秒)", "rtt_ms": "RTT(ms)",
                    "tcp_state": "TCP状態",
                })
                st.dataframe(df_conv, use_container_width=True, hide_index=True)
                st.caption(f"合計 {len(_convs_f)} フロー（双方向集計・バイト数降順）")
            else:
                st.info("TCP/UDP フローが検出されませんでした")

            # ── トップトーカー ──────────────────────────
            st.markdown("---")
            st.markdown("### 📡 トップトーカー（帯域消費上位）")
            st.caption("送受信の合計バイト数が多いIPアドレス（ランキング上位20件）")
            if talkers:
                df_tk = pd.DataFrame(talkers)
                df_tk["sent_MB"]  = (df_tk["sent_bytes"]  / 1024 / 1024).round(3)
                df_tk["recv_MB"]  = (df_tk["recv_bytes"]  / 1024 / 1024).round(3)
                df_tk["total_MB"] = (df_tk["total_bytes"] / 1024 / 1024).round(3)
                df_tk_show = df_tk[["ip", "total_MB", "sent_MB", "recv_MB", "sent_pkts", "recv_pkts"]]
                df_tk_show.columns = ["IPアドレス", "合計(MB)", "送信(MB)", "受信(MB)", "送信パケット数", "受信パケット数"]
                st.dataframe(df_tk_show, use_container_width=True, hide_index=True)

                _tk_chart = df_tk.set_index("ip")[["sent_MB", "recv_MB"]].head(10)
                _tk_chart.columns = ["送信MB", "受信MB"]
                st.bar_chart(_tk_chart)
            else:
                st.info("データなし")

            # ── フィルター解析 ──────────────────────────
            st.markdown("---")
            st.markdown("### 🔍 フィルター解析")
            st.caption("IPアドレス・ポート・プロトコル・キーワードでパケットを絞り込みます")
            with st.form("pcap_filter_form"):
                _fc1, _fc2, _fc3 = st.columns(3)
                with _fc1:
                    _f_ip     = st.text_input("IPアドレス（送受信どちらか）", placeholder="10.0.0.1")
                    _f_src_ip = st.text_input("送信元IP（厳密指定）", placeholder="10.0.0.1")
                with _fc2:
                    _f_dst_ip   = st.text_input("宛先IP（厳密指定）", placeholder="10.0.0.2")
                    _f_port_str = st.text_input("ポート番号（送受信どちらか）", placeholder="80")
                with _fc3:
                    _f_proto   = st.selectbox("プロトコル", ["（全て）", "TCP", "UDP", "ICMP", "ARP"])
                    _f_keyword = st.text_input("キーワード（ペイロード内テキスト）",
                                               placeholder="GET / HTTP / password")
                _filter_btn = st.form_submit_button("🔍 フィルター実行")

            if _filter_btn:
                _f_port  = int(_f_port_str) if _f_port_str.strip().isdigit() else 0
                _f_proto_arg = "" if _f_proto == "（全て）" else _f_proto
                with st.spinner("フィルタリング中..."):
                    _filtered = pcap_analyzer.filter_pcap(
                        raw_bytes,
                        src_ip=_f_src_ip.strip(),
                        dst_ip=_f_dst_ip.strip(),
                        ip=_f_ip.strip(),
                        port=_f_port,
                        protocol=_f_proto_arg,
                        keyword=_f_keyword.strip(),
                    )
                if _filtered:
                    st.success(f"✅ {len(_filtered)} パケット一致（最大500件）")
                    df_filt = pd.DataFrame(_filtered)
                    _fcols = ["timestamp", "protocol", "src_ip", "src_port",
                              "dst_ip", "dst_port", "length", "info"]
                    if _f_keyword.strip():
                        _fcols.append("payload_text")
                    df_filt = df_filt[_fcols].rename(columns={
                        "timestamp": "時刻", "protocol": "プロトコル",
                        "src_ip": "送信元IP", "src_port": "送信元Port",
                        "dst_ip": "宛先IP", "dst_port": "宛先Port",
                        "length": "長さ(B)", "info": "情報",
                        "payload_text": "ペイロード（一部）",
                    })
                    st.dataframe(df_filt, use_container_width=True, hide_index=True)
                else:
                    st.warning("条件に一致するパケットが見つかりませんでした")

            # ── ICMP 分布 ──────────────────────────────
            if res["icmp_summary"]:
                st.markdown("---")
                st.markdown("### 📈 ICMP タイプ別分布")
                df_icmp = pd.DataFrame(res["icmp_summary"])
                df_icmp["label"] = df_icmp.apply(lambda r: f"Type{r['type']} {r['name']}", axis=1)
                st.bar_chart(df_icmp.set_index("label")["count"])

    else:
        st.markdown("""
### 使い方

1. **Wiresharkでキャプチャ** → `ファイル` → `名前を付けて保存` → `.pcapng` 形式で保存
2. **上のアップローダーにドラッグ&ドロップ**
3. 自動解析結果が表示されます

---

### キャプチャのポイント（ICMP redirect 調査時）

```
# センターCatalyst に SSHログインし、debug を有効化
debug ip icmp

# またはWiresharkをセンターに繋がるPCで実行
# フィルター例（ICMP redirectのみ表示）:
icmp.type == 5

# RIPも合わせて確認したい場合:
icmp.type == 5 or udp.port == 520
```

### このツールで解析できること

| 項目 | 内容 |
|------|------|
| 🔀 ICMP redirect | どのルーターが・どのホストに・どのGWへredirectしたか |
| 🔄 RIP | ネイバー一覧・Request/Response の交換状況 |
| ⚠️ ARP異常 | MACアドレス変化（ARPスプーフィング検出） |
| 🔌 TCP RST多発 | 接続拒否・強制切断が多い通信ペア |
| 🔁 TCP再送多発 | 同一シーケンス番号の再送（輻輳・ロス・遅延の検出） |
| 🚫 接続失敗 | SYNに対してSYN-ACKが返ってこなかった通信 |
| 🪟 ゼロウィンドウ | 受信バッファ枯渇によるフロー制御問題（スループット低下） |
| 🌐 DNS解析 | NXDOMAIN・SERVFAIL・REFUSED・応答遅延の検出 |
| 🧩 IPフラグメント | MTU問題・Path MTU Discovery障害によるフラグメント化の検出 |
| 🌍 HTTP解析 | 平文HTTPの応答コード集計・4xx/5xxエラー一覧 |
| 🔒 TLS/HTTPS解析 | SNI（接続先ホスト名）・TLSバージョン・Fatal Alert の検出 |
| 📋 DHCP解析 | NAK・DECLINE・DISCOVER未応答などのIPアドレス割り当て問題 |
| 💬 会話フロー一覧 | RTT・スループット付きで全フローをバイト数順に表示 |
| 📡 トップトーカー | 帯域を最も消費しているIPアドレスのランキング |
| 🔍 フィルター解析 | IP・ポート・プロトコル・キーワードでパケット絞り込み |
| 🤖 AI統合診断 | pcap + syslog + SNMP を統合してAIが根本原因推定 |
| 📞 VoIP/RTP品質 | MOSスコア・ジッター・パケットロス（RTPストリーム自動検出） |
        """)

# ═══════════════════════════════════════════
# TAB: ネットワークトポロジー
# ═══════════════════════════════════════════
with tab_topo:
    import restconf_client as _rc_topo

    st.markdown("## 🗺️ ネットワークトポロジー")
    st.caption("RESTCONF で取得した LLDP/CDP ネイバー情報をもとにスイッチ/ルーターの接続図を自動生成します。")

    _topo_c1, _topo_c2 = st.columns([3, 1])

    with _topo_c2:
        st.markdown("**プロトコル選択**")
        _topo_proto = st.radio(
            "ネイバー探索プロトコル",
            options=["lldp", "cdp", "both"],
            format_func=lambda x: {"lldp": "🔵 LLDP（標準・マルチベンダー）",
                                   "cdp":  "🟠 CDP（Cisco独自）",
                                   "both": "🟣 両方（重複除去）"}[x],
            index=2,
            key="topo_proto",
        )
        st.markdown("---")
        if st.button("🔄 トポロジー取得", key="topo_refresh", use_container_width=True):
            _proto_label = {"lldp": "LLDP", "cdp": "CDP", "both": "LLDP+CDP"}[_topo_proto]
            with st.spinner(f"RESTCONF で {_proto_label} ネイバーを取得中..."):
                _topo_neighbors = _rc_topo.get_all_topology(_topo_proto)
            st.session_state["_topo_neighbors"] = _topo_neighbors
            st.session_state["_topo_proto_used"] = _topo_proto
            st.rerun()

        _devs_for_topo = _rc_topo.get_devices()
        if not _devs_for_topo:
            st.warning("RESTCONFデバイスが未登録です。\n「機器コンフィグ」タブで登録してください。")
        else:
            st.success(f"{len(_devs_for_topo)} 台登録済み")
            for _td in _devs_for_topo:
                st.code(_td["ip"])

        st.markdown("---")
        st.markdown("**ルーター/SW側の設定**")
        if _topo_proto in ("lldp", "both"):
            st.markdown("🔵 **LLDP**")
            st.code("""conf t
 lldp run
 interface Gi0/0
  lldp transmit
  lldp receive
end""", language="text")
        if _topo_proto in ("cdp", "both"):
            st.markdown("🟠 **CDP**")
            st.code("""conf t
 cdp run
 interface Gi0/0
  cdp enable
end""", language="text")

    with _topo_c1:
        _cached_topo      = st.session_state.get("_topo_neighbors", None)
        _cached_topo_proto = st.session_state.get("_topo_proto_used", "")
        if _cached_topo is not None:
            if _cached_topo:
                _proto_label = {"lldp": "LLDP", "cdp": "CDP", "both": "LLDP + CDP"}.get(_cached_topo_proto, "")
                _topo_cap_col, _topo_ai_col = st.columns([4, 1])
                _topo_cap_col.caption(f"取得プロトコル: **{_proto_label}** | ネイバー数: {len(_cached_topo)}")
                _topo_llm_ok = (analyzer.check_claude_available() or analyzer.check_gemini_available()
                                or analyzer.check_groq_available() or analyzer.check_ollama_available())
                if _topo_ai_col.button("🤖 AI解説", key="topo_ai", disabled=not _topo_llm_ok):
                    _topo_ctx = "\n".join(
                        f"{n['local_device']} {n['local_if']} ←[{n['protocol']}]→ "
                        f"{n['neighbor_id']} {n['neighbor_if']} (管理IP:{n['neighbor_ip']})"
                        for n in _cached_topo
                    )
                    with st.spinner("LLMがトポロジーを解析中..."):
                        _topo_ai_text, _topo_ai_model = analyzer.ask_llm(
                            "あなたはネットワーク設計の専門家です。"
                            "提供されるLLDP/CDPネイバー情報からネットワーク構成を日本語で解説してください。"
                            "冗長性・スパニングツリー・設計上の注意点があれば指摘してください。",
                            _topo_ctx,
                            st.session_state.get("llm_mode", "auto"),
                        )
                    st.session_state["_topo_ai"] = (_topo_ai_text, _topo_ai_model)

                if st.session_state.get("_topo_ai"):
                    _tai = st.session_state["_topo_ai"]
                    if _tai[0]:
                        with st.expander(f"🤖 AI解説（{_tai[1]}）", expanded=True):
                            st.markdown(_tai[0])

                _dot_str = _rc_topo.build_topology_dot(_cached_topo)
                st.graphviz_chart(_dot_str, use_container_width=True)
                st.markdown("---")
                st.markdown("**ネイバー一覧**")
                df_topo = pd.DataFrame(_cached_topo)
                _topo_show = df_topo[["local_device", "local_if", "neighbor_id", "neighbor_if",
                                      "neighbor_ip", "protocol"]].rename(columns={
                    "local_device": "自デバイスIP", "local_if": "ローカルIF",
                    "neighbor_id": "ネイバー名", "neighbor_if": "ネイバーIF",
                    "neighbor_ip": "ネイバー管理IP", "protocol": "プロトコル",
                })
                st.dataframe(_topo_show, use_container_width=True, hide_index=True)

                # プロトコル別件数
                if "protocol" in df_topo.columns:
                    _proto_counts = df_topo["protocol"].value_counts()
                    _pc_cols = st.columns(len(_proto_counts))
                    for _i, (proto, cnt) in enumerate(_proto_counts.items()):
                        _icon = "🔵" if proto == "LLDP" else "🟠"
                        _pc_cols[_i].metric(f"{_icon} {proto}", cnt)
            else:
                _hints = {
                    "lldp": "- `lldp run` がグローバルに設定されているか確認\n- インターフェースで `lldp transmit / receive` が有効か確認",
                    "cdp":  "- `cdp run` がグローバルに設定されているか確認\n- インターフェースで `cdp enable` が有効か確認",
                    "both": "- LLDP: `lldp run` / インターフェースで `lldp transmit / receive`\n- CDP: `cdp run` / インターフェースで `cdp enable`",
                }
                st.warning(f"ネイバー情報が取得できませんでした。\n\n"
                           f"{_hints.get(_cached_topo_proto, '')}\n\n"
                           "- RESTCONF 認証情報を確認してください")
        else:
            st.info("左のパネルでプロトコルを選択して「🔄 トポロジー取得」を押してください。")
            st.markdown("""
| プロトコル | 特徴 | 対応機器 |
|-----------|------|----------|
| 🔵 **LLDP** | IEEE 802.1AB 標準、マルチベンダー対応 | Cisco / Juniper / Arista / HP 等 |
| 🟠 **CDP** | Cisco 独自、Cisco機器は確実に対応 | Cisco のみ |
| 🟣 **両方** | どちらか一方でも取得できれば表示（重複除去） | 混在環境に最適 |

RESTCONF デバイスは「🗂️ 機器コンフィグ」タブで登録できます。
""")

# ═══════════════════════════════════════════
# TAB: アプリケーション応答時間 / IP SLA
# ═══════════════════════════════════════════
with tab_probe:
    import app_probe as _probe

    st.markdown("## ⏱️ アプリケーション応答時間")
    st.caption("HTTP/HTTPS エンドポイントや ping の応答時間を定期計測してトレンドを可視化します。IP SLA 結果もルーターから RESTCONF で取得できます。")

    if _is_cloud_mode():
        _probe_tab0, _probe_tab1, _probe_tab2 = st.tabs(
            ["🌐 クラウド/キャリア疎通", "📡 HTTP/Ping プローブ", "📊 IP SLA（ルーター）"])
        with _probe_tab0:
            st.markdown("### 🌐 主要クラウド/通信キャリアへの疎通状況")
            st.caption("このアプリのサーバーから、主要クラウド事業者・国内通信キャリアの公開サイトへ"
                       "HTTPで応答時間を計測した参考値です（1分キャッシュ・全訪問者で共有）。"
                       "あくまで**このサーバー1拠点から見た**値であり、お使いの回線の体感速度や"
                       "「世の中全体の回線混雑状況」を代表するものではない点にご注意ください。")
            if st.button("🔄 今すぐ再計測", key="cloud_latency_refresh"):
                _measure_cloud_latency.clear()
            _lat_results = _measure_cloud_latency()
            _lat_cols = st.columns(3)
            for _li, _lr in enumerate(_lat_results):
                with _lat_cols[_li % 3]:
                    if _lr["success"]:
                        _rtt = _lr["rtt_ms"]
                        _icon = "🟢" if _rtt < 150 else ("🟡" if _rtt < 400 else "🔴")
                        st.metric(f"{_icon} {_lr['name']}", f"{_rtt:.0f} ms")
                    else:
                        st.metric(f"🔴 {_lr['name']}", "応答なし")
            st.caption("🟢 150ms未満（良好） / 🟡 150〜400ms（やや遅延） / 🔴 400ms以上 or 応答なし（遅延・疎通不可）")
    else:
        _probe_tab1, _probe_tab2 = st.tabs(["📡 HTTP/Ping プローブ", "📊 IP SLA（ルーター）"])

    # ── HTTP/Ping プローブ ──
    with _probe_tab1:
        _pb_c1, _pb_c2 = st.columns([2, 1])

        with _pb_c2:
            st.markdown("**ターゲット登録**")
            with st.form("probe_add_form"):
                _pb_name  = st.text_input("名前", placeholder="Google DNS")
                _pb_url   = st.text_input("URL または ping://ホスト",
                                          placeholder="https://8.8.8.8 または ping://8.8.8.8")
                _pb_type  = st.selectbox("プローブ種別", ["http", "ping"])
                _pb_add   = st.form_submit_button("➕ 追加")
            if _pb_add and _pb_name and _pb_url:
                _probe.add_target(_pb_name, _pb_url, _pb_type)
                st.success(f"追加しました: {_pb_name}")
                st.rerun()

            st.markdown("**登録済みターゲット**")
            for _pt in _probe.get_targets():
                _pc1, _pc2 = st.columns([3, 1])
                _pc1.markdown(f"**{_pt['name']}**  \n`{_pt['url']}`")
                if _pc2.button("🗑️", key=f"del_probe_{_pt['id']}"):
                    _probe.remove_target(_pt["id"])
                    st.rerun()

            st.markdown("---")
            if "probe_bg_started" not in st.session_state:
                st.session_state.probe_bg_started = False

            _probe_interval = st.number_input("自動計測間隔（秒）", min_value=30,
                                              value=60, step=30, key="probe_interval")
            _pb_col1, _pb_col2 = st.columns(2)
            if _pb_col1.button("▶ 自動計測開始", use_container_width=True,
                               disabled=st.session_state.probe_bg_started):
                _probe.start_background_probe(_probe_interval)
                st.session_state.probe_bg_started = True
                st.rerun()
            if _pb_col2.button("⏹ 停止", use_container_width=True,
                               disabled=not st.session_state.probe_bg_started):
                _probe.stop_background_probe()
                st.session_state.probe_bg_started = False
                st.rerun()

            if st.button("🔄 今すぐ計測", use_container_width=True):
                with st.spinner("計測中..."):
                    _now_results = _probe.run_all_probes()
                st.session_state["_probe_now"] = _now_results
                st.rerun()

        with _pb_c1:
            _probe_hours = st.select_slider(
                "集計期間", options=[1, 3, 6, 12, 24], value=6,
                format_func=lambda x: f"過去 {x} 時間", key="probe_hours"
            )
            _summary = _probe.get_probe_summary(_probe_hours)

            if _summary:
                st.markdown("### 📊 サマリー")
                for _ps in _summary:
                    _avail = _ps.get("availability_pct", 0)
                    _last  = _ps.get("last_ok", None)
                    _rtt   = _ps.get("last_rtt") or 0
                    _col_icon = "🟢" if _last else "🔴"
                    _st_c1, _st_c2, _st_c3, _st_c4 = st.columns([2, 1, 1, 1])
                    _st_c1.markdown(f"{_col_icon} **{_ps['name']}**  \n`{_ps['url']}`")
                    _st_c2.metric("可用性", f"{_avail:.0f}%")
                    _st_c3.metric("平均RTT", f"{_ps.get('avg_rtt') or 0:.0f} ms")
                    _st_c4.metric("直近RTT", f"{_rtt:.0f} ms")

                # 個別ターゲットのトレンドグラフ
                st.markdown("---")
                st.markdown("### 📈 応答時間トレンド")
                _targets_list = _probe.get_targets()
                if _targets_list:
                    _sel_probe = st.selectbox(
                        "ターゲット選択",
                        _targets_list,
                        format_func=lambda t: t["name"],
                        key="probe_target_sel"
                    )
                    if _sel_probe:
                        _hist = _probe.get_probe_history(_sel_probe["id"], _probe_hours)
                        if _hist:
                            df_hist = pd.DataFrame(_hist)
                            df_hist["RTT(ms)"] = df_hist["rtt_ms"]
                            st.line_chart(df_hist.set_index("measured_at")["RTT(ms)"], height=200)
                            _ok_rate = df_hist["success"].mean() * 100
                            _avg_rtt = df_hist[df_hist["success"] == 1]["rtt_ms"].mean()
                            _hc1, _hc2, _hc3 = st.columns(3)
                            _hc1.metric("成功率", f"{_ok_rate:.1f}%")
                            _hc2.metric("平均RTT", f"{_avg_rtt:.1f} ms" if _avg_rtt == _avg_rtt else "N/A")
                            _hc3.metric("計測回数", len(_hist))
                        else:
                            st.info("このターゲットの履歴がありません。計測を実行してください。")
            else:
                st.info("ターゲットを登録して計測を開始してください。\n\n"
                        "例:\n- `https://8.8.8.8` → Google DNS（HTTP応答確認）\n"
                        "- `ping://192.168.1.1` → デフォルトゲートウェイへの ping")

            if "_probe_now" in st.session_state:
                st.markdown("---")
                st.markdown("### 🕐 最新計測結果")
                for _nr in st.session_state["_probe_now"]:
                    _icon = "✅" if _nr["success"] else "❌"
                    st.markdown(f"{_icon} **{_nr['name']}** — RTT: `{_nr['rtt_ms']} ms` "
                                f"| ステータス: `{_nr.get('status_code', '-')}` "
                                f"| エラー: {_nr.get('error_msg', '') or 'なし'}")

    # ── IP SLA ──
    with _probe_tab2:
        st.markdown("### 📡 IP SLA 統計（Cisco IOS-XE RESTCONF）")
        st.caption("ルーターで設定された IP SLA プローブの RTT・ジッター・パケットロスを取得します。")
        st.code("""# ルーター側設定例（ICMP-echo SLA）
ip sla 1
 icmp-echo 8.8.8.8 source-ip 192.168.1.1
 frequency 60
ip sla schedule 1 life forever start-time now

# UDP-jitter（VoIP品質評価）
ip sla 2
 udp-jitter 10.0.0.1 5000 codec g711alaw
 frequency 60
ip sla schedule 2 life forever start-time now""", language="text")

        if st.button("🔄 IP SLA データ取得", key="ipsla_refresh"):
            with st.spinner("RESTCONF で IP SLA を取得中..."):
                _ipsla_data = _rc_topo.get_all_ip_sla()
            st.session_state["_ipsla_data"] = _ipsla_data
            st.rerun()

        _ipsla_cached = st.session_state.get("_ipsla_data", None)
        if _ipsla_cached is not None:
            if _ipsla_cached:
                df_sla = pd.DataFrame(_ipsla_cached)
                _sla_show_cols = ["device_ip", "sla_id", "type", "destination",
                                  "rtt_avg_ms", "rtt_min_ms", "rtt_max_ms",
                                  "success_count", "failure_count", "return_code"]
                df_sla = df_sla[[c for c in _sla_show_cols if c in df_sla.columns]].rename(columns={
                    "device_ip": "デバイスIP", "sla_id": "SLA ID", "type": "種別",
                    "destination": "宛先", "rtt_avg_ms": "RTT平均(ms)",
                    "rtt_min_ms": "RTT最小(ms)", "rtt_max_ms": "RTT最大(ms)",
                    "success_count": "成功", "failure_count": "失敗", "return_code": "結果",
                })
                st.dataframe(df_sla, use_container_width=True, hide_index=True)

                # RTT グラフ
                if "RTT平均(ms)" in df_sla.columns and not df_sla.empty:
                    df_sla_chart = df_sla.set_index("SLA ID")[["RTT平均(ms)", "RTT最大(ms)"]].dropna()
                    if not df_sla_chart.empty:
                        st.bar_chart(df_sla_chart)
            else:
                st.warning("IP SLA データが取得できませんでした。\n"
                           "- ip sla が設定・スケジュール済みか確認してください\n"
                           "- RESTCONF デバイスが登録済みか確認してください")
