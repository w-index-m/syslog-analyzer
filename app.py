import streamlit as st
import threading
import time
import json
from datetime import datetime
import pandas as pd

import db
import analyzer
import syslog_server
import snmp_trap_server
import snmp_poller
import health_engine as he
import vendor_recommendations as vendor_rec
from parsers import parse_syslog

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
  .main { background: #0d1117; color: #c9d1d9; }
  .stApp { background: #0d1117; }
  .metric-card {
    background: #161b22; border: 1px solid #30363d;
    border-radius: 8px; padding: 16px; text-align: center;
  }
  .severity-EMERGENCY, .severity-ALERT, .severity-CRITICAL {
    color: #ff4d4d; font-weight: bold;
  }
  .severity-ERROR   { color: #f97316; font-weight: bold; }
  .severity-WARNING { color: #fbbf24; }
  .severity-NOTICE  { color: #60a5fa; }
  .severity-INFO    { color: #86efac; }
  .severity-DEBUG   { color: #94a3b8; }
  .log-card {
    background: #161b22; border-left: 3px solid #30363d;
    border-radius: 6px; padding: 12px; margin-bottom: 8px;
    font-family: 'JetBrains Mono', monospace; font-size: 12px;
  }
  .tag-chip {
    display: inline-block; background: #21262d;
    border: 1px solid #30363d; border-radius: 12px;
    padding: 2px 8px; margin: 2px; font-size: 11px; color: #8b949e;
  }
  .ai-explanation {
    background: #0d2137; border: 1px solid #1f6feb;
    border-radius: 6px; padding: 12px; margin-top: 8px;
    font-size: 13px;
  }
  .telemetry-note {
    background: #0f2b1a; border: 1px solid #238636;
    border-radius: 6px; padding: 8px; margin-top: 6px;
    font-size: 12px; color: #3fb950;
  }
  div[data-testid="stMetricValue"] { font-size: 2rem; }
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
if "auto_analyze" not in st.session_state:
    st.session_state.auto_analyze = True
if "judge_enabled" not in st.session_state:
    st.session_state.judge_enabled = False
if "llm_mode" not in st.session_state:
    st.session_state.llm_mode = "auto"
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

    st.markdown("---")
    st.markdown("### 🤖 AI解析エンジン")
    claude_ok = analyzer.check_claude_available()
    ollama_ok = analyzer.check_ollama_available()

    st.markdown(f"{'✅' if claude_ok else '❌'} Claude API "
                f"({'APIキーあり' if claude_ok else 'ANTHROPIC_API_KEY未設定'})")
    st.markdown(f"{'✅' if ollama_ok else '❌'} Ollama "
                f"({'接続OK' if ollama_ok else 'localhost:11434 未起動'})")

    llm_mode = st.selectbox("解析モード", [
        ("auto",   "🔄 自動 (Claude優先→Ollama)"),
        ("claude", "☁️  Claude APIのみ"),
        ("ollama", "🏠 Ollamaのみ（完全ローカル）"),
        ("none",   "⛔ AI解析なし（高速）"),
    ], format_func=lambda x: x[1], index=0)
    st.session_state.llm_mode = llm_mode[0]

    if ollama_ok:
        import os
        current_model = os.environ.get("OLLAMA_MODEL", "llama3")
        st.text_input("Ollamaモデル名", value=current_model,
                      help="ollama pull llama3 などで取得したモデル名")

    st.session_state.auto_analyze = st.checkbox("受信ログを自動AI解析", value=True)
    st.session_state.judge_enabled = st.checkbox(
        "🧑‍⚖️ AI解析結果の品質チェック（Judge）を実行",
        value=False,
        help="一次解析の結果を別のLLM呼び出しで審査します。Claude APIの呼び出し回数が2倍になります。"
    )

    st.markdown("---")

    # テストログ投入
    st.markdown("### 🧪 テストログ投入")
    test_vendor = st.selectbox("ベンダー", [
        "Cisco IOS/IOS-XE", "Cisco NX-OS", "富士通 Si-R",
        "APRESIA", "RHEL/Linux", "Windows"
    ])
    if st.button("📨 テストログ送信", use_container_width=True):
        _inject_test_log(test_vendor)
        st.success("投入しました")

    st.markdown("---")

    # ログクリア
    if st.button("🗑️ 全ログ削除", use_container_width=True):
        db.clear_logs()
        st.success("クリアしました")

    st.markdown("---")
    st.caption("v1.0 | Cisco/NX-OS/Si-R/APRESIA/RHEL/Windows対応")

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
        ("<22>Jun 30 10:00:00 SiR-G120 siRd[123]: INFO PPP line up (BRI0) remote=203.0.113.1", "192.168.1.3"),
        ("<19>Jun 30 10:01:00 SiR-G120 siRd[123]: ERR PPP line down (BRI0) reason=LCP timeout", "192.168.1.3"),
        ("<22>Jun 30 10:02:00 SiR-G120 ospfd[456]: INFO OSPF neighbor 10.1.1.2 state changed to Full", "192.168.1.3"),
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
tab_health, tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🩺 健全性ダッシュボード", "📋 ログビューア", "📊 テレメトリダッシュボード",
    "📡 SNMPモニター", "🗂️ 機器コンフィグ", "📖 セットアップガイド"
])

# ═══════════════════════════════════════════
# TAB: 健全性ダッシュボード（メイン画面）
# ═══════════════════════════════════════════
with tab_health:
    st.markdown("## 🩺 ネットワーク健全性ダッシュボード")

    overall = he.get_network_overall_health()

    if overall["overall_score"] is None:
        st.info("まだ健全性データがありません。「📡 SNMPモニター」タブでデバイスを登録し、"
                "下の「健全性チェック実行」ボタンを押すか、SNMPポーラーを起動してください。")
    else:
        score = overall["overall_score"]
        score_color = "#3fb950" if score >= 85 else "#d29922" if score >= 60 else "#f85149"
        status_label = "正常" if score >= 85 else "注意" if score >= 60 else "異常"

        col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
        with col1:
            st.markdown(f"""
<div style="background:#161b22; border:2px solid {score_color}; border-radius:12px; padding:20px; text-align:center;">
  <div style="color:#8b949e; font-size:13px;">ネットワーク総合健全度</div>
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
        st.markdown("### 機器別ヘルスステータス")
    with col_run2:
        run_llm = st.checkbox("LLM診断を含める", value=False,
                              help="各機器をLLMが総合診断します（時間とAPI呼び出しが増えます）")
        if st.button("🔄 健全性チェック実行", use_container_width=True):
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
                st.success("健全性チェック完了")
                st.rerun()

    st.caption("💡 スループット・破棄・ブロードキャスト率は2回目以降のチェックで差分計算されます。初回は基準値の取得のみです。")

    devices_health = he.get_latest_health_all()
    if devices_health:
        for dh in devices_health:
            dh_score = dh["health_score"]
            dh_color = "#3fb950" if dh_score >= 85 else "#d29922" if dh_score >= 60 else "#f85149"
            dh_icon = "🟢" if dh_score >= 85 else "🟡" if dh_score >= 60 else "🔴"
            metrics = dh.get("metrics", {})
            issues = dh.get("issues", [])

            with st.expander(f"{dh_icon} {dh['hostname']} ({dh['source_ip']}) — {dh_score}/100", expanded=(dh_score < 60)):
                mcols = st.columns(4)
                with mcols[0]:
                    cpu = metrics.get("cpu_5min")
                    st.metric("CPU(5分)", f"{cpu}%" if cpu is not None else "—")
                with mcols[1]:
                    mem = metrics.get("memory_used_pct")
                    st.metric("メモリ", f"{mem}%" if mem is not None else "—")
                with mcols[2]:
                    st.metric("検出問題数", len(issues))
                with mcols[3]:
                    st.metric("最終チェック", dh["recorded_at"][11:19])

                if issues:
                    st.markdown("**検出された問題:**")
                    for iss in issues:
                        lv_color = "#f85149" if iss["level"] == "critical" else "#d29922"
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

                trend = he.get_health_trend(dh["source_ip"], hours=6)
                if len(trend) >= 2:
                    df_trend = pd.DataFrame(trend)
                    df_trend["time"] = df_trend["recorded_at"].str[11:16]
                    st.line_chart(df_trend.set_index("time")["health_score"])

    st.markdown("---")
    with st.expander("📖 ヘルススコアの算出基準"):
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
| インターフェースダウン | — | -15 |

**ステータス判定:** 85点以上=🟢正常 / 60〜84点=🟡注意 / 60点未満=🔴異常

**Cisco系の相関分析:**
ブロードキャスト急増 → CPU上昇 → 破棄増加 → ルーティング不安定、という連鎖を
LLM診断が「根本原因はブロードキャストストーム」と推定します。
        """)

# ═══════════════════════════════════════════
# TAB1: ログビューア
# ═══════════════════════════════════════════
with tab1:
    st.markdown("## 📋 受信ログ一覧")

    # フィルター
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        f_vendor = st.selectbox("ベンダー", ["すべて", "Cisco IOS/IOS-XE", "Cisco NX-OS",
                                              "富士通 Si-R", "APRESIA ApresiaLight",
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
                "EMERGENCY": "#ff4d4d", "ALERT": "#ff4d4d", "CRITICAL": "#ff4d4d",
                "ERROR": "#f97316", "WARNING": "#fbbf24",
                "NOTICE": "#60a5fa", "INFO": "#86efac", "DEBUG": "#94a3b8"
            }.get(sev, "#94a3b8")

            border_color = sev_color if sev in ("EMERGENCY","ALERT","CRITICAL","ERROR") else "#30363d"

            with st.container():
                st.markdown(f"""
<div class="log-card" style="border-left-color:{border_color}">
  <div style="display:flex; justify-content:space-between; align-items:center;">
    <span style="color:{sev_color}; font-weight:bold;">◉ {sev}</span>
    <span style="color:#8b949e; font-size:11px;">{received} | {src_ip}</span>
  </div>
  <div style="color:#c9d1d9; margin:4px 0;">
    <span style="color:#a5f3fc;">[{vendor}]</span>
    <span style="color:#fde68a;"> {hostname}</span>
    <span style="color:#c084fc;"> {process}</span>
  </div>
  <div style="color:#e2e8f0; margin:4px 0; word-break:break-all;">{message[:300]}</div>
  <div>{"".join(f'<span class="tag-chip">{t}</span>' for t in tags)}</div>
</div>
""", unsafe_allow_html=True)

                # AI解析結果表示
                if ai_text:
                    try:
                        ai_data = json.loads(ai_text)
                        impact_color = {
                            "重大": "#ff4d4d", "中程度": "#f97316",
                            "軽微": "#fbbf24", "なし": "#86efac"
                        }.get(ai_data.get("impact",""), "#94a3b8")
                        config_note = ai_data.get('config_context_note', '')
                        config_note_html = f'''
<div class="telemetry-note" style="background:#1a1530; border-color:#8957e5; color:#bc8cff;">
  🗂️ コンフィグ参照: {config_note}
</div>''' if config_note else ''
                        st.markdown(f"""
<div class="ai-explanation">
  <div style="color:#58a6ff; font-size:11px; margin-bottom:4px;">
    🤖 AI解析 ({ai_model})
  </div>
  <div style="font-weight:bold; color:#f0f6fc;">
    📌 {ai_data.get('summary','')}
  </div>
  <div style="margin:4px 0; color:#c9d1d9;">{ai_data.get('detail','')}</div>
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
                        if st.button("🤖 AI解析", key=f"analyze_{log['id']}"):
                            with st.spinner("解析中..."):
                                raw = log.get("raw","")
                                from parsers import parse_syslog as ps
                                parsed = ps(raw, log.get("source_ip",""))
                                config_ctx = _get_config_context(log.get("source_ip",""))
                                expl, model = analyzer.analyze(
                                    parsed, raw, st.session_state.llm_mode, config_ctx)
                                db.update_ai_explanation(log["id"], expl, model)
                            st.rerun()

                st.markdown("<hr style='border-color:#21262d; margin:8px 0;'>", unsafe_allow_html=True)

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
                    "CRITICAL": "#ff4d4d", "ERROR": "#f97316",
                    "WARNING": "#fbbf24", "NOTICE": "#60a5fa", "INFO": "#86efac"
                }.get(sev, "#94a3b8")
                tags = json.loads(log.get("tags") or "[]")
                st.markdown(f"""
<div class="log-card" style="border-left-color:{sev_color}">
  <span style="color:{sev_color}; font-weight:bold;">◉ {sev}</span>
  <span style="color:#a5f3fc; margin-left:8px;">{log.get('vendor','')}</span>
  <span style="color:#fde68a; margin-left:8px;">{log.get('hostname','')}</span>
  <span style="color:#8b949e; float:right; font-size:11px;">{log.get('received_at','')[:19]}</span>
  <div style="margin-top:6px; color:#e2e8f0;">{log.get('message','')}</div>
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
                if st.button("🩺 健全性チェック（スループット/破棄/CPU）"):
                    with st.spinner(f"{sel_ip} の健全性を評価中..."):
                        dev = next((d for d in devices if d["ip"] == sel_ip), {})
                        health = snmp_poller.poll_device_health(
                            sel_ip, dev.get("community","public"),
                            dev.get("version","v2c"), dev.get("port",161),
                            llm_mode="none"
                        )
                    st.success(f"ヘルススコア: {health['health_score']}/100 ({health['status']})")
                    st.caption("詳細は「🩺 健全性ダッシュボード」タブで確認できます")
        else:
            st.info("デバイスが登録されていません。上のフォームから追加してください。")

        st.markdown("---")
        st.markdown("### 閾値アラート（直近10分）")
        alerts = snmp_poller.get_alert_metrics()
        if alerts:
            for a in alerts:
                level_color = "#ff4d4d" if a["alert_level"] == "critical" else "#fbbf24"
                st.markdown(f"""
<div class="log-card" style="border-left-color:{level_color}">
  <span style="color:{level_color}; font-weight:bold;">
    {'🔴 CRITICAL' if a['alert_level']=='critical' else '🟡 WARNING'}
  </span>
  <span style="color:#a5f3fc; margin-left:8px;">{a['source_ip']}</span>
  <span style="color:#8b949e; margin-left:8px;">{a['oid_name']}</span>
  <span style="color:#fde68a; margin-left:8px; font-weight:bold;">{a['value']} {a['unit']}</span>
  <span style="color:#8b949e; float:right; font-size:11px;">{a['recorded_at'][:19]}</span>
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
                "APRESIA", "RHEL/Linux", "Windows", "その他"
            ])

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
