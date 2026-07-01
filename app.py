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
tab_health, tab1, tab2, tab3, tab4, tab5, tab_pcap = st.tabs([
    "📊 品質ルーブリック", "📋 ログビューア", "📊 テレメトリダッシュボード",
    "📡 SNMPモニター", "🗂️ 機器コンフィグ", "📖 セットアップガイド",
    "📦 パケット解析"
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
        if st.button("🔄 品質チェック実行", use_container_width=True):
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

                st.markdown("<hr style='border-color:#e9edf2; margin:8px 0;'>", unsafe_allow_html=True)

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
            st.markdown("#### 📍 ルーティングテーブル取得（SNMP Walk）")
            st.caption("ipRouteTable(RFC1213)をSNMP Walkで自動取得します。")
            rt_col1, rt_col2 = st.columns([1, 3])
            with rt_col1:
                if st.button("📍 ルーティングテーブル取得", key="fetch_rt"):
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
                                st.warning("ルートが取得できませんでした（機器の到達性・コミュニティを確認してください）")
                        except Exception as e:
                            st.error(f"取得エラー: {e}")
                    st.rerun()
            with rt_col2:
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
            snmp_routes = snmp_poller.get_routing_table(sel_icmp_ip)
            routing_summary = ""
            if snmp_routes:
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

            # ── ④ AI自動原因推定 ──
            st.markdown("**🤖 AI自動原因推定**")
            llm_ok = analyzer.check_claude_available() or analyzer.check_ollama_available()
            if llm_ok:
                if st.button("🔍 ICMP redirect根本原因をAIで診断", key="icmp_ai_diag"):
                    with st.spinner("AIがICMP redirect原因を分析中..."):
                        dev_snmp = [r for r in icmp_rows if r["source_ip"] == sel_icmp_ip]
                        dev_logs = [l for l in redirect_logs if l.get("source_ip") == sel_icmp_ip]
                        result = analyzer.diagnose_icmp_redirect(
                            ip=sel_icmp_ip,
                            snmp_data=dev_snmp,
                            redirect_logs=dev_logs,
                            routing_summary=routing_summary,
                            mode=st.session_state.get("llm_mode", "auto")
                        )
                    if result:
                        st.markdown(f"**🎯 根本原因:** {result.get('root_cause','')}")
                        if result.get("causal_chain"):
                            st.markdown("**🔗 因果連鎖:** " + " ".join(result["causal_chain"]))
                        if result.get("routing_issue"):
                            st.markdown(f"**⚙️ ルーティング問題:** {result.get('routing_issue','')}")
                        st.markdown(f"**🚨 最優先対処:** {result.get('priority_action','')}")
                        if result.get("additional_checks"):
                            st.markdown("**📋 追加確認事項:**")
                            for c in result["additional_checks"]:
                                st.markdown(f"  - {c}")
                        st.markdown(f"**⚠️ 放置リスク:** {result.get('risk_if_ignored','')}")
                        st.caption(f"診断モデル: {result.get('diagnosis_model','')}")
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

# ═══════════════════════════════════════════
# TAB: パケット解析（Wireshark pcap/pcapng）
# ═══════════════════════════════════════════
with tab_pcap:
    import pcap_analyzer

    st.markdown("## 📦 パケット解析（Wireshark pcap/pcapng）")
    st.caption("Wiresharkでキャプチャしたファイルをアップロードすると、ICMP redirect・RIP・ARP異常などを自動解析します。")

    uploaded_pcap = st.file_uploader(
        "pcap / pcapng ファイルをアップロード",
        type=["pcap", "pcapng", "cap"],
        help="Wiresharkの「名前を付けて保存」で .pcapng 形式で保存したファイルをそのままアップロードできます。"
    )

    if uploaded_pcap is not None:
        with st.spinner("パケットを解析中..."):
            raw_bytes = uploaded_pcap.read()
            res = pcap_analyzer.analyze_pcap(raw_bytes)

        if res["error"]:
            st.error(f"解析エラー: {res['error']}")
        else:
            # ── 概要 ───────────────────────────────────
            st.markdown("---")
            st.markdown("### 📊 キャプチャ概要")
            ov_cols = st.columns(5)
            with ov_cols[0]:
                st.metric("総パケット数", f"{res['total_packets']:,}")
            with ov_cols[1]:
                st.metric("ICMP redirect 検出", len(res["icmp_redirects"]),
                          delta="⚠️ 要確認" if res["icmp_redirects"] else None)
            with ov_cols[2]:
                st.metric("pcap内syslog", len(res.get("syslog_packets", [])),
                          delta="📋 解析済" if res.get("syslog_packets") else None)
            with ov_cols[3]:
                st.metric("RIPパケット", len(res["rip_packets"]))
            with ov_cols[4]:
                st.metric("ARP異常", len(res["arp_anomalies"]),
                          delta="⚠️ 要確認" if res["arp_anomalies"] else None)
            st.caption(f"📅 キャプチャ範囲: {res['capture_start']} 〜 {res['capture_end']}")

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
                st.dataframe(pair_count, use_container_width=True, hide_index=True)

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

                llm_ok = analyzer.check_claude_available() or analyzer.check_ollama_available()
                if llm_ok:
                    if st.button("🔍 統合AI診断を実行", key="pcap_ai_diag"):
                        # ルーターIPを自動検出
                        router_ips = df_red["router_ip"].unique().tolist()
                        sel_router = router_ips[0] if router_ips else ""

                        # routing summary（SNMP or コンフィグ）
                        routing_summary = ""
                        snmp_routes = snmp_poller.get_routing_table(sel_router)
                        if snmp_routes:
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

                        with st.spinner("AIが pcap + syslog + SNMP を統合分析中..."):
                            result_ai = analyzer.diagnose_icmp_redirect(
                                ip=sel_router,
                                snmp_data=snmp_latest,
                                redirect_logs=dev_logs,
                                routing_summary=routing_summary + "\n" + pcap_ctx,
                                mode=st.session_state.get("llm_mode", "auto")
                            )
                        if result_ai:
                            st.markdown(f"**🎯 根本原因:** {result_ai.get('root_cause','')}")
                            if result_ai.get("causal_chain"):
                                st.markdown("**🔗 因果連鎖:** " + " → ".join(result_ai["causal_chain"]))
                            if result_ai.get("routing_issue"):
                                st.markdown(f"**⚙️ ルーティング問題:** {result_ai.get('routing_issue','')}")
                            st.markdown(f"**🚨 最優先対処:** {result_ai.get('priority_action','')}")
                            if result_ai.get("additional_checks"):
                                st.markdown("**📋 追加確認事項:**")
                                for c in result_ai["additional_checks"]:
                                    st.markdown(f"  - {c}")
                            st.warning(f"**⚠️ 放置リスク:** {result_ai.get('risk_if_ignored','')}")
                            st.caption(f"診断モデル: {result_ai.get('diagnosis_model','')} | "
                                       f"データソース: pcapng + syslog + SNMP")
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
                st.markdown("### 🔌 TCP RST 多発")
                df_tcp = pd.DataFrame(res["tcp_issues"])
                df_tcp.columns = ["送信元","宛先","RST回数","説明"]
                st.dataframe(df_tcp, use_container_width=True, hide_index=True)

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
| 🤖 AI統合診断 | pcap + syslog + SNMP を統合してAIが根本原因推定 |
        """)
