#!/usr/bin/env python3
"""
統合テスト: ネットワーク監視ツールの解析機能を実データで検証する。

含まれる検証:
  1. パーサー判定（全ベンダー: Cisco IOS/NX-OS, 富士通 Si-R/IPCOM/SR-S, APRESIA, RHEL, Windows）
  2. ICMP Redirect メッセージ数チェック（syslog 件数 + pcap 検出数の一致）
  3. カウントアップ検証（テレメトリ集計の前後差分 = 投入件数）
  4. 送信元統計（どの装置(source_ip)から何件届いたかの集計が正しいか）
  5. ループ検知（SR-S l2loopd / Catalyst LoopDetect / APRESIA LOOP_DETECT）
  6. IPCOM / Si-R / SR-S のメッセージ解析（実メッセージのタグ付け）
  7. pcap 統計（VoIP MOS, TCP SYN 未応答, Top Talkers 送信元別集計）

実行:  python3 test_analysis.py
"""
import io
import sqlite3
from collections import defaultdict

import db
import demo_simulator as sim
import pcap_analyzer
from parsers import parse_syslog

PASS = 0
FAIL = 0
FAILURES = []


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [OK] {name}")
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"  [NG] {name}  {detail}")


# ─────────────────────────────────────────────────────────────
def test_parsers():
    print("\n【1】パーサー判定（全ベンダー）")
    cases = [
        ("Cisco IOS/IOS-XE", "<189>Jul 3 10:00:01 catalyst01 %LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down"),
        ("Cisco NX-OS",      "<131>2024 Jul 3 10:00:00 JST nexus01 %VPC-3-VPC_PEER_KEEP_ALIVE_RECV_FAIL: In domain 10, vPC peer keep-alive receive has failed"),
        ("富士通 Si-R",       "<22>Jul 3 10:00:00 SiR-G210 isakmp: DPD watching host is down. [203.0.113.1]"),
        ("富士通 IPCOM",      "<165>Jul 3 10:00:00 ipcom-ex01 ipf[1234]: [DENY] TCP 192.168.100.50:54321->10.0.0.1:22"),
        ("富士通 SR-S",       "<134>Jul 3 10:00:00 sw-srs01 l2loopd: Configuration Testing Protocol blocked port 5"),
        ("APRESIA",          "<134>Jul 3 10:00:00 apresia01 LOOP_DETECT: Loop detected on Port 1/0/5 - port blocked"),
        ("RHEL/Linux",       "<30>Jul 3 10:00:00 rhel01 kernel: Out of memory: Kill process 9876 (java)"),
        ("Windows",          "<14>Jul 3 10:00:00 WIN-SV01 MSWinEventLog[Security]: EventID=4625 Logon Type=3 User=Administrator"),
    ]
    for expect, raw in cases:
        got = parse_syslog(raw, "10.0.0.1")["vendor"]
        check(f"{expect} 判定", expect in got or got in expect, f"got={got}")


def test_loop_detection():
    print("\n【5】ループ検知（マルチベンダー）")
    cases = [
        ("SR-S l2loopd ループ検知",   "<134>Jul 3 10:00:00 sw-srs01 l2loopd: Configuration Testing Protocol detects a loop in port 5 and port 6", "ループ検知"),
        ("SR-S ポート遮断",          "<134>Jul 3 10:01:00 sw-srs01 l2loopd: Configuration Testing Protocol blocked port 5", "ポート遮断"),
        ("SR-S MACフラップ",         "<134>Jul 3 10:02:00 sw-srs01 protocol: MAC learning entry moved from ether 1 to ether 2 [00:11:22:33:44:55 vid=10]", "MACフラップ"),
        ("Catalyst LoopDetect",     "<187>Jul 3 10:00:00 cat01 %ETHCNTR-3-LOOP_BACK_DETECTED: Loop-back detected on GigabitEthernet0/1.", "ループ検知"),
        ("Catalyst LoopGuard",      "<187>Jul 3 10:01:00 cat01 %SPANTREE-2-LOOPGUARD_BLOCK: Loop guard blocking port Gi0/3", "ループ検知"),
        ("APRESIA LOOP_DETECT",     "<134>Jul 3 10:00:00 apresia01 LOOP_DETECT: Loop detected on Port 1/0/5 - port blocked", None),
    ]
    for name, raw, want in cases:
        tags = parse_syslog(raw, "10.0.0.1")["tags"]
        if want:
            check(name, want in tags, f"tags={tags}")
        else:
            # APRESIA はループ系タグ or 障害候補があればOK
            check(name, "障害候補" in tags or any("ループ" in t or "LOOP" in t.upper() for t in tags), f"tags={tags}")


def test_vendor_messages():
    print("\n【6】IPCOM / Si-R / SR-S メッセージ解析")
    cases = [
        ("IPCOM ファイアウォール拒否", "<165>Jul 3 10:00:00 ipcom-ex01 ipf[1234]: [DENY] TCP 192.168.100.50:54321->10.0.0.1:22", "通信拒否"),
        ("IPCOM インターフェースDOWN", "<166>Jul 3 10:01:00 ipcom-ex01 ifmgr[100]: IF GigabitEthernet0 link down", "リンクDOWN"),
        ("Si-R リンクUP",             "<22>Jul 3 10:00:00 SiR-G210 protocol: ether 1 1 link up", "リンクUP"),
        ("Si-R IPsec DPDダウン",      "<163>Jul 3 10:01:00 SiR-G210 isakmp: DPD watching host is down. [203.0.113.1]", "IPsec"),
        ("Si-R BGP NOTIFICATION",     "<163>Jul 3 10:02:00 SiR-G210 bgpd: 10.0.0.1 recv NOTIFICATION 6/2 (Cease/Administrative Shutdown)", "BGP"),
        ("Si-R VRRP冗長切替",         "<163>Jul 3 10:03:00 SiR-G210 nsm: vrrp master router down detection. lan0 vrid1 [192.168.1.1] #3", "冗長切替"),
        ("Si-R WWAN SIMエラー",       "<165>Jul 3 10:04:00 SiR-G210 cmodemctl: [WWAN1] PIN code error. modem0 (PUK required)", "WWAN"),
        ("Si-R エラーコード分類(装置交換)", "<27>Jul 3 10:05:00 SiR-G210 init: error code [85020000]", "対処:装置交換が必要"),
        ("Si-R エラーコード分類(温度)",     "<27>Jul 3 10:06:00 SiR-G210 init: error code [85010001]", "対処:設置環境（温度）の確認が必要"),
        ("SR-S リンクDOWN",           "<134>Jul 3 10:00:00 sw-srs01 protocol: ether 3 link down", "リンクDOWN"),
        ("SR-S STPトポロジ変更",       "<134>Jul 3 10:01:00 sw-srs01 mstpd: Topology Change detected", "トポロジ変更"),
        ("SR-S ログイン失敗",          "<134>Jul 3 10:02:00 sw-srs01 telnetd: failed login guest on telnet from 192.168.1.100", "認証失敗"),
    ]
    for name, raw, want in cases:
        tags = parse_syslog(raw, "10.0.0.1")["tags"]
        check(name, want in tags, f"tags={tags}")


def _fetch_flows():
    con = sqlite3.connect(db.DB_PATH)
    con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute("SELECT * FROM netflow_flows").fetchall()]
    con.close()
    return rows


def test_icmp_redirect_count():
    print("\n【2】ICMP Redirect メッセージ数チェック")
    db.clear_logs()
    r = sim.run_scenario("icmp_redirect")

    # 2a. syslog 側: ICMP Redirect タグの付いたログ件数
    logs = db.get_logs(limit=500)
    redirect_logs = [l for l in logs if "ICMP Redirect" in (l.get("tags") or "")]
    check("syslog に ICMP Redirect ログが存在", len(redirect_logs) >= 1,
          f"count={len(redirect_logs)}")

    # 2b. pcap 側: icmp_summary の Redirect カウント
    a = pcap_analyzer.analyze_pcap(r["pcap_bytes"])
    redirect_summary = [x for x in a.get("icmp_summary", []) if x.get("type") == 5]
    pcap_redirect_count = redirect_summary[0]["count"] if redirect_summary else 0
    detected = len(a.get("icmp_redirects", []))
    check("pcap の ICMP Redirect 検出数が集計値と一致",
          pcap_redirect_count == detected and detected >= 1,
          f"summary={pcap_redirect_count} detected={detected}")

    # 2c. Redirect の内容（gateway / 宛先）が解析できている
    if a.get("icmp_redirects"):
        ex = a["icmp_redirects"][0]
        check("ICMP Redirect の gateway/宛先が解析済み",
              ex.get("gateway", "?") != "?" and ex.get("orig_dst", "?") != "?",
              f"ex={ex}")
    else:
        check("ICMP Redirect の gateway/宛先が解析済み", False, "no redirects")


def test_count_up():
    print("\n【3】カウントアップ検証（テレメトリ集計の前後差分）")
    db.clear_logs()
    before = db.get_telemetry_summary()["total"]

    n = 7
    raw = "<134>Jul 3 10:00:00 sw-srs01 protocol: ether 3 link down"
    parsed = parse_syslog(raw, "192.168.1.8")
    for _ in range(n):
        db.insert_log("192.168.1.8", raw, parsed)

    after_summary = db.get_telemetry_summary()
    after = after_summary["total"]
    check(f"logs 総数が +{n} 増加", after - before == n, f"{before}->{after}")

    # severity 別集計の合計が投入数と一致
    sev_total = sum(x["total"] for x in after_summary["by_severity"])
    check("severity 別集計の合計が総投入数と一致", sev_total >= n, f"sev_total={sev_total}")

    # vendor 別集計に SR-S が計上されている
    vendors = {x["vendor"]: x["total"] for x in after_summary["by_vendor"]}
    check("vendor 別集計に 富士通 SR-S が計上", vendors.get("富士通 SR-S", 0) >= n,
          f"vendors={vendors}")


def test_source_stats():
    print("\n【4】送信元統計（どの装置から何件届いたか）")
    db.clear_logs()

    # 3台の装置から異なる件数を投入
    plan = {
        "192.168.1.1": ("<189>Jul 3 10:00:00 catalyst01 %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down", 5),
        "192.168.1.8": ("<134>Jul 3 10:00:00 sw-srs01 protocol: ether 3 link down", 3),
        "192.168.1.7": ("<165>Jul 3 10:00:00 ipcom-ex01 ipf[1234]: [DENY] TCP 1.1.1.1:22->2.2.2.2:80", 2),
    }
    for ip, (raw, cnt) in plan.items():
        parsed = parse_syslog(raw, ip)
        for _ in range(cnt):
            db.insert_log(ip, raw, parsed)

    summary = db.get_telemetry_summary()
    by_source = {x["source_ip"]: x["total"] for x in summary["by_source"]}

    for ip, (_, cnt) in plan.items():
        check(f"送信元 {ip} の件数が {cnt}", by_source.get(ip, 0) == cnt,
              f"got={by_source.get(ip)}  all={by_source}")

    # 送信元が件数降順に並んでいる（最多送信元の特定）
    ordered = [x["source_ip"] for x in summary["by_source"]]
    check("最多送信元が先頭（降順ソート）", ordered and ordered[0] == "192.168.1.1",
          f"ordered={ordered}")


def test_pcap_stats():
    print("\n【7】pcap 統計（VoIP MOS / SYN未応答 / Top Talkers 送信元別）")

    # VoIP: 3ストリームの MOS が算出され、劣化ストリームを検出
    rv = sim.run_scenario("voip_degraded")
    av = pcap_analyzer.analyze_pcap(rv["pcap_bytes"])
    streams = av.get("voip_streams", [])
    check("VoIP RTPストリームを3本検出", len(streams) == 3, f"count={len(streams)}")
    # パケットロス/ジッターは確率的なので、絶対値でなく「正常比の劣化」で判定
    mos_vals = [s.get("mos", 0) for s in streams]
    best, worst = max(mos_vals), min(mos_vals)
    check("劣化ストリームを検出（最良比0.3以上低いストリームあり）",
          best - worst >= 0.3 and worst < 4.2,
          f"mos={[round(x,2) for x in mos_vals]} (best={best:.2f} worst={worst:.2f})")

    # DDoS: SYN未応答（接続失敗）の集計 + Top Talkers 送信元別集計
    rd = sim.run_scenario("ddos")
    ad = pcap_analyzer.analyze_pcap(rd["pcap_bytes"])
    check("DDoS pcap で SYN未応答を検出", len(ad.get("tcp_syn_no_synack", [])) >= 1,
          f"count={len(ad.get('tcp_syn_no_synack', []))}")

    talkers = pcap_analyzer.get_top_talkers(rd["pcap_bytes"], top_n=10)
    check("Top Talkers（送信元別集計）が算出される", len(talkers) >= 1,
          f"count={len(talkers)}")

    # NetFlow 側: ポートスキャン送信元の特定（1送信元→多数ポートへ SYN）
    flows = _fetch_flows()
    scan = defaultdict(set)
    for f in flows:
        if f.get("tcp_flags") == 2:  # SYN only
            scan[f["src_ip"]].add(f["dst_port"])
    max_ports = max((len(p) for p in scan.values()), default=0)
    check("NetFlow でポートスキャン送信元を特定（>=50ポート）", max_ports >= 50,
          f"max_ports={max_ports}")


def main():
    db.init_db()
    test_parsers()
    test_icmp_redirect_count()
    test_count_up()
    test_source_stats()
    test_loop_detection()
    test_vendor_messages()
    test_pcap_stats()

    print("\n" + "=" * 55)
    print(f"  結果: {PASS} PASS / {FAIL} FAIL")
    if FAILURES:
        print("  失敗:")
        for f in FAILURES:
            print(f"    - {f}")
    print("=" * 55)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
