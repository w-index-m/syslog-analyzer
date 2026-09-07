#!/usr/bin/env python3
"""
リアルタイム簡易IDS（ライブキャプチャ→検知→syslog通知）

このリポジトリの検知エンジン（pcap_analyzer.py）をそのまま再利用し、
一定間隔ごとにライブキャプチャしたトラフィックを解析、検知結果をsyslogで
リアルタイム通知する常駐プログラム。Windows / Linux / macOS 対応。

Streamlit UI / pcap_mcp_server.py（MCP版）と同じ検知エンジンを使うため、
検知内容（横展開8手口・IPS/IDSシグネチャ・フィッシング・DNSトンネリング・
脅威インテリジェンス照合・GeoIP/ASN判定等）は完全に一致する。
「N秒ごとにキャプチャ→まとめて解析」という設計のため、パケット単位の
即時通知ではなく準リアルタイム（既定30秒間隔）である点に注意。

要件:
  - Windows: Npcap（https://npcap.com からインストール。Wiresharkに同梱の
    インストーラでも可）。キャプチャ本体は同梱の dumpcap.exe を使う
    （既定パス: C:\\Program Files\\Wireshark\\dumpcap.exe。別の場所に
    インストールした場合は --capture-tool で指定）。管理者権限で実行すること。
  - Linux/macOS: tcpdump（大抵は標準搭載。無ければ `apt install tcpdump` 等）。
    root権限（またはCAP_NET_RAW）で実行すること。

使い方:
  # Windows（管理者権限のコマンドプロンプト/PowerShellで）
  python realtime_ids.py --iface "イーサネット" --syslog-host 127.0.0.1 --syslog-port 5140

  # Windowsでインターフェース名が分からない場合、一覧を表示
  python realtime_ids.py --list-interfaces

  # Linux（sudoで）
  sudo python3 realtime_ids.py --iface eth0 --syslog-host 127.0.0.1 --syslog-port 5140

  # BPFフィルタで対象を絞る例（SSH管理通信は除外）
  sudo python3 realtime_ids.py --iface eth0 --filter "not port 22"

  # 動作確認用: 既存のpcapファイルを1回だけ解析してsyslog送信（キャプチャツール不要）
  python3 realtime_ids.py --replay-file demo.pcap --syslog-host 127.0.0.1 --syslog-port 5140
"""
import argparse
import hashlib
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime

import pcap_analyzer

IS_WINDOWS = platform.system() == "Windows"

# Windows で dumpcap.exe が入っていそうな既定パス（Wireshark同梱）
_DEFAULT_DUMPCAP_PATHS = [
    r"C:\Program Files\Wireshark\dumpcap.exe",
    r"C:\Program Files (x86)\Wireshark\dumpcap.exe",
]

# ── syslog送信 ──────────────────────────────────────────────
# severity(このツールの検知結果の重大度語) -> syslog severity番号(RFC5424)
_SEVERITY_TO_SYSLOG = {"critical": 2, "high": 3, "medium": 4, "low": 5}


def send_syslog(host: str, port: int, facility: int, severity_word: str,
                 tag: str, message: str) -> None:
    """RFC3164形式の簡易syslogメッセージをUDPで送信する。"""
    pri_severity = _SEVERITY_TO_SYSLOG.get(severity_word, 5)
    pri = facility * 8 + pri_severity
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    hostname = socket.gethostname()
    raw = f"<{pri}>{ts} {hostname} {tag}: {message}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(raw.encode("utf-8", errors="replace")[:2048], (host, port))
    finally:
        sock.close()


# ── 管理者/root権限チェック（OS別） ─────────────────────────
def is_elevated() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


# ── キャプチャツールの解決（OS別） ───────────────────────────
def _resolve_capture_tool(explicit_path: str = "") -> str:
    """使用するキャプチャコマンド（dumpcap.exe または tcpdump）の実行パスを返す。"""
    if explicit_path:
        return explicit_path
    if IS_WINDOWS:
        for p in _DEFAULT_DUMPCAP_PATHS:
            if os.path.isfile(p):
                return p
        return "dumpcap.exe"   # PATHが通っている前提でフォールバック
    return "tcpdump"


def list_interfaces(explicit_path: str = "") -> None:
    """利用可能なキャプチャインターフェース一覧を表示する（-D相当）。"""
    tool = _resolve_capture_tool(explicit_path)
    cmd = [tool, "-D"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        print(out.stdout or out.stderr)
    except FileNotFoundError:
        _print_tool_missing_hint(tool)
        sys.exit(1)


def _print_tool_missing_hint(tool: str) -> None:
    if IS_WINDOWS:
        print(f"❌ キャプチャツールが見つかりません: {tool}\n"
              "   Npcap（https://npcap.com）または Wireshark をインストールしてください。\n"
              "   インストール先が既定と異なる場合は --capture-tool で dumpcap.exe の"
              "パスを指定してください。", file=sys.stderr)
    else:
        print(f"❌ キャプチャツールが見つかりません: {tool}\n"
              "   `sudo apt install tcpdump`（Debian/Ubuntu）や"
              "`sudo yum install tcpdump`（RHEL系）でインストールしてください。",
              file=sys.stderr)


# ── ライブキャプチャ ─────────────────────────────────────────
def capture_snippet(iface: str, duration: int, bpf_filter: str = "",
                     capture_tool: str = "") -> bytes:
    """指定秒数キャプチャし、pcapバイト列を返す（Windows: dumpcap / Linux: tcpdump）。"""
    tool = _resolve_capture_tool(capture_tool)
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)

    if IS_WINDOWS:
        # dumpcap は -a duration:N で自動停止できるため確実に終了させられる
        cmd = [tool, "-i", iface, "-w", path, "-a", f"duration:{duration}"]
        if bpf_filter:
            cmd += ["-f", bpf_filter]
        try:
            subprocess.run(cmd, capture_output=True, timeout=duration + 15)
        except FileNotFoundError:
            _print_tool_missing_hint(tool)
            raise
        except subprocess.TimeoutExpired:
            pass
    else:
        cmd = [tool, "-i", iface, "-w", path, "-U"]
        if bpf_filter:
            cmd += bpf_filter.split()
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            _print_tool_missing_hint(tool)
            raise
        try:
            time.sleep(duration)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    try:
        with open(path, "rb") as f:
            return f.read()
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


# ── 検知結果 → syslog通知 ───────────────────────────────────
# (result辞書のキー, syslogタグ) の対応。いずれもpcap_analyzer.analyze_pcap()の
# 出力に含まれるリスト型フィールドで、各要素は {"severity", "detail"|"description", ...} の形式。
_FINDING_FIELDS = [
    ("lateral_movement_techniques", "IDS-LATERAL"),
    ("worm_propagation",            "IDS-WORM"),
    ("beaconing",                   "IDS-C2BEACON"),
    ("data_exfil",                  "IDS-EXFIL"),
    ("suspicious_destinations",     "IDS-SUSPDEST"),
    ("threat_intel_hits",           "IDS-THREATINTEL"),
    ("ips_alerts",                  "IDS-SIGNATURE"),
    ("scan_patterns",               "IDS-SCAN"),
    ("dns_tunneling",               "IDS-DNSTUNNEL"),
    ("icmp_exfil",                  "IDS-ICMPEXFIL"),
    ("geo_alerts",                  "IDS-GEO"),
    ("asn_hosts",                   "IDS-ASN"),
]

_seen_hashes: set[str] = set()


def _finding_key(tag: str, item: dict) -> str:
    """同じ検知を毎サイクル再通知しないための重複排除キー。"""
    basis = f"{tag}|{item.get('src','')}|{item.get('dst','')}|" \
            f"{item.get('technique') or item.get('type') or item.get('domain') or ''}"
    return hashlib.sha1(basis.encode("utf-8", errors="replace")).hexdigest()


def analyze_and_notify(pcap_bytes: bytes, syslog_host: str, syslog_port: int,
                        facility: int, quiet: bool = False) -> int:
    """pcapバイト列をanalyze_pcap()に通し、新規検知だけsyslog通知する。戻り値: 通知件数。"""
    if not pcap_bytes:
        return 0
    result = pcap_analyzer.analyze_pcap(pcap_bytes)
    if result.get("error"):
        print(f"[!] 解析エラー: {result['error']}", file=sys.stderr)
        return 0

    notified = 0
    for field, tag in _FINDING_FIELDS:
        for item in (result.get(field) or []):
            key = _finding_key(tag, item)
            if key in _seen_hashes:
                continue
            _seen_hashes.add(key)
            severity = item.get("severity", "medium")
            detail = item.get("detail") or item.get("description") or str(item)
            send_syslog(syslog_host, syslog_port, facility, severity, tag, detail[:800])
            notified += 1
            if not quiet:
                print(f"  [{severity}] {tag}: {detail[:120]}")

    if notified and not quiet:
        print(f"[{datetime.now().isoformat(timespec='seconds')}] "
              f"{notified}件の新規検知をsyslog通知しました "
              f"({syslog_host}:{syslog_port})")
    return notified


# ── メインループ ─────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="リアルタイム簡易IDS: ライブキャプチャ→検知→syslog通知（Windows/Linux対応）")
    ap.add_argument("--iface",
                     help="キャプチャするインターフェース名"
                          "（Linux: 'eth0' 等 / Windows: --list-interfaces で確認した名前）")
    ap.add_argument("--list-interfaces", action="store_true",
                     help="利用可能なキャプチャインターフェース一覧を表示して終了")
    ap.add_argument("--capture-tool", default="",
                     help="キャプチャツールの実行パス（既定: Windows=dumpcap.exe / Linux=tcpdump）")
    ap.add_argument("--replay-file",
                     help="ライブキャプチャの代わりに、既存のpcapファイルを1回だけ解析する"
                          "（動作確認用・キャプチャツール不要）")
    ap.add_argument("--interval", type=int, default=30,
                     help="キャプチャ間隔(秒)。準リアルタイムのため短くしすぎると"
                          "解析が追いつかない場合がある（既定30秒）")
    ap.add_argument("--filter", default="", help="BPFフィルタ（例: 'not port 22'）")
    ap.add_argument("--syslog-host", default="127.0.0.1")
    ap.add_argument("--syslog-port", type=int, default=5140)
    ap.add_argument("--facility", type=int, default=4,
                     help="syslog facility番号(0-23、既定4=security/auth相当)")
    ap.add_argument("--quiet", action="store_true", help="標準出力への経過表示を抑制")
    args = ap.parse_args()

    if args.list_interfaces:
        list_interfaces(args.capture_tool)
        return

    if not args.iface and not args.replay_file:
        ap.error("--iface（ライブキャプチャ）または --replay-file（動作確認用）のいずれかが必要です")

    if args.replay_file:
        with open(args.replay_file, "rb") as f:
            data = f.read()
        n = analyze_and_notify(data, args.syslog_host, args.syslog_port,
                               args.facility, quiet=args.quiet)
        print(f"完了: {n}件をsyslog通知しました。")
        return

    if not is_elevated():
        who = "管理者として実行（右クリック→管理者として実行）" if IS_WINDOWS else "sudoで実行"
        print(f"⚠️ パケットキャプチャには管理者/root権限が必要です（{who}してください）",
              file=sys.stderr)

    print(f"[+] インターフェース {args.iface} を{args.interval}秒間隔でキャプチャし、"
          f"検知結果を {args.syslog_host}:{args.syslog_port} へsyslog通知します"
          f"（Ctrl+Cで終了）")
    while True:
        try:
            data = capture_snippet(args.iface, args.interval,
                                    bpf_filter=args.filter, capture_tool=args.capture_tool)
            analyze_and_notify(data, args.syslog_host, args.syslog_port,
                               args.facility, quiet=args.quiet)
        except KeyboardInterrupt:
            print("\n[+] 終了します")
            break
        except FileNotFoundError:
            sys.exit(1)
        except Exception as e:
            print(f"[!] エラー: {e}", file=sys.stderr)
            time.sleep(5)


if __name__ == "__main__":
    main()


# ─────────────────────────────────────────────────────────────
# 常駐サービス化する場合の例
#
# ■ Windows: タスクスケジューラで「ログオン時」「管理者として実行」トリガーの
#   タスクを作成し、以下を実行させる:
#     プログラム: C:\Python311\python.exe
#     引数: C:\syslog-analyzer\realtime_ids.py --iface "イーサネット" ^
#           --syslog-host 192.168.1.10 --syslog-port 5140
#   （NSSM 等でWindowsサービス化することも可能）
#
# ■ Linux: systemdサービス化する場合の例
#   /etc/systemd/system/realtime-ids.service
#
#   [Unit]
#   Description=Realtime IDS (syslog notify)
#   After=network.target
#
#   [Service]
#   ExecStart=/usr/bin/python3 /opt/syslog-analyzer/realtime_ids.py \
#       --iface eth0 --interval 30 --syslog-host 192.168.1.10 --syslog-port 5140
#   Restart=always
#   User=root
#
#   [Install]
#   WantedBy=multi-user.target
#
#   有効化: sudo systemctl enable --now realtime-ids
# ─────────────────────────────────────────────────────────────
