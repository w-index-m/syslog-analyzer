"""
Cisco IOS-XE RESTCONF クライアント
- ルーティングテーブル取得（SNMP Walk より高速）
- EPC（monitor capture）のリモート起動・停止・エクスポート
- ICMP Redirect 急増時の EPC 自動トリガー

IOS-XE 側の事前設定:
    conf t
     ip http server
     ip http secure-server
     ip http authentication local
     restconf
    end
"""
import os
import json
import sqlite3
import threading
import time
import requests
from datetime import datetime
from pathlib import Path

# SSL 警告を抑制（自己署名証明書対応）
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DB_PATH = Path(os.environ.get("DB_PATH", str(Path(__file__).parent / "syslog.db")))

_RESTCONF_HEADERS = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}

# EPC 自動起動中のデバイスを追跡（IP → threading.Timer）
_epc_active: dict[str, threading.Timer] = {}
_epc_lock = threading.Lock()


# ─────────────────────────────────────────
# DB 初期化・CRUD
# ─────────────────────────────────────────

def _init_tables():
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS restconf_devices (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                ip                TEXT UNIQUE NOT NULL,
                username          TEXT NOT NULL,
                password          TEXT NOT NULL,
                port              INTEGER DEFAULT 443,
                verify_ssl        INTEGER DEFAULT 0,
                epc_interface     TEXT DEFAULT '',
                epc_auto_trigger  INTEGER DEFAULT 0,
                epc_threshold     INTEGER DEFAULT 10,
                epc_duration_sec  INTEGER DEFAULT 60
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS epc_events (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                triggered_at     TEXT NOT NULL,
                source_ip        TEXT NOT NULL,
                trigger_reason   TEXT,
                capture_name     TEXT,
                status           TEXT,
                pcap_flash_path  TEXT
            )
        """)
        conn.commit()


def add_device(ip: str, username: str, password: str, port: int = 443,
               verify_ssl: bool = False, epc_interface: str = "",
               epc_auto_trigger: bool = False, epc_threshold: int = 10,
               epc_duration_sec: int = 60):
    _init_tables()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            INSERT INTO restconf_devices
            (ip, username, password, port, verify_ssl, epc_interface,
             epc_auto_trigger, epc_threshold, epc_duration_sec)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
                username=excluded.username, password=excluded.password,
                port=excluded.port, verify_ssl=excluded.verify_ssl,
                epc_interface=excluded.epc_interface,
                epc_auto_trigger=excluded.epc_auto_trigger,
                epc_threshold=excluded.epc_threshold,
                epc_duration_sec=excluded.epc_duration_sec
        """, (ip, username, password, port, int(verify_ssl), epc_interface,
              int(epc_auto_trigger), epc_threshold, epc_duration_sec))
        conn.commit()


def get_devices() -> list[dict]:
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("SELECT * FROM restconf_devices").fetchall()]


def get_device(ip: str) -> dict | None:
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM restconf_devices WHERE ip=?", (ip,)
        ).fetchone()
        return dict(row) if row else None


def remove_device(ip: str):
    _init_tables()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("DELETE FROM restconf_devices WHERE ip=?", (ip,))
        conn.commit()


def _log_epc_event(source_ip: str, trigger_reason: str, capture_name: str,
                   status: str, pcap_flash_path: str = ""):
    _init_tables()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            INSERT INTO epc_events
            (triggered_at, source_ip, trigger_reason, capture_name, status, pcap_flash_path)
            VALUES (?,?,?,?,?,?)
        """, (datetime.now().isoformat(), source_ip, trigger_reason,
              capture_name, status, pcap_flash_path))
        conn.commit()


def get_epc_events(ip: str = None, limit: int = 20) -> list[dict]:
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if ip:
            rows = conn.execute("""
                SELECT * FROM epc_events WHERE source_ip=?
                ORDER BY triggered_at DESC LIMIT ?
            """, (ip, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM epc_events ORDER BY triggered_at DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]


# ─────────────────────────────────────────
# RESTCONF クライアント
# ─────────────────────────────────────────

class RestconfClient:
    def __init__(self, ip: str, username: str, password: str,
                 port: int = 443, verify_ssl: bool = False):
        self.ip = ip
        self.base = f"https://{ip}:{port}"
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = verify_ssl
        self.session.headers.update(_RESTCONF_HEADERS)

    def _get(self, path: str) -> dict | None:
        try:
            r = self.session.get(f"{self.base}{path}", timeout=10)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            print(f"[RESTCONF GET] {self.ip}{path}: {e}")
            return None

    def _post(self, path: str, body: dict) -> dict | None:
        try:
            r = self.session.post(f"{self.base}{path}", json=body, timeout=15)
            r.raise_for_status()
            return r.json() if r.content else {"status": "ok"}
        except Exception as e:
            print(f"[RESTCONF POST] {self.ip}{path}: {e}")
            return None

    # ── CLI RPC ──────────────────────────────
    def run_cli(self, command: str) -> str | None:
        """IOS-XE CLI RPC でコマンドを実行して出力を返す"""
        body = {"Cisco-IOS-XE-rpc:input": {"commands": command}}
        result = self._post("/restconf/operations/Cisco-IOS-XE-rpc:cli", body)
        if result:
            return (result.get("Cisco-IOS-XE-rpc:output") or {}).get("result", "")
        return None

    # ── ルーティングテーブル ──────────────────
    def get_routing_table(self) -> list[dict]:
        """ルーティングテーブルを RESTCONF で取得（Cisco native → IETF の順に試行）"""
        # 1. Cisco IOS-XE 固有（推奨）
        data = self._get(
            "/restconf/data/Cisco-IOS-XE-routing-oper:routing-oper-data"
            "/vrf-operations/vrf-operation=default/route-table-entries"
        )
        if data:
            key = "Cisco-IOS-XE-routing-oper:route-table-entries"
            entries = (data.get(key) or {}).get("route-table-entry", [])
            if entries:
                return [self._norm_cisco(e) for e in entries]

        # 2. IETF standard fallback
        data = self._get(
            "/restconf/data/ietf-routing:routing-state"
            "/routing-instance=default-vrf/ribs/rib=ipv4-unicast/routes"
        )
        if data:
            routes = (data.get("ietf-routing:routes") or {}).get("route", [])
            return [self._norm_ietf(r) for r in routes]

        return []

    def _norm_cisco(self, e: dict) -> dict:
        nh = (e.get("next-hop") or {}).get("next-hop-address", "")
        prefix = e.get("prefix", "")
        parts = prefix.split("/")
        return {
            "dest":    parts[0] if parts else prefix,
            "mask":    parts[1] if len(parts) > 1 else "",
            "nexthop": nh,
            "proto":   e.get("source-protocol", ""),
            "metric":  str(e.get("metric", "")),
            "source":  "restconf",
        }

    def _norm_ietf(self, r: dict) -> dict:
        dest = r.get("destination-prefix", "")
        parts = dest.split("/")
        nh = r.get("next-hop") or {}
        return {
            "dest":    parts[0] if parts else dest,
            "mask":    parts[1] if len(parts) > 1 else "",
            "nexthop": nh.get("next-hop-address", nh.get("outgoing-interface", "")),
            "proto":   r.get("source-protocol", ""),
            "metric":  str(r.get("metric", "")),
            "source":  "restconf",
        }

    # ── EPC 制御 ─────────────────────────────
    def start_epc(self, capture_name: str, interface: str,
                  match: str = "any", buffer_mb: int = 10) -> bool:
        """EPC キャプチャを開始する"""
        cmd = "\n".join([
            f"monitor capture {capture_name} interface {interface} both",
            f"monitor capture {capture_name} match {match}",
            f"monitor capture {capture_name} buffer size {buffer_mb}",
            f"monitor capture {capture_name} start",
        ])
        result = self.run_cli(cmd)
        return result is not None

    def stop_epc(self, capture_name: str) -> bool:
        """EPC キャプチャを停止する"""
        result = self.run_cli(f"monitor capture {capture_name} stop")
        return result is not None

    def export_epc(self, capture_name: str) -> str | None:
        """EPC を flash に pcap エクスポートし、flash パスを返す"""
        fname = f"epc_{capture_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        result = self.run_cli(
            f"monitor capture {capture_name} export flash:{fname}"
        )
        return f"flash:{fname}" if result is not None else None

    def get_epc_status(self, capture_name: str) -> str:
        """show monitor capture の出力を返す"""
        return self.run_cli(f"show monitor capture {capture_name}") or ""


# ─────────────────────────────────────────
# ICMP Redirect → EPC 自動トリガー
# ─────────────────────────────────────────

def check_and_trigger_epc(ip: str, icmp_redirect_diff: int):
    """
    snmp_poller から呼ばれる。ICMP Redirect 差分が閾値を超えたら EPC を自動起動。
    既にキャプチャ中の場合はスキップ。
    """
    dev = get_device(ip)
    if not dev or not dev.get("epc_auto_trigger") or not dev.get("epc_interface"):
        return

    threshold = dev.get("epc_threshold", 10)
    duration = dev.get("epc_duration_sec", 60)
    if icmp_redirect_diff < threshold:
        return

    with _epc_lock:
        if ip in _epc_active:
            return  # 既にキャプチャ中
        _trigger_epc(dev, ip, duration,
                     f"ICMP Redirect {icmp_redirect_diff}/poll (閾値:{threshold})")


def _trigger_epc(dev: dict, ip: str, duration: int, reason: str):
    """EPC を起動し、duration 秒後に自動停止するタイマーをセット"""
    capture_name = f"AUTO_{ip.replace('.', '_')}"
    client = RestconfClient(
        ip, dev["username"], dev["password"],
        dev.get("port", 443), bool(dev.get("verify_ssl"))
    )
    iface = dev["epc_interface"]

    ok = client.start_epc(capture_name, iface)
    status = "started" if ok else "start_failed"
    _log_epc_event(ip, reason, capture_name, status)
    print(f"[EPC AutoTrigger] {ip} capture={capture_name} status={status} reason={reason}")

    if ok:
        timer = threading.Timer(duration, _stop_and_export_epc,
                                args=(ip, capture_name, dev))
        timer.daemon = True
        timer.start()
        _epc_active[ip] = timer


def _stop_and_export_epc(ip: str, capture_name: str, dev: dict):
    """タイマー満了時に EPC を停止してエクスポート"""
    client = RestconfClient(
        ip, dev["username"], dev["password"],
        dev.get("port", 443), bool(dev.get("verify_ssl"))
    )
    client.stop_epc(capture_name)
    pcap_path = client.export_epc(capture_name)
    status = f"exported:{pcap_path}" if pcap_path else "export_failed"
    _log_epc_event(ip, "auto_stop", capture_name, status, pcap_path or "")
    print(f"[EPC AutoTrigger] {ip} auto-stopped capture={capture_name} pcap={pcap_path}")

    with _epc_lock:
        _epc_active.pop(ip, None)


def manual_start_epc(ip: str, capture_name: str = None,
                     duration: int = None) -> dict:
    """手動で EPC を起動（UI や API から呼ぶ）"""
    dev = get_device(ip)
    if not dev:
        return {"ok": False, "error": "RESTCONF デバイス未登録"}
    if not dev.get("epc_interface"):
        return {"ok": False, "error": "EPC インターフェースが設定されていません"}

    cname = capture_name or f"MANUAL_{ip.replace('.','_')}"
    dur = duration or dev.get("epc_duration_sec", 60)
    reason = "手動起動"

    with _epc_lock:
        if ip in _epc_active:
            return {"ok": False, "error": f"既にキャプチャ中です（{cname}）"}
        _trigger_epc(dev, ip, dur, reason)

    return {"ok": True, "capture_name": cname, "duration_sec": dur}


def manual_stop_epc(ip: str) -> dict:
    """手動で EPC を停止しエクスポート"""
    dev = get_device(ip)
    if not dev:
        return {"ok": False, "error": "RESTCONF デバイス未登録"}

    with _epc_lock:
        timer = _epc_active.pop(ip, None)
        if timer:
            timer.cancel()

    capture_name = f"MANUAL_{ip.replace('.','_')}"
    client = RestconfClient(
        ip, dev["username"], dev["password"],
        dev.get("port", 443), bool(dev.get("verify_ssl"))
    )
    client.stop_epc(capture_name)
    pcap_path = client.export_epc(capture_name)
    _log_epc_event(ip, "手動停止", capture_name,
                   f"exported:{pcap_path}" if pcap_path else "export_failed",
                   pcap_path or "")
    return {"ok": True, "pcap_flash_path": pcap_path}


def is_capturing(ip: str) -> bool:
    with _epc_lock:
        return ip in _epc_active
