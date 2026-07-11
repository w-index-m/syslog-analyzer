"""
sFlow v5 受信サーバー
- Arista/HPE/Juniper(一部)等の switch/router が送信する sFlow v5 を受信
- Flow Sample（サンプリングされた生パケットヘッダ）を解析し、既存の
  NetFlow集計テーブル(netflow_flows)に統合して保存する（source='sflow'）
- Counter Sample（インターフェースカウンタ）はifInDiscards/ifOutDiscards等を
  収集し、バッファ/キュー枯渇の検知に使う

sFlowはNetFlowと異なり「全数計上」ではなく「サンプリング」（例: 1/1000パケットに1回）
のため、sampling_rateを掛けて実トラフィック量を推定する。

スイッチ側の設定例（Arista EOS）:
    sflow sample 1000
    sflow destination <このPCのIP> 6343
    sflow run

参考仕様: sFlow.org "sFlow Version 5" (https://sflow.org/sflow_version_5.txt)
"""
import os
import struct
import socket
import socketserver
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path

import dpkt

import netflow_collector as _nfc

DB_PATH     = Path(os.environ.get("DB_PATH", str(Path(__file__).parent / "syslog.db")))
SFLOW_PORT  = int(os.environ.get("SFLOW_PORT", 6343))

# sFlow サンプルタイプ（format部分。enterprise=0のみ対応）
_FMT_FLOW_SAMPLE           = 1
_FMT_COUNTER_SAMPLE        = 2
_FMT_EXPANDED_FLOW_SAMPLE  = 3
_FMT_EXPANDED_COUNTER_SAMPLE = 4

# フローレコードのformat（enterprise=0）
_FLOWDATA_RAW_PACKET_HEADER = 1

# カウンタレコードのformat（enterprise=0）
_CTRDATA_GENERIC_IF = 1


def _init_tables():
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sflow_counters (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at   TEXT NOT NULL,
                agent_ip      TEXT NOT NULL,
                if_index      INTEGER NOT NULL,
                if_speed      INTEGER DEFAULT 0,
                in_octets     INTEGER DEFAULT 0,
                in_pkts       INTEGER DEFAULT 0,
                in_discards   INTEGER DEFAULT 0,
                in_errors     INTEGER DEFAULT 0,
                out_octets    INTEGER DEFAULT 0,
                out_pkts      INTEGER DEFAULT 0,
                out_discards  INTEGER DEFAULT 0,
                out_errors    INTEGER DEFAULT 0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sfc_recv ON sflow_counters(received_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sfc_agent ON sflow_counters(agent_ip, if_index)")
        conn.commit()


def _save_counters(rows: list[dict]):
    if not rows:
        return
    _init_tables()
    now = datetime.now().isoformat()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.executemany("""
            INSERT INTO sflow_counters
            (received_at, agent_ip, if_index, if_speed, in_octets, in_pkts,
             in_discards, in_errors, out_octets, out_pkts, out_discards, out_errors)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, [(now, r["agent_ip"], r["if_index"], r["if_speed"],
               r["in_octets"], r["in_pkts"], r["in_discards"], r["in_errors"],
               r["out_octets"], r["out_pkts"], r["out_discards"], r["out_errors"])
              for r in rows])
        conn.commit()


def _parse_raw_packet_header(header_bytes: bytes, frame_length: int, sampling_rate: int) -> dict | None:
    """Raw Packet Header(Ethernetフレーム)をdpktでパースし、フロー情報を抽出する。"""
    try:
        eth = dpkt.ethernet.Ethernet(header_bytes)
        if not isinstance(eth.data, dpkt.ip.IP):
            return None
        ip = eth.data
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        sport = dport = 0
        tcp_flags = 0
        if isinstance(ip.data, dpkt.tcp.TCP):
            sport, dport, tcp_flags = ip.data.sport, ip.data.dport, ip.data.flags
        elif isinstance(ip.data, dpkt.udp.UDP):
            sport, dport = ip.data.sport, ip.data.dport
        rate = max(1, sampling_rate)
        return {
            "src_ip": src_ip, "dst_ip": dst_ip, "src_port": sport, "dst_port": dport,
            "protocol": ip.p, "tcp_flags": tcp_flags, "tos": getattr(ip, "tos", 0),
            "packets": rate,                 # サンプル1件 = sampling_rate 個のパケット相当
            "bytes": frame_length * rate,    # 実フレーム長 × サンプリング率で実トラフィック推定
        }
    except Exception:
        return None


def _parse_flow_sample(body: bytes, expanded: bool) -> dict | None:
    """Flow Sample(format1) / Expanded Flow Sample(format3) をパースする。"""
    try:
        off = 0
        _seq = struct.unpack_from("!I", body, off)[0]; off += 4
        if expanded:
            off += 4   # source_id_type
            off += 4   # source_id_index
        else:
            off += 4   # source_id (type+index 詰め込み)
        sampling_rate = struct.unpack_from("!I", body, off)[0]; off += 4
        off += 4   # sample_pool
        off += 4   # drops
        if expanded:
            off += 8   # input type+index, output type+index (4+4+4+4)
        else:
            off += 8   # input(4) + output(4)
        num_records = struct.unpack_from("!I", body, off)[0]; off += 4

        result = None
        for _ in range(num_records):
            if off + 8 > len(body):
                break
            flow_format = struct.unpack_from("!I", body, off)[0]; off += 4
            flow_len = struct.unpack_from("!I", body, off)[0]; off += 4
            flow_data = body[off:off + flow_len]
            padded_len = (flow_len + 3) & ~3   # 4バイト境界にパディング
            off += padded_len
            fmt = flow_format & 0xFFF
            enterprise = flow_format >> 12
            if enterprise == 0 and fmt == _FLOWDATA_RAW_PACKET_HEADER and len(flow_data) >= 16:
                header_protocol = struct.unpack_from("!I", flow_data, 0)[0]
                frame_length = struct.unpack_from("!I", flow_data, 4)[0]
                # stripped(4) は使わない
                header_length = struct.unpack_from("!I", flow_data, 12)[0]
                header_bytes = flow_data[16:16 + header_length]
                if header_protocol == 1:   # Ethernet
                    parsed = _parse_raw_packet_header(header_bytes, frame_length, sampling_rate)
                    if parsed:
                        result = parsed
        return result
    except Exception:
        return None


def _parse_counter_sample(body: bytes, agent_ip: str, expanded: bool) -> list[dict]:
    """Counter Sample(format2) / Expanded Counter Sample(format4) をパースする。"""
    out = []
    try:
        off = 0
        off += 4   # sequence_number
        if expanded:
            off += 8   # source_id type+index
        else:
            off += 4   # source_id
        num_records = struct.unpack_from("!I", body, off)[0]; off += 4
        for _ in range(num_records):
            if off + 8 > len(body):
                break
            ctr_format = struct.unpack_from("!I", body, off)[0]; off += 4
            ctr_len = struct.unpack_from("!I", body, off)[0]; off += 4
            ctr_data = body[off:off + ctr_len]
            padded_len = (ctr_len + 3) & ~3
            off += padded_len
            fmt = ctr_format & 0xFFF
            enterprise = ctr_format >> 12
            if enterprise == 0 and fmt == _CTRDATA_GENERIC_IF and len(ctr_data) >= 88:
                (if_index, if_type, if_speed, _if_dir, _if_status,
                 in_octets, in_ucast, in_mcast, in_bcast, in_disc, in_err, _in_unk,
                 out_octets, out_ucast, out_mcast, out_bcast, out_disc, out_err,
                 _promisc) = struct.unpack_from("!IIQIIQIIIIIIQIIIIII", ctr_data, 0)
                out.append({
                    "agent_ip": agent_ip, "if_index": if_index, "if_speed": if_speed,
                    "in_octets": in_octets, "in_pkts": in_ucast + in_mcast + in_bcast,
                    "in_discards": in_disc, "in_errors": in_err,
                    "out_octets": out_octets, "out_pkts": out_ucast + out_mcast + out_bcast,
                    "out_discards": out_disc, "out_errors": out_err,
                })
    except Exception:
        pass
    return out


def parse_sflow_datagram(data: bytes, agent_ip: str) -> tuple[list[dict], list[dict]]:
    """
    sFlow v5 データグラムをパースする。
    戻り値: (flows, counters) — flowsはnetflow_flows互換dict、countersはIF統計dict
    """
    flows, counters = [], []
    try:
        if len(data) < 28:
            return flows, counters
        version = struct.unpack_from("!I", data, 0)[0]
        if version != 5:
            return flows, counters
        agent_addr_type = struct.unpack_from("!I", data, 4)[0]
        off = 8
        off += 4 if agent_addr_type == 1 else 16   # IPv4=4B / IPv6=16B
        off += 4   # sub_agent_id
        off += 4   # sequence_number
        off += 4   # uptime
        num_samples = struct.unpack_from("!I", data, off)[0]; off += 4

        for _ in range(num_samples):
            if off + 8 > len(data):
                break
            sample_type = struct.unpack_from("!I", data, off)[0]; off += 4
            sample_len = struct.unpack_from("!I", data, off)[0]; off += 4
            sample_body = data[off:off + sample_len]
            off += sample_len   # サンプル本体は4バイト境界前提（仕様上そろっている）
            fmt = sample_type & 0xFFF
            enterprise = sample_type >> 12
            if enterprise != 0:
                continue   # ベンダー拡張は対象外
            if fmt == _FMT_FLOW_SAMPLE:
                fl = _parse_flow_sample(sample_body, expanded=False)
                if fl:
                    fl["exporter_ip"] = agent_ip
                    fl["source"] = "sflow"
                    flows.append(fl)
            elif fmt == _FMT_EXPANDED_FLOW_SAMPLE:
                fl = _parse_flow_sample(sample_body, expanded=True)
                if fl:
                    fl["exporter_ip"] = agent_ip
                    fl["source"] = "sflow"
                    flows.append(fl)
            elif fmt == _FMT_COUNTER_SAMPLE:
                counters.extend(_parse_counter_sample(sample_body, agent_ip, expanded=False))
            elif fmt == _FMT_EXPANDED_COUNTER_SAMPLE:
                counters.extend(_parse_counter_sample(sample_body, agent_ip, expanded=True))
    except Exception as e:
        print(f"[sFlow] パースエラー: {e}")
    return flows, counters


# ─────────────────────────────────────────
# UDP サーバー
# ─────────────────────────────────────────

class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        agent_ip = self.client_address[0]
        flows, counters = parse_sflow_datagram(data, agent_ip)
        if flows:
            _nfc._save_flows(flows, source="sflow")
            print(f"[sFlow] {agent_ip}: {len(flows)} flow samples")
        if counters:
            _save_counters(counters)


class SFlowServer:
    def __init__(self, host="0.0.0.0", port=SFLOW_PORT):
        self.host = host
        self.port = port
        self._srv = None
        self._th  = None
        self.running = False
        self.error   = None

    def start(self):
        try:
            self._srv = socketserver.UDPServer((self.host, self.port), _Handler)
            self._srv.socket.settimeout(1.0)
            self.running = True   # スレッド開始前に立てる（開始直後のwhileチェックのレース回避）
            self._th = threading.Thread(target=self._serve, daemon=True)
            self._th.start()
            self.error   = None
            print(f"[SFlowServer] UDP {self.host}:{self.port}")
        except Exception as e:
            self.error   = str(e)
            self.running = False

    def _serve(self):
        while self.running:
            try:
                self._srv.handle_request()
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self._srv:
            try:
                self._srv.server_close()
            except Exception:
                pass


_instance = None


def get_server(port: int = SFLOW_PORT) -> SFlowServer:
    global _instance
    if _instance is None:
        _instance = SFlowServer(port=port)
    return _instance


# ─────────────────────────────────────────
# クエリ関数（インターフェースカウンタ＝バッファ/キュー枯渇検知）
# ─────────────────────────────────────────

def get_interface_issues(hours: int = 1, discard_threshold_pct: float = 0.1) -> list[dict]:
    """
    直近のsFlowカウンタから、破棄率(discard)・エラー率が閾値を超えるIFを検出する。
    SNMPの health_engine.discard_pct 判定と同じ考え方（バッファ/キュー枯渇）。
    """
    try:
        _init_tables()
        issues = []
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT agent_ip, if_index,
                       MAX(in_octets) - MIN(in_octets)     as d_in_octets,
                       MAX(in_pkts) - MIN(in_pkts)         as d_in_pkts,
                       MAX(in_discards) - MIN(in_discards) as d_in_disc,
                       MAX(out_octets) - MIN(out_octets)   as d_out_octets,
                       MAX(out_pkts) - MIN(out_pkts)       as d_out_pkts,
                       MAX(out_discards) - MIN(out_discards) as d_out_disc,
                       MAX(if_speed) as if_speed,
                       COUNT(*) as samples
                FROM sflow_counters
                WHERE received_at >= datetime('now', ? || ' hours')
                GROUP BY agent_ip, if_index HAVING samples >= 2
            """, (f"-{hours}",)).fetchall()
            for r in rows:
                for direction, pkts, disc in (("入力", r["d_in_pkts"], r["d_in_disc"]),
                                              ("出力", r["d_out_pkts"], r["d_out_disc"])):
                    if pkts and pkts > 0 and disc and disc > 0:
                        pct = disc / pkts * 100
                        if pct >= discard_threshold_pct:
                            issues.append({
                                "agent_ip": r["agent_ip"], "if_index": r["if_index"],
                                "direction": direction, "discard_pct": round(pct, 3),
                                "discards": disc, "packets": pkts,
                                "detail": f"{r['agent_ip']} IF{r['if_index']} {direction}破棄率 {round(pct,3)}%"
                                         f"（{disc}/{pkts}パケット）— バッファ/キュー枯渇の可能性",
                            })
        issues.sort(key=lambda x: x["discard_pct"], reverse=True)
        return issues
    except Exception:
        return []


# ─────────────────────────────────────────
# サンプルデータ（実機なしでバッファ枯渇検知のデモを試すため）
# ─────────────────────────────────────────

_SAMPLE_AGENT_IP = "203.0.113.10"


def generate_sample_counters() -> dict:
    """
    デモ用：リンク速度が 10G→1G に変わり、出力バッファが枯渇していくシナリオを
    sflow_counters に投入する（get_interface_issues() が検知できることを確認できる）。
    """
    _init_tables()
    now = datetime.now()
    if_index = 1
    # (経過秒, if_speed[bps], in_octets, in_pkts, in_disc, out_octets, out_pkts, out_disc)
    samples = [
        (-900, 10_000_000_000,           0,       0,       0,           0,       0,      0),
        (-600, 10_000_000_000, 8_000_000_000, 6_000_000,       0, 7_500_000_000, 5_800_000,      0),
        (-300,  1_000_000_000, 8_400_000_000, 6_300_000,       0, 7_900_000_000, 6_100_000,      0),
        (   0,  1_000_000_000, 9_000_000_000, 6_800_000, 350_000, 8_400_000_000, 6_500_000, 12_000),
    ]
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        for offset, speed, in_oct, in_pkt, in_disc, out_oct, out_pkt, out_disc in samples:
            ts = (now + timedelta(seconds=offset)).isoformat()
            conn.execute("""
                INSERT INTO sflow_counters
                (received_at, agent_ip, if_index, if_speed, in_octets, in_pkts,
                 in_discards, in_errors, out_octets, out_pkts, out_discards, out_errors)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (ts, _SAMPLE_AGENT_IP, if_index, speed, in_oct, in_pkt, in_disc, 0,
                  out_oct, out_pkt, out_disc, 0))
        conn.commit()
    return {"agent_ip": _SAMPLE_AGENT_IP, "if_index": if_index, "samples": len(samples)}


def clear_sample_counters() -> int:
    """generate_sample_counters() で投入したデモ行のみを削除する（実データは残す）。"""
    _init_tables()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        cur = conn.execute("DELETE FROM sflow_counters WHERE agent_ip = ?", (_SAMPLE_AGENT_IP,))
        conn.commit()
        return cur.rowcount


def has_sample_counters() -> bool:
    try:
        _init_tables()
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT 1 FROM sflow_counters WHERE agent_ip = ? LIMIT 1",
                                (_SAMPLE_AGENT_IP,)).fetchone()
            return row is not None
    except Exception:
        return False


if __name__ == "__main__":
    print("sFlow collector ready. import して SFlowServer を起動してください。")
