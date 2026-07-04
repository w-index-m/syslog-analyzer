"""
CISCO-CONFIG-COPY-MIB (enterprise 1.3.6.1.4.1.9.9.96) 経由での
running-config 取得。

手順:
  1) このホストで簡易TFTPサーバーを一時起動（WRQ受信のみ対応。UDP/69、root権限が必要）
  2) SNMP SET で対象Cisco機器に「running-configをこのホストへTFTP送信せよ」と指示
  3) ccCopyState をポーリングしつつ、TFTPサーバーでのファイル受信を待つ
  4) 後始末として ccCopyEntry の RowStatus を destroy にセット

Cisco専用（CISCO-CONFIG-COPY-MIB）。書き込み権限のあるSNMPコミュニティ(RW)が必要。
SNMP(MIB)はスカラー値を1つ取得する仕組みが基本で、show running-config のような
長大なテキストを直接GETすることはできないため、本モジュールでは「機器にTFTPで
設定ファイルを送らせて受信する」という迂回策（Ciscoの公式な仕組み）を実装している。
"""
import random
import socket
import struct
import threading
import time

from pysnmp.hlapi.v3arch.asyncio import Integer32, OctetString, IpAddress

import snmp_poller as sp

# ── CISCO-CONFIG-COPY-MIB OID ──────────────────────────────
_CC_BASE       = "1.3.6.1.4.1.9.9.96.1.1.1.1"
_CC_PROTOCOL   = f"{_CC_BASE}.2"   # ccCopyProtocol
_CC_SRC_TYPE   = f"{_CC_BASE}.3"   # ccCopySourceFileType
_CC_DST_TYPE   = f"{_CC_BASE}.4"   # ccCopyDestFileType
_CC_SERVER     = f"{_CC_BASE}.5"   # ccCopyServerAddress
_CC_FILENAME   = f"{_CC_BASE}.6"   # ccCopyFileName
_CC_STATE      = f"{_CC_BASE}.10"  # ccCopyState
_CC_FAIL_CAUSE = f"{_CC_BASE}.13"  # ccCopyFailCause
_CC_ROWSTATUS  = f"{_CC_BASE}.14"  # ccCopyEntryRowStatus

_PROTO_TFTP = 1
_FILETYPE_RUNNING_CONFIG = 4
_FILETYPE_NETWORK_FILE = 1
_ROWSTATUS_CREATE_AND_GO = 4
_ROWSTATUS_DESTROY = 6
_STATE_LABELS = {"1": "waiting", "2": "running", "3": "successful", "4": "failed"}

# ── TFTP (RFC1350) opcode ──
_OP_WRQ   = 2
_OP_DATA  = 3
_OP_ACK   = 4
_OP_ERROR = 5


class TFTPReceiveServer:
    """1回分のファイル受信専用の簡易TFTPサーバー（WRQ受信のみ対応）。"""

    def __init__(self, bind_ip: str = "0.0.0.0", port: int = 69, timeout: int = 30):
        self.bind_ip = bind_ip
        self.port = port
        self.timeout = timeout
        self.error = None
        self.bound_event = threading.Event()
        self._sock = None

    def start_and_wait(self) -> bytes | None:
        """port(既定69)でWRQを1件待ち受け、ファイル内容を受信して返す。"""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.bind((self.bind_ip, self.port))
        except PermissionError:
            self.error = f"TFTPポート{self.port}のバインドに失敗しました（root権限が必要です）。"
            self.bound_event.set()
            return None
        except OSError as e:
            self.error = f"TFTPサーバー起動エラー: {e}"
            self.bound_event.set()
            return None
        self.bound_event.set()

        deadline = time.time() + self.timeout
        try:
            client_addr = None
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    self.error = "TFTP転送がタイムアウトしました（機器からの接続がありません）。"
                    return None
                self._sock.settimeout(remaining)
                try:
                    data, addr = self._sock.recvfrom(4096)
                except socket.timeout:
                    self.error = "TFTP転送がタイムアウトしました（機器からの接続がありません）。"
                    return None
                if len(data) < 2:
                    continue
                opcode = struct.unpack("!H", data[:2])[0]
                if opcode == _OP_WRQ:
                    client_addr = addr
                    break
        finally:
            try:
                self._sock.close()
            except Exception:
                pass

        if client_addr is None:
            return None

        # 転送専用の新しいソケット（エフェメラルポート）でACK(block=0)を返す
        # ※TFTPの仕様上、以降のDATAパケットはこの新しいポート宛てに送られてくる
        xfer_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            xfer_sock.bind((self.bind_ip, 0))
            xfer_sock.sendto(struct.pack("!HH", _OP_ACK, 0), client_addr)

            buf = bytearray()
            expected_block = 1
            xfer_deadline = time.time() + self.timeout
            while True:
                remaining = xfer_deadline - time.time()
                if remaining <= 0:
                    self.error = "TFTPデータ転送中にタイムアウトしました。"
                    return None
                xfer_sock.settimeout(remaining)
                try:
                    data, addr = xfer_sock.recvfrom(4096)
                except socket.timeout:
                    self.error = "TFTPデータ転送中にタイムアウトしました。"
                    return None
                if len(data) < 4:
                    continue
                op, block = struct.unpack("!HH", data[:4])
                if op == _OP_ERROR:
                    msg = data[4:].split(b"\x00")[0].decode("ascii", errors="replace")
                    self.error = f"機器からTFTPエラーを受信しました: {msg}"
                    return None
                if op != _OP_DATA:
                    continue
                payload = data[4:]
                if block == expected_block:
                    buf.extend(payload)
                    xfer_sock.sendto(struct.pack("!HH", _OP_ACK, block), addr)
                    expected_block += 1
                    if len(payload) < 512:
                        return bytes(buf)  # 最終ブロック（512byte未満）
                elif block < expected_block:
                    # ACK取りこぼしによる再送。再ACKのみ返す
                    xfer_sock.sendto(struct.pack("!HH", _OP_ACK, block), addr)
                # block > expected_block は順序異常のため無視
        finally:
            try:
                xfer_sock.close()
            except Exception:
                pass


def fetch_running_config(ip: str, rw_community: str, tftp_server_ip: str,
                          version: str = "v2c", port: int = 161,
                          tftp_port: int = 69, timeout: int = 30) -> dict:
    """
    CISCO-CONFIG-COPY-MIB 経由でCisco機器の running-config を取得する。
    戻り値: {"ok": bool, "config_text": str, "error": str}
    """
    idx = random.randint(10000, 99999)
    filename = f"autocfg_{idx}.cfg"
    result = {"ok": False, "config_text": "", "error": ""}

    tftp = TFTPReceiveServer(bind_ip="0.0.0.0", port=tftp_port, timeout=timeout)
    holder = {}

    def _run_tftp():
        holder["data"] = tftp.start_and_wait()

    th = threading.Thread(target=_run_tftp, daemon=True)
    th.start()
    if not tftp.bound_event.wait(timeout=5):
        result["error"] = "TFTPサーバーの起動待ちがタイムアウトしました。"
        return result
    if tftp.error:
        result["error"] = tftp.error
        return result

    ok, err = sp.snmp_set(ip, rw_community, [
        (f"{_CC_PROTOCOL}.{idx}", Integer32(_PROTO_TFTP)),
        (f"{_CC_SRC_TYPE}.{idx}", Integer32(_FILETYPE_RUNNING_CONFIG)),
        (f"{_CC_DST_TYPE}.{idx}", Integer32(_FILETYPE_NETWORK_FILE)),
        (f"{_CC_SERVER}.{idx}", IpAddress(tftp_server_ip)),
        (f"{_CC_FILENAME}.{idx}", OctetString(filename)),
        (f"{_CC_ROWSTATUS}.{idx}", Integer32(_ROWSTATUS_CREATE_AND_GO)),
    ], port=port, version=version)

    if not ok:
        th.join(timeout=2)
        result["error"] = ("SNMP SETに失敗しました。書き込み権限のあるコミュニティ(RW)か、"
                           f"機器がCISCO-CONFIG-COPY-MIBに対応しているか確認してください: {err}")
        return result

    # ccCopyState をポーリング（successful/failedになるまで）
    deadline = time.time() + timeout
    state = None
    while time.time() < deadline:
        state = sp.snmp_get(ip, rw_community, f"{_CC_STATE}.{idx}", port, version)
        if state in ("3", "4"):
            break
        time.sleep(1)

    th.join(timeout=timeout + 2)

    # 後始末：エントリを削除（失敗しても致命的ではないため結果は無視）
    sp.snmp_set(ip, rw_community, [
        (f"{_CC_ROWSTATUS}.{idx}", Integer32(_ROWSTATUS_DESTROY)),
    ], port=port, version=version)

    data = holder.get("data")
    if data:
        result["ok"] = True
        result["config_text"] = data.decode("utf-8", errors="replace")
        return result

    if state == "4":
        cause = sp.snmp_get(ip, rw_community, f"{_CC_FAIL_CAUSE}.{idx}", port, version)
        result["error"] = f"機器側でコピー処理が失敗しました（failCause={cause}）。"
    elif tftp.error:
        result["error"] = tftp.error
    else:
        result["error"] = "設定の取得に失敗しました（原因不明。SNMP応答やTFTP到達性を確認してください）。"
    return result
