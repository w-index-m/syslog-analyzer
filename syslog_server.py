import socketserver
import threading
import queue
import time
from parsers import parse_syslog

# スレッド間でログを渡すキュー
log_queue = queue.Queue(maxsize=1000)

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, _ = self.request
        source_ip = self.client_address[0]
        raw = data.decode("utf-8", errors="replace").strip()
        if raw:
            parsed = parse_syslog(raw, source_ip)
            log_queue.put({
                "source_ip": source_ip,
                "raw": raw,
                "parsed": parsed
            })

class SyslogServer:
    def __init__(self, host="0.0.0.0", port=514):
        self.host = host
        self.port = port
        self._server = None
        self._thread = None
        self.running = False
        self.error = None

    def start(self):
        try:
            self._server = socketserver.UDPServer((self.host, self.port), SyslogUDPHandler)
            self._server.socket.settimeout(1.0)
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
            self.running = True
            self.error = None
            print(f"[SyslogServer] Listening on UDP {self.host}:{self.port}")
        except PermissionError:
            self.error = f"ポート{self.port}のバインドに失敗しました。sudo で実行するか、ポート番号を5140などに変更してください。"
            self.running = False
        except OSError as e:
            self.error = f"サーバー起動エラー: {e}"
            self.running = False

    def _serve(self):
        while self.running:
            try:
                self._server.handle_request()
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self._server:
            self._server.server_close()

# シングルトンサーバーインスタンス
_server_instance = None

def get_server(port=514) -> SyslogServer:
    global _server_instance
    if _server_instance is None:
        _server_instance = SyslogServer(port=port)
    return _server_instance
