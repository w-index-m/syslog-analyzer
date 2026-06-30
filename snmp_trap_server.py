"""
SNMP Trap 受信サーバー (UDP 162 / 16200)
pysnmp を使って v1/v2c/v3 Trap を受信し log_queue に投入する
"""
import threading
import queue
from parsers.snmp_trap import build_parsed_dict

# syslog_serverと共有するキューに投入する
# importは循環参照を避けるため遅延
trap_queue = queue.Queue(maxsize=1000)

_trap_server_thread = None
_trap_running = False
_trap_error = None
_trap_port = 16200

def _run_trap_receiver(port: int, communities: list[str]):
    """pysnmp の非同期Trapレシーバーをスレッド内で実行"""
    global _trap_running, _trap_error

    try:
        from pysnmp.carrier.asyncio.dgram import udp
        from pysnmp.entity import engine, config
        from pysnmp.entity.rfc3413 import ntfrcv
        from pysnmp.proto.api import v2c
        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        snmpEngine = engine.SnmpEngine()

        # UDPトランスポート設定
        config.addTransport(
            snmpEngine,
            udp.domainName,
            udp.UdpTransport().openServerMode(("0.0.0.0", port))
        )

        # v1/v2cコミュニティ設定
        for community in communities:
            config.addV1System(snmpEngine, community, community)

        # v3 (noAuthNoPriv) - デフォルトユーザー
        config.addV3User(snmpEngine, "snmpv3user")

        def trap_callback(snmpEngine, stateReference, contextEngineId,
                          contextName, varBinds, cbCtx):
            transport_domain, transport_address = snmpEngine.msgAndPduDsp.getTransportInfo(stateReference)
            source_ip = str(transport_address[0])

            # Trap OIDを取得（snmpTrapOID.0 = 1.3.6.1.6.3.1.1.4.1.0）
            trap_oid = ""
            varbinds_raw = []
            for oid, val in varBinds:
                oid_str = str(oid)
                val_str = str(val)
                if "1.3.6.1.6.3.1.1.4.1" in oid_str:
                    trap_oid = val_str
                else:
                    varbinds_raw.append((oid_str, val_str))

            if not trap_oid:
                trap_oid = "1.3.6.1.6.3.1.1.5.1"  # coldStart fallback

            parsed = build_parsed_dict(
                source_ip=source_ip,
                trap_oid=trap_oid,
                varbinds=varbinds_raw,
                community="v2c",
                version="v2c"
            )
            trap_queue.put({
                "source_ip": source_ip,
                "raw": parsed.get("raw_for_ai", f"SNMP-Trap oid={trap_oid}"),
                "parsed": parsed
            })

        ntfrcv.NotificationReceiver(snmpEngine, trap_callback)
        snmpEngine.transportDispatcher.jobStarted(1)

        _trap_running = True
        _trap_error = None
        print(f"[SNMPTrapServer] Listening on UDP {port}")

        try:
            snmpEngine.transportDispatcher.runDispatcher()
        except Exception:
            pass
        finally:
            snmpEngine.transportDispatcher.closeDispatcher()
            _trap_running = False

    except PermissionError:
        _trap_error = f"ポート{port}のバインドに失敗（root権限が必要）。16200などに変更してください。"
        _trap_running = False
    except Exception as e:
        _trap_error = f"SNMP Trapサーバーエラー: {e}"
        _trap_running = False


class SNMPTrapServer:
    def __init__(self, port: int = 16200, communities: list[str] = None):
        self.port = port
        self.communities = communities or ["public", "private"]
        self.running = False
        self.error = None
        self._thread = None

    def start(self):
        global _trap_running, _trap_error, _trap_server_thread
        if _trap_running:
            return
        self._thread = threading.Thread(
            target=_run_trap_receiver,
            args=(self.port, self.communities),
            daemon=True
        )
        self._thread.start()
        # 起動確認（最大2秒待機）
        import time
        for _ in range(20):
            time.sleep(0.1)
            if _trap_running or _trap_error:
                break
        self.running = _trap_running
        self.error = _trap_error

    def stop(self):
        global _trap_running
        _trap_running = False
        self.running = False


# シングルトン
_snmp_instance: SNMPTrapServer | None = None

def get_snmp_server(port: int = 16200, communities: list[str] = None) -> SNMPTrapServer:
    global _snmp_instance
    if _snmp_instance is None:
        _snmp_instance = SNMPTrapServer(port=port, communities=communities)
    return _snmp_instance

def is_running() -> bool:
    return _trap_running
