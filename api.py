"""
REST API サーバー（FastAPI）
Streamlit UI とは別プロセスで起動し、同じ syslog.db を共有する。

起動方法:
    uvicorn api:app --host 0.0.0.0 --port 8000 --reload

主なエンドポイント:
    GET  /api/logs                    ログ一覧
    POST /api/logs                    syslog を HTTP 経由で投入
    POST /api/analyze                 syslog を投入して即 AI 解析
    POST /api/analyze/health          機器ヘルスの LLM 診断
    POST /api/analyze/icmp-redirect   ICMP Redirect 大量発生の LLM 診断
    GET  /api/health                  全機器のヘルススコア一覧
    GET  /api/health/{ip}             特定機器の最新ヘルス＋推移
    POST /api/snmp/poll               SNMP ポーリング即時実行（LLM 診断付き）
    GET  /api/metrics                 SNMP メトリクス一覧
    GET  /api/icmp-redirects          ICMP Redirect カウンタ
    GET  /api/status                  サービス死活確認
"""
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

import db
import health_engine as he
import snmp_poller
import analyzer
import restconf_client as rc
from parsers import parse_syslog

app = FastAPI(
    title="Syslog Analyzer API",
    description="ネットワーク syslog / SNMP 解析 REST API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

db.init_db()


# ─────────────────────────────────────────
# ステータス
# ─────────────────────────────────────────
@app.get("/api/status")
def status():
    return {"status": "ok", "time": datetime.now().isoformat()}


# ─────────────────────────────────────────
# syslog ログ
# ─────────────────────────────────────────
@app.get("/api/logs")
def get_logs(
    source_ip: Optional[str] = None,
    severity: Optional[str] = None,
    vendor: Optional[str] = None,
    keyword: Optional[str] = None,
    limit: int = Query(100, le=1000),
):
    rows = db.get_logs(
        limit=limit,
        source_ip=source_ip,
        severity=severity,
        vendor=vendor,
        keyword=keyword,
    )
    return {"count": len(rows), "logs": rows}


class SyslogEntry(BaseModel):
    raw: str
    source_ip: str = "0.0.0.0"


@app.post("/api/logs", status_code=201)
def post_log(entry: SyslogEntry):
    parsed = parse_syslog(entry.raw, entry.source_ip)
    import json
    import sqlite3
    with sqlite3.connect(db.DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            INSERT INTO logs
            (received_at, source_ip, raw, vendor, severity, facility,
             hostname, process, message, tags)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            datetime.now().isoformat(),
            entry.source_ip,
            entry.raw,
            parsed.get("vendor", ""),
            parsed.get("severity", ""),
            parsed.get("facility", ""),
            parsed.get("hostname", ""),
            parsed.get("process", ""),
            parsed.get("message", ""),
            json.dumps(parsed.get("tags", []), ensure_ascii=False),
        ))
        conn.commit()
    return {"status": "accepted", "parsed": parsed}


# ─────────────────────────────────────────
# AI 解析エンドポイント
# ─────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    raw: str
    source_ip: str = "0.0.0.0"
    mode: str = "auto"          # "auto" | "claude" | "ollama" | "none"
    config_context: str = ""
    save: bool = True           # DB に保存するか


@app.post("/api/analyze")
def analyze_log(req: AnalyzeRequest):
    """
    syslog テキストをパース → AI 解析 → 結果を返す（オプションで DB 保存）。
    Zabbix / Grafana アラートから叩いて即時解析する用途を想定。
    """
    import json, sqlite3
    parsed = parse_syslog(req.raw, req.source_ip)
    explanation, model = analyzer.analyze(parsed, req.raw, req.mode, req.config_context)

    explanation_dict = {}
    try:
        explanation_dict = json.loads(explanation) if explanation else {}
    except Exception:
        explanation_dict = {"raw": explanation}

    if req.save:
        with sqlite3.connect(db.DB_PATH, check_same_thread=False) as conn:
            conn.execute("""
                INSERT INTO logs
                (received_at, source_ip, raw, vendor, severity, facility,
                 hostname, process, message, tags, ai_explanation, ai_model)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                datetime.now().isoformat(), req.source_ip, req.raw,
                parsed.get("vendor", ""), parsed.get("severity", ""),
                parsed.get("facility", ""), parsed.get("hostname", ""),
                parsed.get("process", ""), parsed.get("message", ""),
                json.dumps(parsed.get("tags", []), ensure_ascii=False),
                explanation, model,
            ))
            conn.commit()

    return {
        "parsed": parsed,
        "analysis": explanation_dict,
        "model": model,
    }


class HealthDiagnoseRequest(BaseModel):
    ip: str
    community: str = "public"
    version: str = "v2c"
    port: int = 161
    mode: str = "auto"
    log_limit: int = 10


@app.post("/api/analyze/health")
def analyze_health(req: HealthDiagnoseRequest):
    """
    SNMP ポーリング → ヘルススコア算出 → LLM で総合診断まで一気に実行。
    """
    try:
        health = snmp_poller.poll_device_health(
            req.ip, req.community, req.version, req.port, llm_mode=req.mode
        )
        return {"status": "ok", "result": health}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class IcmpRedirectDiagnoseRequest(BaseModel):
    ip: str
    mode: str = "auto"
    log_limit: int = 20


@app.post("/api/analyze/icmp-redirect")
def analyze_icmp_redirect(req: IcmpRedirectDiagnoseRequest):
    """
    指定機器の ICMP Redirect カウンタ・syslog・ルーティング情報を集めて LLM 診断。
    """
    snmp_data = [
        r for r in snmp_poller.get_icmp_redirect_latest()
        if r.get("source_ip") == req.ip
    ]
    redirect_logs = db.get_logs(
        limit=req.log_limit,
        source_ip=req.ip,
        keyword="redirect",
    )
    cfg = db.get_device_config(req.ip)
    routing_summary = cfg.get("routing_summary", "") if cfg else ""

    result = analyzer.diagnose_icmp_redirect(
        req.ip, snmp_data, redirect_logs, routing_summary, req.mode
    )
    return {"ip": req.ip, "diagnosis": result}


# ─────────────────────────────────────────
# ヘルス / 品質スコア
# ─────────────────────────────────────────
@app.get("/api/health")
def get_health_all():
    devices = he.get_latest_health_all()
    overall = he.get_network_overall_health()
    return {"overall": overall, "devices": devices}


@app.get("/api/health/{ip}")
def get_health_device(ip: str, hours: int = 6):
    latest = he.get_latest_health_all()
    device = next((d for d in latest if d["source_ip"] == ip), None)
    trend = he.get_health_trend(ip, hours=hours)
    return {"latest": device, "trend": trend}


# ─────────────────────────────────────────
# SNMP
# ─────────────────────────────────────────
class PollRequest(BaseModel):
    ip: str
    community: str = "public"
    version: str = "v2c"
    port: int = 161
    llm_mode: str = "none"      # "auto" にすると SNMP 後に LLM 診断も実行


@app.post("/api/snmp/poll")
def poll_now(req: PollRequest):
    try:
        result = snmp_poller.poll_device_health(
            req.ip, req.community, req.version, req.port, llm_mode=req.llm_mode
        )
        return {"status": "ok", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/metrics")
def get_metrics(ip: Optional[str] = None, limit: int = Query(200, le=1000)):
    rows = snmp_poller.get_latest_metrics(ip=ip, limit=limit)
    return {"count": len(rows), "metrics": rows}


@app.get("/api/icmp-redirects")
def get_icmp_redirects():
    return {"redirects": snmp_poller.get_icmp_redirect_latest()}


@app.get("/api/snmp/devices")
def get_snmp_devices():
    return {"devices": snmp_poller.get_devices()}


@app.post("/api/snmp/devices")
def add_snmp_device(req: PollRequest):
    snmp_poller.add_device(req.ip, req.community, req.version, req.port)
    return {"status": "added", "ip": req.ip}


@app.delete("/api/snmp/devices/{ip}")
def remove_snmp_device(ip: str):
    snmp_poller.remove_device(ip)
    return {"status": "removed", "ip": ip}


# ─────────────────────────────────────────
# RESTCONF / EPC
# ─────────────────────────────────────────

class RestconfDeviceRequest(BaseModel):
    ip: str
    username: str
    password: str
    port: int = 443
    verify_ssl: bool = False
    epc_interface: str = ""
    epc_auto_trigger: bool = False
    epc_threshold: int = 10
    epc_duration_sec: int = 60


@app.get("/api/restconf/devices")
def list_restconf_devices():
    devs = rc.get_devices()
    # パスワードはマスク
    for d in devs:
        d["password"] = "***"
    return {"devices": devs}


@app.post("/api/restconf/devices", status_code=201)
def add_restconf_device(req: RestconfDeviceRequest):
    rc.add_device(
        req.ip, req.username, req.password, req.port, req.verify_ssl,
        req.epc_interface, req.epc_auto_trigger, req.epc_threshold, req.epc_duration_sec
    )
    return {"status": "added", "ip": req.ip}


@app.delete("/api/restconf/devices/{ip}")
def remove_restconf_device(ip: str):
    rc.remove_device(ip)
    return {"status": "removed", "ip": ip}


@app.get("/api/restconf/routes/{ip}")
def get_routes_restconf(ip: str):
    """RESTCONF でルーティングテーブルを取得（SNMP Walk より高速）"""
    dev = rc.get_device(ip)
    if not dev:
        raise HTTPException(status_code=404, detail="RESTCONF デバイス未登録")
    client = rc.RestconfClient(
        ip, dev["username"], dev["password"],
        dev.get("port", 443), bool(dev.get("verify_ssl"))
    )
    routes = client.get_routing_table()
    return {"ip": ip, "count": len(routes), "routes": routes}


class EpcRequest(BaseModel):
    ip: str
    capture_name: Optional[str] = None
    duration_sec: Optional[int] = None


@app.post("/api/restconf/epc/start")
def epc_start(req: EpcRequest):
    result = rc.manual_start_epc(req.ip, req.capture_name, req.duration_sec)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@app.post("/api/restconf/epc/stop")
def epc_stop(req: EpcRequest):
    result = rc.manual_stop_epc(req.ip)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@app.get("/api/restconf/epc/events")
def get_epc_events(ip: Optional[str] = None, limit: int = 20):
    return {"events": rc.get_epc_events(ip=ip, limit=limit)}


@app.get("/api/restconf/epc/status/{ip}")
def get_epc_status(ip: str):
    return {"ip": ip, "capturing": rc.is_capturing(ip)}
