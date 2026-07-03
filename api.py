"""
REST API サーバー（FastAPI）
Streamlit UI とは別プロセスで起動し、同じ syslog.db を共有する。

起動方法:
    uvicorn api:app --host 0.0.0.0 --port 8000 --reload

主なエンドポイント:
    GET  /api/logs              ログ一覧
    POST /api/logs              syslog を HTTP 経由で投入
    GET  /api/health            全機器のヘルススコア一覧
    GET  /api/health/{ip}       特定機器の最新ヘルス＋推移
    POST /api/snmp/poll         SNMP ポーリング即時実行
    GET  /api/metrics           SNMP メトリクス一覧
    GET  /api/icmp-redirects    ICMP Redirect カウンタ
    GET  /api/status            サービス死活確認
"""
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

import db
import health_engine as he
import snmp_poller
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
    from pathlib import Path
    import sqlite3
    DB_PATH = Path(__file__).parent / "syslog.db"
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
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


@app.post("/api/snmp/poll")
def poll_now(req: PollRequest):
    try:
        result = snmp_poller.poll_device_health(
            req.ip, req.community, req.version, req.port, llm_mode="none"
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
