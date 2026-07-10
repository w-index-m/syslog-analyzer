"""
クラウド監査ログ（CloudTrail等）の取り込み・異常検知

このアプリの他の収集モジュール（syslog/SNMP/NetFlow/sFlow/pcap）は
ネットワーク層（パケット・フロー・機器の状態）を見るが、IAMトークン悪用・
不可能なトラベル・ストレージの大量ダウンロード・スナップショットの
不審なエクスポートといった攻撃は、クラウドの**コントロールプレーン層**
（誰が・どのAPIを・いつ・どこから呼んだか）を記録する監査ログ
（AWS CloudTrail / Azure Activity Log / GCP Audit Log 等）でしか見えない。
そのため専用の取り込み経路として本モジュールを用意する。

対応入力形式:
  - AWS CloudTrailのネイティブ形式（{"Records":[...]}、または1レコードのdict、
    またはレコードのJSON配列）
  - 汎用簡易形式（time/identity/source_ip/region/event_name/event_source/resource）
    ※ Azure Activity Log / GCP Audit Log はフィールド名が異なるため、現状は
      ネイティブ対応しない。取り込む場合は上記の汎用形式に変換してから投入する。

検知は他のコレクター（NetFlowのDDoS検知等）と同じ「閾値・頻度ベースの
振る舞い検知」であり、シグネチャ不要で新しい攻撃パターンにも追従できる。

IPの国判定は geoip.py（現状 CN/HK/KP/MO のみ収録）を利用するため、
「不可能なトラベル」検知の国ベース判定はこの4カ国が関わる場合に限られる
（それ以外の国同士の移動は判定できない）。国に依存しない
「短時間での複数IPからのアクセス」検知もあわせて提供する。
"""
import os
import json
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path

import geoip

DB_PATH = Path(os.environ.get("DB_PATH", str(Path(__file__).parent / "syslog.db")))

_lock = threading.Lock()

# イベント名 -> 分類（ダウンロード系 / スナップショット・エクスポート系）
_DOWNLOAD_EVENT_NAMES = {
    "GetObject", "ListObjects", "ListObjectsV2", "RestoreObject",
    "SelectObjectContent", "GetObjectTorrent",
}
_SNAPSHOT_EVENT_NAMES = {
    "CreateSnapshot", "CreateSnapshots", "CopySnapshot", "CreateImage",
    "ExportImage", "CreateDBSnapshot", "CopyDBSnapshot", "ExportSnapshot",
    "ExportTask", "CreateExportTask",
}


def _classify_event(event_name: str) -> str:
    if event_name in _DOWNLOAD_EVENT_NAMES:
        return "download"
    if event_name in _SNAPSHOT_EVENT_NAMES:
        return "snapshot_export"
    return "other"


def _init_tables():
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cloud_audit_events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at   TEXT NOT NULL,
                event_time    TEXT NOT NULL,
                identity      TEXT NOT NULL,
                source_ip     TEXT DEFAULT '',
                country       TEXT DEFAULT '',
                region        TEXT DEFAULT '',
                event_name    TEXT DEFAULT '',
                event_source  TEXT DEFAULT '',
                event_class   TEXT DEFAULT 'other',
                resource_name TEXT DEFAULT '',
                is_sample     INTEGER DEFAULT 0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cae_time ON cloud_audit_events(event_time)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cae_identity ON cloud_audit_events(identity)")
        conn.commit()


# ─────────────────────────────────────────
# パース
# ─────────────────────────────────────────

def _identity_of(user_identity: dict) -> str:
    if not isinstance(user_identity, dict):
        return "不明"
    return (user_identity.get("arn") or user_identity.get("userName")
            or user_identity.get("principalId") or "不明")


def _resource_of(record: dict) -> str:
    rp = record.get("requestParameters") or {}
    if isinstance(rp, dict):
        if rp.get("bucketName"):
            key = rp.get("key", "")
            return f"s3://{rp['bucketName']}/{key}" if key else f"s3://{rp['bucketName']}"
        for k in ("snapshotId", "dBSnapshotIdentifier", "imageId", "exportTaskId"):
            if rp.get(k):
                return str(rp[k])
    resources = record.get("resources")
    if isinstance(resources, list) and resources:
        r0 = resources[0]
        if isinstance(r0, dict) and r0.get("ARN"):
            return r0["ARN"]
    return ""


def _normalize_one(record: dict) -> dict | None:
    """CloudTrailネイティブ形式、または汎用簡易形式の1レコードを正規化する。"""
    if not isinstance(record, dict):
        return None

    # AWS CloudTrail ネイティブ形式
    if "eventTime" in record and "eventName" in record:
        return {
            "event_time":   record.get("eventTime", ""),
            "identity":     _identity_of(record.get("userIdentity") or {}),
            "source_ip":    record.get("sourceIPAddress", "") or "",
            "region":       record.get("awsRegion", "") or "",
            "event_name":   record.get("eventName", ""),
            "event_source": record.get("eventSource", ""),
            "resource_name": _resource_of(record),
        }

    # 汎用簡易形式
    if "event_name" in record or "time" in record:
        return {
            "event_time":   record.get("time", "") or record.get("event_time", ""),
            "identity":     record.get("identity", "不明"),
            "source_ip":    record.get("source_ip", "") or "",
            "region":       record.get("region", "") or "",
            "event_name":   record.get("event_name", ""),
            "event_source": record.get("event_source", ""),
            "resource_name": record.get("resource", ""),
        }
    return None


def parse_audit_log(text: str) -> list[dict]:
    """
    CloudTrail JSON（{"Records":[...]}/配列/単体）または改行区切りJSON
    (NDJSON)をパースし、正規化済みレコードのリストを返す。
    """
    text = (text or "").strip()
    if not text:
        return []

    raw_records: list = []
    try:
        data = json.loads(text)
        if isinstance(data, dict) and isinstance(data.get("Records"), list):
            raw_records = data["Records"]
        elif isinstance(data, list):
            raw_records = data
        elif isinstance(data, dict):
            raw_records = [data]
    except json.JSONDecodeError:
        # NDJSON（1行1JSON）として再トライ
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw_records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    out = []
    for rec in raw_records:
        norm = _normalize_one(rec)
        if norm:
            norm["event_class"] = _classify_event(norm["event_name"])
            norm["country"] = geoip.lookup_country(norm["source_ip"]) or "" if norm["source_ip"] else ""
            out.append(norm)
    return out


def ingest_events(events: list[dict], is_sample: bool = False) -> int:
    if not events:
        return 0
    _init_tables()
    now = datetime.now().isoformat()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.executemany("""
            INSERT INTO cloud_audit_events
            (received_at, event_time, identity, source_ip, country, region,
             event_name, event_source, event_class, resource_name, is_sample)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, [(now, e["event_time"], e["identity"], e["source_ip"], e.get("country", ""),
               e["region"], e["event_name"], e["event_source"], e["event_class"],
               e["resource_name"], int(is_sample))
              for e in events])
        conn.commit()
    return len(events)


# ─────────────────────────────────────────
# クエリ・集計
# ─────────────────────────────────────────

def get_summary(hours: float = 24) -> dict:
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("""
            SELECT COUNT(*), COUNT(DISTINCT identity), COUNT(DISTINCT region)
            FROM cloud_audit_events WHERE event_time >= datetime('now', ? || ' hours')
        """, (f"-{hours}",)).fetchone()
        return {"total_events": row[0], "unique_identities": row[1], "unique_regions": row[2]}


def get_recent_events(hours: float = 24, limit: int = 500) -> list[dict]:
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT * FROM cloud_audit_events
            WHERE event_time >= datetime('now', ? || ' hours')
            ORDER BY event_time DESC LIMIT ?
        """, (f"-{hours}", limit)).fetchall()
        return [dict(r) for r in rows]


def get_cross_region_alerts(hours: float = 24, threshold: int = 3) -> list[dict]:
    """同一アイデンティティが短時間に多数の異なるリージョンからAPIを呼んでいないか。"""
    _init_tables()
    alerts = []
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT identity, COUNT(DISTINCT region) as n_regions,
                   GROUP_CONCAT(DISTINCT region) as regions, COUNT(*) as events
            FROM cloud_audit_events
            WHERE event_time >= datetime('now', ? || ' hours') AND region != ''
            GROUP BY identity HAVING n_regions >= ?
            ORDER BY n_regions DESC
        """, (f"-{hours}", threshold)).fetchall()
        for r in rows:
            alerts.append({
                "identity": r["identity"], "n_regions": r["n_regions"],
                "regions": r["regions"], "events": r["events"],
                "detail": f"{r['identity']} が {r['n_regions']}個の異なるリージョン"
                          f"（{r['regions']}）からAPIを呼び出し — "
                          "認証情報の漏えい・不正利用の可能性",
            })
    return alerts


def get_mass_download_alerts(hours: float = 24, threshold: int = 50) -> list[dict]:
    """同一アイデンティティが短時間に大量の異なるオブジェクトをダウンロードしていないか。"""
    _init_tables()
    alerts = []
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT identity, COUNT(DISTINCT resource_name) as n_objs, COUNT(*) as events
            FROM cloud_audit_events
            WHERE event_time >= datetime('now', ? || ' hours') AND event_class = 'download'
            GROUP BY identity HAVING n_objs >= ?
            ORDER BY n_objs DESC
        """, (f"-{hours}", threshold)).fetchall()
        for r in rows:
            alerts.append({
                "identity": r["identity"], "n_objects": r["n_objs"], "events": r["events"],
                "detail": f"{r['identity']} が短時間に{r['n_objs']}個の異なるオブジェクトを"
                          "取得 — ランサムウェア/情報持ち出しの可能性",
            })
    return alerts


def get_snapshot_export_alerts(hours: float = 24, threshold: int = 5) -> list[dict]:
    """同一アイデンティティによるスナップショット/エクスポート系操作の急増を検知する。"""
    _init_tables()
    alerts = []
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT identity, COUNT(*) as n
            FROM cloud_audit_events
            WHERE event_time >= datetime('now', ? || ' hours') AND event_class = 'snapshot_export'
            GROUP BY identity HAVING n >= ?
            ORDER BY n DESC
        """, (f"-{hours}", threshold)).fetchall()
        for r in rows:
            alerts.append({
                "identity": r["identity"], "count": r["n"],
                "detail": f"{r['identity']} がスナップショット/エクスポート系操作を"
                          f"{r['n']}回実行 — 認証情報・機密データの持ち出し準備の可能性",
            })
    return alerts


def get_impossible_travel_alerts(hours: float = 24, max_minutes: int = 60) -> list[dict]:
    """
    同一アイデンティティの連続イベントが、短時間で異なる国から発生していないか判定する。
    国判定は geoip.py（CN/HK/KP/MOのみ収録）に依存するため、この4カ国が
    関わる移動のみ判定できる（それ以外の国同士の移動は「不明」扱いで対象外）。
    """
    _init_tables()
    alerts = []
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        identities = [r["identity"] for r in conn.execute("""
            SELECT DISTINCT identity FROM cloud_audit_events
            WHERE event_time >= datetime('now', ? || ' hours')
        """, (f"-{hours}",)).fetchall()]
        for identity in identities:
            rows = conn.execute("""
                SELECT event_time, source_ip, country FROM cloud_audit_events
                WHERE identity = ? AND event_time >= datetime('now', ? || ' hours')
                ORDER BY event_time ASC
            """, (identity, f"-{hours}")).fetchall()
            for i in range(1, len(rows)):
                prev, cur = rows[i - 1], rows[i]
                # 追跡対象国(CN/HK/KP/MO)への出入りが無ければスキップ。
                # 両方とも追跡対象国外(空文字)の場合は移動を判定できないため対象外だが、
                # 片方だけが追跡対象国に該当する場合（国内/不明 → 中国 等）も
                # 実運用上は重要な兆候のため対象に含める。
                if prev["country"] == cur["country"]:
                    continue
                if not prev["country"] and not cur["country"]:
                    continue
                try:
                    t1 = datetime.fromisoformat(prev["event_time"])
                    t2 = datetime.fromisoformat(cur["event_time"])
                except ValueError:
                    continue
                delta_min = abs((t2 - t1).total_seconds()) / 60
                if delta_min <= max_minutes:
                    c1 = geoip.country_label(prev["country"]) if prev["country"] else "不明(追跡対象国以外)"
                    c2 = geoip.country_label(cur["country"]) if cur["country"] else "不明(追跡対象国以外)"
                    alerts.append({
                        "identity": identity,
                        "from_country": c1, "to_country": c2,
                        "from_ip": prev["source_ip"], "to_ip": cur["source_ip"],
                        "minutes": round(delta_min, 1),
                        "detail": f"{identity} が {round(delta_min,1)}分の間に "
                                  f"{c1}({prev['source_ip']}) → {c2}({cur['source_ip']}) "
                                  "からアクセス — 不可能なトラベル（認証情報漏えい）の可能性",
                    })

    # 国に依存しない代替シグナル: 短時間での複数IP切り替え
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT identity, COUNT(DISTINCT source_ip) as n_ips,
                   GROUP_CONCAT(DISTINCT source_ip) as ips
            FROM cloud_audit_events
            WHERE event_time >= datetime('now', ? || ' hours') AND source_ip != ''
            GROUP BY identity HAVING n_ips >= 3
        """, (f"-{hours}",)).fetchall()
        for r in rows:
            alerts.append({
                "identity": r["identity"], "from_country": "", "to_country": "",
                "from_ip": "", "to_ip": r["ips"], "minutes": None,
                "detail": f"{r['identity']} が直近{hours}時間で{r['n_ips']}個の異なる"
                          f"送信元IP（{r['ips']}）からアクセス — "
                          "複数拠点からの短時間アクセス（認証情報の使い回し・漏えいの可能性）",
            })
    return alerts


# ─────────────────────────────────────────
# サンプルデータ（実際のCloudTrail等が無くても試せるように）
# ─────────────────────────────────────────

def generate_sample_events() -> dict:
    """4パターン（不可能なトラベル・クロスリージョン・大量DL・スナップショット急増)を投入する。"""
    _init_tables()
    now = datetime.now()

    def ev(offset_sec, identity, ip, region, name, source, resource=""):
        ts = (now + timedelta(seconds=offset_sec)).isoformat()
        return {"event_time": ts, "identity": identity, "source_ip": ip, "region": region,
                "event_name": name, "event_source": source, "resource_name": resource,
                "event_class": _classify_event(name),
                "country": geoip.lookup_country(ip) or ""}

    events = []
    # 1) 不可能なトラベル: alice が国内IP→中国IPへ5分で切り替え
    events.append(ev(-600, "arn:aws:iam::111111111111:user/alice", "203.0.113.10",
                      "ap-northeast-1", "ConsoleLogin", "signin.amazonaws.com"))
    events.append(ev(-300, "arn:aws:iam::111111111111:user/alice", "1.0.1.5",
                      "ap-northeast-1", "ConsoleLogin", "signin.amazonaws.com"))

    # 2) 複数IP切り替え: bob が短時間に3つの異なるIPから
    for i, ip in enumerate(["198.51.100.11", "198.51.100.22", "198.51.100.33"]):
        events.append(ev(-200 + i * 30, "arn:aws:iam::111111111111:user/bob", ip,
                          "us-east-1", "GetCallerIdentity", "sts.amazonaws.com"))

    # 3) クロスリージョンAPIバースト: carol が4リージョンから
    for i, region in enumerate(["us-east-1", "eu-west-1", "ap-southeast-1", "sa-east-1"]):
        events.append(ev(-120 + i * 10, "arn:aws:iam::111111111111:user/carol",
                          "203.0.113.20", region, "DescribeInstances", "ec2.amazonaws.com"))

    # 4) 大量ダウンロード: dave が60個の異なるS3オブジェクトを取得
    for i in range(60):
        events.append(ev(-100 + i, "arn:aws:iam::111111111111:user/dave", "203.0.113.30",
                          "ap-northeast-1", "GetObject", "s3.amazonaws.com",
                          resource=f"customer-data-{i}.csv"))

    # 5) スナップショットエクスポート急増: backup-svc ロールが短時間に8回
    for i in range(8):
        events.append(ev(-90 + i * 5, "arn:aws:iam::111111111111:role/backup-svc",
                          "203.0.113.40", "ap-northeast-1", "CreateSnapshot", "ec2.amazonaws.com",
                          resource=f"vol-{1000+i}"))

    n = ingest_events(events, is_sample=True)
    return {"events_inserted": n}


def clear_sample_events() -> int:
    _init_tables()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        cur = conn.execute("DELETE FROM cloud_audit_events WHERE is_sample = 1")
        conn.commit()
        return cur.rowcount


def has_sample_events() -> bool:
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(
            "SELECT 1 FROM cloud_audit_events WHERE is_sample = 1 LIMIT 1").fetchone() is not None
