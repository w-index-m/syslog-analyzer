"""
公開アプリ（streamlit.app等）向けの軽量・自前アクセス解析。

Google Analytics等の外部サービスは使わない。Streamlitはブラウザタブごとに
サーバー側セッションを持つため、新規セッションの発生を「1訪問」とみなして
SQLiteに記録する。IPアドレスは保存しない（プライバシー配慮）。User-Agentは
Streamlitのバージョンによって取得できない場合があるため、取得できた範囲で
参考情報として保持する。

任意でGoogleスプレッドシートへも転記できる（Slack通知と同じ方式:
st.secrets優先、なければ環境変数からWebhook URLを取得）。スプレッドシート側に
Google Apps ScriptのWebアプリ(doPost)を1つ用意し、そのURLを
ACCESS_LOG_SHEET_WEBHOOK_URL として設定するだけで動く。未設定なら
スプレッドシートへの転記はスキップされ、ローカルSQLite記録のみ行われる。
"""
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

DB_PATH = Path(os.environ.get("DB_PATH", str(Path(__file__).parent / "syslog.db")))

JST = timezone(timedelta(hours=9))


def _now_jst() -> datetime:
    """サーバーのタイムゾーン(Streamlit Cloud等はUTC)に依らず、常にJSTの現在時刻を返す。"""
    return datetime.now(JST)


def get_sheet_webhook_url() -> str:
    """スプレッドシート転記用Webhook URLを取得する（st.secrets優先、なければ環境変数）。"""
    try:
        import streamlit as st
        if "ACCESS_LOG_SHEET_WEBHOOK_URL" in st.secrets:
            return str(st.secrets["ACCESS_LOG_SHEET_WEBHOOK_URL"])
    except Exception:
        pass
    return os.environ.get("ACCESS_LOG_SHEET_WEBHOOK_URL", "")


def post_to_sheet(session_id: str, visited_at: str, user_agent: str) -> None:
    """
    スプレッドシートへ1件転記する（ベストエフォート）。
    Webhook未設定・通信失敗のいずれでもアプリの動作は止めない。
    """
    url = get_sheet_webhook_url()
    if not url:
        return
    try:
        requests.post(
            url,
            json={"session_id": session_id, "visited_at": visited_at, "user_agent": user_agent},
            timeout=3,
        )
    except requests.RequestException:
        pass


def _init_table():
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS access_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT NOT NULL,
                visited_at  TEXT NOT NULL,
                user_agent  TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_access_visited ON access_log(visited_at)")
        conn.commit()


def record_visit(session_id: str, user_agent: str = ""):
    """新規ブラウザセッション1回につき1回だけ呼ぶ想定（app.py側でsession_stateにより1回化）。"""
    _init_table()
    visited_at = _now_jst().strftime("%Y-%m-%dT%H:%M:%S+09:00")
    ua = (user_agent or "")[:300]
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute(
            "INSERT INTO access_log (session_id, visited_at, user_agent) VALUES (?,?,?)",
            (session_id, visited_at, ua),
        )
        conn.commit()
    post_to_sheet(session_id, visited_at, ua)


def simplify_user_agent(ua: str) -> str:
    """User-Agent文字列から大まかなブラウザ/クライアント名を抽出する（表示用）。"""
    if not ua:
        return "(不明)"
    u = ua.lower()
    if "bot" in u or "crawl" in u or "spider" in u:
        return "🤖 Bot/クローラー"
    if "edg/" in u:
        return "Edge"
    if "chrome" in u and "safari" in u and "edg/" not in u:
        return "Chrome"
    if "firefox" in u:
        return "Firefox"
    if "safari" in u and "chrome" not in u:
        return "Safari"
    return "その他"


def get_stats(days: int = 30) -> dict:
    """概要統計: 総訪問数・ユニークセッション数・日別推移・UA内訳を返す。"""
    _init_table()
    since = (_now_jst() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S+09:00")
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.row_factory = sqlite3.Row
        total_all = conn.execute("SELECT COUNT(*) c FROM access_log").fetchone()["c"]
        unique_all = conn.execute(
            "SELECT COUNT(DISTINCT session_id) c FROM access_log").fetchone()["c"]
        total_recent = conn.execute(
            "SELECT COUNT(*) c FROM access_log WHERE visited_at >= ?", (since,)).fetchone()["c"]
        unique_recent = conn.execute(
            "SELECT COUNT(DISTINCT session_id) c FROM access_log WHERE visited_at >= ?",
            (since,)).fetchone()["c"]
        daily = conn.execute(
            """SELECT substr(visited_at,1,10) AS day,
                      COUNT(*) AS visits,
                      COUNT(DISTINCT session_id) AS unique_sessions
               FROM access_log WHERE visited_at >= ?
               GROUP BY day ORDER BY day""",
            (since,),
        ).fetchall()
        top_ua = conn.execute(
            """SELECT user_agent, COUNT(*) c FROM access_log
               WHERE visited_at >= ? AND user_agent != ''
               GROUP BY user_agent ORDER BY c DESC LIMIT 10""",
            (since,),
        ).fetchall()
    return {
        "total_all_time":  total_all,
        "unique_all_time": unique_all,
        "total_recent":    total_recent,
        "unique_recent":   unique_recent,
        "daily":           [dict(r) for r in daily],
        "top_user_agents": [dict(r) for r in top_ua],
    }
