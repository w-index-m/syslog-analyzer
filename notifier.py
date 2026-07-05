"""
Slack通知モジュール。
Incoming Webhook URL 経由でアラートをSlackへ送信する。

有効化条件: 環境変数 SLACK_NOTIFY_ENABLED="1" かつ Webhook URL 設定済み。
Webhook URLは st.secrets（Streamlit Cloud）または環境変数 SLACK_WEBHOOK_URL
から取得する（APIキーと同じ優先順位）。

通知の重複送信を防ぐため、キー単位で「状態が変化した時」または
「前回送信から一定時間経過した時」のみ送信する（SQLiteで状態管理）。
"""
import os
import sqlite3
from datetime import datetime
from pathlib import Path

import requests

DB_PATH = Path(os.environ.get("DB_PATH", str(Path(__file__).parent / "syslog.db")))


def get_webhook_url() -> str:
    """Slack Incoming Webhook URLを取得する（st.secrets優先、なければ環境変数）。"""
    try:
        import streamlit as st
        if "SLACK_WEBHOOK_URL" in st.secrets:
            return str(st.secrets["SLACK_WEBHOOK_URL"])
    except Exception:
        pass
    return os.environ.get("SLACK_WEBHOOK_URL", "")


def is_enabled() -> bool:
    """通知が有効化されており、Webhook URLが設定されているか。"""
    return os.environ.get("SLACK_NOTIFY_ENABLED", "") == "1" and bool(get_webhook_url())


def send_slack_message(text: str, webhook_url: str = None) -> tuple:
    """
    Slack Incoming Webhookへメッセージを送信する。
    戻り値: (成功したか, エラーメッセージ or None)
    """
    url = webhook_url or get_webhook_url()
    if not url:
        return False, "Slack Webhook URLが設定されていません。"
    try:
        resp = requests.post(url, json={"text": text}, timeout=5)
        if resp.ok:
            return True, None
        return False, f"Slack応答異常: HTTP {resp.status_code} {resp.text[:200]}"
    except requests.RequestException as e:
        return False, f"Slack送信エラー: {e}"


def _init_table():
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS notification_state (
                key TEXT PRIMARY KEY,
                last_level TEXT,
                last_notified_at TEXT
            )
        """)
        conn.commit()


def should_notify(key: str, level: str, min_interval_sec: int = 1800) -> bool:
    """
    同じkeyについて、前回とレベルが変化した場合、または
    前回送信からmin_interval_sec秒以上経過した場合のみTrueを返す（スパム防止）。
    """
    _init_table()
    now = datetime.now()
    notify = False
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        row = conn.execute(
            "SELECT last_level, last_notified_at FROM notification_state WHERE key=?", (key,)
        ).fetchone()
        if row is None:
            notify = True
        else:
            last_level, last_at = row
            if last_level != level:
                notify = True
            elif last_at:
                try:
                    elapsed = (now - datetime.fromisoformat(last_at)).total_seconds()
                    notify = elapsed >= min_interval_sec
                except ValueError:
                    notify = True
            else:
                notify = True
        if notify:
            conn.execute("""
                INSERT INTO notification_state (key, last_level, last_notified_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    last_level=excluded.last_level, last_notified_at=excluded.last_notified_at
            """, (key, level, now.isoformat()))
            conn.commit()
    return notify


def notify_alert(key: str, level: str, message: str, min_interval_sec: int = 1800) -> None:
    """
    通知が有効な場合に、重複防止ロジックを通してSlackへ送信する。
    バックグラウンドのポーラースレッドから呼ばれるため、例外は握りつぶし
    コンソール出力のみに留める（監視ループを止めないため）。
    """
    if not is_enabled():
        return
    try:
        if should_notify(key, level, min_interval_sec):
            ok, err = send_slack_message(message)
            if not ok:
                print(f"[notifier] Slack送信失敗: {err}")
    except Exception as e:
        print(f"[notifier] 通知処理エラー: {e}")
