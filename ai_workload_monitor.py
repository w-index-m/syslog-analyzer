"""
AIワークロード監視（クラウドAIワークロード保護）

このアプリが呼び出す外部LLM API（Claude/Gemini/Groq/Ollama）の呼び出しを
継続的に記録し、以下のような「異常な挙動」を検知する:
  - 呼び出し頻度の急上昇（コスト枯渇・乱用の兆候）
  - 失敗の連続発生（APIキー失効・クォータ枯渇・意図的な妨害の兆候）
  - 異常に大きいプロンプトサイズ（リソース消費型の乱用の兆候）

record_call() を analyzer.ask_llm() の一元窓口から呼び出すことで、
呼び出し経路（analyze/judge/diagnose_* いずれの入口でも）によらず
全LLM呼び出しを横断的に可視化・監視する。
また check_rate_limit() を同じ場所で呼び出し、短時間の大量呼び出しを
ブロックする（コスト枯渇・DoS的な乱用への耐性）。
"""
import os
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path

DB_PATH = Path(os.environ.get("DB_PATH", str(Path(__file__).parent / "syslog.db")))

_lock = threading.Lock()

# レート制限（コスト枯渇・DoS対策）
RATE_LIMIT_WINDOW_SEC = 60
RATE_LIMIT_MAX_CALLS  = 30
_call_timestamps: list = []

# 異常検知の閾値
_PROMPT_SIZE_ANOMALY_CHARS = 20000
_FAILURE_BURST_THRESHOLD   = 5
_RATE_SPIKE_MULTIPLIER     = 4


def _init_tables():
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ai_calls (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           TEXT NOT NULL,
                provider     TEXT,
                prompt_chars INTEGER DEFAULT 0,
                success      INTEGER DEFAULT 0,
                latency_ms   INTEGER DEFAULT 0,
                error        TEXT,
                dlp_masked   INTEGER DEFAULT 0
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_calls_ts ON ai_calls(ts)")
        conn.commit()


def check_rate_limit() -> tuple[bool, str]:
    """AI呼び出し前に確認する。制限超過なら (False, 理由) を返す。"""
    now = time.time()
    with _lock:
        cutoff = now - RATE_LIMIT_WINDOW_SEC
        while _call_timestamps and _call_timestamps[0] < cutoff:
            _call_timestamps.pop(0)
        if len(_call_timestamps) >= RATE_LIMIT_MAX_CALLS:
            return False, (
                f"直近{RATE_LIMIT_WINDOW_SEC}秒間のAI呼び出しが{RATE_LIMIT_MAX_CALLS}件に達したため、"
                "一時的に制限しています（コスト枯渇・乱用対策）。しばらく待ってから再度お試しください。")
        _call_timestamps.append(now)
    return True, ""


def record_call(provider: str, prompt_chars: int, success: bool,
                 latency_ms: int, error: str = "", dlp_masked: int = 0):
    _init_tables()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            INSERT INTO ai_calls (ts, provider, prompt_chars, success, latency_ms, error, dlp_masked)
            VALUES (?,?,?,?,?,?,?)
        """, (datetime.now().isoformat(), provider, prompt_chars, int(success),
              latency_ms, error or "", dlp_masked))
        conn.commit()


def get_recent_calls(hours: float = 1) -> list[dict]:
    _init_tables()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT * FROM ai_calls WHERE ts >= datetime('now', ? || ' hours')
            ORDER BY ts DESC
        """, (f"-{hours}",)).fetchall()
        return [dict(r) for r in rows]


def get_summary(hours: float = 1) -> dict:
    calls = get_recent_calls(hours)
    total = len(calls)
    success = sum(1 for c in calls if c["success"])
    fail = total - success
    avg_latency = round(sum(c["latency_ms"] for c in calls) / total, 1) if total else 0
    max_prompt = max((c["prompt_chars"] for c in calls), default=0)
    dlp_total = sum(c["dlp_masked"] for c in calls)
    return {
        "total": total, "success": success, "fail": fail,
        "fail_rate_pct": round(fail / total * 100, 1) if total else 0,
        "avg_latency_ms": avg_latency, "max_prompt_chars": max_prompt,
        "dlp_masked_total": dlp_total,
    }


def get_anomalies(hours: float = 1) -> list[dict]:
    """
    直近の呼び出し履歴から異常な挙動を検知する:
      - 失敗の連続バースト / 異常に大きいプロンプト / 呼び出し頻度の急上昇
    """
    calls = get_recent_calls(hours)   # 新しい順
    anomalies = []

    consecutive_fail = 0
    for c in calls:
        if not c["success"]:
            consecutive_fail += 1
        else:
            break
    if consecutive_fail >= _FAILURE_BURST_THRESHOLD:
        anomalies.append({
            "type": "failure_burst", "severity": "high",
            "detail": f"直近{consecutive_fail}件のLLM呼び出しが連続して失敗しています"
                      "（APIキー失効・クォータ枯渇・意図的な妨害の可能性）。",
        })

    oversized = [c for c in calls if c["prompt_chars"] > _PROMPT_SIZE_ANOMALY_CHARS]
    if oversized:
        anomalies.append({
            "type": "oversized_prompt", "severity": "medium",
            "detail": f"{len(oversized)}件、{_PROMPT_SIZE_ANOMALY_CHARS:,}文字を超える"
                      "巨大なプロンプトが送信されています（リソース消費型の乱用の可能性）。",
        })

    if len(calls) >= 10:
        now_ts = datetime.now()
        recent_1min = sum(1 for c in calls
                           if (now_ts - datetime.fromisoformat(c["ts"])).total_seconds() <= 60)
        window_min = max(hours * 60, 1)
        avg_per_min = len(calls) / window_min
        if avg_per_min > 0 and recent_1min >= 5 and recent_1min > avg_per_min * _RATE_SPIKE_MULTIPLIER:
            anomalies.append({
                "type": "rate_spike", "severity": "medium",
                "detail": f"直近1分間の呼び出しが{recent_1min}件と、平均"
                          f"（{avg_per_min:.1f}件/分）の{_RATE_SPIKE_MULTIPLIER}倍を超えています。",
            })

    return anomalies
