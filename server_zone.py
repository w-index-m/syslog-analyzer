"""
サーバーゾーンCIDR設定モジュール。

自分のネットワークで「サーバー/DMZ機器が属する」と申告したIPレンジ(CIDR)を、
ユーザーがUIから登録・管理する。生成AI/LLMサービス宛の通信
（ai_service_domains.py で判定）が、このゾーンに属するIPから発生している
場合、ユーザー端末からの通常利用（AIチャットをブラウザで使う等）とは区別し、
重大度の高いアラートとして扱う。

これは別リポジトリ（ai-agent-attack-defense）の検知ルール R1/R4
（サーバー系ホストからのLLM/メッセージングAPI egressを最優先で検知する）と
同じ考え方をこちらのpcap解析に持ち込んだもの。サーバーは通常、人が対話的に
AIチャットを使う場所ではないため、もしそこから生成AIサービスへの通信が
発生していれば、侵害されたサーバー上で動くエージェント/マルウェアが、
外部LLM API経由でのC2通信・データ持ち出し・自動化された攻撃の一部として
通信している可能性がある。

CIDRの登録が無い環境では、この機能は常に false を返すだけで、
既存のAIサービス検知（ai_service_sessions）には一切影響しない。
"""
import ipaddress
import os
import sqlite3
from pathlib import Path

DB_PATH = Path(os.environ.get("DB_PATH", str(Path(__file__).parent / "syslog.db")))


def _init_table():
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS server_zone_cidrs (
                cidr  TEXT PRIMARY KEY,
                label TEXT DEFAULT ''
            )
        """)
        conn.commit()


def add_cidr(cidr: str, label: str = "") -> tuple[bool, str]:
    """CIDR表記を検証して登録する。不正な形式は拒否し、(False, 理由) を返す。"""
    cidr = (cidr or "").strip()
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return False, f"不正なCIDR表記です: {e}"
    _init_table()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO server_zone_cidrs (cidr, label) VALUES (?, ?)",
            (cidr, label),
        )
        conn.commit()
    return True, ""


def remove_cidr(cidr: str):
    _init_table()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("DELETE FROM server_zone_cidrs WHERE cidr = ?", (cidr,))
        conn.commit()


def get_cidrs() -> list[dict]:
    """登録済みの {"cidr": ..., "label": ...} の一覧をCIDR昇順で返す。"""
    _init_table()
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT cidr, label FROM server_zone_cidrs ORDER BY cidr"
        ).fetchall()
        return [dict(r) for r in rows]


def is_server_zone_ip(ip: str, cidrs: list[str] | None = None) -> bool:
    """
    IPが登録済みのサーバーゾーンCIDRのいずれかに含まれるか判定する。
    cidrs を渡さない場合は get_cidrs() を呼んでDBから取得する
    （pcap内の全セッションに対して繰り返し判定する場合は、
    呼び出し側で一度だけ取得して渡すことで余分なDBアクセスを避けられる）。
    """
    if cidrs is None:
        cidrs = [c["cidr"] for c in get_cidrs()]
    if not cidrs:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False
