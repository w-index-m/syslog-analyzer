"""
llmshark 連携（LLM ストリーミング通信のパフォーマンス解析: TTFT/ITL）

llmshark (https://github.com/llmshark/llmshark, `pip install llmshark`) は
pcapファイルから **平文の** HTTP/SSEストリーミングを直接パースし、
Time to First Token(TTFT)・Inter-Token Latency(ITL)等を計測するツール。

このアプリの他の解析（pcap_analyzer.py等）はネットワーク/セキュリティ層を
見るのに対し、llmsharkはLLM APIレスポンスの**内容そのもの**（SSEの
`data: {...}`チャンク）を読む必要があるため、**暗号化されていない通信
にしか使えない**（例: ローカルOllama http://localhost:11434 のキャプチャ。
Claude/OpenAI等のHTTPS通信は復号しない限り解析できない — これは
dlp.py/mitmproxyプロトタイプの回で説明した制約と同じ）。

llmsharkは重い依存関係（scipy/matplotlib/scikit-learn等）を持つため、
このアプリの必須要件には含めず、ローカルで `pip install llmshark` した
場合のみ有効になるオプトイン機能として実装する。
"""
import tempfile
from pathlib import Path

try:
    from llmshark.parser import PCAPParser
    from llmshark.analyzer import StreamAnalyzer
    LLMSHARK_AVAILABLE = True
except ImportError:
    LLMSHARK_AVAILABLE = False


def analyze_streaming_pcap(data: bytes) -> dict:
    """
    pcapバイト列をllmsharkで解析し、TTFT/ITL等のストリーミング性能統計を返す。
    平文HTTP/SSEのストリーミングセッションが含まれない場合は
    session_count=0 で返る（暗号化されている、または対象外の通信）。
    """
    if not LLMSHARK_AVAILABLE:
        return {"available": False, "error": "llmsharkが未インストールです（pip install llmshark）"}

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)

    try:
        parser = PCAPParser()
        sessions = parser.parse_file(tmp_path)
        if not sessions:
            return {"available": True, "session_count": 0, "sessions": [], "result": None}

        analyzer = StreamAnalyzer()
        result = analyzer.analyze_sessions(sessions)

        stats = result.overall_timing_stats
        return {
            "available": True,
            "session_count": result.session_count,
            "total_tokens": result.total_tokens_analyzed,
            "total_bytes": result.total_bytes_analyzed,
            "ttft_ms": round(stats.ttft_ms, 1) if stats else None,
            "mean_itl_ms": round(stats.mean_itl_ms, 1) if stats else None,
            "p95_itl_ms": round(float(stats.p95_itl_ms), 1) if stats else None,
            "tokens_per_second": round(stats.tokens_per_second, 1) if stats else None,
            "key_insights": result.key_insights,
            "anomalies": {
                "large_gaps": len(result.anomalies.large_gaps) if result.anomalies else 0,
                "outlier_chunks": len(result.anomalies.outlier_chunks) if result.anomalies else 0,
                "unusual_patterns": result.anomalies.unusual_patterns if result.anomalies else [],
                "silence_periods": len(result.anomalies.silence_periods) if result.anomalies else 0,
            } if result.anomalies else {},
            "sessions": [
                {
                    "session_id": s.session_id, "source_ip": s.source_ip, "dest_ip": s.dest_ip,
                    "dest_port": s.dest_port, "chunks": len(s.chunks),
                    "request_path": s.request_path, "response_status": s.response_status,
                } for s in sessions
            ],
        }
    finally:
        tmp_path.unlink(missing_ok=True)
