"""
軽量Web診断（アクティブスキャン）モジュール。

【重要 - 必ず読むこと】
本モジュールは呼び出すと実際にネットワークリクエストを対象へ送信する。
- テスト対象への正当な権限（自己管理下、または書面による許可）がある場合のみ使用すること。
- 破壊的な操作（データの作成/変更/削除、認証情報の総当たり、大量リクエストによる
  負荷試験など）は一切含まない。すべて読み取り専用の診断的リクエストに限定している。
- 各チェックは対象への配慮のため小規模なリクエスト数・タイムアウト・
  リクエスト間隔（REQUEST_DELAY_SEC）を設けている。
- 呼び出し側（UI）で、利用者が対象への認可を明示的に確認したことをもって
  初めて実行される設計を前提とする（本モジュール自体は認可の有無を検証しない）。
"""
import re
import time
import urllib.parse
from datetime import datetime, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 8
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; syslog-analyzer-webdiag/1.0)"
REQUEST_DELAY_SEC = 0.25  # 対象への配慮のためリクエスト間隔を空ける
MAX_SENSITIVE_PATHS = 30

# 安全に確認できる、よく晒される機密パス/管理画面の小規模ワードリスト。
# 単純なGETでの存在確認(ステータスコード/Content-Length)のみ行い、
# 認証試行やペイロード送信は一切行わない。
_COMMON_SENSITIVE_PATHS = [
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/.htaccess",
    "/wp-admin/", "/wp-login.php", "/phpmyadmin/", "/admin/", "/administrator/",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    "/backup.zip", "/backup.sql", "/database.sql", "/dump.sql",
    "/config.php.bak", "/web.config", "/.aws/credentials",
    "/actuator/health", "/actuator/env", "/debug", "/console",
    "/swagger-ui.html", "/api/swagger.json", "/graphql",
    "/.svn/entries", "/.DS_Store", "/composer.json", "/package.json",
    "/server-status", "/server-info",
]

_SECURITY_HEADERS = {
    "content-security-policy": "CSP未設定 — XSS等の被害範囲を広げる可能性",
    "x-frame-options": "X-Frame-Options未設定 — クリックジャッキング対策なし",
    "x-content-type-options": "X-Content-Type-Options未設定 — MIME種別スニッフィングのリスク",
    "strict-transport-security": "HSTS未設定 — HTTPSへの強制がない(SSL Strip等のリスク)",
    "referrer-policy": "Referrer-Policy未設定 — リファラ経由の情報漏洩の可能性",
    "permissions-policy": "Permissions-Policy未設定 — ブラウザ機能の制限がない",
}

_SQLI_ERROR_PATTERNS = [
    (re.compile(r"(?i)you have an error in your sql syntax"), "MySQL"),
    (re.compile(r"(?i)warning:\s*mysql_"), "MySQL"),
    (re.compile(r"(?i)unclosed quotation mark after the character string"), "MSSQL"),
    (re.compile(r"(?i)microsoft ole db provider for sql server"), "MSSQL"),
    (re.compile(r"(?i)quoted string not properly terminated"), "Oracle"),
    (re.compile(r"(?i)ora-\d{5}"), "Oracle"),
    (re.compile(r"(?i)pg_query\(\)|postgresql.*?error|invalid input syntax for"), "PostgreSQL"),
    (re.compile(r"(?i)sqlite3?\.OperationalError|sqlite_(step|exec)"), "SQLite"),
    (re.compile(r"(?i)django\.db\.utils\.(Integrity|Operational)Error"), "Django ORM"),
]

# open redirect判定用: パラメータ名にリダイレクト意図が読み取れるものだけを対象にする
_REDIRECT_PARAM_HINTS = re.compile(r"(?i)redirect|return|url|next|continue|dest|target|goto")

_REQUEST_ID_PREFIX = "wdscan"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_get(url: str, timeout: int = DEFAULT_TIMEOUT, headers: dict | None = None,
              allow_redirects: bool = True):
    _headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        _headers.update(headers)
    return requests.get(url, timeout=timeout, headers=_headers,
                         allow_redirects=allow_redirects, verify=True)


def check_security_headers(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    対象URLへ1回GETし、レスポンスヘッダのセキュリティ設定・Cookie属性・
    バージョン情報の開示を確認する（通常のブラウザアクセス相当の1リクエストのみ）。
    """
    result = {"url": url, "ok": False, "status_code": None, "issues": [],
              "headers_present": [], "server_banner": "", "powered_by": "",
              "cookie_issues": [], "error": None}
    try:
        resp = _safe_get(url, timeout=timeout)
        result["ok"] = True
        result["status_code"] = resp.status_code
        h = {k.lower(): v for k, v in resp.headers.items()}

        for header, msg in _SECURITY_HEADERS.items():
            if header in h:
                result["headers_present"].append(header)
            else:
                result["issues"].append({"severity": "medium", "detail": msg})

        server = h.get("server", "")
        powered = h.get("x-powered-by", "")
        if server:
            result["server_banner"] = server
            if re.search(r"\d+\.\d+", server):
                result["issues"].append({
                    "severity": "low",
                    "detail": f"Serverヘッダーでバージョン番号を開示: {server}"
                              "（既知脆弱性の特定に悪用され得る）",
                })
        if powered:
            result["powered_by"] = powered
            result["issues"].append({
                "severity": "low",
                "detail": f"X-Powered-Byヘッダーで実装技術を開示: {powered}",
            })

        # Set-Cookieヘッダーを生の形で取り出しSecure/HttpOnly/SameSite属性を確認
        try:
            raw_cookies = resp.raw.headers.get_all("Set-Cookie") if resp.raw else None
        except Exception:
            raw_cookies = None
        if not raw_cookies:
            sc = resp.headers.get("Set-Cookie")
            raw_cookies = [sc] if sc else []
        for raw in raw_cookies:
            name = raw.split("=", 1)[0].strip()
            low = raw.lower()
            missing = []
            if "secure" not in low:
                missing.append("Secure")
            if "httponly" not in low:
                missing.append("HttpOnly")
            if "samesite" not in low:
                missing.append("SameSite")
            if missing:
                result["cookie_issues"].append({
                    "name": name,
                    "missing": missing,
                    "detail": f"Cookie「{name}」に{'/'.join(missing)}属性がありません",
                })
    except requests.exceptions.SSLError as e:
        result["error"] = f"TLS証明書エラー: {e}"
    except requests.exceptions.RequestException as e:
        result["error"] = f"接続エラー: {e}"
    return result


def check_sensitive_paths(url: str, extra_paths: list | None = None,
                           timeout: int = DEFAULT_TIMEOUT,
                           max_paths: int = MAX_SENSITIVE_PATHS) -> dict:
    """
    既知の機密パス/管理画面の小規模ワードリストへGETし、露出していないか確認する。
    存在確認のみ（認証試行やダウンロード内容の解析は行わない）。
    """
    parsed = urllib.parse.urlsplit(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    paths = list(_COMMON_SENSITIVE_PATHS)
    if extra_paths:
        paths += [p for p in extra_paths if p not in paths]
    paths = paths[:max_paths]

    result = {"base_url": base, "checked": 0, "exposed": [], "errors": []}
    for path in paths:
        try:
            resp = _safe_get(base + path, timeout=timeout, allow_redirects=False)
            result["checked"] += 1
            if resp.status_code in (200, 201, 206):
                result["exposed"].append({
                    "path": path, "status_code": resp.status_code,
                    "content_length": len(resp.content),
                    "detail": f"{path} が公開されています(HTTP {resp.status_code})",
                })
            elif resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                # 単純にトップページへのリダイレクト等は除外し、パス自体が
                # 存在してリダイレクトされているケースのみ拾う
                if loc and path.rstrip("/") not in loc and loc not in ("/", ""):
                    continue
        except requests.exceptions.RequestException as e:
            result["errors"].append({"path": path, "error": str(e)})
        time.sleep(REQUEST_DELAY_SEC)
    return result


def check_reflected_xss(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    URLの既存クエリパラメータそれぞれに、実行はされない一意なマーカー文字列を注入し、
    レスポンス内でHTMLエスケープされずに反射していないか確認する
    （<script>等は実際にブラウザで実行させるものではなく、反射の有無を見るだけの
    無害なマーカー文字列を使用）。
    """
    parsed = urllib.parse.urlsplit(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    result = {"url": url, "tested_params": list(params.keys()), "findings": [], "errors": []}
    if not params:
        result["note"] = "URLにクエリパラメータが無いため、パラメータ単位のXSS確認は実施していません。"
        return result

    for pname in params:
        marker = f"{_REQUEST_ID_PREFIX}xss{abs(hash((url, pname))) % 100000}"
        payload = f'"><svg id={marker}>'
        test_params = dict(params)
        test_params[pname] = payload
        test_qs = urllib.parse.urlencode(test_params)
        test_url = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, test_qs, parsed.fragment))
        try:
            resp = _safe_get(test_url, timeout=timeout)
            if payload in resp.text:
                result["findings"].append({
                    "param": pname, "severity": "high",
                    "detail": f"パラメータ「{pname}」への入力がHTMLエスケープされずに反射"
                              "（反射型XSSの可能性）",
                })
            elif marker in resp.text:
                result["findings"].append({
                    "param": pname, "severity": "low",
                    "detail": f"パラメータ「{pname}」への入力が(一部エスケープされつつ)反射"
                              "（要目視確認）",
                })
        except requests.exceptions.RequestException as e:
            result["errors"].append({"param": pname, "error": str(e)})
        time.sleep(REQUEST_DELAY_SEC)
    return result


def check_sqli_indicators(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    URLの既存クエリパラメータそれぞれにSQLi判定用のトリガー文字（'等）を注入し、
    レスポンスに既知のDBエラーメッセージが出現しないか確認する（エラーベース検知のみ。
    UNION/ブラインド/時間ベースの抽出は行わない — 対象への負荷・データ露出リスクを避けるため）。
    """
    parsed = urllib.parse.urlsplit(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    result = {"url": url, "tested_params": list(params.keys()), "findings": [], "errors": []}
    if not params:
        result["note"] = "URLにクエリパラメータが無いため、パラメータ単位のSQLi確認は実施していません。"
        return result

    probe_suffixes = ["'", "''", "\""]
    for pname, pval in params.items():
        for suffix in probe_suffixes:
            test_params = dict(params)
            test_params[pname] = f"{pval}{suffix}"
            test_qs = urllib.parse.urlencode(test_params)
            test_url = urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, test_qs, parsed.fragment))
            try:
                resp = _safe_get(test_url, timeout=timeout)
                for pattern, dbname in _SQLI_ERROR_PATTERNS:
                    if pattern.search(resp.text):
                        result["findings"].append({
                            "param": pname, "severity": "high", "db_hint": dbname,
                            "detail": f"パラメータ「{pname}」への「{suffix}」注入で"
                                      f"{dbname}のエラーメッセージを検出（SQLインジェクションの可能性）",
                        })
                        break
                else:
                    time.sleep(REQUEST_DELAY_SEC)
                    continue
                break  # このパラメータで既に検出済みなら他の記号は試さない
            except requests.exceptions.RequestException as e:
                result["errors"].append({"param": pname, "error": str(e)})
            time.sleep(REQUEST_DELAY_SEC)
    return result


def check_open_redirect(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    URLパラメータのうちリダイレクト意図が読み取れる名前(redirect/next/url等)について、
    外部ドメインを注入した際に実際にそこへリダイレクトされないか確認する。
    """
    parsed = urllib.parse.urlsplit(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    candidates = [p for p in params if _REDIRECT_PARAM_HINTS.search(p)]
    result = {"url": url, "tested_params": candidates, "findings": [], "errors": []}
    if not candidates:
        result["note"] = "リダイレクト系のパラメータ名(redirect/next/url等)が見つからないため、実施していません。"
        return result

    probe_target = "https://example.com/wdscan-openredirect-probe"
    for pname in candidates:
        test_params = dict(params)
        test_params[pname] = probe_target
        test_qs = urllib.parse.urlencode(test_params)
        test_url = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, test_qs, parsed.fragment))
        try:
            resp = _safe_get(test_url, timeout=timeout, allow_redirects=False)
            loc = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and "example.com" in loc:
                result["findings"].append({
                    "param": pname, "severity": "medium",
                    "detail": f"パラメータ「{pname}」に外部URLを指定するとそのまま"
                              f"リダイレクトされました（オープンリダイレクトの可能性、Location: {loc}）",
                })
        except requests.exceptions.RequestException as e:
            result["errors"].append({"param": pname, "error": str(e)})
        time.sleep(REQUEST_DELAY_SEC)
    return result


def check_cors_config(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    偽装したOriginヘッダーを送信し、Access-Control-Allow-Originがそのまま
    反射されていないか（かつAllow-Credentialsも有効か）確認する（CORS誤設定の検知）。
    """
    result = {"url": url, "ok": False, "issues": [], "error": None}
    probe_origin = "https://wdscan-cors-probe.example.org"
    try:
        resp = _safe_get(url, timeout=timeout, headers={"Origin": probe_origin})
        result["ok"] = True
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == probe_origin or acao == "*" and acac.lower() == "true":
            result["issues"].append({
                "severity": "high",
                "detail": f"任意のOriginヘッダーがAccess-Control-Allow-Originにそのまま反射され"
                          f"（Allow-Credentials: {acac or 'なし'}）、他オリジンからの"
                          "認証済みリクエストが許可される可能性があります。",
            })
        elif acao == "*":
            result["issues"].append({
                "severity": "low",
                "detail": "Access-Control-Allow-Origin: * が設定されています"
                          "（認証情報を伴わないAPIであれば通常問題ありません）。",
            })
    except requests.exceptions.RequestException as e:
        result["error"] = f"接続エラー: {e}"
    return result


def run_basic_web_diagnostics(url: str, checks: list | None = None,
                               timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    上記チェックをまとめて実行し、統合レポートを返す。
    checks未指定時は全チェックを実行する。
    重要: 呼び出し前に対象への認可確認をUI側で必ず行うこと。
    """
    all_checks = ("headers", "sensitive_paths", "xss", "sqli", "open_redirect", "cors")
    checks = checks or list(all_checks)
    report = {
        "url": url, "started_at": _now_iso(), "checks_run": checks,
        "headers": None, "sensitive_paths": None, "xss": None,
        "sqli": None, "open_redirect": None, "cors": None,
        "finished_at": None,
    }
    if "headers" in checks:
        report["headers"] = check_security_headers(url, timeout=timeout)
    if "sensitive_paths" in checks:
        report["sensitive_paths"] = check_sensitive_paths(url, timeout=timeout)
    if "xss" in checks:
        report["xss"] = check_reflected_xss(url, timeout=timeout)
    if "sqli" in checks:
        report["sqli"] = check_sqli_indicators(url, timeout=timeout)
    if "open_redirect" in checks:
        report["open_redirect"] = check_open_redirect(url, timeout=timeout)
    if "cors" in checks:
        report["cors"] = check_cors_config(url, timeout=timeout)
    report["finished_at"] = _now_iso()
    return report
