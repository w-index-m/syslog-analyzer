"""
複数の show 系コマンド出力をまとめて解析する。

機器で採取した show logging / show running-config / show interface status /
show version などを1つのテキストにまとめて貼り付けると、
  1) コマンドごとにセクション分割
  2) show logging はログ行を抽出（DB取り込み用）
  3) running-config / interface status / version から異常性をチェック
を行う。

異常性チェックはヒューリスティック（APIキー不要）。より詳細な相関診断は
LLM 解析（analyzer.ask_llm）を併用する。
"""
import re

# コマンドプロンプト + show コマンドのエコー行
#   例: "Switch#show logging" / "Router>show run" / "SW1#sh int status"
_PROMPT_CMD_RE = re.compile(r"^\s*([\w\-\.]+)\s*[#>]\s*(sh(?:ow)?\b.*)$", re.IGNORECASE)
# 単なるプロンプト行（例 "Switch#"）
_BARE_PROMPT_RE = re.compile(r"^\s*[\w\-\.]+\s*[#>]\s*$")


def _classify_command(cmd: str) -> str:
    """show コマンド文字列をセクション種別に分類。"""
    c = cmd.lower()
    if re.search(r"\blogg", c):
        return "logging"
    if re.search(r"\brun|\bstart|\bconfig", c):
        return "config"
    if re.search(r"\bint\w*\s+status|\binterface.*status", c):
        return "intf_status"
    if re.search(r"\bip\s+int\w*\s+br|\bint\w*\s+br", c):
        return "intf_brief"
    if re.search(r"\bint", c):
        return "interfaces"
    if re.search(r"\bver", c):
        return "version"
    if re.search(r"\bcdp\s+neigh", c):
        return "cdp"
    if re.search(r"\bproc\w*\s+cpu|\bcpu", c):
        return "cpu"
    return "other"


def split_sections(text: str) -> list[dict]:
    """
    まとめ貼り付けテキストを show コマンドごとに分割。
    戻り値: [{"cmd": コマンド文字列, "kind": 種別, "body": 本文}]
    プロンプトが1つも無い場合は全体を1つの logging セクションとみなす。
    """
    lines = (text or "").splitlines()
    sections: list[dict] = []
    cur = None
    for line in lines:
        m = _PROMPT_CMD_RE.match(line)
        if m:
            # 新しい show セクション開始
            if cur:
                sections.append(cur)
            cmd = m.group(2).strip()
            cur = {"cmd": cmd, "kind": _classify_command(cmd), "body": []}
            continue
        if _BARE_PROMPT_RE.match(line):
            # プロンプトのみ → セクション区切り（本文には含めない）
            continue
        if cur is not None:
            cur["body"].append(line)
    if cur:
        sections.append(cur)

    # プロンプトが無く分割できなかった場合、全体を logging とみなす
    if not sections and (text or "").strip():
        sections = [{"cmd": "show logging", "kind": "logging",
                     "body": text.splitlines()}]

    for s in sections:
        s["body"] = "\n".join(s["body"]).strip()
    return sections


# ── 異常性チェック ────────────────────────────────────────────
def _add(anoms, severity, category, detail, evidence="", remedy=""):
    anoms.append({"severity": severity, "category": category,
                  "detail": detail, "evidence": evidence, "remedy": remedy})


def _check_config(body: str, anoms: list):
    """running-config の異常/注意点を検出。"""
    if not body:
        return
    low = body.lower()

    # ホスト名が既定値
    hm = re.search(r"^\s*hostname\s+(\S+)", body, re.IGNORECASE | re.MULTILINE)
    if hm and hm.group(1) in ("Switch", "Router", "switch", "router"):
        _add(anoms, "WARNING", "未設定", "ホスト名が既定値のまま（未設定機の可能性）",
             f"hostname {hm.group(1)}",
             remedy="ホスト名を設定: (config)# hostname <装置名>")

    # 特権パスワード未設定
    if "enable secret" not in low and "enable password" not in low:
        _add(anoms, "WARNING", "セキュリティ", "特権EXEC(enable)パスワードが未設定",
             "enable secret / enable password なし",
             remedy="特権パスワードを設定: (config)# enable secret <強固なパスワード>")

    # パスワード平文
    if "no service password-encryption" in low:
        _add(anoms, "NOTICE", "セキュリティ", "パスワード暗号化が無効（平文保存）",
             "no service password-encryption",
             remedy="平文保存を回避: (config)# service password-encryption")

    # HTTP サーバ有効
    if re.search(r"^\s*ip http server", body, re.IGNORECASE | re.MULTILINE):
        _add(anoms, "NOTICE", "セキュリティ", "HTTPサーバが有効（未使用なら無効化推奨）",
             "ip http server",
             remedy="未使用なら無効化: (config)# no ip http server / no ip http secure-server")

    # SSH/ユーザ・VTY 認証
    has_user = bool(re.search(r"^\s*username\s+\S+", body, re.IGNORECASE | re.MULTILINE))
    vty_block = re.search(r"line vty[\s\S]*?(?=\n\S|\nline |\Z)", body, re.IGNORECASE)
    if vty_block:
        vb = vty_block.group(0).lower()
        if "transport input telnet" in vb or ("transport input all" in vb):
            _add(anoms, "WARNING", "セキュリティ", "VTYでTelnet(平文)が許可されている",
                 "line vty: transport input telnet/all",
                 remedy="SSHのみ許可: (config-line)# transport input ssh")
        if "login" not in vb and "password" not in vb and not has_user:
            _add(anoms, "WARNING", "リモート管理", "VTYにログイン認証が設定されていない",
                 "line vty: login/password なし",
                 remedy="ローカル認証を設定: (config)# username admin secret <pw> → "
                        "(config-line)# login local")
    if "crypto key generate rsa" not in low and "ip ssh" not in low and not has_user:
        _add(anoms, "NOTICE", "リモート管理", "SSHが設定されていない可能性（鍵/ユーザなし）",
             "ip ssh / username なし",
             remedy="SSH有効化: (config)# ip domain-name <名> → crypto key generate rsa "
                    "modulus 2048 → ip ssh version 2")

    # 管理IP(SVI)の有無
    svi_ip = re.search(r"interface Vlan\d+[\s\S]*?ip address\s+[\d.]+", body, re.IGNORECASE)
    if not svi_ip:
        _add(anoms, "WARNING", "管理性", "管理用IPアドレス(SVI)が未設定（インバンド管理不可）",
             "interface Vlan* に ip address なし",
             remedy="管理SVIを設定: (config)# interface vlan1 → ip address <IP> <mask> → no shutdown")

    # syslog 転送
    if not re.search(r"^\s*logging\s+(host\s+)?[\d.]+", body, re.IGNORECASE | re.MULTILINE):
        _add(anoms, "NOTICE", "運用", "syslog転送先(logging host)が未設定",
             "logging <ip> なし",
             remedy="syslog転送先を設定: (config)# logging host <SYSLOGサーバIP>")


def _check_intf_status(body: str, anoms: list):
    """show interface status の異常を検出。"""
    if not body:
        return
    lines = [l for l in body.splitlines() if l.strip()]
    total = connected = notconnect = errdis = disabled = halfdup = 0
    for l in lines:
        low = l.lower()
        if low.startswith("port") and "status" in low:
            continue  # ヘッダ
        if not re.search(r"(connected|notconnect|disabled|err-disabled|monitoring|faulty)", low):
            continue
        total += 1
        if "err-disabled" in low:
            errdis += 1
            _add(anoms, "ERROR", "ポート", "err-disabled ポートを検出（要復旧）", l.strip(),
                 remedy="原因確認後に復旧: # show interface <port> → 原因除去 → "
                        "(config-if)# shutdown → no shutdown（errdisable recovery設定も検討）")
        elif "connected" in low:
            connected += 1
            # 半二重は不一致の疑い
            if re.search(r"\bhalf\b", low):
                halfdup += 1
                _add(anoms, "WARNING", "ポート", "接続中ポートが半二重（デュプレックス不一致の疑い）", l.strip(),
                     remedy="両端の速度/デュプレックスを揃える: (config-if)# duplex auto / speed auto、"
                            "または両端で固定値を一致させる")
        elif "disabled" in low:
            disabled += 1
        elif "notconnect" in low:
            notconnect += 1
    if total and connected == 0:
        _add(anoms, "WARNING", "接続性", f"稼働中のリンクが1つもない（全{total}ポートが未接続/停止）",
             f"connected=0 / notconnect={notconnect} / disabled={disabled}",
             remedy="ケーブル接続とポート状態を確認: # show interface status、"
                    "SFP未実装(Not Present)なら必要に応じてモジュール装着")


def _check_intf_brief(body: str, anoms: list):
    """show ip interface brief の異常（up/down 不一致など）。"""
    if not body:
        return
    for l in body.splitlines():
        low = l.lower()
        # protocol down while admin up → L1/L2 問題
        if re.search(r"\bup\s+down\b", low):
            _add(anoms, "WARNING", "接続性", "administratively up だが protocol down（L1/L2要確認）", l.strip(),
                 remedy="物理/データリンク層を確認: ケーブル・SFP・対向機・カプセル化/クロック等")
        if "administratively down" in low:
            pass  # 意図的shutdown（設定由来）なので単体では警告しない


def _check_license(sections_text: str, anoms: list):
    if re.search(r"no valid license", sections_text, re.IGNORECASE):
        _add(anoms, "WARNING", "ライセンス",
             "有効なライセンスが無い（次回起動で機能レベルが降格する可能性）",
             "No valid license found",
             remedy="# show license / show version でレベル確認。必要な機能なら正規ライセンス適用、"
                    "不要なら (config)# license boot level ipbase で警告解消")


def check_anomalies(sections: list) -> dict:
    """
    セクション群から異常性をチェック。
    戻り値: {"anomalies": [...], "kinds": {kind: 件数}, "logging_body": str,
             "config_body": str, "intf_body": str, "version_body": str}
    """
    anoms: list = []
    kinds: dict = {}
    logging_body = config_body = intf_body = version_body = ""
    extra_parts = []   # routing/cpu/counters/cdp/other → LLM相関解析の追加材料
    all_text = []

    _kind_ja = {"interfaces": "show interfaces", "intf_brief": "show ip int brief",
                "version": "show version", "cdp": "show cdp neighbors",
                "cpu": "show processes cpu", "other": "その他show出力"}

    for s in sections:
        kinds[s["kind"]] = kinds.get(s["kind"], 0) + 1
        all_text.append(s["body"])
        if s["kind"] == "logging":
            logging_body = (logging_body + "\n" + s["body"]).strip()
        elif s["kind"] == "config":
            config_body = s["body"]
            _check_config(s["body"], anoms)
        elif s["kind"] == "intf_status":
            intf_body = s["body"]
            _check_intf_status(s["body"], anoms)
        elif s["kind"] == "intf_brief":
            intf_body = (intf_body + "\n" + s["body"]).strip()
            _check_intf_brief(s["body"], anoms)
        elif s["kind"] == "version":
            version_body = s["body"]
        else:
            # interfaces / cpu / cdp / other 等は LLM 相関解析へ回す
            _hdr = _kind_ja.get(s["kind"], s.get("cmd", s["kind"]))
            extra_parts.append(f"[{_hdr}]\n{s['body']}")

    _check_license("\n".join(all_text), anoms)

    # 重要度順にソート
    rank = {"EMERGENCY": 0, "ALERT": 1, "CRITICAL": 2, "ERROR": 3,
            "WARNING": 4, "NOTICE": 5, "INFO": 6}
    anoms.sort(key=lambda a: rank.get(a["severity"], 6))
    return {"anomalies": anoms, "kinds": kinds, "logging_body": logging_body,
            "config_body": config_body, "intf_body": intf_body,
            "version_body": version_body,
            "extra_body": "\n\n".join(extra_parts).strip()}


def quality_score(anomalies: list, bug_count: int = 0,
                  ops_count: int = 0) -> dict:
    """
    貼り付けた show 出力の健全性を採点する（ネットワーク品質ルーブリック）。
    戻り値: {score, grade, label, deductions:[...]}
    """
    score = 100
    deductions = []

    def _ded(pts, why):
        nonlocal score
        score -= pts
        deductions.append(f"-{pts}: {why}")

    sev_pts = {"EMERGENCY": 30, "ALERT": 28, "CRITICAL": 25, "ERROR": 20,
               "WARNING": 8, "NOTICE": 3, "INFO": 1}
    sev_count: dict = {}
    for a in anomalies:
        s = a["severity"]
        sev_count[s] = sev_count.get(s, 0) + 1
    for s, n in sev_count.items():
        if sev_pts.get(s, 0) and n:
            _ded(sev_pts[s] * n, f"{s} 異常 {n}件")
    if bug_count:
        _ded(25 * bug_count, f"バグ疑い {bug_count}件")

    score = max(0, min(100, score))
    if score >= 90:
        grade, label = "A", "良好（重大な問題なし）"
    elif score >= 75:
        grade, label = "B", "概ね良好（軽微な注意点あり）"
    elif score >= 60:
        grade, label = "C", "要注意（複数の課題あり）"
    elif score >= 40:
        grade, label = "D", "課題多数（設定・運用の見直し推奨）"
    else:
        grade, label = "E", "重大（早急な対処が必要）"
    return {"score": score, "grade": grade, "label": label,
            "deductions": deductions, "sev_count": sev_count}


if __name__ == "__main__":
    sample = """Switch#show running-config
hostname Switch
no service password-encryption
ip http server
interface Vlan1
 no ip address
 shutdown
line vty 5 15
Switch#show interface status
Port      Name    Status       Vlan   Duplex  Speed Type
Gi0/1             notconnect   1       auto   auto  10/100/1000BaseTX
Gi0/2             notconnect   1       auto   auto  10/100/1000BaseTX
Switch#show logging
Jul  4 00:56:06: %IOS_LICENSE_IMAGE_APPLICATION-6-LICENSE_LEVEL: License = No valid license found
Switch#"""
    secs = split_sections(sample)
    print("=== セクション分割 ===")
    for s in secs:
        print(f"  [{s['kind']}] {s['cmd']}  ({len(s['body'])}文字)")
    print("\n=== 異常性チェック ===")
    res = check_anomalies(secs)
    for a in res["anomalies"]:
        print(f"  [{a['severity']}] {a['category']}: {a['detail']}  <{a['evidence']}>")
