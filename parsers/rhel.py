import re

# RHEL/Linux syslog formats:
# RFC3164: <priority>Mon DD HH:MM:SS hostname process[pid]: message
# RFC5424: <priority>version timestamp hostname app-name procid msgid message
# journald forwarded: hostname systemd[1]: message

SEVERITY_MAP = {
    0: "EMERGENCY", 1: "ALERT", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG"
}

FACILITY_MAP = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7"
}

# RFC3164パターン
RFC3164 = re.compile(
    r"(?:<(\d+)>)?"
    r"(\w{3}\s+\d+\s+[\d:]+)\s+"
    r"([\w\-\.]+)\s+"
    r"([\w\-\./]+?)(?:\[(\d+)\])?:\s+"
    r"(.*)"
)

# RFC5424パターン
RFC5424 = re.compile(
    r"<(\d+)>(\d+)\s+"
    r"([\d\-T:.Z+]+)\s+"
    r"([\w\-\.]+)\s+"
    r"([\w\-\.]+)\s+"
    r"([\w\-]+)\s+"
    r"([\w\-]+)\s+"
    r"(.*)"
)

# よく出るRHELプロセスと解説ヒント
RHEL_PROCESSES = {
    "sshd": "SSH",
    "sudo": "特権昇格",
    "kernel": "カーネル",
    "systemd": "システム管理",
    "crond": "定期実行",
    "auditd": "監査",
    "firewalld": "ファイアウォール",
    "NetworkManager": "ネットワーク",
    "rsyslogd": "syslog",
    "yum": "パッケージ管理",
    "dnf": "パッケージ管理",
    "postfix": "メール",
    "httpd": "Webサーバー",
    "nginx": "Webサーバー",
    "mysqld": "DB",
    "chronyd": "時刻同期",
    "ntpd": "時刻同期",
    "pam": "認証",
    "login": "ログイン",
    "su": "ユーザー切替",
}

def _get_tags(process: str, message: str, facility_name: str) -> list:
    tags = ["RHEL/Linux"]
    msg_lower = message.lower()
    proc_lower = process.lower()

    # プロセスベースのタグ
    for proc, label in RHEL_PROCESSES.items():
        if proc.lower() in proc_lower:
            tags.append(label)
            break

    # メッセージ内容ベースのタグ
    if any(k in msg_lower for k in ["failed", "failure", "error", "denied"]):
        tags.append("エラー/拒否")
    if any(k in msg_lower for k in ["accepted", "opened session", "logged in"]):
        tags.append("認証成功")
    if any(k in msg_lower for k in ["authentication failure", "invalid user", "failed password"]):
        tags.append("認証失敗"); tags.append("障害候補")
    if "sudo" in proc_lower:
        tags.append("特権操作")
    if facility_name in ("auth", "authpriv"):
        tags.append("認証系")
    if any(k in msg_lower for k in ["oom", "out of memory", "killed process"]):
        tags.append("メモリ不足"); tags.append("障害候補")
    if any(k in msg_lower for k in ["segfault", "segmentation fault"]):
        tags.append("クラッシュ"); tags.append("障害候補")
    if any(k in msg_lower for k in ["started", "stopped", "restarted", "active"]):
        tags.append("サービス状態変化")
    return tags

def parse(raw: str, source_ip: str) -> dict | None:
    # RFC5424を最初に試す
    m5 = RFC5424.match(raw)
    if m5:
        pri, ver, timestamp, hostname, app, procid, msgid, message = m5.groups()
        pri_int = int(pri)
        severity = SEVERITY_MAP.get(pri_int & 0x07, "INFO")
        facility_num = pri_int >> 3
        facility_name = FACILITY_MAP.get(facility_num, f"local{facility_num}")
        tags = _get_tags(app, message, facility_name)
        return {
            "vendor": "RHEL/Linux",
            "hostname": hostname or source_ip,
            "facility": facility_name,
            "severity": severity,
            "severity_digit": str(pri_int & 0x07),
            "process": f"{app}[{procid}]" if procid != "-" else app,
            "message": message.strip(),
            "timestamp": timestamp,
            "tags": tags
        }

    # RFC3164を試す
    m3 = RFC3164.match(raw)
    if m3:
        pri, timestamp, hostname, process, pid, message = m3.groups()
        # Linuxらしいホスト名/プロセスかチェック
        linux_procs = list(RHEL_PROCESSES.keys()) + [
            "kernel", "init", "bash", "python", "java", "ruby", "php"
        ]
        if not any(p.lower() in process.lower() for p in linux_procs):
            # Cisco/APRESIAっぽいパターンは除外
            if "%" in raw or any(k in raw for k in ["Si-R", "siRd", "apresia", "APRESIA"]):
                return None

        pri_int = int(pri) if pri else 0
        severity = SEVERITY_MAP.get(pri_int & 0x07, "INFO")
        facility_num = pri_int >> 3
        facility_name = FACILITY_MAP.get(facility_num, "user")
        proc_label = f"{process}[{pid}]" if pid else process
        tags = _get_tags(process, message, facility_name)
        return {
            "vendor": "RHEL/Linux",
            "hostname": hostname or source_ip,
            "facility": facility_name,
            "severity": severity,
            "severity_digit": str(pri_int & 0x07),
            "process": proc_label,
            "message": message.strip(),
            "timestamp": timestamp or "",
            "tags": tags
        }

    return None
