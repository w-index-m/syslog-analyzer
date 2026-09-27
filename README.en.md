# 🛰️ Syslog AI Analyzer (NetScore AI)

🌐 English (this page) / [日本語READMEはこちら](README.md)

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Live%20Demo-FF4B4B?logo=streamlit&logoColor=white)](https://netscore-ai.streamlit.app/)
[![IPS Signatures](https://img.shields.io/badge/IPS%20Signatures-1600%2B-informational)](ips_signatures.json)

An all-in-one **network monitoring, log analysis, and packet analysis** tool with AI (LLM)-powered diagnostics.
It auto-summarizes intrusion detection, malware, and DoS events from FortiGate/Palo Alto/Cisco UTM/IPS logs, and detects 8 lateral-movement techniques, C2 beaconing, phishing emails, and TLS over non-standard ports from pcap files.
No real hardware? Try every feature instantly with the built-in **Demo Simulator**.

### 🌐 Try it right now in your browser

**👉 https://netscore-ai.streamlit.app/** (no install, no signup)

> The cloud deployment is centered on the demo simulator and pcap/log upload analysis (receiving live syslog/SNMP from real devices requires running it locally). If you want to monitor your own network, see the [Installation](#installation) section below.

> 📘 **For detailed usage, see [docs/使い方ガイド.md](docs/使い方ガイド.md)** (Japanese only for now).
> It covers each tab's operations, packet analysis/CTF features, Slack notifications, and how to choose an AI engine.

If you find this useful, a ⭐ **Star** would be greatly appreciated.

## What it does (overview)

| Category | Features |
|------|------|
| 🩺 Health monitoring | Collects CPU/memory/link stats via SNMP; traffic-light status, graphing, threshold alerts (quality rubric / MRTG-style / SNMP monitor) |
| 📜 Log analysis | AI-driven Japanese diagnosis of received syslog / pasted `show log` output, auto-classified into bugs/operations/info. FortiGate/Palo Alto UTM/IPS logs are also auto-aggregated into an attack-category summary (intrusion detection, malware, DoS, etc.) |
| 📦 Packet analysis | Detects TCP anomalies, scans, VoIP quality issues, ICMP redirects, etc. from pcap files + AI diagnosis. IPS/IDS-style inspection (signature-based, anomaly-based, behavior-based), lateral-movement detection (PsExec/WinRM/RDP/VNC/DCOM/SSH/Pass-the-Hash/Lateral Tool Transfer), email phishing detection (attachments/headers/body links), TLS-over-non-standard-port detection, GeoIP/ASN lookup. Also includes CTF/forensics features (flag detection, TCP stream reassembly, file extraction) |
| 🌊 Flow/routing | NetFlow aggregation, automatic topology discovery, response-time monitoring |
| 🗂️ Device config | Register interface/routing configs; FortiGate additionally supports AI-powered config review (security concerns, SSL inspection settings, etc.) |
| 📊 Access analytics | Self-hosted visitor count / country breakdown for the public app (optional Google Sheets integration) |
| 🔔 Notifications | Automatic Slack alerts for high-severity events |

Choose your AI analysis engine from **Gemini / Groq (free tier available) / Claude / Ollama (fully local)**.

## Supported vendors

| Vendor | Example devices |
|----------|--------|
| Cisco IOS/IOS-XE | Catalyst 9300, 9500, etc. |
| Cisco NX-OS | Nexus 9000, 7000, etc. |
| FortiGate | FortiOS (syslog parsing, attack summary, AI config review) |
| Palo Alto Networks | PAN-OS (TRAFFIC/THREAT/SYSTEM CSV logs, etc.) |
| F5 BIG-IP | LTM (tmm/mcpd logs) |
| Fujitsu Si-R / IPCOM / SR-S | Si-R G100/G120/G200, IPCOM, SR-S series |
| APRESIA | ApresiaLight series |
| RHEL/Linux | RHEL 8/9, CentOS, Rocky Linux, etc. |
| Windows | Windows Server (via NXLog/Winlogbeat) |

## Key features

- **🩺 Health dashboard**: 100-point health score per device and network-wide, shown as traffic-light status. Evaluates throughput, discards, broadcast ratio, CPU, and memory together; an LLM infers the root cause of Cisco-style congestion chains (broadcast → CPU → discards → routing instability)
- Syslog receiving + AI diagnosis in Japanese (Catalyst/Nexus/FortiGate/Palo Alto/F5/Si-R/APRESIA/RHEL/Windows)
- **🎯 Detected attack summary**: cross-tabulates tags from FortiGate/Palo Alto UTM/IPS logs into detection counts per attack category, blocked/unblocked status, and attacker source IPs
- SNMP Trap receiving + SNMP polling (throughput delta calculation, 64-bit counter support, threshold monitoring)
- Quality checks on AI analysis output (LLM-as-a-Judge)
- **🛡️ IPS/IDS-style inspection**: signature-based (1,600+ rules), anomaly-based (port scans/DDoS/DNS tunneling), and behavior-based (8 lateral-movement techniques = PsExec/WinRM/RDP/VNC/DCOM/SSH/Pass-the-Hash/Lateral Tool Transfer, C2 beaconing, data exfiltration) detections plus threat-intel matching, all rolled up into a per-host risk score
- **📧 Email phishing / ransomware-delivery detection**: inspects attachments (EICAR/executables/macros/typical ransom-note filenames/encrypted-file naming patterns), headers (urgency-driven subject lines, From/Reply-To mismatches, display-name spoofing), and body links (brand impersonation, URL shorteners, punycode, raw IP links)
- **🌐 Traffic visibility**: GeoIP (watchlist countries), ASN/cloud-provider identification, TLS-over-non-standard-port detection (proxy tunneling/port disguising), JA3/JA3S and [JA4/JA4S](https://github.com/FoxIO-LLC/ja4) (JA3's successor) TLS fingerprinting
- **🚨 Threat intelligence**: matches traffic destinations against known-bad IPs/domains from abuse.ch (Feodo Tracker/URLhaus/ThreatFox) and the CINS Army List
- Device config registration (interface/routing settings as a baseline reference). **FortiGate also supports AI config review** (security concerns, SSL inspection settings, etc.)
- **📊 Access analytics**: self-hosted visitor count / country breakdown (no IP addresses stored, optional Google Sheets integration)
- Vendor-specific recommended-settings library

## Requirements

- Python **3.10** or later
- Windows / macOS / Linux
- A browser (Chrome / Edge / Firefox)

---

## Installation

### Step 1: Check Python

```bash
python --version
# Must be Python 3.10.x or later
```

### Step 2: Get the files

```
syslog-analyzer/
├── app.py
├── syslog_server.py
├── analyzer.py
├── db.py
├── requirements.txt
└── parsers/
    ├── __init__.py
    ├── cisco_ios.py
    ├── cisco_nxos.py
    ├── fujitsu_sir.py
    ├── apresia.py
    ├── rhel.py
    └── windows.py
```

### Step 3: Install dependencies

```bash
cd syslog-analyzer

pip install -r requirements.txt
```

#### requirements.txt contents (for manual/individual install)

```bash
pip install streamlit      # Web UI framework
pip install pandas         # Data aggregation / table display
pip install requests       # HTTP calls to Claude API / Ollama
```

> **Using a virtual environment (recommended)**
> ```bash
> python -m venv venv
> venv\Scripts\activate    # Windows
> source venv/bin/activate # Linux/Mac
> pip install -r requirements.txt
> ```

---

## Running the app

```bash
streamlit run app.py
```

Open **http://localhost:8501** in your browser.

---

## Configuring the AI analysis engine

### A. Claude API (paid, high quality)

Requires an Anthropic API key (a separate contract from claude.ai Pro).

```bash
# Set as an environment variable
export ANTHROPIC_API_KEY="sk-ant-..."    # Linux/Mac
set ANTHROPIC_API_KEY=sk-ant-...         # Windows Command Prompt
$env:ANTHROPIC_API_KEY="sk-ant-..."      # Windows PowerShell
```

Get a key at: https://console.anthropic.com

### B. Ollama (free, fully local, works offline)

```bash
# 1. Install Ollama
#    Linux/Mac:
curl -fsSL https://ollama.com/install.sh | sh
#    Windows: download the installer from https://ollama.com

# 2. Pull a model (a Japanese-capable model is recommended)
ollama pull gemma3          # Google, good Japanese support (recommended)
ollama pull llama3          # Meta, general purpose
ollama pull elyza/llama3-jp # Japanese-specialized

# 3. Start the Ollama server (in a separate terminal)
ollama serve
```

Once Ollama is running, the app works fully offline with no internet connection.

---

## About the syslog listening port

| Port | Required privilege | Recommendation |
|--------|----------|------|
| 514 | Requires root/administrator | Production |
| 5140 | Works as a regular user | ✅ Recommended for dev/testing |

The port number can be changed in the app's sidebar.
Make sure to configure the matching destination port on the device side as well.

---

## Device-side syslog configuration examples

### Cisco IOS/IOS-XE (Catalyst)
```
(config)# logging host 192.168.x.x transport udp port 5140
(config)# logging trap informational
(config)# logging on
```

### Cisco NX-OS (Nexus)
```
(config)# logging server 192.168.x.x 6 use-vrf management
```

### FortiGate
```
config log syslogd setting
    set status enable
    set server "192.168.x.x"
    set port 5140
end
```

### Palo Alto Networks (PAN-OS)
```
Add 192.168.x.x:5140 (UDP) under Device > Server Profiles > Syslog,
then configure Log Settings to forward System/Threat/Traffic etc. logs to that profile.
```

### Fujitsu Si-R
```
syslog host 192.168.x.x
syslog facility local0
```

### APRESIA ApresiaLight
```
syslog-server 192.168.x.x
```

### RHEL/Linux (rsyslog)
```bash
# Add to /etc/rsyslog.conf
*.* @192.168.x.x:5140       # UDP forwarding
# systemctl restart rsyslog
```

### Windows: NXLog Community Edition (free)

1. Download and install from https://nxlog.co/downloads
2. Edit `C:\Program Files\nxlog\conf\nxlog.conf`:

```xml
<Output syslog_out>
  Module  om_udp
  Host    192.168.x.x
  Port    5140
  Exec    to_syslog_bsd();
</Output>

<Route eventlog_to_syslog>
  Path    eventlog => syslog_out
</Route>
```

3. Restart the NXLog service

### Windows: Winlogbeat (Elastic, free)

1. Download from https://www.elastic.co/beats/winlogbeat
2. Configure `winlogbeat.yml` and register it as a service

---

## Project layout

```
syslog-analyzer/
├── app.py                  # Streamlit main UI
├── syslog_server.py        # UDP syslog receiver
├── analyzer.py             # LLM analysis engine (Claude/Gemini/Groq/Ollama)
├── db.py                   # SQLite database management
├── pcap_analyzer.py        # Packet analysis, IPS inspection, email phishing detection, etc.
├── demo_simulator.py       # Demo data generation (syslog/NetFlow/pcap)
├── threat_log_summary.py   # Attack-category summary aggregation for UTM/IPS logs
├── threat_intel.py         # Threat-intel matching (abuse.ch, etc.)
├── geoip.py                # GeoIP (watchlist countries) lookup
├── asn.py                  # ASN/cloud/ISP identification
├── ai_service_domains.py   # SNI/hostname identification for generative-AI services
├── access_analytics.py     # Visitor analytics for the public app
├── access_security.py      # Brute-force / unauthorized-access detection
├── netflow_collector.py    # NetFlow aggregation
├── health_engine.py        # Health-score calculation
├── notifier.py             # Slack notifications
├── check_all.py            # Combined syntax/test/signature check script
├── requirements.txt        # pip install list
├── syslog.db               # ← Auto-generated DB file
└── parsers/
    ├── __init__.py         # Parser dispatcher
    ├── cisco_ios.py        # Cisco IOS/IOS-XE
    ├── cisco_nxos.py       # Cisco NX-OS
    ├── fortigate.py        # FortiGate
    ├── paloalto.py         # Palo Alto Networks (PAN-OS)
    ├── f5_bigip.py         # F5 BIG-IP LTM
    ├── fujitsu_sir.py      # Fujitsu Si-R
    ├── fujitsu_ipcom.py    # Fujitsu IPCOM
    ├── fujitsu_srs.py      # Fujitsu SR-S
    ├── apresia.py          # APRESIA ApresiaLight
    ├── rhel.py             # RHEL/Linux
    └── windows.py          # Windows (NXLog/Winlogbeat)
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|------|------|------|
| `streamlit: command not found` | Installation incomplete | `pip install streamlit` |
| Error on port 514 | Insufficient privileges | Switch to port 5140 |
| Can't connect to Ollama | Service not running | Run `ollama serve` |
| Logs not being received | Firewall/device config | Allow UDP 5140 through the Windows Firewall on the receiving PC |
| Garbled Japanese text | Encoding issue | Set your terminal to UTF-8 |
