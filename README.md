# 🛰️ Syslog AI アナライザー

ネットワークの **監視・ログ解析・パケット解析** を、AI（LLM）による日本語診断つきで行えるオールインワンツールです。
実機がなくても「デモシミュレーター」で全機能を試せます。

> 📘 **使い方の詳細は [docs/使い方ガイド.md](docs/使い方ガイド.md) を参照してください。**
> 各タブの操作、パケット解析・CTF機能、Slack通知、AIエンジンの選び方などをまとめています。

## できること（概要）

| 系統 | 機能 |
|------|------|
| 🩺 状態監視 | SNMPで機器のCPU/メモリ/回線を収集し、信号機表示・グラフ化・閾値アラート（品質ルーブリック / MRTG風 / SNMPモニター） |
| 📜 ログ解析 | syslog受信・show log貼り付けをAIが日本語診断し、バグ/運用/情報に自動仕分け |
| 📦 パケット解析 | pcapからTCP問題・スキャン・VoIP品質・ICMPリダイレクト等を検出＋AI診断。CTF/フォレンジック機能（flag検出・TCPストリーム再構成・ファイル抽出）も対応 |
| 🌊 フロー/経路 | NetFlow集計・トポロジー自動検出・応答時間監視 |
| 🔔 通知 | 危険水準アラートをSlackへ自動通知 |

AI解析は **Gemini / Groq（無料枠あり）/ Claude / Ollama（完全ローカル）** から選べます。

## 対応機器

| ベンダー | 機器例 |
|----------|--------|
| Cisco IOS/IOS-XE | Catalyst 9300, 9500 など |
| Cisco NX-OS | Nexus 9000, 7000 など |
| 富士通 Si-R | Si-R G100, G120, G200 など |
| APRESIA | ApresiaLight シリーズ |
| RHEL/Linux | RHEL 8/9, CentOS, Rocky Linux など |
| Windows | Windows Server (NXLog/Winlogbeat経由) |

## 主な機能

- **🩺 健全性ダッシュボード**：ネットワーク全体・機器ごとのヘルススコア（100点満点）を信号機表示。スループット・破棄・ブロードキャスト率・CPU・メモリを総合評価し、Cisco系の輻輳連鎖（ブロードキャスト→CPU→破棄→ルーティング不安定）をLLMが根本原因推定
- syslog受信・AI日本語解析（Catalyst/Nexus/Si-R/APRESIA/RHEL/Windows対応）
- SNMP Trap受信・SNMPポーリング（スループット差分計算・64bitカウンタ対応・閾値監視）
- AI解析結果の品質チェック（LLM-as-a-Judge）
- 機器コンフィグ登録（インターフェース・ルーティング設定を正常構成として参照）
- ベンダー別推奨設定集

## 動作環境

- Python **3.10** 以上
- Windows / macOS / Linux
- ブラウザ（Chrome / Edge / Firefox）

---

## インストール手順

### Step 1: Python の確認

```bash
python --version
# Python 3.10.x 以上であること
```

### Step 2: ファイルをダウンロード

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

### Step 3: pip インストール

```bash
cd syslog-analyzer

pip install -r requirements.txt
```

#### requirements.txt の内容（個別インストールする場合）

```bash
pip install streamlit      # WebUI フレームワーク
pip install pandas         # データ集計・テーブル表示
pip install requests       # Claude API / Ollama への HTTP通信
```

> **仮想環境を使う場合（推奨）**
> ```bash
> python -m venv venv
> venv\Scripts\activate    # Windows
> source venv/bin/activate # Linux/Mac
> pip install -r requirements.txt
> ```

---

## 起動方法

```bash
streamlit run app.py
```

ブラウザで **http://localhost:8501** を開く。

---

## AI解析エンジンの設定

### A. Claude API（有償・高品質）

Anthropic の API キーが必要です（claude.ai Pro とは別契約）。

```bash
# 環境変数に設定
export ANTHROPIC_API_KEY="sk-ant-..."    # Linux/Mac
set ANTHROPIC_API_KEY=sk-ant-...         # Windows コマンドプロンプト
$env:ANTHROPIC_API_KEY="sk-ant-..."      # Windows PowerShell
```

取得先: https://console.anthropic.com

### B. Ollama（無料・完全ローカル・オフライン対応）

```bash
# 1. Ollama のインストール
#    Linux/Mac:
curl -fsSL https://ollama.com/install.sh | sh
#    Windows: https://ollama.com からインストーラーをダウンロード

# 2. モデルのダウンロード（日本語対応モデル推奨）
ollama pull gemma3          # Google製 日本語対応良好 (推奨)
ollama pull llama3          # Meta製 汎用
ollama pull elyza/llama3-jp # 日本語特化

# 3. Ollama サーバー起動（別ターミナルで）
ollama serve
```

Ollama が起動していれば、インターネットなしで完全ローカル動作します。

---

## syslog 受信ポートについて

| ポート | 必要権限 | 推奨 |
|--------|----------|------|
| 514 | root/管理者権限が必要 | 本番環境 |
| 5140 | 一般ユーザーで可 | ✅ 開発・テスト推奨 |

アプリのサイドバーでポート番号を変更できます。
機器側の転送先ポートも合わせて設定してください。

---

## 機器側 syslog 設定例

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

### 富士通 Si-R
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
# /etc/rsyslog.conf に追記
*.* @192.168.x.x:5140       # UDP転送
# systemctl restart rsyslog
```

### Windows: NXLog Community Edition（無料）

1. https://nxlog.co/downloads からダウンロード・インストール
2. `C:\Program Files\nxlog\conf\nxlog.conf` を編集:

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

3. NXLog サービスを再起動

### Windows: Winlogbeat（Elastic製・無料）

1. https://www.elastic.co/beats/winlogbeat からダウンロード
2. `winlogbeat.yml` を設定してサービス登録

---

## ファイル構成

```
syslog-analyzer/
├── app.py              # Streamlit メインUI
├── syslog_server.py    # UDP syslog 受信サーバー
├── analyzer.py         # LLM 解析エンジン（Claude/Ollama）
├── db.py               # SQLite データベース管理
├── requirements.txt    # pip インストールリスト
├── syslog.db           # ← 自動生成されるDBファイル
└── parsers/
    ├── __init__.py     # パーサーディスパッチャー
    ├── cisco_ios.py    # Cisco IOS/IOS-XE
    ├── cisco_nxos.py   # Cisco NX-OS
    ├── fujitsu_sir.py  # 富士通 Si-R
    ├── apresia.py      # APRESIA ApresiaLight
    ├── rhel.py         # RHEL/Linux
    └── windows.py      # Windows (NXLog/Winlogbeat)
```

---

## トラブルシューティング

| 症状 | 原因 | 対処 |
|------|------|------|
| `streamlit: command not found` | インストール未完了 | `pip install streamlit` |
| ポート514でエラー | 権限不足 | ポートを5140に変更 |
| Ollamaに繋がらない | サービス未起動 | `ollama serve` を実行 |
| ログが受信されない | FW/機器設定 | PC側のWindowsファイアウォールでUDP5140を許可 |
| 日本語が文字化け | エンコード問題 | ターミナルをUTF-8に設定 |
