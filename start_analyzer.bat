@echo off
chcp 65001 >NUL
REM ============================================================
REM  Syslog Analyzer 起動バッチ（Ollama も一緒に起動）
REM  ダブルクリック、または: start_analyzer.bat
REM ============================================================
cd /d "%~dp0"

echo ============================================
echo   Syslog Analyzer を起動します
echo ============================================

REM --- Ollama サーバが応答するか確認（未起動なら起動） ---
curl -s -o NUL http://localhost:11434/api/tags
if errorlevel 1 (
    echo [1/2] Ollama が未起動のため起動します...
    start "Ollama" ollama serve
    REM 起動待ち（最大10秒、応答したら先へ）
    setlocal enabledelayedexpansion
    set /a _n=0
    :WAIT_OLLAMA
    timeout /t 1 /nobreak >NUL
    curl -s -o NUL http://localhost:11434/api/tags
    if not errorlevel 1 goto OLLAMA_READY
    set /a _n+=1
    if !_n! LSS 10 goto WAIT_OLLAMA
    echo     ※Ollama の応答待ちがタイムアウトしました（後でアプリ内の「Ollama起動」ボタンでも起動できます）
    :OLLAMA_READY
    endlocal
) else (
    echo [1/2] Ollama は既に起動しています。
)

REM --- アナライザー（Streamlit）を起動 ---
echo [2/2] アナライザーを起動します（ブラウザが自動で開きます）...
python -m streamlit run app.py

REM 終了時に画面を残す
echo.
echo アナライザーを終了しました。
pause
