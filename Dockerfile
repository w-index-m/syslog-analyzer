FROM python:3.11-slim

WORKDIR /app

# システム依存パッケージ（pysnmp が必要とする libffi 等）
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# データ永続化用ディレクトリ
RUN mkdir -p /data
ENV DB_PATH=/data/syslog.db

EXPOSE 8501 8000 514/udp 162/udp

# デフォルトは Streamlit UI。docker-compose で api サービスは上書き
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
