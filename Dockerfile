FROM python:3.12-slim

# certifi — CA-бандл для TLS; cryptography — шифрование секретов «в покое».
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /app
COPY *.py ./

# Три порта: ADMIN (панель), SUB (подписки), CLUSTER (peer-API кластера).
# БД кластера — в /data (volume), переживает пересоздание контейнера.
ENV LISTEN_HOST=0.0.0.0 \
    ADMIN_PORT=8080 \
    SUB_PORT=8081 \
    CLUSTER_PORT=8083 \
    DB_FILE=/data/cluster.db \
    PYTHONUNBUFFERED=1

EXPOSE 8080 8081 8083

# Не работаем под root. /data — для персистентной БД кластера.
RUN useradd --create-home --uid 10001 app \
    && mkdir -p /data && chown app:app /data
VOLUME ["/data"]
USER app

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=5s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3).read()==b'ok' else 1)"

CMD ["python", "sub_server.py"]
