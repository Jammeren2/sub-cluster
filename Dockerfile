FROM python:3.12-slim

# certifi — надёжный CA-бандл для TLS (приложение само его подхватит, если есть).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /app
COPY sub_server.py .

# Внутри контейнера всегда слушаем 0.0.0.0:8080 (наружу маппится через compose).
# PYTHONUNBUFFERED=1 — чтобы логи сразу попадали в `docker logs`, без буферизации.
# CONFIG_FILE — конфиг маршрутов в /data (пробрось как volume, чтобы не терялся).
ENV LISTEN_HOST=0.0.0.0 \
    LISTEN_PORT=8080 \
    CONFIG_FILE=/data/config.json \
    PYTHONUNBUFFERED=1

EXPOSE 8080

# Не работаем под root. /data — для персистентного конфига маршрутов.
RUN useradd --create-home --uid 10001 app \
    && mkdir -p /data && chown app:app /data
VOLUME ["/data"]
USER app

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=5s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3).read()==b'ok' else 1)"

CMD ["python", "sub_server.py"]
