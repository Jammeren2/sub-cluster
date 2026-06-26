FROM python:3.12-slim

# certifi — CA-бандл для TLS; cryptography — шифрование секретов «в покое».
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /app
COPY *.py editor.js editor.css ./

# zapret (обход DPI) — ОПЦИОНАЛЬНО, по умолчанию ВЫКЛЮЧЕНО (образ не пухнет,
# поведение не меняется). Включить: docker build --build-arg INSTALL_ZAPRET=1 ...
# Тогда нужны cap NET_ADMIN/NET_RAW (см. docker-compose) и ZAPRET_ENABLE_APPLY=1 в env,
# чтобы авто-тест реально применял стратегии. Без этого /zapret даёт только baseline.
ARG INSTALL_ZAPRET=0
# Версия zapret. ВАЖНО: prebuilt-бинарники (nfqws) лежат только в release-тарболе, в git
# их НЕТ — поэтому ставим из релиза, а не `git clone`. Бинарники статические (musl).
ARG ZAPRET_VERSION=v72.12
RUN if [ "$INSTALL_ZAPRET" = "1" ]; then \
      apt-get update && apt-get install -y --no-install-recommends iptables libcap2-bin ca-certificates && \
      rm -rf /var/lib/apt/lists/* && \
      mkdir -p /opt/zapret && \
      python -c "import urllib.request; urllib.request.urlretrieve('https://github.com/bol-van/zapret/releases/download/${ZAPRET_VERSION}/zapret-${ZAPRET_VERSION}.tar.gz', '/tmp/zapret.tgz')" && \
      tar -xzf /tmp/zapret.tgz -C /opt/zapret --strip-components=1 && rm /tmp/zapret.tgz && \
      setcap cap_net_admin,cap_net_raw+ep /opt/zapret/binaries/linux-x86_64/nfqws && \
      chmod -R a+rX /opt/zapret ; \
    fi
# Пути к nfqws и fake-payload'ам (если zapret не ставился — файлов нет, is_available()=False).
ENV ZAPRET_NFQWS=/opt/zapret/binaries/linux-x86_64/nfqws \
    ZAPRET_FAKE_DIR=/opt/zapret/files/fake

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
