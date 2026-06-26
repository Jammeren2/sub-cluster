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
# Ставить zapret+xray в образ. ПО УМОЛЧАНИЮ ВКЛЮЧЕНО (=1): иначе в Coolify build-arg из
# .env не прокидывается на сборку и nfqws никогда не попадает в образ. Рантайм-применение
# гейтит ZAPRET=true (ZAPRET_ENABLE_APPLY). Лёгкий образ без zapret: build-arg INSTALL_ZAPRET=0.
ARG INSTALL_ZAPRET=1
# Версия zapret. ВАЖНО: prebuilt-бинарники (nfqws) лежат только в release-тарболе, в git
# их НЕТ — поэтому ставим из релиза, а не `git clone`. Бинарники статические (musl).
ARG ZAPRET_VERSION=v72.12
# xray-core для узла-gateway (vless-ws inbound + server-side routing). В zip — ещё и
# geoip.dat/geosite.dat (нужны для geosite-правил роутера).
ARG XRAY_VERSION=v26.3.27
RUN if [ "$INSTALL_ZAPRET" = "1" ] || [ "$INSTALL_ZAPRET" = "true" ]; then \
      apt-get update && apt-get install -y --no-install-recommends iptables libcap2-bin ca-certificates && \
      rm -rf /var/lib/apt/lists/* && \
      mkdir -p /opt/zapret && \
      python -c "import urllib.request; urllib.request.urlretrieve('https://github.com/bol-van/zapret/releases/download/${ZAPRET_VERSION}/zapret-${ZAPRET_VERSION}.tar.gz', '/tmp/zapret.tgz')" && \
      tar -xzf /tmp/zapret.tgz -C /opt/zapret --strip-components=1 && rm /tmp/zapret.tgz && \
      ( setcap cap_net_admin,cap_net_raw+ep /opt/zapret/binaries/linux-x86_64/nfqws || \
        echo "WARN: setcap nfqws не удался (caps дадим рантаймом)" ) && \
      for b in /usr/sbin/xtables-nft-multi /usr/sbin/xtables-legacy-multi; do \
        [ -e "$b" ] && setcap cap_net_admin,cap_net_raw+ep "$b" || true ; \
      done && \
      chmod -R a+rX /opt/zapret && \
      mkdir -p /opt/xray && \
      python -c "import urllib.request, zipfile; urllib.request.urlretrieve('https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip', '/tmp/xray.zip'); zipfile.ZipFile('/tmp/xray.zip').extractall('/opt/xray')" && \
      rm /tmp/xray.zip && chmod 0755 /opt/xray/xray && \
      ( setcap cap_net_admin,cap_net_raw+ep /opt/xray/xray || echo "WARN: setcap xray не удался" ) && \
      chmod -R a+rX /opt/xray ; \
    fi
# Пути к nfqws/fake (zapret) и xray/geo (gateway). Если ZAPRET!=true — файлов нет,
# is_available()=False у обоих → /zapret и gateway дают только генерацию/ссылку.
ENV ZAPRET_NFQWS=/opt/zapret/binaries/linux-x86_64/nfqws \
    ZAPRET_FAKE_DIR=/opt/zapret/files/fake \
    XRAY_BIN=/opt/xray/xray \
    XRAY_LOCATION_ASSET=/opt/xray

# Три порта: ADMIN (панель), SUB (подписки), CLUSTER (peer-API кластера).
# БД кластера — в /data (volume), переживает пересоздание контейнера.
ENV LISTEN_HOST=0.0.0.0 \
    ADMIN_PORT=8080 \
    SUB_PORT=8081 \
    CLUSTER_PORT=8083 \
    DB_FILE=/data/cluster.db \
    PYTHONUNBUFFERED=1

EXPOSE 8080 8081 8083

# Работаем от ROOT — узлу нужны NET_ADMIN/NET_RAW (nfqws/iptables/NFQUEUE, xray SO_MARK).
# non-root процесс НЕ получает эти права даже при cap_add (capability не попадает в его
# effective-set, и apt/setcap в рантайме недоступны). Контейнер изолирован и за прокси
# (Caddy/Coolify), доступ в панель под паролем. /data — персистентная БД кластера.
RUN mkdir -p /data
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=5s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3).read()==b'ok' else 1)"

CMD ["python", "sub_server.py"]
