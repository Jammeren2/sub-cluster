#!/usr/bin/env python3
"""
sub_server.py — зеркало (прокси) VPN-подписки.

Поднимает HTTP-сервер, который по своей ссылке ходит на upstream-подписку
с заголовками клиента Happ, получает JSON-конфиг и отдаёт его как ВАШУ
собственную подписку — вместе со всеми заголовками подписки
(Subscription-Userinfo, Profile-Title, Profile-Update-Interval и т.д.).

Таким образом ваша ссылка становится полноценной заменой оригинальной:
её можно вставить в Happ / любой клиент, и он увидит те же ноды, тот же
трафик/срок и название профиля.

Зависимостей нет — только стандартная библиотека Python 3.7+.

Запуск:
    python3 sub_server.py
Настройка через переменные окружения (см. блок «Настройки» ниже).
"""

import os
import ssl
import gzip
import time
import base64
import threading
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── Настройки (переопределяются переменными окружения) ────────────────────
# Оригинальная подписка, которую дублируем.
UPSTREAM_URL = os.environ.get(
    "UPSTREAM_URL", "https://sub.by-concord.pro/FwPx2Mt2MyW4hqsE"
)
# На каком адресе/порту слушать. 0.0.0.0 = на всех интерфейсах сервера.
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
# Путь, по которому будет доступна ВАША подписка. Сделайте его секретным —
# это, по сути, пароль к вашей ссылке. Пример: /my-secret-abc123
SUB_PATH = os.environ.get("SUB_PATH", "/sub")
# Сколько секунд держать ответ upstream в кэше, чтобы не ходить на него
# на каждый запрос клиента (клиенты опрашивают подписку часто).
CACHE_TTL = int(os.environ.get("CACHE_TTL", "60"))
# Таймаут запроса к upstream, сек.
UPSTREAM_TIMEOUT = int(os.environ.get("UPSTREAM_TIMEOUT", "20"))
# Своё название подписки. Если задано — подменяет Profile-Title от upstream.
# Пусто = оставляем оригинальное название (Concord).
PROFILE_TITLE = os.environ.get("PROFILE_TITLE", "")

# Заголовки, которые отправляем на upstream — имитируем клиент Happ.
# Менять обычно не нужно; HWID/версию можно переопределить через env.
UPSTREAM_HEADERS = {
    "User-Agent": os.environ.get("HAPP_UA", "Happ/2.16.2/Windows/2605221224603"),
    "X-App-Version": os.environ.get("HAPP_VERSION", "2.16.2"),
    "X-Device-Locale": "RU",
    "X-Device-Os": "Windows",
    "X-Device-Model": "DESKTOP-0000000_x86_64",
    "X-Hwid": os.environ.get("HAPP_HWID", "00000000-0000-0000-0000-000000000000"),
    "X-Ver-Os": "10_10.0.19045",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "ru-RU,en,*",
}

# Заголовки ответа upstream, которые пробрасываем клиенту (метаданные подписки).
# Content-Encoding/Content-Length/Etag НЕ пробрасываем намеренно: мы отдаём
# уже распакованный JSON и считаем длину сами.
PASS_THROUGH_HEADERS = [
    "Content-Type",
    "Content-Disposition",
    "Profile-Title",
    "Profile-Update-Interval",
    "Profile-Web-Page-Url",
    "Subscription-Userinfo",
    "Announce",
    "Support-Url",
    "Use-Progress-Bar",
    "Pro-Mode",
    "Protocols-Hidden",
    "Routing",
]

# ── SSL-контекст для запроса к upstream ──────────────────────────────────
def build_ssl_context():
    """
    Контекст с проверкой сертификата, но без излишне строгой структурной
    проверки X.509 (в OpenSSL 3.x / Python 3.13+ она по умолчанию отвергает
    валидные, но технически «неидеальные» сертификаты — например выданные
    Caddy/ZeroSSL, без Authority Key Identifier). Цепочка доверия проверяется.

    INSECURE_TLS=1 полностью отключает проверку (крайний случай).
    """
    if os.environ.get("INSECURE_TLS", "").lower() in ("1", "true", "yes"):
        return ssl._create_unverified_context()
    ctx = ssl.create_default_context()
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    try:
        import certifi  # необязательная зависимость; если есть — берём её CA-бандл
        ctx.load_verify_locations(certifi.where())
    except Exception:
        pass
    return ctx


_SSL_CTX = build_ssl_context()

# ── Простой потокобезопасный кэш с TTL ───────────────────────────────────
_cache_lock = threading.Lock()
_cache = {"ts": 0.0, "body": b"", "headers": {}}


def fetch_upstream():
    """Идёт на upstream-подписку. Возвращает (body_bytes, headers_dict)."""
    req = urllib.request.Request(UPSTREAM_URL, headers=UPSTREAM_HEADERS)
    with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT, context=_SSL_CTX) as resp:
        raw = resp.read()
        # Сервер обычно отдаёт gzip — распаковываем, чтобы отдать клиенту как есть.
        if "gzip" in resp.headers.get("Content-Encoding", "").lower():
            raw = gzip.decompress(raw)
        headers = {}
        for name in PASS_THROUGH_HEADERS:
            val = resp.headers.get(name)
            if val is not None:
                headers[name] = val
        headers.setdefault("Content-Type", "application/json; charset=utf-8")
        # Подменяем название подписки на своё, если задан PROFILE_TITLE.
        # Happ ожидает заголовок в виде base64:<база64 от UTF-8 названия>.
        if PROFILE_TITLE:
            encoded = base64.b64encode(PROFILE_TITLE.encode("utf-8")).decode("ascii")
            headers["Profile-Title"] = "base64:" + encoded
        return raw, headers


def get_subscription():
    """Отдаёт закэшированный ответ upstream, обновляя его раз в CACHE_TTL сек."""
    now = time.time()
    with _cache_lock:
        if _cache["body"] and (now - _cache["ts"]) < CACHE_TTL:
            return _cache["body"], _cache["headers"]
    # Обновляем кэш вне лока, чтобы запрос к upstream не блокировал других клиентов.
    body, headers = fetch_upstream()
    with _cache_lock:
        _cache.update(ts=time.time(), body=body, headers=headers)
    return body, headers


class Handler(BaseHTTPRequestHandler):
    server_version = "subproxy/1.0"
    protocol_version = "HTTP/1.1"

    def _client_ip(self):
        """
        Реальный IP клиента. Если перед нами reverse-proxy (nginx/Caddy/
        Traefik), сокет показывает IP прокси, а настоящий адрес — в заголовке
        X-Forwarded-For (берём первый = самый левый) или X-Real-IP.
        """
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.headers.get("X-Real-IP") or self.client_address[0]

    def _log_device(self):
        """
        Пишет в консоль контейнера, какое устройство обратилось к подписке
        и с какого IP. Данные устройства — из заголовков клиента (Happ и пр.).
        """
        ip = self._client_ip()
        hwid = self.headers.get("X-Hwid", "-")
        model = self.headers.get("X-Device-Model", "-")
        os_name = self.headers.get("X-Device-Os", "-")
        app_ver = self.headers.get("X-App-Version", "-")
        locale = self.headers.get("X-Device-Locale", "-")
        ua = self.headers.get("User-Agent", "-")
        print(
            f"[{self.log_date_time_string()}] DEVICE ip={ip} hwid={hwid} "
            f"model={model} os={os_name} app={app_ver} locale={locale} ua=\"{ua}\"",
            flush=True,
        )

    def _respond(self, code, body=b"", headers=None):
        self.send_response(code)
        sent = set()
        for k, v in (headers or {}).items():
            self.send_header(k, v)
            sent.add(k.lower())
        if "content-type" not in sent:
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        norm = (self.path.split("?", 1)[0].rstrip("/")) or "/"
        target = (SUB_PATH.rstrip("/")) or "/"

        if norm == target:
            self._log_device()
            try:
                body, up_headers = get_subscription()
            except urllib.error.HTTPError as e:
                self._respond(502, f"upstream HTTP {e.code}".encode())
            except Exception as e:
                self._respond(502, f"upstream error: {e}".encode())
            else:
                self._respond(200, body, up_headers)
            return

        if norm == "/healthz":
            self._respond(200, b"ok")
            return

        self._respond(404, b"not found")

    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")


def main():
    httpd = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"[*] Зеркало подписки запущено на http://{LISTEN_HOST}:{LISTEN_PORT}{SUB_PATH}")
    print(f"[*] Источник (upstream): {UPSTREAM_URL}")
    print(f"[*] Кэш: {CACHE_TTL} сек. Ctrl+C для остановки.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Остановлено.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
