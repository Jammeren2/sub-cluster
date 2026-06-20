#!/usr/bin/env python3
"""
redeploy-agent.py — крошечный вебхук-агент для редеплоя узла БЕЗ Coolify.

Запускается НА ХОСТЕ (не в контейнере), где есть git, docker compose и репозиторий.
Кнопка «Редеплой» в панели заставляет узел дёрнуть СВОЙ redeploy-вебхук — этот агент
по валидному запросу делает `git pull && docker compose up -d --build` в фоне.

Запуск (пример, через systemd/nohup):
    REDEPLOY_TOKEN=секрет REPO_DIR=/root/concord-sub-mirror \
    COMPOSE_FILE=docker-compose.standalone.yml BIND=0.0.0.0 PORT=9090 \
    python3 redeploy-agent.py

В панели у узла:
    redeploy-вебхук = http://host.docker.internal:9090/redeploy
    redeploy-токен   = тот же REDEPLOY_TOKEN
(в docker-compose у app есть extra_hosts host.docker.internal:host-gateway —
 контейнер достучится до агента на хосте).

Зависимостей нет (стандартная библиотека). Никакого docker.sock у приложения —
агент работает с docker от пользователя хоста.
"""

import os
import hmac
import shlex
import threading
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("REDEPLOY_TOKEN", "")
REPO_DIR = os.environ.get("REPO_DIR", os.path.dirname(os.path.abspath(__file__)))
COMPOSE_FILE = os.environ.get("COMPOSE_FILE", "docker-compose.standalone.yml")
BIND = os.environ.get("BIND", "0.0.0.0")
PORT = int(os.environ.get("PORT", "9090"))
# Команда редеплоя (можно переопределить целиком через REDEPLOY_CMD).
REDEPLOY_CMD = os.environ.get(
    "REDEPLOY_CMD",
    f"git pull --ff-only && docker compose -f {shlex.quote(COMPOSE_FILE)} up -d --build",
)
LOG_FILE = os.environ.get("REDEPLOY_LOG", os.path.join(REPO_DIR, "redeploy.log"))

_lock = threading.Lock()
_running = {"v": False}


def _run_redeploy():
    with open(LOG_FILE, "ab", buffering=0) as log:
        log.write(b"\n==== redeploy start ====\n")
        try:
            subprocess.run(["bash", "-lc", REDEPLOY_CMD], cwd=REPO_DIR,
                           stdout=log, stderr=log, timeout=1800)
        except Exception as e:
            log.write(("redeploy error: " + str(e) + "\n").encode())
        log.write(b"==== redeploy done ====\n")
    with _lock:
        _running["v"] = False


class Handler(BaseHTTPRequestHandler):
    def _reply(self, code, msg):
        b = msg.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/healthz":
            self._reply(200, "ok")
            return
        if path != "/redeploy":
            self._reply(404, "not found")
            return
        # авторизация: Bearer-токен (если задан REDEPLOY_TOKEN)
        if TOKEN:
            auth = self.headers.get("Authorization", "")
            given = auth[7:] if auth.startswith("Bearer ") else ""
            if not hmac.compare_digest(given, TOKEN):
                self._reply(401, "unauthorized")
                return
        # дочитать тело, чтобы не висло соединение
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n > 0:
            self.rfile.read(n)
        with _lock:
            if _running["v"]:
                self._reply(409, "redeploy already running")
                return
            _running["v"] = True
        threading.Thread(target=_run_redeploy, daemon=True).start()
        self._reply(202, "redeploy started")

    def do_GET(self):
        if (self.path.split("?", 1)[0].rstrip("/") or "/") == "/healthz":
            self._reply(200, "ok")
        else:
            self._reply(405, "use POST /redeploy")

    def log_message(self, fmt, *args):
        print(f"[redeploy-agent] {self.address_string()} {fmt % args}", flush=True)


def main():
    if not TOKEN:
        print("[!] REDEPLOY_TOKEN не задан — агент примет ЛЮБОЙ запрос. Задай токен!", flush=True)
    print(f"[*] redeploy-agent на {BIND}:{PORT}, repo={REPO_DIR}, cmd={REDEPLOY_CMD}", flush=True)
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
