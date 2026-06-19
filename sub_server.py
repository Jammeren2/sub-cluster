#!/usr/bin/env python3
"""
sub_server.py — точка входа кластерного зеркала/агрегатора подписок.

Поднимает ТРИ слушателя на разных портах:
  • ADMIN_PORT   — веб-панель (граф, список, кластер, настройки). За ней
                   reverse-proxy с доменом admin.example.net.
  • SUB_PORT     — отдача подписок клиентам. Домен happ.example.com.
  • CLUSTER_PORT — peer-API кластера (HMAC), узлы ходят сюда друг к другу по IP.

Состояние — в SQLite (store.py), синхронизируется между узлами (cluster.py).
DNS-фейловер доменов — через reg.ru (dns_providers.py).

Запуск: python3 sub_server.py
Настройка — переменные окружения (см. README) + веб-панель.
"""

import os
import re
import json
import time
import hmac
import secrets
import threading
import urllib.parse
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import store as storemod
import subscriptions as subs
import graph
import cluster as clustermod
import secretbox
import webui

# ── окружение ──────────────────────────────────────────────────────────────
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8080"))
SUB_PORT = int(os.environ.get("SUB_PORT", "8081"))
CLUSTER_PORT = int(os.environ.get("CLUSTER_PORT", "8083"))

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
SESSION_TTL = int(os.environ.get("SESSION_TTL", "86400"))

LEGACY_UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "")
LEGACY_SUB_PATH = os.environ.get("SUB_PATH", "")
LEGACY_PROFILE_TITLE = os.environ.get("PROFILE_TITLE", "")

STORE = storemod.Store(origin=clustermod.NODE_ID)
CLUSTER = clustermod.Cluster(STORE)

# ── сессии ─────────────────────────────────────────────────────────────────
_sessions_lock = threading.Lock()
_sessions = {}


def create_session():
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    with _sessions_lock:
        _sessions[token] = {"exp": time.time() + SESSION_TTL, "csrf": csrf}
    return token, csrf


def get_session(token):
    if not token:
        return None
    with _sessions_lock:
        s = _sessions.get(token)
        if not s:
            return None
        if s["exp"] < time.time():
            _sessions.pop(token, None)
            return None
        return dict(s)


def drop_session(token):
    with _sessions_lock:
        _sessions.pop(token, None)


def check_credentials(user, password):
    # Никогда не пускаем с пустым/дефолтным паролем, даже если стартовая проверка обойдена.
    if not ADMIN_PASSWORD or ADMIN_PASSWORD == "admin":
        return False
    return (hmac.compare_digest(user or "", ADMIN_USER)
            and hmac.compare_digest(password or "", ADMIN_PASSWORD))


# ── троттлинг входа (защита от перебора пароля) ────────────────────────────
_login_lock = threading.Lock()
_login_fails = {}  # ip -> [fail_count, lock_until_epoch]
LOGIN_MAX_FAILS = int(os.environ.get("LOGIN_MAX_FAILS", "5"))
LOGIN_LOCK_SECONDS = int(os.environ.get("LOGIN_LOCK_SECONDS", "300"))


def login_blocked(ip):
    now = time.time()
    with _login_lock:
        rec = _login_fails.get(ip)
        if rec and rec[1] > now:
            return int(rec[1] - now)
        return 0


def login_register(ip, success):
    now = time.time()
    with _login_lock:
        # подчистим протухшие блокировки, чтобы словарь не рос
        for k in [k for k, v in _login_fails.items() if v[1] and v[1] < now and v[0] == 0]:
            _login_fails.pop(k, None)
        if success:
            _login_fails.pop(ip, None)
            return
        rec = _login_fails.get(ip) or [0, 0.0]
        rec[0] += 1
        if rec[0] >= LOGIN_MAX_FAILS:
            rec[1] = now + LOGIN_LOCK_SECONDS
            rec[0] = 0
        _login_fails[ip] = rec


def allowed_tls_domains():
    """FQDN'ы, для которых разрешаем выдачу сертификатов (on-demand TLS Caddy)."""
    s = STORE.get_settings()
    dns = s.get("dns") or {}
    out = set()
    for key in ("admin", "sub"):
        d = dns.get(key) or {}
        if d.get("subdomain") and d.get("zone"):
            out.add(f"{d['subdomain']}.{d['zone']}".lower())
    base = (s.get("sub_public_base") or "").strip()
    if base:
        host = urllib.parse.urlsplit(base if "://" in base else "https://" + base).hostname
        if host:
            out.add(host.lower())
    return out


def sub_public_base():
    s = STORE.get_settings()
    base = (s.get("sub_public_base") or "").strip()
    if base:
        return base.rstrip("/")
    d = (s.get("dns") or {}).get("sub") or {}
    if d.get("subdomain") and d.get("zone"):
        return f"https://{d['subdomain']}.{d['zone']}"
    return ""


# ── базовый обработчик ─────────────────────────────────────────────────────
class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "subcluster/3.0"

    def _is_https(self):
        return self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def _client_ip(self):
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.headers.get("X-Real-IP") or self.client_address[0]

    def _respond(self, code, body=b"", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
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

    def _json(self, code, obj):
        self._respond(code, json.dumps(obj, ensure_ascii=False),
                      {"Content-Type": "application/json; charset=utf-8"})

    def _redirect(self, location, cookies=None):
        self.send_response(302)
        self.send_header("Location", location)
        for c in (cookies or []):
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _read_body(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(n) if 0 < n <= 8_000_000 else b""

    def _read_form(self):
        return urllib.parse.parse_qs(self._read_body().decode("utf-8", errors="ignore"),
                                     keep_blank_values=True)

    def _read_json(self):
        raw = self._read_body()
        try:
            return json.loads(raw.decode("utf-8", errors="ignore")) if raw else None
        except Exception:
            return None

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")


# ── admin-сервер ───────────────────────────────────────────────────────────
class AdminHandler(_Base):
    def _cookies(self):
        out = {}
        for part in (self.headers.get("Cookie", "") or "").split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def _session(self):
        return get_session(self._cookies().get("session"))

    def _session_cookie(self, token):
        flags = "HttpOnly; SameSite=Lax; Path=/"
        if self._is_https():
            flags += "; Secure"
        return f"session={token}; {flags}; Max-Age={SESSION_TTL}"

    def _html(self, code, html):
        self._respond(code, html, {"Content-Type": "text/html; charset=utf-8"})

    def do_GET(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/healthz":
            self._respond(200, b"ok")
            return
        # ask-эндпоинт для on-demand TLS Caddy: разрешаем только наши домены.
        if path == "/tls-check":
            qs = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
            domain = (qs.get("domain", [""])[0] or "").lower()
            self._respond(200 if domain in allowed_tls_domains() else 404,
                          b"ok" if domain in allowed_tls_domains() else b"no")
            return
        if path == "/login":
            self._html(200, webui.render_login()) if not self._session() else self._redirect("/")
            return
        sess = self._session()
        if not sess:
            self._html(200, webui.render_login())
            return
        if path == "/":
            self._html(200, webui.render_editor(graph.get_graph(STORE), sub_public_base(), sess["csrf"]))
        elif path == "/classic":
            self._html(200, webui.render_classic(graph.get_routes(STORE), sub_public_base()))
        elif path == "/cluster":
            self._html(200, webui.render_cluster(CLUSTER.status(), sub_public_base()))
        elif path == "/settings":
            s = STORE.get_settings()
            has_pw = bool((s.get("dns") or {}).get("regru_password_enc"))
            self._html(200, webui.render_settings(s, sub_public_base(),
                                                  crypto_ok=secretbox.crypto_ready(), has_regru_pw=has_pw))
        else:
            self._respond(404, b"not found")

    do_HEAD = do_GET

    def do_POST(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"

        if path == "/login":
            ip = self._client_ip()
            wait = login_blocked(ip)
            if wait:
                self._html(429, webui.render_login(f"Слишком много попыток. Повтори через {wait} с."))
                return
            form = self._read_form()
            if check_credentials(form.get("user", [""])[0], form.get("password", [""])[0]):
                login_register(ip, True)
                token, _ = create_session()
                self._redirect("/", [self._session_cookie(token)])
            else:
                login_register(ip, False)
                self._html(401, webui.render_login("Неверный логин или пароль"))
            return

        # graph/save — JSON + CSRF
        if path == "/graph/save":
            sess = self._session()
            if not sess:
                self._json(401, {"ok": False, "errors": ["Сессия истекла"]})
                return
            if not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), sess.get("csrf", "")):
                self._json(403, {"ok": False, "errors": ["Неверный CSRF-токен"]})
                return
            data = self._read_json()
            if data is None:
                self._json(400, {"ok": False, "errors": ["Некорректный JSON"]})
                return
            ok, errors = graph.save_graph(STORE, data)
            self._json(200 if ok else 400, {"ok": ok, "errors": errors})
            return

        if not self._session():
            self._redirect("/login")
            return

        if path == "/logout":
            drop_session(self._cookies().get("session"))
            self._redirect("/login", ["session=; Path=/; Max-Age=0"])
            return

        # ── маршруты (классический) ──
        if path == "/routes/create":
            form = self._read_form()
            p = form.get("path", [""])[0].strip()
            err = graph.validate_route_path(STORE, p)
            if err:
                self._html(400, webui.render_classic(graph.get_routes(STORE), sub_public_base(), err, True))
                return
            graph.add_route(STORE, p, form.get("title", [""])[0].strip(),
                            graph.parse_upstreams(form.get("upstreams", [""])[0]),
                            form.get("mode", ["merge"])[0].strip())
            self._redirect("/classic")
            return

        m = re.match(r"^/routes/([A-Za-z0-9_-]{1,64})/(update|delete)$", path)
        if m:
            rid, action = m.group(1), m.group(2)
            if action == "delete":
                graph.delete_route(STORE, rid)
                self._redirect("/classic")
                return
            form = self._read_form()
            p = form.get("path", [""])[0].strip()
            err = graph.validate_route_path(STORE, p, ignore_id=rid)
            if err:
                self._html(400, webui.render_classic(graph.get_routes(STORE), sub_public_base(), err, True))
                return
            graph.update_route(STORE, rid, path=p, title=form.get("title", [""])[0].strip(),
                               mode=form.get("mode", ["merge"])[0].strip(),
                               upstreams=graph.parse_upstreams(form.get("upstreams", [""])[0]),
                               enabled=("enabled" in form))
            self._redirect("/classic")
            return

        # ── кластер ──
        if path == "/cluster/switch":
            node = self._read_form().get("node", [""])[0].strip()
            ok, msg = CLUSTER.set_active_to(node, by="manual", pin=True)
            self._cluster_flash(ok, f"Переключено на {node}: {msg}" if ok else f"Ошибка: {msg}")
            return
        if path == "/cluster/pin/clear":
            CLUSTER.clear_pin()
            self._redirect("/cluster")
            return
        if path == "/cluster/nodes/add":
            f = self._read_form()
            CLUSTER.add_node({
                "label": f.get("label", [""])[0].strip(),
                "public_ip": f.get("public_ip", [""])[0].strip(),
                "priority": int(f.get("priority", ["100"])[0] or "100"),
                "cluster_port": int(f.get("cluster_port", [str(CLUSTER_PORT)])[0] or CLUSTER_PORT),
            })
            self._redirect("/cluster")
            return
        m = re.match(r"^/cluster/nodes/([A-Za-z0-9_.:-]{1,80})/(update|delete)$", path)
        if m:
            nid, action = m.group(1), m.group(2)
            if action == "delete":
                CLUSTER.remove_node(nid)
                self._redirect("/cluster")
                return
            f = self._read_form()
            fields = {
                "label": f.get("label", [""])[0].strip(),
                "public_ip": f.get("public_ip", [""])[0].strip(),
                "enabled": ("enabled" in f),
            }
            for numf in ("priority", "cluster_port", "admin_port", "sub_port"):
                if f.get(numf, [""])[0].strip():
                    try:
                        fields[numf] = int(f[numf][0])
                    except ValueError:
                        pass
            CLUSTER.set_node(nid, fields)
            self._redirect("/cluster")
            return

        # ── настройки ──
        if path == "/settings/save":
            self._save_settings(self._read_form())
            self._redirect("/settings")
            return

        self._respond(404, b"not found")

    def _cluster_flash(self, ok, msg):
        self._html(200 if ok else 400,
                   webui.render_cluster(CLUSTER.status(), sub_public_base(), msg, not ok))

    def _save_settings(self, f):
        def first(name, default=""):
            return f.get(name, [default])[0].strip()

        def mut(cfg):
            s = cfg.setdefault("settings", {})
            dns = s.setdefault("dns", {})
            dns["regru_username"] = first("regru_username")
            pw = first("regru_password")
            if pw:  # пустой — не менять
                dns["regru_password_enc"] = secretbox.encrypt(pw)
            dns.setdefault("provider", "regru")
            dns["admin"] = {"zone": first("admin_zone"), "subdomain": first("admin_subdomain")}
            dns["sub"] = {"zone": first("sub_zone"), "subdomain": first("sub_subdomain")}
            s["sub_public_base"] = first("sub_public_base")
            s["failover_enabled"] = ("failover_enabled" in f)
            s["require_quorum"] = ("require_quorum" in f)
            s["preempt"] = ("preempt" in f)
            for key in ("poll_interval", "fail_threshold", "cooldown"):
                try:
                    s[key] = int(first(key, str(s.get(key, 0))))
                except ValueError:
                    pass
        STORE.update_config(mut)


# ── sub-сервер (отдача подписок) ───────────────────────────────────────────
class SubHandler(_Base):
    def _log_device(self):
        ip = (self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
              or self.headers.get("X-Real-IP") or self.client_address[0])
        print(f"[{self.log_date_time_string()}] DEVICE ip={ip} "
              f"hwid={self.headers.get('X-Hwid','-')} model={self.headers.get('X-Device-Model','-')} "
              f"app={self.headers.get('X-App-Version','-')} ua=\"{self.headers.get('User-Agent','-')}\"",
              flush=True)

    def do_GET(self):
        raw_path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if raw_path == "/healthz":
            self._respond(200, b"ok")
            return
        route = graph.find_route(STORE, raw_path)
        if route:
            self._log_device()
            try:
                body, headers = subs.build_route_response(route)
            except urllib.error.HTTPError as e:
                self._respond(502, f"upstream HTTP {e.code}".encode())
            except Exception as e:
                self._respond(502, f"upstream error: {e}".encode())
            else:
                self._respond(200, body, headers)
            return
        self._respond(404, b"not found")

    do_HEAD = do_GET


# ── cluster-сервер (peer-API, HMAC) ────────────────────────────────────────
class ClusterHandler(_Base):
    def _serve(self):
        path = self.path.split("?", 1)[0]
        body = self._read_body()
        if path == "/healthz":
            self._respond(200, b"ok")
            return
        if not CLUSTER.verify(self.headers.get, path, body):
            self._respond(401, b"unauthorized")
            return
        if path == "/cluster/ping":
            self._json(200, CLUSTER.ping_view())
        elif path == "/cluster/members":
            self._json(200, CLUSTER.members_doc())
        elif path.startswith("/cluster/state/"):
            key = path.rsplit("/", 1)[-1]
            if key in ("config", "failover"):
                self._json(200, STORE.get_meta(key))
            else:
                self._respond(404, b"not found")
        else:
            self._respond(404, b"not found")

    do_GET = _serve
    do_POST = _serve
    do_HEAD = _serve


def seed_legacy_route():
    if graph.get_routes(STORE):
        return
    if LEGACY_UPSTREAM_URL and LEGACY_SUB_PATH:
        graph.add_route(STORE, LEGACY_SUB_PATH, LEGACY_PROFILE_TITLE, [LEGACY_UPSTREAM_URL], "mirror")
        print(f"[*] Легаси-маршрут (зеркало) {LEGACY_SUB_PATH} → {LEGACY_UPSTREAM_URL}", flush=True)


def _serve(handler_cls, port, name):
    httpd = ThreadingHTTPServer((LISTEN_HOST, port), handler_cls)
    print(f"[*] {name} слушает {LISTEN_HOST}:{port}", flush=True)
    httpd.serve_forever()


def main():
    graph.migrate_config(STORE)
    seed_legacy_route()
    CLUSTER.start()

    if ADMIN_PASSWORD in ("", "admin"):
        if os.environ.get("ALLOW_WEAK_ADMIN_PASSWORD") == "1":
            print("[!] ВНИМАНИЕ: слабый/дефолтный ADMIN_PASSWORD (разрешён ALLOW_WEAK_ADMIN_PASSWORD=1).", flush=True)
        else:
            print("[FATAL] ADMIN_PASSWORD не задан или равен 'admin'. Установи надёжный ADMIN_PASSWORD "
                  "(или ALLOW_WEAK_ADMIN_PASSWORD=1 для локального теста).", flush=True)
            raise SystemExit(1)
    if not clustermod.CLUSTER_SECRET:
        print("[!] ВНИМАНИЕ: CLUSTER_SECRET не задан — peer-API кластера отключён.", flush=True)
    if not secretbox.crypto_ready():
        print("[!] ВНИМАНИЕ: SECRET_KEY не задан/нет cryptography — секреты хранятся открыто.", flush=True)

    print(f"[*] Узел: {CLUSTER.id} (ip={CLUSTER.public_ip or '?'}, приоритет={CLUSTER.priority})", flush=True)
    print(f"[*] БД: {storemod.DB_FILE}", flush=True)

    threads = [
        threading.Thread(target=_serve, args=(SubHandler, SUB_PORT, "SUB"), daemon=True),
        threading.Thread(target=_serve, args=(ClusterHandler, CLUSTER_PORT, "CLUSTER"), daemon=True),
    ]
    for t in threads:
        t.start()
    try:
        _serve(AdminHandler, ADMIN_PORT, "ADMIN")  # главный поток
    except KeyboardInterrupt:
        print("\n[*] Остановлено.", flush=True)


if __name__ == "__main__":
    main()
