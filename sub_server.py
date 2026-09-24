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
import socket
import secrets
import ipaddress
import base64
import hashlib
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
import zapret
import gateway
import provision
import personal
import portal

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
PERSONAL = personal.Registry(storemod.DB_FILE)
_PORTAL_SECRET = (clustermod.CLUSTER_SECRET or secrets.token_urlsafe(32)).encode()

def portal_csrf(route, host, stamp=None):
    stamp = str(int(time.time()) if stamp is None else stamp)
    message = (route["id"] + "|" + host + "|" + stamp).encode()
    return stamp + "." + hmac.new(_PORTAL_SECRET, message, hashlib.sha256).hexdigest()


def valid_portal_csrf(token, route, host):
    try:
        stamp = token.split(".", 1)[0]
        return 0 <= time.time() - int(stamp) <= 3600 and hmac.compare_digest(token, portal_csrf(route, host, stamp))
    except (ValueError, TypeError):
        return False


def personal_operation(route, payload, remote=False):
    """Forward to the fixed owner; never create a competing local registry."""
    owner = route.get("personal_owner")
    if not owner:
        raise personal.PersonalError("Администратору нужно сохранить личный маршрут ещё раз.", 503)
    if owner != CLUSTER.id:
        if remote:
            raise personal.PersonalError("Настройки кластера обновляются. Повторите позже.", 503)
        node = CLUSTER.find_node(owner)
        base = CLUSTER._peer_base(node) if node else None
        if not base:
            raise personal.PersonalError("Сервер личных подписок недоступен. Попробуйте позже.", 503)
        try:
            result = CLUSTER._http(base, "/cluster/personal", method="POST", payload={**payload, "route_id": route["id"]}, timeout=60)
        except Exception:
            raise personal.PersonalError("Сервер личных подписок недоступен. Попробуйте позже.", 503)
        if not result.get("ok"):
            raise personal.PersonalError(result.get("error", "Ошибка личной подписки"), result.get("status", 503))
        return result
    op = payload.get("op")
    slug = str(payload.get("slug") or "")
    if op not in ("catalog", "create", "manage", "update", "fetch"):
        raise personal.PersonalError("Неизвестное действие.")
    if op != "fetch":
        PERSONAL.limit(op + ":" + str(payload.get("ip", "")), 12 if op == "create" else 300)
    details = None
    if op in ("manage", "update"):
        details = PERSONAL.access(route["id"], slug, token=payload.get("token") or "")
    if op == "fetch":
        device = payload.get("device") or {}
        if STORE.is_device_blocked(route["id"], device.get("hwid", ""), device.get("ip", "")):
            body, headers = subs.build_blocked_response(payload.get("format", "legacy"))
            return {"ok": True, "body": base64.b64encode(body).decode(), "headers": headers}
        details = PERSONAL.access(route["id"], slug, hwid=device.get("hwid", ""), claim=False)
    if op == "create":
        personal.verify_turnstile(payload.get("captcha"), payload.get("hostname", ""))
        # Reserve only suffixes that cannot shadow another configured route.
        candidate = route["path"].rstrip('/') + '/' + str(payload.get("slug") or "")
        for other in graph.get_routes(STORE):
            if other["path"] == candidate or other["path"].startswith(candidate + '/'):
                raise personal.PersonalError("Это название занято другим маршрутом.", 409)
    spec = graph.resolve_links_spec(STORE, route)
    # Normalize mirrors through the merger so JSON and base64 catalogs have one shape.
    body, headers = subs.build_route_response({**route, "mode": "merge"}, spec, route.get("announce", ""))
    items = personal.catalog(body)
    if op in ("create", "update"):
        selected = payload.get("selected")
        valid = {item["id"] for item in items}
        if not isinstance(selected, list) or not selected or len(selected) > 1000 or any(not isinstance(x, str) or x not in valid for x in selected):
            raise personal.PersonalError("Выберите доступные серверы. Если список изменился, обновите страницу.")
        selected = list(dict.fromkeys(selected))
        if op == "create":
            return {"ok": True, **PERSONAL.create(route["id"], payload.get("name"), slug, selected)}
        details = PERSONAL.access(route["id"], slug, token=payload.get("token") or "", selected=selected)
    if op == "fetch":
        # Claim only after materializing the subscription. Transaction rechecks races.
        details = PERSONAL.access(route["id"], slug, hwid=device.get("hwid", ""), claim=payload.get("claim", True) and any(item["id"] in details["selected"] for item in items))
        title = (route.get("title") or route["path"]) + " ● Личная"
        body, headers = personal.selected_response(items, details["selected"], headers, payload.get("format", "legacy"), title)
        if any(item['id'] in details['selected'] for item in items):
            # Never inherit an upstream announcement when the route description is empty.
            headers = {key: value for key, value in headers.items() if key.lower() != 'announce'}
            announce = (route.get('announce') or '').strip()
            if announce:
                headers['Announce'] = subs._b64_header(announce)
        return {"ok": True, "body": base64.b64encode(body).decode(), "headers": headers}
    return {"ok": True, "items": [{"id": item["id"], "name": item["name"]} for item in items],
            "configured": bool(os.environ.get('TURNSTILE_SITE_KEY') and os.environ.get('TURNSTILE_SECRET_KEY')),
            **(details or {})}


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


def _host_of(url):
    if not url:
        return None
    h = urllib.parse.urlsplit(url if "://" in url else "https://" + url).hostname
    return h.lower() if h else None


def _safe_outbound_url(url):
    """Защита от SSRF на /graph/preview: только http(s), и хост не должен резолвиться
    в приватные/loopback/link-local/служебные адреса (метадата 169.254.169.254,
    RFC1918, localhost). → (ok, причина). Каветка: TOCTOU/DNS-rebinding не закрыт —
    эндпоинт только для аутентифицированного админа, цель — отсечь тривиальный SSRF."""
    try:
        u = urllib.parse.urlsplit((url or "").strip())
        scheme = (u.scheme or "").lower()
        host = u.hostname
        port = u.port
    except Exception:
        return False, "Некорректный URL"
    if scheme not in ("http", "https"):
        return False, "Только http(s)"
    if not host:
        return False, "Нет хоста"
    try:
        infos = socket.getaddrinfo(host, port or (443 if scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except Exception as e:
        return False, f"DNS: {e}"
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False, "Плохой IP"
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified):
            return False, "Адрес запрещён (внутренний/служебный)"
    return True, ""


def allowed_tls_domains():
    """FQDN'ы, для которых разрешаем выдачу сертификатов (on-demand TLS Caddy):
    собственный admin-домен этого узла (из CLUSTER_URL/env ADMIN_DOMAIN) и FQDN всех
    включённых доменов подписок (+ их public_base)."""
    s = STORE.get_settings()
    out = set()
    # собственный admin-домен узла
    for src in (clustermod.CLUSTER_URL, os.environ.get("ADMIN_DOMAIN", "")):
        h = _host_of(src)
        if h:
            out.add(h)
    # все включённые домены подписок (фейловерные)
    for d in graph.enabled_domains(s):
        fq = graph.domain_fqdn(d)
        if fq:
            out.add(fq)
        h = _host_of(d.get("public_base") or "")
        if h:
            out.add(h)
    # легаси-фолбэк (до миграции)
    leg = (s.get("dns") or {}).get("sub") or {}
    if leg.get("subdomain") and leg.get("zone"):
        out.add(f"{leg['subdomain']}.{leg['zone']}".lower())
    h = _host_of(s.get("sub_public_base") or "")
    if h:
        out.add(h)
    return out


def sub_public_base():
    """Публичная база ссылок ДЕФОЛТНОГО домена (для общих ссылок в UI)."""
    s = STORE.get_settings()
    base = graph.domain_public_base(graph.default_domain(s) or {})
    if base:
        return base
    base = (s.get("sub_public_base") or "").strip()
    if base:
        return base.rstrip("/")
    d = (s.get("dns") or {}).get("sub") or {}
    if d.get("subdomain") and d.get("zone"):
        return f"https://{d['subdomain']}.{d['zone']}"
    return ""


def domains_for_ui():
    """Слим-список доменов для редактора/классики: id, fqdn, base, enabled, default."""
    s = STORE.get_settings()
    return [{"id": d.get("id"), "fqdn": graph.domain_fqdn(d) or (d.get("id") or ""),
             "base": graph.domain_public_base(d), "enabled": d.get("enabled", True),
             "default": bool(d.get("default"))} for d in graph.domain_list(s)]


def _normalize_zapret(data):
    """Список zapret-стратегий из UI → (strategies, active_id, errors). Параметры каждой
    стратегии валидируются белым списком флагов nfqws (защита от инъекции в subprocess)."""
    raw = data.get("strategies") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        raw = []
    out, errors, seen = [], [], set()
    for item in raw[:50]:
        if not isinstance(item, dict):
            continue
        label = str(item.get("label") or "").strip()[:80]
        params = str(item.get("params") or "").strip()[:1000]
        if not label and not params:
            continue
        ok, res = zapret.validate_params(params)
        if not ok:
            errors.append(f"«{label or 'стратегия'}»: {res}")
            continue
        sid = str(item.get("id") or "").strip()
        if not re.match(r"^[A-Za-z0-9_-]{1,64}$", sid) or sid in seen:
            sid = secrets.token_hex(6)
        seen.add(sid)
        out.append({"id": sid, "label": label or "стратегия", "params": params})
    active = str((data or {}).get("active_id") or "").strip()
    if active and active not in seen:
        active = ""
    return out, active, errors


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

    def _req_host(self):
        """Запрошенный хост (для host-aware маршрутизации по домену подписок)."""
        h = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
        return h.split(",")[0].strip()

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

    # peer-API кластера (HMAC). Обслуживается и на cluster-порту, и на admin-порту
    # (чтобы узлы ходили друг к другу через статичный admin-домен по 443).
    CLUSTER_API_PATHS = ("/cluster/ping", "/cluster/members", "/cluster/stats", "/cluster/personal")

    @staticmethod
    def is_cluster_api(path):
        return path in _Base.CLUSTER_API_PATHS or path.startswith("/cluster/state/")

    def _serve_cluster_api(self, path, body):
        if not CLUSTER.verify(self.headers.get, path, body):
            self._respond(401, b"unauthorized")
            return
        if path == "/cluster/personal":
            try:
                payload = json.loads(body)
                route = next((r for r in graph.get_routes(STORE) if r["id"] == payload.get("route_id") and r.get("enabled", True) and r.get("access") == "private"), None)
                if not route:
                    raise personal.PersonalError("Личный маршрут недоступен.", 404)
                result = personal_operation(route, payload, remote=True)
            except personal.PersonalError as e:
                result = {"ok": False, "error": str(e), "status": e.status}
            except Exception:
                result = {"ok": False, "error": "Личный сервис временно недоступен.", "status": 503}
            self._json(200, result)
        elif path == "/cluster/ping":
            self._json(200, CLUSTER.ping_view())
        elif path == "/cluster/members":
            self._json(200, CLUSTER.members_doc())
        elif path == "/cluster/stats":
            self._json(200, CLUSTER.stats_doc())
        elif path == "/cluster/reset-stats":
            try:
                payload = json.loads(body or b"{}")
            except Exception:
                payload = {}
            STORE.reset_stats(payload.get("route") or None)
            self._json(200, {"ok": True})
        elif path == "/cluster/redeploy":
            ok, msg = CLUSTER._fire_redeploy()
            self._json(200, {"ok": ok, "msg": msg})
        elif path.startswith("/cluster/state/"):
            key = path.rsplit("/", 1)[-1]
            if key in ("config", "failover"):
                self._json(200, STORE.get_meta(key))
            else:
                self._respond(404, b"not found")
        else:
            self._respond(404, b"not found")


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
            allowed = domain in allowed_tls_domains()
            self._respond(200 if allowed else 404, b"ok" if allowed else b"no")
            return
        # peer-API кластера через admin-домен (443) — HMAC, до сессионной проверки.
        if self.is_cluster_api(path):
            self._serve_cluster_api(path, self._read_body())
            return
        if path == "/login":
            self._html(200, webui.render_login()) if not self._session() else self._redirect("/")
            return
        sess = self._session()
        if not sess:
            self._html(200, webui.render_login())
            return
        if path == "/":
            self._html(200, webui.render_editor(graph.get_graph(STORE), sub_public_base(),
                                                sess["csrf"], domains=domains_for_ui()))
        elif path == "/classic":
            self._html(200, webui.render_classic(graph.get_routes(STORE), sub_public_base(),
                                                 domains=domains_for_ui()))
        elif path == "/cluster":
            self._html(200, webui.render_cluster(CLUSTER.status(), sub_public_base()))
        elif path == "/stats":
            self._html(200, webui.render_stats(CLUSTER.cluster_stats(), graph.get_routes(STORE),
                                               CLUSTER.id, sub_public_base(),
                                               STORE.get_blocked_devices(), sess["csrf"]))
        elif path == "/settings":
            s = STORE.get_settings()
            self._html(200, webui.render_settings(s, CLUSTER.all_nodes(),
                                                  crypto_ok=secretbox.crypto_ready(),
                                                  sub_port=SUB_PORT, admin_port=ADMIN_PORT))
        elif path == "/zapret":
            z = STORE.get_settings().get("zapret") or {}
            self._html(200, webui.render_zapret(z, zapret.SERVICES, zapret.is_available(),
                                                zapret.can_apply(), CLUSTER.id, sess["csrf"],
                                                zapret.unavailable_reason(), zapret.DEFAULT_STRATEGIES,
                                                zapret.COMMUNITY_STRATEGIES))
        elif path == "/zapret/test/status":
            qs = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
            self._json(200, zapret.test_status(qs.get("cursor", ["0"])[0]))
        elif path == "/gateway/status":
            self._json(200, gateway.status(STORE))
        else:
            self._respond(404, b"not found")

    do_HEAD = do_GET

    def do_POST(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"

        # peer-API кластера (POST, через admin-домен по 443) — HMAC, до сессии.
        if path in ("/cluster/reset-stats", "/cluster/redeploy", "/cluster/personal"):
            self._serve_cluster_api(path, self._read_body())
            return

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
            if ok:
                try:
                    gateway.reconcile(STORE)   # серверный gateway: подхватить изменения графа
                except Exception as e:
                    print(f"[gateway] reconcile после save: {e}", flush=True)
            self._json(200 if ok else 400, {"ok": ok, "errors": errors})
            return

        # graph/preview — скачать подписку и вернуть её ссылки (для UI-переименования)
        if path == "/graph/preview":
            sess = self._session()
            if not sess:
                self._json(401, {"ok": False, "error": "Сессия истекла"})
                return
            if not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), sess.get("csrf", "")):
                self._json(403, {"ok": False, "error": "Неверный CSRF-токен"})
                return
            data = self._read_json()
            url = ((data or {}).get("url") or "").strip() if isinstance(data, dict) else ""
            ok, why = _safe_outbound_url(url)
            if not ok:
                self._json(400, {"ok": False, "error": why})
                return
            try:
                links = subs.preview_subscription(url)
            except urllib.error.HTTPError as e:
                self._json(502, {"ok": False, "error": f"upstream HTTP {e.code}"})
            except Exception as e:
                self._json(502, {"ok": False, "error": f"upstream: {e}"})
            else:
                self._json(200, {"ok": True, "links": links})
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
            did = form.get("domain_id", [""])[0].strip()
            err = graph.validate_route_path(STORE, p, domain_id=did, access=form.get("access", ["public"])[0])
            if err:
                self._html(400, webui.render_classic(graph.get_routes(STORE), sub_public_base(),
                                                     err, True, domains=domains_for_ui()))
                return
            graph.add_route(STORE, p, form.get("title", [""])[0].strip(),
                            graph.parse_upstreams(form.get("upstreams", [""])[0]),
                            form.get("mode", ["merge"])[0].strip(),
                            announce=form.get("announce", [""])[0], domain_id=did, access=form.get("access", ["public"])[0])
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
            did = form.get("domain_id", [""])[0].strip()
            err = graph.validate_route_path(STORE, p, ignore_id=rid, domain_id=did, access=form.get("access", ["public"])[0])
            if err:
                self._html(400, webui.render_classic(graph.get_routes(STORE), sub_public_base(),
                                                     err, True, domains=domains_for_ui()))
                return
            graph.update_route(STORE, rid, path=p, title=form.get("title", [""])[0].strip(),
                               mode=form.get("mode", ["merge"])[0].strip(),
                               upstreams=graph.parse_upstreams(form.get("upstreams", [""])[0]),
                               announce=form.get("announce", [""])[0],
                               domain_id=did, enabled=("enabled" in form), access=form.get("access", ["public"])[0])
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
                "cluster_url": f.get("cluster_url", [""])[0].strip(),
                "redeploy_url": f.get("redeploy_url", [""])[0].strip(),
                "redeploy_token": f.get("redeploy_token", [""])[0],
                "priority": int(f.get("priority", ["100"])[0] or "100"),
                "cluster_port": int(f.get("cluster_port", [str(CLUSTER_PORT)])[0] or CLUSTER_PORT),
            })
            self._redirect("/cluster")
            return
        m = re.match(r"^/cluster/nodes/([A-Za-z0-9_.:-]{1,80})/(update|delete|redeploy)$", path)
        if m:
            nid, action = m.group(1), m.group(2)
            if action == "delete":
                CLUSTER.remove_node(nid)
                self._redirect("/cluster")
                return
            if action == "redeploy":
                ok, msg = CLUSTER.trigger_redeploy(nid)
                self._cluster_flash(ok, f"Редеплой {nid}: {msg}" if ok else f"Редеплой {nid} не запущен: {msg}")
                return
            f = self._read_form()
            fields = {
                "label": f.get("label", [""])[0].strip(),
                "public_ip": f.get("public_ip", [""])[0].strip(),
                "cluster_url": f.get("cluster_url", [""])[0].strip(),
                "redeploy_url": f.get("redeploy_url", [""])[0].strip(),
                "redeploy_token": f.get("redeploy_token", [""])[0],
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

        # ── статистика ──
        if path == "/stats/reset":
            CLUSTER.reset_stats_cluster(self._read_form().get("route", [""])[0].strip() or None)
            self._redirect("/stats")
            return
        if path == "/stats/block":
            f = self._read_form()
            if not hmac.compare_digest(f.get("csrf", [""])[0], self._session().get("csrf", "")):
                self._respond(403, "Неверный CSRF-токен")
                return
            route_id = f.get("route", [""])[0].strip()
            device = f.get("device", [""])[0].strip()
            blocked = f.get("action", ["block"])[0] != "unblock"
            valid_route = any(r.get("id") == route_id for r in graph.get_routes(STORE))
            if valid_route and device:
                STORE.set_device_blocked(route_id, device, blocked)
            self._redirect("/stats")
            return

        # ── настройки ──
        if path == "/settings/save":
            if self._save_settings(self._read_form()) is not False:
                self._redirect("/settings")
            return

        # ── zapret (обход DPI): сохранение стратегий + авто-тест (JSON + CSRF) ──
        if path in ("/zapret/save", "/zapret/test/start", "/zapret/test/stop"):
            sess = self._session()
            if not sess:
                self._json(401, {"ok": False, "error": "Сессия истекла"})
                return
            if not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), sess.get("csrf", "")):
                self._json(403, {"ok": False, "error": "Неверный CSRF-токен"})
                return
            data = self._read_json() or {}
            if path == "/zapret/save":
                strategies, active_id, errs = _normalize_zapret(data)
                if errs:
                    self._json(400, {"ok": False, "error": "; ".join(errs)})
                    return

                def mut(cfg):
                    z = cfg.setdefault("settings", {}).setdefault("zapret", {})
                    z["strategies"] = strategies
                    z["active_id"] = active_id
                STORE.update_config(mut)
                self._json(200, {"ok": True})
            elif path == "/zapret/test/start":
                z = STORE.get_settings().get("zapret") or {}
                saved = {s["id"]: s for s in z.get("strategies", []) if s.get("id")}
                ids = data.get("strategy_ids") if isinstance(data.get("strategy_ids"), list) else None
                strategies = [saved[i] for i in (ids or list(saved.keys())) if i in saved]
                if not strategies:  # хотя бы прямой режим (baseline)
                    strategies = [{"id": "direct", "label": "Прямой (без обхода)", "params": ""}]
                svc_in = data.get("service_keys") if isinstance(data.get("service_keys"), list) else None
                svc_keys = [k for k in (svc_in or [s["key"] for s in zapret.SERVICES])
                            if k in zapret.SERVICE_BY_KEY]

                def on_done(results, best_id):
                    if best_id and best_id in saved:   # авто-выбор лучшей (можно сменить)
                        STORE.update_config(lambda cfg: cfg.setdefault("settings", {})
                                            .setdefault("zapret", {}).__setitem__("active_id", best_id))
                started = zapret.start_test(strategies, svc_keys, on_done=on_done)
                self._json(200 if started else 409,
                           {"ok": started, "error": "" if started else "тест уже идёт"})
            else:  # /zapret/test/stop
                zapret.stop_test()
                self._json(200, {"ok": True})
            return

        self._respond(404, b"not found")

    def _cluster_flash(self, ok, msg):
        self._html(200 if ok else 400,
                   webui.render_cluster(CLUSTER.status(), sub_public_base(), msg, not ok))

    def _save_settings(self, f):
        """Сохранить настройки. Домены приходят одним JSON-полем domains_json (список
        объектов домена). Валидируем (дубли FQDN/конфликт зоны), пароль пустой = не
        менять (по id), ровно один default. → True, либо False (отрендерил ошибку)."""
        def first(name, default=""):
            return f.get(name, [default])[0].strip()

        raw = first("domains_json")
        try:
            incoming = json.loads(raw) if raw else []
        except Exception:
            incoming = []

        cur = {d.get("id"): d for d in graph.domain_list(STORE.get_settings())}
        parsed, errors = graph.normalize_domains(incoming, cur, secretbox.encrypt)

        if errors:
            self._html(400, webui.render_settings(STORE.get_settings(), CLUSTER.all_nodes(),
                       flash="; ".join(errors), flash_err=True, crypto_ok=secretbox.crypto_ready(),
                       sub_port=SUB_PORT, admin_port=ADMIN_PORT))
            return False

        def mut(cfg):
            s = cfg.setdefault("settings", {})
            dns = s.setdefault("dns", {})
            dns["domains"] = parsed
            dns.setdefault("provider", "regru")
            # зеркалим дефолтный домен в легаси-поля (смешанная раскатка со старыми
            # узлами + миграция без потерь туда-обратно)
            dflt = next((d for d in parsed if d["default"]), (parsed[0] if parsed else None))
            if dflt:
                dns["sub"] = {"zone": dflt["zone"], "subdomain": dflt["subdomain"]}
                dns["regru_username"] = dflt["regru_username"]
                dns["regru_password_enc"] = dflt["regru_password_enc"]
                s["sub_public_base"] = dflt.get("public_base", "")
            s["require_client_version"] = ("require_client_version" in f)
            s["failover_enabled"] = ("failover_enabled" in f)
            s["require_quorum"] = ("require_quorum" in f)
            s["preempt"] = ("preempt" in f)
            for key in ("poll_interval", "fail_threshold", "cooldown"):
                try:
                    s[key] = int(first(key, str(s.get(key, 0))))
                except ValueError:
                    pass
        STORE.update_config(mut)
        return True


# ── sub-сервер (отдача подписок) ───────────────────────────────────────────
class SubHandler(_Base):
    def _device(self):
        return {
            "ip": personal.client_ip(self.client_address[0], self.headers),
            "hwid": self.headers.get("X-Hwid", "").strip(),
            "model": self.headers.get("X-Device-Model", ""),
            "app": self.headers.get("X-App-Version", ""),
            "ua": self.headers.get("User-Agent", "-"),
        }

    def _public_route(self):
        path = self.path.split('?', 1)[0].rstrip('/') or '/'
        route = graph.find_route(STORE, path, host=self._req_host())
        if route:
            return route, ''
        parent, _, slug = path.rpartition('/')
        if re.fullmatch(r'[A-Za-z0-9_-]{4,64}', slug):
            route = graph.find_route(STORE, parent, host=self._req_host())
            if route and route.get('access') == 'private':
                return route, slug
        return None, ''

    def do_POST(self):
        route, slug = self._public_route()
        if not route or route.get('access') != 'private':
            self._respond(404, b'not found')
            return
        try:
            if int(self.headers.get('Content-Length', '0')) > 65536:
                self.close_connection = True
                raise personal.PersonalError('Слишком большой запрос.', 413)
            if not valid_portal_csrf(self.headers.get('X-Portal-CSRF', ''), route, self._req_host()):
                raise personal.PersonalError('Обновите страницу и повторите запрос.', 403)
            payload = self._read_json()
            if not isinstance(payload, dict):
                raise personal.PersonalError('Некорректный запрос.')
            if payload.get('op') not in ('catalog', 'create', 'manage', 'update'):
                raise personal.PersonalError('Неизвестное действие.')
            payload['ip'] = self._device()['ip']
            payload['hostname'] = urllib.parse.urlsplit('//' + self._req_host()).hostname or ''
            result = personal_operation(route, payload)
            self._respond(200, json.dumps(result, ensure_ascii=False), {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store'})
        except personal.PersonalError as e:
            self._respond(e.status, json.dumps({'ok': False, 'error': str(e)}, ensure_ascii=False), {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store'})
        except Exception:
            self._json(503, {'ok': False, 'error': 'Сервис временно недоступен. Попробуйте позже.'})

    def do_GET(self):
        raw_path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if raw_path == "/healthz":
            self._respond(200, b"ok")
            return
        route, slug = self._public_route()
        if not route:
            self._respond(404, b"not found")
            return
        d = self._device()
        output_format = subs.select_output_format(self.path, self.headers.get("User-Agent", ""), self.headers.get("Accept", ""))
        if route.get('access') == 'private' and 'text/html' in self.headers.get('Accept', '').lower():
            page = portal.render(route, portal_csrf(route, self._req_host()), os.environ.get('TURNSTILE_SITE_KEY', ''), slug)
            self._respond(200, page, {'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
            return
        if STORE.is_device_blocked(route["id"], d["hwid"], d["ip"]):
            body, headers = subs.build_blocked_response(output_format)
        elif route.get('access') == 'private' and not slug:
            settings = STORE.get_settings()
            base = graph.domain_public_base(graph.effective_domain(settings, route) or {})
            if not base:
                base = (settings.get('sub_public_base') or '').strip().rstrip('/')
            if not base:
                base = ('https' if self._is_https() else 'http') + '://' + self._req_host()
            subscription_url = base.rstrip('/') + route['path']
            message = personal.OPEN_MESSAGE + '\n\nСсылка подписки: ' + subscription_url
            body, headers = personal.notice('Откройте в браузере', message, output_format)
        elif STORE.get_settings().get('require_client_version', False) and d['ip'] not in personal.EXEMPT_IPS and not personal.has_version(self.headers):
            body, headers = personal.notice('Используйте другой VPN-клиент', personal.VERSION_MESSAGE, output_format)
        elif slug:
            try:
                result = personal_operation(route, {'op': 'fetch', 'slug': slug, 'device': d, 'format': output_format, 'claim': self.command != 'HEAD'})
                body, headers = base64.b64decode(result['body']), result['headers']
            except personal.PersonalError as e:
                body, headers = personal.notice('Личная подписка недоступна', str(e), output_format)
            except Exception:
                body, headers = personal.notice('Попробуйте позже', 'Сервис временно недоступен. Обновите подписку позже.', output_format)
        else:
            try:
                body, headers = subs.build_route_response(route, graph.resolve_links_spec(STORE, route), route.get('announce', ''), output_format=output_format)
            except Exception:
                self._respond(502, b'upstream temporarily unavailable')
                return
        if self.command != 'HEAD':
            try:
                STORE.record_device(route['id'], d['hwid'], d['model'], d['app'], d['ip'])
            except Exception:
                pass
        headers = {**headers, "Cache-Control": "no-store", "Vary": "Accept, User-Agent, X-App-Version, X-Hwid"}
        self._respond(200, body, headers)

    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        # Do not put personal bearer subscription URLs in application logs.
        print(f"[{self.log_date_time_string()}] SUB {self.command} {args[1] if len(args) > 1 else ''}")


class ClusterHandler(_Base):
    def _serve(self):
        path = self.path.split("?", 1)[0]
        body = self._read_body()
        if path == "/healthz":
            self._respond(200, b"ok")
            return
        self._serve_cluster_api(path, body)

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


def _start_gateway_boot():
    """В фоне (чтобы не блокировать старт веб-сервера/healthcheck скачиванием ~30МБ):
    при ZAPRET=true доустановить nfqws/xray, если их нет в образе (важно для сборок
    через Coolify/Nixpacks, где наш Dockerfile может не выполняться), затем поднять gateway."""
    def _run():
        try:
            if zapret.apply_enabled():
                provision.ensure_all(lambda m: print(m, flush=True))
            gateway.reconcile(STORE)
        except Exception as e:
            print(f"[gateway] boot: {e}", flush=True)
    threading.Thread(target=_run, daemon=True, name="gateway-boot").start()


def main():
    graph.migrate_config(STORE)
    seed_legacy_route()
    CLUSTER.start()
    _start_gateway_boot()

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
        # peer-API доступен и по 443 (admin-домен); конфиг с reg.ru-секретом
        # не должен лежать в открытом виде — требуем SECRET_KEY в проде.
        if os.environ.get("ALLOW_PLAINTEXT_SECRETS") == "1":
            print("[!] ВНИМАНИЕ: SECRET_KEY не задан/нет cryptography — секреты хранятся открыто "
                  "(разрешено ALLOW_PLAINTEXT_SECRETS=1).", flush=True)
        else:
            print("[FATAL] SECRET_KEY не задан или нет cryptography — секреты reg.ru хранились бы "
                  "открыто. Задай SECRET_KEY (или ALLOW_PLAINTEXT_SECRETS=1 для локального теста).", flush=True)
            raise SystemExit(1)

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
