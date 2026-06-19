#!/usr/bin/env python3
"""
sub_server.py — зеркало и агрегатор VPN-подписок с веб-панелью.

Что умеет:
  1. Зеркалить (проксировать) подписку, как раньше: ходит на upstream с
     заголовками клиента Happ, получает JSON-конфиг и отдаёт его как ВАШУ
     подписку вместе со всеми заголовками (Subscription-Userinfo,
     Profile-Title, Profile-Update-Interval и т.д.). Полная обратная
     совместимость со старым поведением через UPSTREAM_URL / SUB_PATH.

  2. СЛИВАТЬ несколько подписок в одну. В веб-панели можно создать «маршрут»
     (например /custom/custom), указать ему несколько upstream-ссылок и своё
     название — сервер сходит на каждую, вытащит все ноды (vless/vmess/
     trojan/ss/...), объединит их и отдаст одной подпиской (base64-список
     ссылок) с агрегированным счётчиком трафика. Название и путь меняются
     в панели.

  3. Веб-панель управления маршрутизированием с авторизацией (логин/пароль
     из переменных окружения ADMIN_USER / ADMIN_PASSWORD).

Зависимостей нет — только стандартная библиотека Python 3.8+ (certifi
подхватывается, если установлен). Конфиг маршрутов хранится в JSON-файле
(CONFIG_FILE) — пробросьте его как volume, чтобы настройки не терялись.

Запуск:
    python3 sub_server.py
Настройка — через переменные окружения (см. блок «Настройки» ниже).
"""

import os
import re
import ssl
import gzip
import json
import time
import hmac
import base64
import secrets
import threading
import urllib.request
import urllib.parse
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── Настройки (переопределяются переменными окружения) ────────────────────
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))

# Где хранить конфиг маршрутов (список объединённых подписок).
CONFIG_FILE = os.environ.get("CONFIG_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json"))

# Сколько секунд держать ответ upstream в кэше.
CACHE_TTL = int(os.environ.get("CACHE_TTL", "60"))
# Таймаут запроса к upstream, сек.
UPSTREAM_TIMEOUT = int(os.environ.get("UPSTREAM_TIMEOUT", "20"))

# ── Веб-панель ────────────────────────────────────────────────────────────
ADMIN_PATH = "/" + os.environ.get("ADMIN_PATH", "/admin").strip("/")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
SESSION_TTL = int(os.environ.get("SESSION_TTL", "86400"))  # 1 сутки

# ── Легаси-настройки одиночного зеркала (для обратной совместимости) ───────
# Если в конфиге ещё нет ни одного маршрута — создаётся маршрут из этих env.
LEGACY_UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "")
LEGACY_SUB_PATH = os.environ.get("SUB_PATH", "")
LEGACY_PROFILE_TITLE = os.environ.get("PROFILE_TITLE", "")

# Заголовки, которые отправляем на upstream — имитируем клиент Happ.
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

# Заголовки ответа upstream, которые пробрасываем клиенту в режиме «зеркало».
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

# Протоколы прокси-ссылок, которые умеем извлекать из подписок.
PROXY_LINK_RE = re.compile(
    r'((?:vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic)://[^\s"\'<>]+)',
    re.IGNORECASE,
)


# ── SSL-контекст для запроса к upstream ──────────────────────────────────
def build_ssl_context():
    """Контекст с проверкой сертификата, но без излишне строгой X.509-проверки."""
    if os.environ.get("INSECURE_TLS", "").lower() in ("1", "true", "yes"):
        return ssl._create_unverified_context()
    ctx = ssl.create_default_context()
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    try:
        import certifi
        ctx.load_verify_locations(certifi.where())
    except Exception:
        pass
    return ctx


_SSL_CTX = build_ssl_context()


# ── Конфиг маршрутов ──────────────────────────────────────────────────────
_config_lock = threading.Lock()
_config = {"routes": []}


def _normalize_path(path):
    """'/custom/custom/' → '/custom/custom'; '' / '/' остаются как есть."""
    p = "/" + (path or "").strip().strip("/")
    return p if p != "/" else "/"


def load_config():
    """Читает конфиг с диска (или создаёт пустой)."""
    global _config
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("routes"), list):
            _config = data
        else:
            _config = {"routes": []}
    except FileNotFoundError:
        _config = {"routes": []}
    except Exception as e:
        print(f"[!] Не удалось прочитать конфиг {CONFIG_FILE}: {e}. Старт с пустым.", flush=True)
        _config = {"routes": []}


def save_config():
    """
    Атомарно пишет конфиг на диск (вызывать под _config_lock).
    Если каталог недоступен для записи (напр. volume смонтирован root'ом, а
    процесс работает под непривилегированным пользователем) — НЕ роняем сервер:
    маршруты продолжают работать в памяти, а в лог пишем понятную подсказку.
    """
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE) or ".", exist_ok=True)
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_config, f, ensure_ascii=False, indent=2)
        os.replace(tmp, CONFIG_FILE)
        return True
    except OSError as e:
        print(
            f"[!] Не удалось сохранить конфиг в {CONFIG_FILE}: {e}\n"
            f"    Изменения действуют только до перезапуска. Проверь права на каталог "
            f"{os.path.dirname(CONFIG_FILE) or '.'} (он должен быть доступен на запись "
            f"пользователю контейнера uid=10001). Проще всего использовать именованный "
            f"docker-volume вместо bind-mount.",
            flush=True,
        )
        return False


def seed_legacy_route():
    """Если маршрутов нет, а заданы легаси-env — создаём зеркало из них."""
    with _config_lock:
        if _config["routes"]:
            return
        if LEGACY_UPSTREAM_URL and LEGACY_SUB_PATH:
            _config["routes"].append({
                "id": secrets.token_hex(8),
                "path": _normalize_path(LEGACY_SUB_PATH),
                "title": LEGACY_PROFILE_TITLE,
                "upstreams": [LEGACY_UPSTREAM_URL],
                "mode": "mirror",
                "enabled": True,
            })
            save_config()
            print(f"[*] Создан легаси-маршрут (зеркало) {LEGACY_SUB_PATH} → {LEGACY_UPSTREAM_URL}", flush=True)


def get_routes():
    with _config_lock:
        return list(_config["routes"])


def find_route(path):
    norm = _normalize_path(path)
    with _config_lock:
        for r in _config["routes"]:
            if r.get("enabled", True) and _normalize_path(r.get("path", "")) == norm:
                return dict(r)
    return None


def add_route(path, title, upstreams, mode):
    with _config_lock:
        _config["routes"].append({
            "id": secrets.token_hex(8),
            "path": _normalize_path(path),
            "title": title,
            "upstreams": upstreams,
            "mode": mode,
            "enabled": True,
        })
        save_config()


def update_route(route_id, **fields):
    with _config_lock:
        for r in _config["routes"]:
            if r.get("id") == route_id:
                if "path" in fields:
                    r["path"] = _normalize_path(fields["path"])
                if "title" in fields:
                    r["title"] = fields["title"]
                if "upstreams" in fields:
                    r["upstreams"] = fields["upstreams"]
                if "mode" in fields:
                    r["mode"] = fields["mode"]
                if "enabled" in fields:
                    r["enabled"] = bool(fields["enabled"])
                save_config()
                return True
    return False


def delete_route(route_id):
    with _config_lock:
        before = len(_config["routes"])
        _config["routes"] = [r for r in _config["routes"] if r.get("id") != route_id]
        changed = len(_config["routes"]) != before
        if changed:
            save_config()
    return changed


# ── Извлечение прокси-ссылок из ответа подписки ──────────────────────────
def _vless_from_outbound(outbound, remarks):
    """JSON-outbound (Happ/xray) → строка vless://."""
    try:
        vnext = outbound["settings"]["vnext"][0]
        address = vnext["address"]
        port = vnext["port"]
        user = vnext["users"][0]
        user_id = user["id"]
        flow = user.get("flow", "")

        stream = outbound.get("streamSettings", {})
        network = stream.get("network", "tcp")
        security = stream.get("security", "")

        reality = stream.get("realitySettings", {})
        pbk = reality.get("publicKey", "")
        fp = reality.get("fingerprint", "")
        sni = reality.get("serverName", "")
        sid = reality.get("shortId", "")

        tag = outbound.get("tag", "proxy")
        name = f"{remarks} ({tag})" if remarks else tag
        encoded_name = urllib.parse.quote(name.strip())

        params = {"type": network, "security": security}
        if pbk: params["pbk"] = pbk
        if fp: params["fp"] = fp
        if sni: params["sni"] = sni
        if sid: params["sid"] = sid
        if flow: params["flow"] = flow

        query = urllib.parse.urlencode(params)
        return f"vless://{user_id}@{address}:{port}?{query}#{encoded_name}"
    except Exception:
        return None


def _find_vless_outbounds(data, current_remarks=""):
    """Рекурсивно ищет vless-настройки в произвольном JSON."""
    found = []
    if isinstance(data, dict):
        if isinstance(data.get("remarks"), str):
            current_remarks = data["remarks"]
        if data.get("protocol") == "vless" and "settings" in data:
            found.append((data, current_remarks))
        else:
            for v in data.values():
                found.extend(_find_vless_outbounds(v, current_remarks))
    elif isinstance(data, list):
        for item in data:
            found.extend(_find_vless_outbounds(item, current_remarks))
    return found


def extract_links(body_bytes):
    """
    Универсально достаёт список прокси-ссылок из тела подписки.
    Поддерживает: JSON-конфиг Happ/xray, base64-список, обычный текст.
    """
    text = body_bytes.decode("utf-8", errors="ignore").strip()
    if not text:
        return []

    # 1) JSON-конфиг (формат Happ/xray).
    try:
        data = json.loads(text)
        links = []
        for ob, rem in _find_vless_outbounds(data):
            link = _vless_from_outbound(ob, rem)
            if link:
                links.append(link)
        if links:
            return links
    except (json.JSONDecodeError, ValueError):
        pass

    # 2) Возможно, всё тело — base64-список ссылок.
    candidate = text
    if "://" not in candidate:
        try:
            padded = candidate + "=" * (-len(candidate) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
            if "://" in decoded:
                candidate = decoded
        except Exception:
            pass

    # 3) Вытаскиваем все ссылки по протоколам.
    links = PROXY_LINK_RE.findall(candidate)
    return links


# ── Агрегация Subscription-Userinfo ──────────────────────────────────────
def _parse_userinfo(value):
    """'upload=1; download=2; total=3; expire=4' → dict чисел."""
    out = {}
    for part in (value or "").split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            try:
                out[k.strip()] = int(v.strip())
            except ValueError:
                pass
    return out


def _aggregate_userinfo(infos):
    """Суммирует трафик/лимит, берёт ближайший срок истечения."""
    upload = download = total = 0
    expires = []
    for info in infos:
        upload += info.get("upload", 0)
        download += info.get("download", 0)
        total += info.get("total", 0)
        exp = info.get("expire", 0)
        if exp:
            expires.append(exp)
    parts = [f"upload={upload}", f"download={download}", f"total={total}"]
    if expires:
        parts.append(f"expire={min(expires)}")
    return "; ".join(parts)


# ── Кэш ответов upstream ─────────────────────────────────────────────────
_cache_lock = threading.Lock()
_cache = {}  # url -> {"ts": float, "body": bytes, "headers": dict}


def fetch_upstream(url):
    """Идёт на upstream-подписку. Возвращает (body_bytes, headers_dict)."""
    req = urllib.request.Request(url, headers=UPSTREAM_HEADERS)
    with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT, context=_SSL_CTX) as resp:
        raw = resp.read()
        if "gzip" in resp.headers.get("Content-Encoding", "").lower():
            raw = gzip.decompress(raw)
        headers = {}
        for name in PASS_THROUGH_HEADERS:
            val = resp.headers.get(name)
            if val is not None:
                headers[name] = val
        headers.setdefault("Content-Type", "application/json; charset=utf-8")
        return raw, headers


def fetch_upstream_cached(url):
    """fetch_upstream с кэшем на CACHE_TTL секунд (по каждому url)."""
    now = time.time()
    with _cache_lock:
        entry = _cache.get(url)
        if entry and (now - entry["ts"]) < CACHE_TTL:
            return entry["body"], entry["headers"]
    body, headers = fetch_upstream(url)
    with _cache_lock:
        _cache[url] = {"ts": time.time(), "body": body, "headers": headers}
    return body, headers


def _profile_title_header(title):
    encoded = base64.b64encode(title.encode("utf-8")).decode("ascii")
    return "base64:" + encoded


def build_mirror_response(route):
    """Режим «зеркало»: один upstream, отдаём его JSON как есть."""
    url = route["upstreams"][0]
    body, headers = fetch_upstream_cached(url)
    headers = dict(headers)
    if route.get("title"):
        headers["Profile-Title"] = _profile_title_header(route["title"])
    return body, headers


def build_merged_response(route):
    """Режим «слияние»: несколько upstream → один base64-список ссылок."""
    all_links = []
    seen = set()
    infos = []
    for url in route["upstreams"]:
        try:
            body, headers = fetch_upstream_cached(url)
        except Exception as e:
            print(f"[-] upstream {url} недоступен: {e}", flush=True)
            continue
        for link in extract_links(body):
            if link not in seen:
                seen.add(link)
                all_links.append(link)
        ui = headers.get("Subscription-Userinfo")
        if ui:
            infos.append(_parse_userinfo(ui))

    payload = base64.b64encode(("\n".join(all_links)).encode("utf-8")).decode("ascii")
    out_headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Profile-Update-Interval": "12",
    }
    if route.get("title"):
        out_headers["Profile-Title"] = _profile_title_header(route["title"])
    if infos:
        out_headers["Subscription-Userinfo"] = _aggregate_userinfo(infos)
    return payload.encode("ascii"), out_headers


def build_route_response(route):
    mode = route.get("mode", "merge")
    if mode == "mirror" and len(route.get("upstreams", [])) == 1:
        return build_mirror_response(route)
    return build_merged_response(route)


# ── Сессии веб-панели ─────────────────────────────────────────────────────
_sessions_lock = threading.Lock()
_sessions = {}  # token -> {"exp": float, "csrf": str}


def create_session():
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    with _sessions_lock:
        _sessions[token] = {"exp": time.time() + SESSION_TTL, "csrf": csrf}
    return token, csrf


def get_session(token):
    if not token:
        return None
    now = time.time()
    with _sessions_lock:
        s = _sessions.get(token)
        if not s:
            return None
        if s["exp"] < now:
            _sessions.pop(token, None)
            return None
        return dict(s)


def drop_session(token):
    with _sessions_lock:
        _sessions.pop(token, None)


def check_credentials(user, password):
    if not ADMIN_PASSWORD:
        return False
    ok_user = hmac.compare_digest(user or "", ADMIN_USER)
    ok_pass = hmac.compare_digest(password or "", ADMIN_PASSWORD)
    return ok_user and ok_pass


# ── HTML веб-панели ───────────────────────────────────────────────────────
def esc(s):
    return (str(s)
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


PAGE_CSS = """
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
       background:#0f1115; color:#e6e6e6; margin:0; padding:0; }
.wrap { max-width: 860px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { font-size: 22px; margin: 0 0 4px; }
.sub { color:#8a93a2; font-size: 13px; margin-bottom: 24px; }
a { color:#6ea8fe; }
.card { background:#171a21; border:1px solid #232833; border-radius:12px;
        padding:18px; margin-bottom:16px; }
.route-head { display:flex; justify-content:space-between; align-items:center; gap:12px; }
.route-title { font-size:16px; font-weight:600; }
.path { font-family: ui-monospace, Menlo, Consolas, monospace; color:#7ee787; font-size:13px; }
label { display:block; font-size:12px; color:#8a93a2; margin:10px 0 4px; }
input, textarea, select { width:100%; background:#0f1115; border:1px solid #2b313d;
        color:#e6e6e6; border-radius:8px; padding:9px 10px; font-size:14px; font-family:inherit; }
textarea { min-height:84px; resize:vertical; font-family: ui-monospace, Menlo, Consolas, monospace; }
.btn { display:inline-block; border:0; border-radius:8px; padding:9px 14px; font-size:14px;
       cursor:pointer; background:#2f6feb; color:#fff; text-decoration:none; }
.btn.gray { background:#2b313d; }
.btn.red { background:#b62324; }
.btn.small { padding:6px 10px; font-size:13px; }
.row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
.muted { color:#8a93a2; font-size:12px; }
.tag { font-size:11px; padding:2px 8px; border-radius:999px; background:#22272f; color:#8a93a2; }
.tag.on { background:#16321f; color:#7ee787; }
.tag.off { background:#3a1d1d; color:#ff8585; }
.flash { background:#16321f; border:1px solid #25502f; color:#9fe6ad;
         padding:10px 12px; border-radius:8px; margin-bottom:16px; font-size:14px; }
.flash.err { background:#3a1d1d; border-color:#5a2a2a; color:#ffb0b0; }
hr { border:0; border-top:1px solid #232833; margin:16px 0; }
.login-box { max-width:360px; margin:80px auto; }
form.inline { display:inline; }
.upstreams { font-family: ui-monospace, Menlo, Consolas, monospace; font-size:12px;
             color:#9aa4b2; white-space:pre-wrap; word-break:break-all; }
"""


def render_login(error=""):
    err = f'<div class="flash err">{esc(error)}</div>' if error else ""
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Вход — Sub Mirror</title><style>{PAGE_CSS}</style></head>
<body><div class="wrap"><div class="card login-box">
<h1>Панель подписок</h1><div class="sub">Войдите для управления маршрутами</div>
{err}
<form method="post" action="{esc(ADMIN_PATH)}/login">
<label>Логин</label><input name="user" autocomplete="username" autofocus>
<label>Пароль</label><input name="password" type="password" autocomplete="current-password">
<div style="margin-top:16px"><button class="btn" type="submit">Войти</button></div>
</form></div></div></body></html>"""


def render_route_card(route, public_base):
    rid = esc(route.get("id", ""))
    path = esc(_normalize_path(route.get("path", "")))
    title = esc(route.get("title", ""))
    mode = route.get("mode", "merge")
    enabled = route.get("enabled", True)
    upstreams = route.get("upstreams", [])
    ups_text = esc("\n".join(upstreams))
    full_url = esc(public_base.rstrip("/") + _normalize_path(route.get("path", "")))
    state = '<span class="tag on">включён</span>' if enabled else '<span class="tag off">выключен</span>'
    mode_label = "слияние" if mode != "mirror" else "зеркало"
    return f"""
<div class="card">
  <div class="route-head">
    <div>
      <div class="route-title">{title or '(без названия)'} {state}
        <span class="tag">{esc(mode_label)}</span></div>
      <div class="path">{path}</div>
    </div>
  </div>
  <div class="muted" style="margin-top:6px">Публичная ссылка: <span class="path">{full_url}</span></div>
  <details style="margin-top:10px"><summary class="muted" style="cursor:pointer">Редактировать ({len(upstreams)} upstream)</summary>
  <form method="post" action="{esc(ADMIN_PATH)}/routes/{rid}/update">
    <label>Название (как видно в клиенте)</label>
    <input name="title" value="{title}">
    <label>Путь подписки</label>
    <input name="path" value="{path}">
    <label>Режим</label>
    <select name="mode">
      <option value="merge"{' selected' if mode != 'mirror' else ''}>Слияние (несколько ссылок → одна, base64-список)</option>
      <option value="mirror"{' selected' if mode == 'mirror' else ''}>Зеркало (один upstream, отдаётся как есть)</option>
    </select>
    <label>Upstream-ссылки (по одной в строке)</label>
    <textarea name="upstreams">{ups_text}</textarea>
    <label class="row" style="margin-top:10px"><input type="checkbox" name="enabled" value="1" style="width:auto"{' checked' if enabled else ''}> <span>Включён</span></label>
    <div class="row" style="margin-top:12px">
      <button class="btn small" type="submit">Сохранить</button>
    </div>
  </form>
  <form class="inline" method="post" action="{esc(ADMIN_PATH)}/routes/{rid}/delete"
        onsubmit="return confirm('Удалить маршрут {path}?')">
    <div style="margin-top:8px"><button class="btn small red" type="submit">Удалить</button></div>
  </form>
  </details>
</div>"""


def render_admin(routes, public_base, flash="", flash_err=False):
    cards = "".join(render_route_card(r, public_base) for r in routes) or \
        '<div class="card muted">Маршрутов пока нет. Создайте первый ниже.</div>'
    flash_html = ""
    if flash:
        cls = "flash err" if flash_err else "flash"
        flash_html = f'<div class="{cls}">{esc(flash)}</div>'
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Маршруты — Sub Mirror</title><style>{PAGE_CSS}</style></head>
<body><div class="wrap">
<div class="route-head">
  <div><h1>Маршрутизирование подписок</h1>
  <div class="sub">Слияние нескольких подписок в одну, переименование, свои пути</div></div>
  <form class="inline" method="post" action="{esc(ADMIN_PATH)}/logout">
    <button class="btn gray small" type="submit">Выйти</button></form>
</div>
{flash_html}
{cards}
<hr>
<div class="card">
  <div class="route-title">Новый маршрут</div>
  <form method="post" action="{esc(ADMIN_PATH)}/routes/create">
    <label>Название</label>
    <input name="title" placeholder="Моя сборная подписка">
    <label>Путь подписки (например /custom/custom)</label>
    <input name="path" placeholder="/custom/custom" required>
    <label>Режим</label>
    <select name="mode">
      <option value="merge">Слияние (несколько ссылок → одна)</option>
      <option value="mirror">Зеркало (один upstream как есть)</option>
    </select>
    <label>Upstream-ссылки (по одной в строке)</label>
    <textarea name="upstreams" placeholder="https://server.example.net:2096/sub/xxxx&#10;https://203.0.113.10:2096/sub/xxxx"></textarea>
    <div style="margin-top:12px"><button class="btn" type="submit">Создать</button></div>
  </form>
</div>
</div></body></html>"""


# ── HTTP-обработчик ───────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "subproxy/2.0"
    protocol_version = "HTTP/1.1"

    # ---- утилиты ----
    def _client_ip(self):
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.headers.get("X-Real-IP") or self.client_address[0]

    def _is_https(self):
        return self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def _public_base(self):
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or f"{LISTEN_HOST}:{LISTEN_PORT}"
        scheme = "https" if self._is_https() else "http"
        return f"{scheme}://{host}"

    def _log_device(self):
        ip = self._client_ip()
        hwid = self.headers.get("X-Hwid", "-")
        model = self.headers.get("X-Device-Model", "-")
        os_name = self.headers.get("X-Device-Os", "-")
        app_ver = self.headers.get("X-App-Version", "-")
        ua = self.headers.get("User-Agent", "-")
        print(
            f"[{self.log_date_time_string()}] DEVICE ip={ip} hwid={hwid} "
            f"model={model} os={os_name} app={app_ver} ua=\"{ua}\"",
            flush=True,
        )

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

    def _redirect(self, location, cookies=None):
        self.send_response(302)
        self.send_header("Location", location)
        for c in (cookies or []):
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _cookies(self):
        out = {}
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def _session_cookie(self, token):
        flags = "HttpOnly; SameSite=Lax; Path=/"
        if self._is_https():
            flags += "; Secure"
        return f"session={token}; {flags}; Max-Age={SESSION_TTL}"

    def _current_session(self):
        return get_session(self._cookies().get("session"))

    def _read_form(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8", errors="ignore") if length else ""
        return urllib.parse.parse_qs(raw, keep_blank_values=True)

    # ---- GET ----
    def do_GET(self):
        norm = _normalize_path(self.path.split("?", 1)[0]) if self.path != "/" else "/"
        raw_path = self.path.split("?", 1)[0].rstrip("/") or "/"

        if raw_path == "/healthz":
            self._respond(200, b"ok")
            return

        # Веб-панель
        if raw_path == ADMIN_PATH or raw_path == ADMIN_PATH + "/login":
            if raw_path == ADMIN_PATH and self._current_session():
                self._respond(200, render_admin(get_routes(), self._public_base()),
                              {"Content-Type": "text/html; charset=utf-8"})
            else:
                self._respond(200, render_login(),
                              {"Content-Type": "text/html; charset=utf-8"})
            return

        # Подписка по маршруту
        route = find_route(raw_path)
        if route:
            self._log_device()
            try:
                body, up_headers = build_route_response(route)
            except urllib.error.HTTPError as e:
                self._respond(502, f"upstream HTTP {e.code}".encode())
            except Exception as e:
                self._respond(502, f"upstream error: {e}".encode())
            else:
                self._respond(200, body, up_headers)
            return

        self._respond(404, b"not found")

    do_HEAD = do_GET

    # ---- POST (только веб-панель) ----
    def do_POST(self):
        raw_path = self.path.split("?", 1)[0].rstrip("/") or "/"

        if raw_path == ADMIN_PATH + "/login":
            form = self._read_form()
            user = form.get("user", [""])[0]
            password = form.get("password", [""])[0]
            if check_credentials(user, password):
                token, _ = create_session()
                self._redirect(ADMIN_PATH, [self._session_cookie(token)])
            else:
                self._respond(401, render_login("Неверный логин или пароль"),
                              {"Content-Type": "text/html; charset=utf-8"})
            return

        # всё остальное требует авторизации
        if not self._current_session():
            self._redirect(ADMIN_PATH)
            return

        if raw_path == ADMIN_PATH + "/logout":
            drop_session(self._cookies().get("session"))
            self._redirect(ADMIN_PATH, ["session=; Path=/; Max-Age=0"])
            return

        if raw_path == ADMIN_PATH + "/routes/create":
            form = self._read_form()
            path = form.get("path", [""])[0].strip()
            title = form.get("title", [""])[0].strip()
            mode = form.get("mode", ["merge"])[0].strip()
            upstreams = [u.strip() for u in form.get("upstreams", [""])[0].splitlines() if u.strip()]
            err = self._validate_route(path)
            if err:
                self._respond(400, render_admin(get_routes(), self._public_base(), err, True),
                              {"Content-Type": "text/html; charset=utf-8"})
                return
            add_route(path, title, upstreams, mode)
            self._redirect(ADMIN_PATH)
            return

        m = re.match(r"^" + re.escape(ADMIN_PATH) + r"/routes/([a-f0-9]+)/(update|delete)$", raw_path)
        if m:
            rid, action = m.group(1), m.group(2)
            if action == "delete":
                delete_route(rid)
                self._redirect(ADMIN_PATH)
                return
            form = self._read_form()
            path = form.get("path", [""])[0].strip()
            err = self._validate_route(path, ignore_id=rid)
            if err:
                self._respond(400, render_admin(get_routes(), self._public_base(), err, True),
                              {"Content-Type": "text/html; charset=utf-8"})
                return
            update_route(
                rid,
                path=path,
                title=form.get("title", [""])[0].strip(),
                mode=form.get("mode", ["merge"])[0].strip(),
                upstreams=[u.strip() for u in form.get("upstreams", [""])[0].splitlines() if u.strip()],
                enabled=("enabled" in form),
            )
            self._redirect(ADMIN_PATH)
            return

        self._respond(404, b"not found")

    def _validate_route(self, path, ignore_id=None):
        """Проверяет, что путь корректный и не конфликтует с панелью/маршрутами."""
        if not path:
            return "Путь не может быть пустым"
        norm = _normalize_path(path)
        if norm == "/":
            return "Путь не может быть просто '/'"
        if norm == ADMIN_PATH or norm.startswith(ADMIN_PATH + "/") or norm == "/healthz":
            return f"Путь {norm} зарезервирован системой"
        for r in get_routes():
            if r.get("id") != ignore_id and _normalize_path(r.get("path", "")) == norm:
                return f"Путь {norm} уже занят другим маршрутом"
        return ""

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")


def main():
    load_config()
    seed_legacy_route()

    if ADMIN_PASSWORD == "admin" or not ADMIN_PASSWORD:
        print("[!] ВНИМАНИE: пароль панели не задан (используется 'admin'/'admin'). "
              "Установите ADMIN_USER и ADMIN_PASSWORD!", flush=True)

    httpd = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"[*] Сервер запущен на http://{LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    print(f"[*] Веб-панель: {ADMIN_PATH}  (логин: {ADMIN_USER})", flush=True)
    print(f"[*] Конфиг маршрутов: {CONFIG_FILE}", flush=True)
    print(f"[*] Маршрутов загружено: {len(get_routes())}. Кэш upstream: {CACHE_TTL} сек.", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Остановлено.", flush=True)
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
