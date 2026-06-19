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
    _migrate_loaded()


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
            sync_graph_from_routes()
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
        sync_graph_from_routes()
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
                sync_graph_from_routes()
                save_config()
                return True
    return False


def delete_route(route_id):
    with _config_lock:
        before = len(_config["routes"])
        _config["routes"] = [r for r in _config["routes"] if r.get("id") != route_id]
        changed = len(_config["routes"]) != before
        if changed:
            sync_graph_from_routes()
            save_config()
    return changed


# ── Граф (нодовый редактор) ───────────────────────────────────────────────
# Модель графа: sources (узлы-подписки), routes (узлы-выходы), edges (связи).
# routes[].upstreams остаётся «истиной» для отдачи подписок и пересчитывается
# из графа при сохранении из редактора; обратно — классические формы правят
# upstreams, а граф пересобирается под них (с сохранением координат по URL/id).
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _new_id():
    return secrets.token_hex(8)


def _parse_upstreams(text):
    """Строки textarea → список upstream-ссылок без пустых и дублей (порядок сохранён)."""
    seen = set()
    out = []
    for line in (text or "").splitlines():
        u = line.strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _ensure_graph_keys():
    _config.setdefault("routes", [])
    _config.setdefault("sources", [])
    _config.setdefault("edges", [])


def _autolayout():
    """Назначает координаты узлам, у которых их ещё нет."""
    sy = 60
    for s in _config["sources"]:
        if not isinstance(s.get("x"), (int, float)):
            s["x"] = 80
        if not isinstance(s.get("y"), (int, float)):
            s["y"] = sy
            sy += 130
    ry = 60
    for r in _config["routes"]:
        if not isinstance(r.get("x"), (int, float)):
            r["x"] = 520
        if not isinstance(r.get("y"), (int, float)):
            r["y"] = ry
            ry += 200


def sync_graph_from_routes():
    """Перестраивает sources+edges из routes[].upstreams (вызывать под локом).
    Координаты/id источников сохраняются по совпадению URL."""
    _ensure_graph_keys()
    old_by_url = {}
    for s in _config.get("sources", []):
        if s.get("url"):
            old_by_url.setdefault(s["url"], s)
    sources = []
    edges = []
    by_url = {}
    for route in _config["routes"]:
        rid = route.get("id")
        if not rid:
            rid = route["id"] = _new_id()
        for url in route.get("upstreams", []):
            node = by_url.get(url)
            if node is None:
                old = old_by_url.get(url)
                node = {
                    "id": (old or {}).get("id") or _new_id(),
                    "url": url,
                    "label": (old or {}).get("label", ""),
                    "x": (old or {}).get("x"),
                    "y": (old or {}).get("y"),
                }
                sources.append(node)
                by_url[url] = node
            edges.append({"from": node["id"], "to": rid})
    _config["sources"] = sources
    _config["edges"] = edges
    _autolayout()


def recompute_upstreams_from_graph():
    """routes[].upstreams := url-ы соединённых источников (вызывать под локом)."""
    _ensure_graph_keys()
    url_by_id = {s.get("id"): (s.get("url") or "") for s in _config["sources"] if s.get("id")}
    incoming = {}
    for e in _config["edges"]:
        incoming.setdefault(e.get("to"), []).append(e.get("from"))
    for route in _config["routes"]:
        rid = route.get("id")
        if not rid:
            rid = route["id"] = _new_id()
        ups = []
        for sid in incoming.get(rid, []):
            url = (url_by_id.get(sid) or "").strip()
            if url and url not in ups:
                ups.append(url)
        route["upstreams"] = ups


def _migrate_loaded():
    """После загрузки конфига приводим граф и upstreams к согласованному виду.
    Любая ошибка миграции (например, повреждённый вручную config.json) не должна
    ронять сервер — логируем и работаем с тем, что есть."""
    with _config_lock:
        try:
            had_graph = isinstance(_config.get("sources"), list) and isinstance(_config.get("edges"), list)
            _ensure_graph_keys()
            if had_graph:
                recompute_upstreams_from_graph()
            else:
                sync_graph_from_routes()
            _autolayout()
        except Exception as e:
            print(f"[!] Ошибка миграции конфига: {e}. Работаем с текущим состоянием.", flush=True)


def get_graph():
    with _config_lock:
        return {
            "sources": [dict(s) for s in _config.get("sources", [])],
            "routes": [dict(r) for r in _config.get("routes", [])],
            "edges": [dict(e) for e in _config.get("edges", [])],
        }


def _num(v, default=0.0):
    try:
        f = float(v)
        return f if f == f and f not in (float("inf"), float("-inf")) else default
    except (TypeError, ValueError):
        return default


def save_graph(data):
    """Принимает граф из редактора, валидирует и сохраняет. → (ok, errors)."""
    if not isinstance(data, dict):
        return False, ["Некорректные данные"]
    raw_sources = data.get("sources")
    raw_routes = data.get("routes")
    raw_edges = data.get("edges")
    if not all(isinstance(x, list) for x in (raw_sources, raw_routes, raw_edges)):
        return False, ["Некорректная структура графа"]
    if len(raw_sources) > 500 or len(raw_routes) > 500 or len(raw_edges) > 5000:
        return False, ["Слишком много узлов/связей"]

    errors = []
    # Если узлу выдаётся новый id (битый/дублирующийся), запоминаем старый→новый,
    # чтобы переназначить концы рёбер и не потерять связи.
    id_map = {}

    sources = []
    src_ids = set()
    for s in raw_sources:
        if not isinstance(s, dict):
            continue
        orig = str(s.get("id") or "")
        sid = orig
        if not _ID_RE.match(sid):
            # битый id: оригинала ни у кого нет — рёбра к нему переназначаем.
            sid = _new_id()
            if orig:
                id_map[orig] = sid
        elif sid in src_ids:
            # дубль валидного id: оригинал остаётся за первым узлом,
            # поэтому рёбра к orig должны указывать на него — НЕ переназначаем.
            sid = _new_id()
        src_ids.add(sid)
        sources.append({
            "id": sid,
            "url": str(s.get("url") or "").strip()[:2048],
            "label": str(s.get("label") or "").strip()[:120],
            "x": _num(s.get("x"), 80.0),
            "y": _num(s.get("y"), 80.0),
        })

    routes = []
    route_ids = set()
    used_paths = set()
    for r in raw_routes:
        if not isinstance(r, dict):
            continue
        orig = str(r.get("id") or "")
        rid = orig
        if not _ID_RE.match(rid):
            rid = _new_id()
            if orig:
                id_map[orig] = rid
        elif rid in route_ids:
            rid = _new_id()
        route_ids.add(rid)
        raw_path = str(r.get("path") or "").strip()
        path = _normalize_path(raw_path)
        title = str(r.get("title") or "").strip()[:200]
        mode = "mirror" if str(r.get("mode") or "") == "mirror" else "merge"
        enabled = bool(r.get("enabled", True))
        label = title or rid
        if not raw_path or path == "/":
            errors.append(f"Маршрут «{label}»: путь не задан")
        elif path == ADMIN_PATH or path.startswith(ADMIN_PATH + "/") or path == "/healthz":
            errors.append(f"Путь {path} зарезервирован системой")
        elif path in used_paths:
            errors.append(f"Путь {path} используется несколькими маршрутами")
        else:
            used_paths.add(path)
        routes.append({
            "id": rid, "path": path, "title": title, "mode": mode,
            "enabled": enabled, "upstreams": [],
            "x": _num(r.get("x"), 520.0), "y": _num(r.get("y"), 80.0),
        })

    if errors:
        return False, errors

    edges = []
    seen_edge = set()
    for e in raw_edges:
        if not isinstance(e, dict):
            continue
        fr = str(e.get("from") or "")
        to = str(e.get("to") or "")
        fr = id_map.get(fr, fr)
        to = id_map.get(to, to)
        key = (fr, to)
        if fr in src_ids and to in route_ids and key not in seen_edge:
            seen_edge.add(key)
            edges.append({"from": fr, "to": to})

    with _config_lock:
        _config["sources"] = sources
        _config["routes"] = routes
        _config["edges"] = edges
        recompute_upstreams_from_graph()
        save_config()
    return True, []


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
        onsubmit="return confirm('Удалить этот маршрут?')">
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


# ── Нодовый редактор (Blender-подобный граф) ──────────────────────────────
def js_embed(obj):
    """Безопасно встраивает Python-объект в <script> как JS-литерал."""
    s = json.dumps(obj, ensure_ascii=False)
    bs = chr(92)  # обратный слэш, чтобы не путаться с экранированием
    s = s.replace("<", bs + "u003c").replace(">", bs + "u003e").replace("&", bs + "u0026")
    # U+2028/U+2029 валидны в JSON, но ломают JS-строку; экранируем их.
    s = s.replace(chr(0x2028), bs + "u2028").replace(chr(0x2029), bs + "u2029")
    return s


EDITOR_CSS = """
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:#1b1b1d;color:#e6e6e6;
  font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;overflow:hidden}
#top{position:fixed;top:0;left:0;right:0;height:50px;display:flex;align-items:center;gap:8px;
  padding:0 12px;background:#2b2b2e;border-bottom:1px solid #111;z-index:50}
#top .title{font-weight:600;font-size:14px;margin-right:6px;white-space:nowrap}
#top .spacer{flex:1}
.btn{border:0;border-radius:6px;padding:8px 12px;font-size:13px;cursor:pointer;background:#3b6fd4;
  color:#fff;text-decoration:none;display:inline-block;white-space:nowrap}
.btn.gray{background:#3a3a3e}
.btn.ghost{background:transparent;border:1px solid #4a4a50;color:#ddd}
.btn:hover{filter:brightness(1.12)}
#editor{position:fixed;top:50px;left:0;right:0;bottom:0;overflow:hidden;background:#1b1b1d;
  background-image:radial-gradient(#303033 1px,transparent 1px);background-size:24px 24px;cursor:grab}
#editor.panning{cursor:grabbing}
#world{position:absolute;left:0;top:0;transform-origin:0 0}
#wires{position:absolute;left:0;top:0;width:100%;height:100%;pointer-events:none;z-index:1;overflow:visible}
#wires path.wire{fill:none;stroke:#9a9aa2;stroke-width:2.5;pointer-events:stroke;cursor:pointer}
#wires path.wire:hover{stroke:#ff5b5b;stroke-width:3.5}
#wires path.temp{fill:none;stroke:#f5a623;stroke-width:2.5;stroke-dasharray:6 4;pointer-events:none}
.node{position:absolute;width:240px;background:#2c2c30;border:1px solid #141416;border-radius:9px;
  box-shadow:0 8px 22px rgba(0,0,0,.5);z-index:2}
.node.sel{outline:2px solid #5b9dff;outline-offset:1px}
.node .hd{height:34px;display:flex;align-items:center;justify-content:space-between;padding:0 10px;
  border-radius:8px 8px 0 0;cursor:grab;font-size:13px;font-weight:600;color:#fff;
  user-select:none;-webkit-user-select:none}
.node.src .hd{background:linear-gradient(180deg,#35817a,#2c6f6a)}
.node.route .hd{background:linear-gradient(180deg,#c47d31,#b06f28)}
.node .hd .x{cursor:pointer;opacity:.85;font-size:15px;line-height:1;padding:2px 5px;border-radius:4px}
.node .hd .x:hover{opacity:1;background:rgba(0,0,0,.25)}
.node .bd{padding:10px 11px 12px}
.node label{display:block;font-size:11px;color:#9a9aa2;margin:7px 0 3px}
.node input,.node select{width:100%;background:#202023;border:1px solid #3a3a40;color:#e6e6e6;
  border-radius:5px;padding:6px 7px;font-size:12px;font-family:inherit}
.node input:focus,.node select:focus{outline:none;border-color:#5b9dff}
.node input.mono{font-family:ui-monospace,Consolas,monospace}
.sock{position:absolute;width:15px;height:15px;border-radius:50%;border:2px solid #141416;top:21px;
  cursor:crosshair;z-index:3}
.sock.out{right:-8px;background:#7ee0c8}
.sock.in{left:-8px;background:#ffce8a}
.sock:hover{filter:brightness(1.25)}
.pub{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:#7ee787;word-break:break-all;margin-top:9px}
.pub .copy{cursor:pointer;color:#6ea8fe;margin-left:6px;white-space:nowrap}
.cnt{font-size:11px;color:#9a9aa2;margin-top:7px}
.chk{display:flex;align-items:center;gap:6px;margin-top:9px;font-size:12px;color:#cfcfd6;cursor:pointer}
.chk input{width:auto}
#hint{position:absolute;left:50%;top:42%;transform:translate(-50%,-50%);color:#6a6a72;font-size:14px;
  text-align:center;pointer-events:none;line-height:1.6}
#toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:#2c2c30;
  border:1px solid #444;padding:11px 18px;border-radius:9px;z-index:100;display:none;font-size:13px;max-width:80%}
#toast.err{border-color:#7a2a2a;background:#3a1d1d;color:#ffb0b0}
#toast.ok{border-color:#2a5a34;background:#16321f;color:#9fe6ad}
"""


EDITOR_JS = r"""
(function(){
  const G = window.__GRAPH__ || {sources:[],routes:[],edges:[]};
  const ADMIN = window.__ADMIN__ || '/admin';
  const CSRF = window.__CSRF__ || '';
  const BASE = window.__BASE__ || '';
  G.sources = G.sources || []; G.routes = G.routes || []; G.edges = G.edges || [];

  const NODE_W = 240, SOCK_Y = 28;
  const editor = document.getElementById('editor');
  const world = document.getElementById('world');
  const svg = document.getElementById('wires');
  const toast = document.getElementById('toast');
  const hint = document.getElementById('hint');
  const nodeEls = {};
  let view = {panX:60, panY:60, zoom:1};
  let connecting = null, tempPath = null, hoverIn = null;

  function genId(){ try{ const a=new Uint8Array(8); crypto.getRandomValues(a); return Array.from(a,b=>b.toString(16).padStart(2,'0')).join(''); }catch(e){ let s=''; for(let i=0;i<16;i++) s+=Math.floor(Math.random()*16).toString(16); return s; } }
  function num(v,d){ v=parseFloat(v); return isFinite(v)?v:d; }
  function rect(){ return editor.getBoundingClientRect(); }
  function el(tag,cls,txt){ const e=document.createElement(tag); if(cls)e.className=cls; if(txt!=null)e.textContent=txt; return e; }
  function normPath(p){ p=(p||'').trim().replace(/^\/+|\/+$/g,''); return p?('/'+p):'/'; }

  // auto-position nodes missing coords
  let sy=60; G.sources.forEach(s=>{ s.x=num(s.x,80); if(!isFinite(parseFloat(s.y))){ s.y=sy; sy+=130; } else { s.y=num(s.y,sy); } });
  let ry=60; G.routes.forEach(r=>{ r.x=num(r.x,520); if(!isFinite(parseFloat(r.y))){ r.y=ry; ry+=200; } else { r.y=num(r.y,ry); } });

  function applyTransform(){ world.style.transform='translate('+view.panX+'px,'+view.panY+'px) scale('+view.zoom+')'; }
  function w2s(p){ return {x:p.x*view.zoom+view.panX, y:p.y*view.zoom+view.panY}; }
  function sockPos(n,kind){ return kind==='out' ? {x:n.x+NODE_W, y:n.y+SOCK_Y} : {x:n.x, y:n.y+SOCK_Y}; }
  function isSource(n){ return G.sources.indexOf(n)>=0; }
  function curve(a,b){ const dx=Math.max(40,Math.abs(b.x-a.x)*0.5); return 'M '+a.x+' '+a.y+' C '+(a.x+dx)+' '+a.y+' '+(b.x-dx)+' '+b.y+' '+b.x+' '+b.y; }

  function redrawWires(){
    while(svg.firstChild) svg.removeChild(svg.firstChild);
    G.edges.forEach(e=>{
      const s=G.sources.find(x=>x.id===e.from), r=G.routes.find(x=>x.id===e.to);
      if(!s||!r) return;
      const a=w2s(sockPos(s,'out')), b=w2s(sockPos(r,'in'));
      const p=document.createElementNS('http://www.w3.org/2000/svg','path');
      p.setAttribute('d',curve(a,b)); p.setAttribute('class','wire');
      p.addEventListener('click',ev=>{ ev.stopPropagation(); const i=G.edges.indexOf(e); if(i>=0)G.edges.splice(i,1); redrawWires(); refreshCounts(); });
      svg.appendChild(p);
    });
    if(connecting && tempPath) svg.appendChild(tempPath);
    hint.style.display=(G.sources.length||G.routes.length)?'none':'block';
  }

  function refreshCounts(){
    document.querySelectorAll('.cnt').forEach(c=>{ const rid=c.dataset.rid; c.textContent='источников подключено: '+G.edges.filter(e=>e.to===rid).length; });
  }

  function dragHeader(handle,node,nEl){
    handle.addEventListener('mousedown',ev=>{
      if(ev.target.classList.contains('x')) return;
      ev.stopPropagation(); ev.preventDefault();
      let lx=ev.clientX, ly=ev.clientY; nEl.classList.add('sel');
      function mm(e){ node.x+=(e.clientX-lx)/view.zoom; node.y+=(e.clientY-ly)/view.zoom; lx=e.clientX; ly=e.clientY; nEl.style.left=node.x+'px'; nEl.style.top=node.y+'px'; redrawWires(); }
      function mu(){ document.removeEventListener('mousemove',mm); document.removeEventListener('mouseup',mu); nEl.classList.remove('sel'); }
      document.addEventListener('mousemove',mm); document.addEventListener('mouseup',mu);
    });
  }

  function deleteBtn(x,node){
    x.addEventListener('mousedown',e=>e.stopPropagation());
    x.addEventListener('click',e=>{
      e.stopPropagation();
      const arr=isSource(node)?G.sources:G.routes; const i=arr.indexOf(node); if(i>=0)arr.splice(i,1);
      G.edges=G.edges.filter(ed=>ed.from!==node.id && ed.to!==node.id);
      const dom=nodeEls[node.id]; if(dom)dom.remove(); delete nodeEls[node.id];
      redrawWires(); refreshCounts();
    });
  }

  function startConnect(ev,src){
    ev.stopPropagation(); ev.preventDefault();
    connecting={from:src.id};
    tempPath=document.createElementNS('http://www.w3.org/2000/svg','path'); tempPath.setAttribute('class','temp');
    function mm(e){ const r=rect(); const a=w2s(sockPos(src,'out')); tempPath.setAttribute('d',curve(a,{x:e.clientX-r.left,y:e.clientY-r.top})); redrawWires(); }
    function mu(){ document.removeEventListener('mousemove',mm); document.removeEventListener('mouseup',mu); finishConnect(hoverIn); }
    document.addEventListener('mousemove',mm); document.addEventListener('mouseup',mu);
  }
  function finishConnect(route){
    if(connecting && route){
      const f=connecting.from, t=route.id;
      if(!G.edges.some(e=>e.from===f && e.to===t)) G.edges.push({from:f,to:t});
    }
    connecting=null; tempPath=null; hoverIn=null; redrawWires(); refreshCounts();
  }

  function makeSource(s){
    const n=el('div','node src'); n.style.left=s.x+'px'; n.style.top=s.y+'px';
    const hd=el('div','hd'); hd.appendChild(el('span',null,'Источник')); const x=el('span','x','✕'); hd.appendChild(x); n.appendChild(hd);
    const bd=el('div','bd');
    bd.appendChild(el('label',null,'Метка'));
    const lab=el('input'); lab.value=s.label||''; lab.placeholder='необязательно'; lab.addEventListener('input',()=>s.label=lab.value); bd.appendChild(lab);
    bd.appendChild(el('label',null,'Ссылка-подписка (upstream)'));
    const url=el('input','mono'); url.value=s.url||''; url.placeholder='https://сервер/sub/xxxx'; url.addEventListener('input',()=>s.url=url.value); bd.appendChild(url);
    n.appendChild(bd);
    const out=el('div','sock out'); out.title='Тяни в маршрут'; n.appendChild(out);
    dragHeader(hd,s,n); deleteBtn(x,s); out.addEventListener('mousedown',ev=>startConnect(ev,s));
    nodeEls[s.id]=n; world.appendChild(n);
  }

  function makeRoute(r){
    const n=el('div','node route'); n.style.left=r.x+'px'; n.style.top=r.y+'px';
    const hd=el('div','hd'); hd.appendChild(el('span',null,'Маршрут')); const x=el('span','x','✕'); hd.appendChild(x); n.appendChild(hd);
    const bd=el('div','bd');
    bd.appendChild(el('label',null,'Название (видно в клиенте)'));
    const t=el('input'); t.value=r.title||''; t.placeholder='Моя подписка'; t.addEventListener('input',()=>r.title=t.value); bd.appendChild(t);
    bd.appendChild(el('label',null,'Путь подписки'));
    const p=el('input','mono'); p.value=r.path||''; p.placeholder='/custom/custom'; bd.appendChild(p);
    bd.appendChild(el('label',null,'Режим'));
    const sel=el('select'); [['merge','Слияние'],['mirror','Зеркало']].forEach(m=>{ const o=el('option',null,m[1]); o.value=m[0]; if((r.mode||'merge')===m[0])o.selected=true; sel.appendChild(o); }); sel.addEventListener('change',()=>r.mode=sel.value); bd.appendChild(sel);
    const chk=el('label','chk'); const cb=el('input'); cb.type='checkbox'; cb.checked=r.enabled!==false; cb.addEventListener('change',()=>r.enabled=cb.checked); chk.appendChild(cb); chk.appendChild(el('span',null,'Включён')); bd.appendChild(chk);
    const pub=el('div','pub');
    function updPub(){ r.path=p.value; pub.innerHTML=''; const span=el('span',null,BASE.replace(/\/$/,'')+normPath(p.value)); pub.appendChild(span); const c=el('span','copy','копировать'); c.addEventListener('click',()=>{ if(navigator.clipboard)navigator.clipboard.writeText(span.textContent); showToast('Ссылка скопирована',false); }); pub.appendChild(c); }
    p.addEventListener('input',updPub); updPub(); bd.appendChild(pub);
    const cnt=el('div','cnt'); cnt.dataset.rid=r.id; bd.appendChild(cnt);
    n.appendChild(bd);
    const inp=el('div','sock in'); inp.title='Вход'; n.appendChild(inp);
    dragHeader(hd,r,n); deleteBtn(x,r);
    inp.addEventListener('mouseenter',()=>hoverIn=r); inp.addEventListener('mouseleave',()=>{ if(hoverIn===r)hoverIn=null; });
    inp.addEventListener('mouseup',()=>finishConnect(r));
    nodeEls[r.id]=n; world.appendChild(n);
  }

  // pan
  editor.addEventListener('mousedown',e=>{
    if(e.target!==editor && e.target!==world && e.target!==hint) return;
    e.preventDefault(); editor.classList.add('panning');
    let lx=e.clientX, ly=e.clientY;
    function mm(ev){ view.panX+=ev.clientX-lx; view.panY+=ev.clientY-ly; lx=ev.clientX; ly=ev.clientY; applyTransform(); redrawWires(); }
    function mu(){ document.removeEventListener('mousemove',mm); document.removeEventListener('mouseup',mu); editor.classList.remove('panning'); }
    document.addEventListener('mousemove',mm); document.addEventListener('mouseup',mu);
  });
  // zoom
  editor.addEventListener('wheel',e=>{
    e.preventDefault(); const r=rect(); const mx=e.clientX-r.left, my=e.clientY-r.top;
    const wx=(mx-view.panX)/view.zoom, wy=(my-view.panY)/view.zoom;
    view.zoom=Math.min(2.5,Math.max(0.2, view.zoom*(e.deltaY<0?1.1:1/1.1)));
    view.panX=mx-wx*view.zoom; view.panY=my-wy*view.zoom; applyTransform(); redrawWires();
  },{passive:false});

  function centerWorld(){ const r=rect(); return {x:(r.width/2-view.panX)/view.zoom, y:(r.height/2-view.panY)/view.zoom}; }
  document.getElementById('addSrc').addEventListener('click',()=>{ const c=centerWorld(); const s={id:genId(),url:'',label:'',x:c.x-NODE_W/2,y:c.y-40}; G.sources.push(s); makeSource(s); redrawWires(); });
  document.getElementById('addRoute').addEventListener('click',()=>{ const c=centerWorld(); const r={id:genId(),title:'',path:'',mode:'merge',enabled:true,x:c.x-NODE_W/2,y:c.y-70}; G.routes.push(r); makeRoute(r); redrawWires(); refreshCounts(); });
  document.getElementById('reset').addEventListener('click',()=>{ view={panX:60,panY:60,zoom:1}; applyTransform(); redrawWires(); });
  document.getElementById('save').addEventListener('click',save);

  let toastT=null;
  function showToast(msg,isErr){ toast.textContent=msg; toast.className=isErr?'err':'ok'; toast.style.display='block'; clearTimeout(toastT); toastT=setTimeout(()=>toast.style.display='none', isErr?6500:2200); }

  function save(){
    const payload={
      sources:G.sources.map(s=>({id:s.id,url:s.url||'',label:s.label||'',x:Math.round(s.x),y:Math.round(s.y)})),
      routes:G.routes.map(r=>({id:r.id,title:r.title||'',path:r.path||'',mode:r.mode||'merge',enabled:r.enabled!==false,x:Math.round(r.x),y:Math.round(r.y)})),
      edges:G.edges.map(e=>({from:e.from,to:e.to}))
    };
    fetch(ADMIN+'/graph/save',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(payload)})
      .then(r=>r.json().then(j=>({ok:r.ok,j})))
      .then(({ok,j})=>{ if(j&&j.ok){ showToast('Сохранено ✓',false); setTimeout(()=>location.reload(),650); } else { showToast('Не сохранено: '+((j&&j.errors)||['ошибка']).join('; '),true); } })
      .catch(()=>showToast('Сервер недоступен',true));
  }

  applyTransform();
  G.sources.forEach(makeSource); G.routes.forEach(makeRoute);
  redrawWires(); refreshCounts();
})();
"""


def render_editor(graph, public_base, csrf):
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Нодовый редактор — Sub Mirror</title><style>{EDITOR_CSS}</style></head>
<body>
<div id="top">
  <span class="title">Маршрутизирование — граф</span>
  <button class="btn" id="addSrc">+ Источник</button>
  <button class="btn" id="addRoute">+ Маршрут</button>
  <button class="btn gray" id="reset">Сбросить вид</button>
  <span class="spacer"></span>
  <a class="btn ghost" href="{esc(ADMIN_PATH)}/classic">Классический вид</a>
  <form method="post" action="{esc(ADMIN_PATH)}/logout" style="display:inline">
    <button class="btn ghost" type="submit">Выйти</button></form>
  <button class="btn" id="save">Сохранить</button>
</div>
<div id="editor">
  <svg id="wires" xmlns="http://www.w3.org/2000/svg"></svg>
  <div id="world"></div>
  <div id="hint">Пусто. Добавь «<b>+ Источник</b>» (ссылки-подписки) и «<b>+ Маршрут</b>» (твой путь),<br>
    протяни связь от источника к маршруту и нажми «<b>Сохранить</b>».<br>
    <span style="opacity:.7">Колесо — зум, перетаскивание фона — панорама.</span></div>
</div>
<div id="toast"></div>
<script>window.__GRAPH__={js_embed(graph)};window.__ADMIN__={js_embed(ADMIN_PATH)};window.__CSRF__={js_embed(csrf)};window.__BASE__={js_embed(public_base)};</script>
<script>{EDITOR_JS}</script>
</body></html>"""


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

    def _read_json(self, max_bytes=4_000_000):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > max_bytes:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8", errors="ignore"))
        except Exception:
            return None

    def _respond_json(self, code, obj):
        self._respond(code, json.dumps(obj, ensure_ascii=False),
                      {"Content-Type": "application/json; charset=utf-8"})

    # ---- GET ----
    def do_GET(self):
        norm = _normalize_path(self.path.split("?", 1)[0]) if self.path != "/" else "/"
        raw_path = self.path.split("?", 1)[0].rstrip("/") or "/"

        if raw_path == "/healthz":
            self._respond(200, b"ok")
            return

        # Веб-панель
        if raw_path == ADMIN_PATH + "/login":
            if self._current_session():
                self._redirect(ADMIN_PATH)
            else:
                self._respond(200, render_login(),
                              {"Content-Type": "text/html; charset=utf-8"})
            return

        if raw_path == ADMIN_PATH:
            sess = self._current_session()
            if sess:
                self._respond(200, render_editor(get_graph(), self._public_base(), sess.get("csrf", "")),
                              {"Content-Type": "text/html; charset=utf-8"})
            else:
                self._respond(200, render_login(),
                              {"Content-Type": "text/html; charset=utf-8"})
            return

        if raw_path == ADMIN_PATH + "/classic":
            if self._current_session():
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

        # Сохранение графа из нодового редактора (JSON + CSRF, отдаёт JSON).
        if raw_path == ADMIN_PATH + "/graph/save":
            sess = self._current_session()
            if not sess:
                self._respond_json(401, {"ok": False, "errors": ["Сессия истекла, обновите страницу"]})
                return
            token = self.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(token, sess.get("csrf", "")):
                self._respond_json(403, {"ok": False, "errors": ["Неверный CSRF-токен, обновите страницу"]})
                return
            data = self._read_json()
            if data is None:
                self._respond_json(400, {"ok": False, "errors": ["Некорректный JSON"]})
                return
            ok, errors = save_graph(data)
            self._respond_json(200 if ok else 400, {"ok": ok, "errors": errors})
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
            upstreams = _parse_upstreams(form.get("upstreams", [""])[0])
            err = self._validate_route(path)
            if err:
                self._respond(400, render_admin(get_routes(), self._public_base(), err, True),
                              {"Content-Type": "text/html; charset=utf-8"})
                return
            add_route(path, title, upstreams, mode)
            self._redirect(ADMIN_PATH)
            return

        m = re.match(r"^" + re.escape(ADMIN_PATH) + r"/routes/([A-Za-z0-9_-]{1,64})/(update|delete)$", raw_path)
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
                upstreams=_parse_upstreams(form.get("upstreams", [""])[0]),
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
