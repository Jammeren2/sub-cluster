#!/usr/bin/env python3
"""
graph.py — операции над графом подписок (маршруты/источники/рёбра) поверх Store.

Логика та же, что в исходном sub_server.py: routes[].upstreams — «истина» для
отдачи, граф (sources/edges) синхронизируется с ним в обе стороны. Здесь функции
читают/пишут конфиг через Store (а не глобальный dict), поэтому изменения попадают
в SQLite и расходятся по кластеру.
"""

import re
import json
import secrets
import urllib.parse

from subscriptions import normalize_path

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# Пути, которые нельзя занимать маршрутами (на sub-сервере).
RESERVED_PATHS = {"/healthz"}

# Детерминированный id дефолтного домена при миграции (литерал, чтобы все узлы
# сошлись на одном id, а не выдали каждый свой случайный → расхождение LWW).
DEFAULT_DOMAIN_ID = "default"


# ── домены подписок (несколько, у каждого свой аккаунт reg.ru) ──────────────
def domain_list(settings):
    return [d for d in ((settings.get("dns") or {}).get("domains") or []) if isinstance(d, dict)]


def enabled_domains(settings):
    return [d for d in domain_list(settings) if d.get("enabled", True)]


def domain_fqdn(d):
    z = (d.get("zone") or "").strip().lower()
    s = (d.get("subdomain") or "").strip().lower()
    return f"{s}.{z}" if (z and s) else ""


def domain_public_base(d):
    pb = (d.get("public_base") or "").strip()
    if pb:
        return pb.rstrip("/")
    fq = domain_fqdn(d)
    return f"https://{fq}" if fq else ""


def default_domain(settings):
    """Домен по умолчанию — ВСЕГДА включённый (это всегда-отдающий фолбэк, который
    должен фейловериться и получать TLS-серт). Помеченный default, но выключенный
    домен игнорируем в пользу первого включённого; если включённых нет — деградируем."""
    doms = domain_list(settings)
    if not doms:
        return None
    pool = [d for d in doms if d.get("enabled", True)] or doms
    for d in pool:
        if d.get("default"):
            return d
    return pool[0]


def domain_by_id(settings, did):
    if not did:
        return None
    for d in domain_list(settings):
        if d.get("id") == did:
            return d
    return None


def effective_domain(settings, route):
    """Домен, на котором реально отдаётся маршрут: его выбранный домен, если тот
    существует и включён, иначе дефолтный (предупреждаем в UI, отдаём в дефолт)."""
    d = domain_by_id(settings, (route or {}).get("domain_id"))
    if d is not None and d.get("enabled", True):
        return d
    return default_domain(settings)


def _host_norm(h):
    if not h:
        return ""
    h = str(h).strip().lower()
    if h.startswith("["):            # IPv6 [::1]:443
        h = h[1:].split("]", 1)[0]
    else:
        h = h.split(":", 1)[0]
    return h.rstrip(".")


def domain_for_host(settings, host):
    """Домен, чей FQDN (или host из public_base) совпадает с Host запроса. Иначе None."""
    hn = _host_norm(host)
    if not hn:
        return None
    for d in domain_list(settings):
        if domain_fqdn(d) == hn:
            return d
        pb = (d.get("public_base") or "").strip()
        if pb:
            ph = (urllib.parse.urlsplit(pb if "://" in pb else "https://" + pb).hostname or "").lower().rstrip(".")
            if ph and ph == hn:
                return d
    return None


def normalize_domains(incoming, current_by_id, encrypt_fn):
    """Список доменов из формы → (parsed, errors). Валидация: дубли FQDN, конфликт
    зоны/поддомена, у включённого домена обязательны зона+поддомен, ровно один default.
    Пароль: пустой = оставить прежний (по id из current_by_id); иначе encrypt_fn(pw)."""
    if not isinstance(incoming, list):
        incoming = []
    current_by_id = current_by_id or {}
    parsed, errors, seen_fqdn, seen_zs = [], [], set(), set()
    for item in incoming[:50]:
        if not isinstance(item, dict):
            continue
        zone = (item.get("zone") or "").strip()
        sub = (item.get("subdomain") or "").strip()
        enabled = bool(item.get("enabled", True))
        if not zone and not sub and not (item.get("regru_username") or "").strip():
            continue  # пустая строка
        did = (str(item.get("id") or "").strip() or secrets.token_hex(6))
        if did != DEFAULT_DOMAIN_ID and did in {d["id"] for d in parsed}:
            did = secrets.token_hex(6)
        if enabled and (not zone or not sub):
            errors.append(f"Домен {did}: нужны и зона, и поддомен")
            continue
        fqdn = f"{sub}.{zone}".lower()
        if fqdn in seen_fqdn:
            errors.append(f"Дубликат FQDN: {fqdn}")
            continue
        if (zone.lower(), sub.lower()) in seen_zs:
            errors.append(f"Конфликт зоны/поддомена: {sub}.{zone}")
            continue
        seen_fqdn.add(fqdn)
        seen_zs.add((zone.lower(), sub.lower()))
        pw = item.get("regru_password") or ""
        pw_enc = encrypt_fn(pw) if pw else ((current_by_id.get(did) or {}).get("regru_password_enc", ""))
        np = item.get("node_priority")
        np = [str(x) for x in np if x] if (isinstance(np, list) and np) else None
        parsed.append({
            "id": did, "zone": zone, "subdomain": sub,
            "regru_username": (item.get("regru_username") or "").strip(),
            "regru_password_enc": pw_enc,
            "enabled": enabled, "default": bool(item.get("default")),
            "note": (item.get("note") or "")[:200],
            "public_base": (item.get("public_base") or "").strip().rstrip("/"),
            "node_priority": np,
        })
    if parsed:
        # ровно один default, и он ОБЯЗАТЕЛЬНО включённый (всегда-отдающий фолбэк
        # должен фейловериться и получать серт). Если помечен выключенный — переносим.
        enabled = [d for d in parsed if d["enabled"]]
        chosen = next((d for d in parsed if d["default"] and d["enabled"]), None) \
            or (enabled[0] if enabled else parsed[0])
        for d in parsed:
            d["default"] = (d is chosen)
    return parsed, errors


ANNOUNCE_MAX = 8000

# Схемы «прямых ключей» — готовая прокси-ссылка, которую НЕ скачивают, а вставляют
# в выдачу как есть. Всё остальное со схемой http(s) считаем URL-подпиской.
PROXY_SCHEMES = ("vless", "vmess", "trojan", "ss", "ssr",
                 "hysteria2", "hysteria", "hy2", "tuic")

# Капы на node_meta (защита от раздувания синкаемого конфига).
KEYS_PER_NODE_MAX = 64
RENAMES_PER_NODE_MAX = 512
LINK_MAX = 2048
NAME_MAX = 200
NODE_META_BYTES_MAX = 256 * 1024


def _new_id():
    return secrets.token_hex(8)


def _scheme(url):
    u = (url or "").strip()
    i = u.find("://")
    return u[:i].lower() if i > 0 else ""


def _is_direct_link(url):
    return _scheme(url) in PROXY_SCHEMES


def _is_key_node(source, node_meta):
    """Нода-ключ (прямые ссылки), а не URL-подписка. Роль выводим из данных, а не
    только из source['type'] — чтобы потеря 'type' старым узлом не ломала поведение."""
    sid = source.get("id")
    meta = (node_meta or {}).get(sid) or {}
    if isinstance(meta.get("keys"), list):
        return True
    if source.get("type") == "key":
        return True
    return _is_direct_link(source.get("url") or "")


def _node_keys(source, node_meta):
    """Прямые ключи ноды [{link,name}], если это нода-ключ; иначе None."""
    sid = source.get("id")
    meta = (node_meta or {}).get(sid) or {}
    raw = meta.get("keys")
    if isinstance(raw, list) and raw:
        out = []
        for k in raw:
            if isinstance(k, dict) and (k.get("link") or "").strip():
                out.append({"link": k["link"].strip(), "name": str(k.get("name") or "")})
        if out:
            return out
    # легаси / авто-починка: прямая ссылка прямо в url ноды
    url = (source.get("url") or "").strip()
    if _is_direct_link(url):
        return [{"link": url, "name": str(source.get("label") or "")}]
    return None


def _norm_name(v):
    return str(v or "").replace("\n", " ").replace("\r", " ").strip()[:NAME_MAX]


def _norm_node_meta(raw, id_map, valid_ids):
    """node_meta из payload → валидный/обрезанный map по существующим id нод (GC)."""
    out = {}
    if not isinstance(raw, dict):
        return out
    for nid_raw, meta in raw.items():
        nid = id_map.get(str(nid_raw), str(nid_raw))
        if nid not in valid_ids or not isinstance(meta, dict):
            continue
        entry = {}
        keys = meta.get("keys")
        if isinstance(keys, list):
            klist = []
            for k in keys[:KEYS_PER_NODE_MAX]:
                if not isinstance(k, dict):
                    continue
                link = str(k.get("link") or "").strip()[:LINK_MAX]
                if link:
                    klist.append({"link": link, "name": _norm_name(k.get("name"))})
            if klist:
                entry["keys"] = klist
        renames = meta.get("renames")
        if isinstance(renames, list):
            rlist = []
            for r in renames[:RENAMES_PER_NODE_MAX]:
                if not isinstance(r, dict):
                    continue
                to = _norm_name(r.get("to"))
                if not to:
                    continue
                rlist.append({
                    "addr": str(r.get("addr") or "").strip()[:LINK_MAX],
                    "name": str(r.get("name") or "").strip()[:LINK_MAX],
                    "to": to,
                })
            if rlist:
                entry["renames"] = rlist
        if entry:
            out[nid] = entry
    return out


def _norm_announce(v):
    return str(v or "")[:ANNOUNCE_MAX]


def _num(v, default=0.0):
    try:
        f = float(v)
        return f if f == f and f not in (float("inf"), float("-inf")) else default
    except (TypeError, ValueError):
        return default


def parse_upstreams(text):
    seen = set()
    out = []
    for line in (text or "").splitlines():
        u = line.strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


# ── операции на dict-конфиге (чистые; вызывать внутри store.update_config) ──
def _ensure_keys(cfg):
    cfg.setdefault("routes", [])
    cfg.setdefault("sources", [])
    cfg.setdefault("edges", [])


def autolayout(cfg):
    sy = 60
    for s in cfg["sources"]:
        if not isinstance(s.get("x"), (int, float)):
            s["x"] = 80
        if not isinstance(s.get("y"), (int, float)):
            s["y"] = sy
            sy += 130
    ry = 60
    for r in cfg["routes"]:
        if not isinstance(r.get("x"), (int, float)):
            r["x"] = 520
        if not isinstance(r.get("y"), (int, float)):
            r["y"] = ry
            ry += 200


def sync_graph_from_routes(cfg):
    _ensure_keys(cfg)
    node_meta = cfg.get("node_meta") or {}
    old_by_url = {}
    for s in cfg.get("sources", []):
        if s.get("url") and not _is_key_node(s, node_meta):
            old_by_url.setdefault(s["url"], s)
    # Ноды-ключи (прямые ссылки) не описываются upstreams маршрутов — сохраняем
    # их и их рёбра как есть, иначе классический редактор стёр бы их (P0).
    key_nodes = [dict(s) for s in cfg.get("sources", []) if _is_key_node(s, node_meta)]
    key_ids = {s.get("id") for s in key_nodes if s.get("id")}
    route_ids = {r.get("id") for r in cfg["routes"] if r.get("id")}
    # сохраняем рёбра маршрут→маршрут и ключ→маршрут (их нет в upstreams)
    kept_edges = [e for e in cfg.get("edges", [])
                  if (e.get("from") in route_ids or e.get("from") in key_ids)
                  and e.get("to") in route_ids]
    sources, edges, by_url = [], [], {}
    for route in cfg["routes"]:
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
                    "type": (old or {}).get("type", "source"),
                    "x": (old or {}).get("x"),
                    "y": (old or {}).get("y"),
                }
                sources.append(node)
                by_url[url] = node
            edges.append({"from": node["id"], "to": rid})
    cfg["sources"] = sources + key_nodes
    cfg["edges"] = edges + kept_edges
    autolayout(cfg)


def recompute_upstreams_from_graph(cfg):
    _ensure_keys(cfg)
    node_meta = cfg.get("node_meta") or {}
    # В upstreams попадают только URL-подписки (их скачивают); ноды-ключи — нет.
    url_by_id = {s.get("id"): (s.get("url") or "")
                 for s in cfg["sources"] if s.get("id") and not _is_key_node(s, node_meta)}
    incoming = {}
    for e in cfg["edges"]:
        incoming.setdefault(e.get("to"), []).append(e.get("from"))
    for route in cfg["routes"]:
        rid = route.get("id")
        if not rid:
            rid = route["id"] = _new_id()
        ups = []
        for sid in incoming.get(rid, []):
            url = (url_by_id.get(sid) or "").strip()
            if url and url not in ups:
                ups.append(url)
        route["upstreams"] = ups


def _creates_cycle(radj, fr, to):
    """Ребро fr→to (to зависит от fr). Цикл, если fr уже (транзитивно) зависит от to."""
    stack, seen = [fr], set()
    while stack:
        n = stack.pop()
        if n == to:
            return True
        if n in seen:
            continue
        seen.add(n)
        stack.extend(radj.get(n, []))
    return False


def resolve_links_spec(store, route):
    """Транзитивный набор для отдачи маршрута (через маршруты на входе):
        {"subs": [{"url", "renames"}], "keys": [{"link", "name"}]}.
    subs — URL-подписки (их скачивают), keys — прямые ключи (вставляются как есть).
    Выключенный маршрут не отдаёт ничего (даже как вход другого). Циклобезопасно
    (visited). Текст под подпиской (announce) — отдельно, на сам маршрут."""
    cfg = store.get_config() or {}
    node_meta = cfg.get("node_meta") or {}
    routes_by_id = {r.get("id"): r for r in cfg.get("routes", []) if r.get("id")}
    src_by_id = {s.get("id"): s for s in cfg.get("sources", []) if s.get("id")}
    incoming = {}
    for e in cfg.get("edges", []):
        incoming.setdefault(e.get("to"), []).append(e.get("from"))
    subs, sub_by_url = [], {}
    keys, seen_key = [], set()
    visited = set()
    # Итеративный DFS (а не рекурсия) — глубина цепочки не упирается в лимит стека.
    stack = [route.get("id")]
    while stack:
        rid = stack.pop()
        if rid in visited:
            continue
        visited.add(rid)
        r = routes_by_id.get(rid)
        if not r or not r.get("enabled", True):
            continue
        for fid in incoming.get(rid, []):
            if fid in src_by_id:
                s = src_by_id[fid]
                node_keys = _node_keys(s, node_meta)
                if node_keys is not None:
                    for k in node_keys:
                        if k["link"] not in seen_key:
                            seen_key.add(k["link"])
                            keys.append(k)
                else:
                    url = (s.get("url") or "").strip()
                    if url:
                        renames = ((node_meta.get(fid) or {}).get("renames")) or []
                        existing = sub_by_url.get(url)
                        if existing is None:
                            entry = {"url": url, "renames": list(renames)}
                            subs.append(entry)
                            sub_by_url[url] = entry
                        else:
                            existing["renames"].extend(renames)
            elif fid in routes_by_id:
                stack.append(fid)
    return {"subs": subs, "keys": keys}


# ── чтение ────────────────────────────────────────────────────────────────
def get_graph(store):
    cfg = store.get_config() or {}
    nm = {}
    for nid, meta in (cfg.get("node_meta") or {}).items():
        if isinstance(meta, dict):
            nm[nid] = {k: list(v) if isinstance(v, list) else v for k, v in meta.items()}
    return {
        "sources": [dict(s) for s in cfg.get("sources", [])],
        "routes": [dict(r) for r in cfg.get("routes", [])],
        "edges": [dict(e) for e in cfg.get("edges", [])],
        "node_meta": nm,
    }


def get_routes(store):
    cfg = store.get_config() or {}
    return [dict(r) for r in cfg.get("routes", [])]


def find_route(store, path, host=None):
    """Host-aware: маршрут отдаётся ТОЛЬКО на своём домене (уникальность пути —
    per-domain). Домен запроса определяем по Host; если он не совпал ни с одним
    доменом (прямой IP/неизвестный хост/до миграции) — отдаём как дефолтный домен."""
    norm = normalize_path(path)
    cfg = store.get_config() or {}
    settings = store.get_settings()
    serving = domain_for_host(settings, host) if host is not None else None
    if serving is None:
        serving = default_domain(settings)
    serving_id = serving.get("id") if serving else None
    default_d = default_domain(settings)
    default_id = default_d.get("id") if default_d else None
    # Точное совпадение домена (маршрут явно закреплён за serving) приоритетнее, чем
    # «осиротевший» маршрут (его домен выключен/удалён → падает в дефолтный): иначе
    # после выключения домена два маршрута с одним путём конкурировали бы по порядку.
    fallback = None
    for r in cfg.get("routes", []):
        if not r.get("enabled", True):
            continue
        if normalize_path(r.get("path", "")) != norm:
            continue
        rd = domain_by_id(settings, r.get("domain_id") or "")
        if rd is not None and rd.get("enabled", True):
            if rd.get("id") == serving_id:
                return dict(r)
        elif default_id == serving_id and fallback is None:
            fallback = r  # домен маршрута выключен/неизвестен → отдаём на дефолтном
    return dict(fallback) if fallback else None


# ── запись через Store ────────────────────────────────────────────────────
def add_route(store, path, title, upstreams, mode, announce="", domain_id=""):
    def mut(cfg):
        _ensure_keys(cfg)
        cfg["routes"].append({
            "id": _new_id(), "path": normalize_path(path), "title": title,
            "upstreams": upstreams, "mode": mode, "enabled": True,
            "domain_id": domain_id or "",
            "announce": _norm_announce(announce),
        })
        sync_graph_from_routes(cfg)
    store.update_config(mut)


def update_route(store, route_id, **fields):
    found = [False]

    def mut(cfg):
        _ensure_keys(cfg)
        for r in cfg["routes"]:
            if r.get("id") == route_id:
                if "path" in fields:
                    r["path"] = normalize_path(fields["path"])
                for k in ("title", "mode", "upstreams", "domain_id"):
                    if k in fields:
                        r[k] = fields[k]
                if "announce" in fields:
                    r["announce"] = _norm_announce(fields["announce"])
                if "enabled" in fields:
                    r["enabled"] = bool(fields["enabled"])
                found[0] = True
                break
        if found[0]:
            sync_graph_from_routes(cfg)
    store.update_config(mut)
    return found[0]


def delete_route(store, route_id):
    changed = [False]

    def mut(cfg):
        _ensure_keys(cfg)
        before = len(cfg["routes"])
        cfg["routes"] = [r for r in cfg["routes"] if r.get("id") != route_id]
        if len(cfg["routes"]) != before:
            changed[0] = True
            sync_graph_from_routes(cfg)
    store.update_config(mut)
    return changed[0]


def validate_route_path(store, path, ignore_id=None, domain_id=""):
    if not path:
        return "Путь не может быть пустым"
    norm = normalize_path(path)
    if norm == "/":
        return "Путь не может быть просто '/'"
    if norm in RESERVED_PATHS:
        return f"Путь {norm} зарезервирован системой"
    # уникальность пути теперь per-domain: /x на домене A и /x на домене B — разные.
    settings = store.get_settings()
    default_id = (default_domain(settings) or {}).get("id")
    enabled_ids = {d.get("id") for d in enabled_domains(settings)}

    def eff(did):
        return did if (did and did in enabled_ids) else default_id

    cand = eff(domain_id)
    for r in get_routes(store):
        if r.get("id") == ignore_id:
            continue
        if normalize_path(r.get("path", "")) != norm:
            continue
        if eff(r.get("domain_id") or "") == cand:
            return f"Путь {norm} уже занят другим маршрутом на этом домене"
    return ""


def save_graph(store, data):
    """Граф из нодового редактора → валидация → сохранение. → (ok, errors)."""
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
    id_map = {}

    # домены для проверки/привязки маршрутов (уникальность пути — per-domain)
    settings = store.get_settings()
    known_domain_ids = {d.get("id") for d in domain_list(settings) if d.get("id")}
    default_id = (default_domain(settings) or {}).get("id")
    enabled_ids = {d.get("id") for d in enabled_domains(settings)}

    def _eff_id(did):
        return did if (did and did in enabled_ids) else default_id

    sources, src_ids = [], set()
    for s in raw_sources:
        if not isinstance(s, dict):
            continue
        orig = str(s.get("id") or "")
        sid = orig
        if not _ID_RE.match(sid):
            sid = _new_id()
            if orig:
                id_map[orig] = sid
        elif sid in src_ids:
            sid = _new_id()
        src_ids.add(sid)
        sources.append({
            "id": sid,
            "url": str(s.get("url") or "").strip()[:2048],
            "label": str(s.get("label") or "").strip()[:120],
            "type": str(s.get("type") or "source") if str(s.get("type") or "") in ("source","key") else "source",
            "x": _num(s.get("x"), 80.0), "y": _num(s.get("y"), 80.0),
        })

    routes, route_ids, used_paths = [], set(), set()
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
        path = normalize_path(raw_path)
        title = str(r.get("title") or "").strip()[:200]
        mode = "mirror" if str(r.get("mode") or "") == "mirror" else "merge"
        enabled = bool(r.get("enabled", True))
        # неизвестный/чужой domain_id → "" (= дефолтный домен)
        raw_did = str(r.get("domain_id") or "").strip()
        did = raw_did if raw_did in known_domain_ids else ""
        label = title or rid
        key = (_eff_id(did), path)
        if not raw_path or path == "/":
            errors.append(f"Маршрут «{label}»: путь не задан")
        elif path in RESERVED_PATHS:
            errors.append(f"Путь {path} зарезервирован системой")
        elif key in used_paths:
            errors.append(f"Путь {path} используется несколькими маршрутами на одном домене")
        else:
            used_paths.add(key)
        routes.append({
            "id": rid, "path": path, "title": title, "mode": mode,
            "enabled": enabled, "upstreams": [], "domain_id": did,
            "announce": _norm_announce(r.get("announce")),
            "x": _num(r.get("x"), 520.0), "y": _num(r.get("y"), 80.0),
        })

    if errors:
        return False, errors

    # Рёбра: from = источник ИЛИ маршрут (маршрут можно подключить в другой
    # маршрут); to = всегда маршрут. Запрещаем самопетли и циклы.
    edges, seen_edge = [], set()
    radj = {}  # route -> [route inputs] для проверки циклов
    for e in raw_edges:
        if not isinstance(e, dict):
            continue
        fr = id_map.get(str(e.get("from") or ""), str(e.get("from") or ""))
        to = id_map.get(str(e.get("to") or ""), str(e.get("to") or ""))
        key = (fr, to)
        if to not in route_ids or fr == to or key in seen_edge:
            continue
        if fr in src_ids:
            seen_edge.add(key)
            edges.append({"from": fr, "to": to})
        elif fr in route_ids and not _creates_cycle(radj, fr, to):
            radj.setdefault(to, []).append(fr)
            seen_edge.add(key)
            edges.append({"from": fr, "to": to})

    # node_meta: ключи/переименования по id нод. Прогоняем id через id_map (как
    # рёбра), оставляем только записи для существующих источников (GC), капаем.
    node_meta = _norm_node_meta(data.get("node_meta"), id_map, src_ids)
    if len(json.dumps(node_meta, ensure_ascii=False).encode("utf-8")) > NODE_META_BYTES_MAX:
        return False, ["Слишком много ключей/переименований (node_meta)"]

    def mut(cfg):
        cfg["sources"] = sources
        cfg["routes"] = routes
        cfg["edges"] = edges
        # пишем node_meta, только если есть данные или он уже был (чтобы не плодить
        # лишний bump версии на конфигах без ключей/переименований)
        if node_meta or cfg.get("node_meta"):
            cfg["node_meta"] = node_meta
        recompute_upstreams_from_graph(cfg)
    store.update_config(mut)
    return True, []


def _migrate_domains(cfg):
    """Легаси один домен (dns.sub + sub_public_base) → domains[0] с id 'default'.
    Идемпотентно (если domains уже есть — no-op) и детерминированно (литерал id,
    поля из реплицируемого легаси-блока), чтобы все узлы сошлись на одном."""
    s = cfg.setdefault("settings", {})
    dns = s.setdefault("dns", {})
    if isinstance(dns.get("domains"), list) and dns["domains"]:
        return  # уже мигрировано
    sub = dns.get("sub") or {}
    dns["domains"] = [{
        "id": DEFAULT_DOMAIN_ID,
        "zone": (sub.get("zone") or "").strip(),
        "subdomain": (sub.get("subdomain") or "").strip(),
        "regru_username": dns.get("regru_username", "") or "",
        "regru_password_enc": dns.get("regru_password_enc", "") or "",
        "enabled": True, "default": True, "note": "",
        "public_base": (s.get("sub_public_base") or "").strip(),
        "node_priority": None,
    }]


def migrate_config(store):
    """Привести граф и upstreams к согласованному виду (устойчиво к битому конфигу)."""
    def mut(cfg):
        try:
            _ensure_keys(cfg)
            _migrate_domains(cfg)
            had_graph = isinstance(cfg.get("sources"), list) and isinstance(cfg.get("edges"), list) \
                and (cfg.get("sources") or cfg.get("edges"))
            if had_graph:
                recompute_upstreams_from_graph(cfg)
            else:
                sync_graph_from_routes(cfg)
            autolayout(cfg)
        except Exception as e:
            print(f"[!] Ошибка миграции конфига: {e}. Работаем как есть.", flush=True)
    # skip_if_unchanged: если конфиг уже согласован, не бампим версию — иначе
    # перезапуск узла со старым конфигом «омолодил» бы его и затёр свежий конфиг кластера.
    store.update_config(mut, skip_if_unchanged=True)
