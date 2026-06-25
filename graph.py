#!/usr/bin/env python3
"""
graph.py — операции над графом подписок (маршруты/источники/рёбра) поверх Store.

Логика та же, что в исходном sub_server.py: routes[].upstreams — «истина» для
отдачи, граф (sources/edges) синхронизируется с ним в обе стороны. Здесь функции
читают/пишут конфиг через Store (а не глобальный dict), поэтому изменения попадают
в SQLite и расходятся по кластеру.
"""

import re
import secrets

from subscriptions import normalize_path

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# Пути, которые нельзя занимать маршрутами (на sub-сервере).
RESERVED_PATHS = {"/healthz"}


ANNOUNCE_MAX = 8000


def _new_id():
    return secrets.token_hex(8)


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
    old_by_url = {}
    for s in cfg.get("sources", []):
        if s.get("url"):
            old_by_url.setdefault(s["url"], s)
    route_ids = {r.get("id") for r in cfg["routes"] if r.get("id")}
    # сохраняем рёбра маршрут→маршрут (классические формы их не описывают)
    kept_route_edges = [e for e in cfg.get("edges", [])
                        if e.get("from") in route_ids and e.get("to") in route_ids]
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
    cfg["sources"] = sources
    cfg["edges"] = edges + kept_route_edges
    autolayout(cfg)


def recompute_upstreams_from_graph(cfg):
    _ensure_keys(cfg)
    url_by_id = {s.get("id"): (s.get("url") or "") for s in cfg["sources"] if s.get("id")}
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
    """Источники маршрута транзитивно (через маршруты на входе). → список url.
    Циклобезопасно (visited). Текст под подпиской (announce) — отдельно, на сам
    маршрут, не собирается с входов."""
    cfg = store.get_config() or {}
    routes_by_id = {r.get("id"): r for r in cfg.get("routes", []) if r.get("id")}
    src_by_id = {s.get("id"): s for s in cfg.get("sources", []) if s.get("id")}
    incoming = {}
    for e in cfg.get("edges", []):
        incoming.setdefault(e.get("to"), []).append(e.get("from"))
    urls, seen, visited = [], set(), set()
    # Итеративный DFS (а не рекурсия) — глубина цепочки не упирается в лимит стека.
    stack = [route.get("id")]
    while stack:
        rid = stack.pop()
        if rid in visited:
            continue
        visited.add(rid)
        r = routes_by_id.get(rid)
        if not r or not r.get("enabled", True):
            # выключенный маршрут не отдаёт свой контент даже как вход другого
            continue
        for fid in incoming.get(rid, []):
            if fid in src_by_id:
                u = (src_by_id[fid].get("url") or "").strip()
                if u and u not in seen:
                    seen.add(u)
                    urls.append(u)
            elif fid in routes_by_id:
                stack.append(fid)
    return urls


# ── чтение ────────────────────────────────────────────────────────────────
def get_graph(store):
    cfg = store.get_config() or {}
    return {
        "sources": [dict(s) for s in cfg.get("sources", [])],
        "routes": [dict(r) for r in cfg.get("routes", [])],
        "edges": [dict(e) for e in cfg.get("edges", [])],
    }


def get_routes(store):
    cfg = store.get_config() or {}
    return [dict(r) for r in cfg.get("routes", [])]


def find_route(store, path):
    norm = normalize_path(path)
    cfg = store.get_config() or {}
    for r in cfg.get("routes", []):
        if r.get("enabled", True) and normalize_path(r.get("path", "")) == norm:
            return dict(r)
    return None


# ── запись через Store ────────────────────────────────────────────────────
def add_route(store, path, title, upstreams, mode, announce=""):
    def mut(cfg):
        _ensure_keys(cfg)
        cfg["routes"].append({
            "id": _new_id(), "path": normalize_path(path), "title": title,
            "upstreams": upstreams, "mode": mode, "enabled": True,
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
                for k in ("title", "mode", "upstreams"):
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


def validate_route_path(store, path, ignore_id=None):
    if not path:
        return "Путь не может быть пустым"
    norm = normalize_path(path)
    if norm == "/":
        return "Путь не может быть просто '/'"
    if norm in RESERVED_PATHS:
        return f"Путь {norm} зарезервирован системой"
    for r in get_routes(store):
        if r.get("id") != ignore_id and normalize_path(r.get("path", "")) == norm:
            return f"Путь {norm} уже занят другим маршрутом"
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
        label = title or rid
        if not raw_path or path == "/":
            errors.append(f"Маршрут «{label}»: путь не задан")
        elif path in RESERVED_PATHS:
            errors.append(f"Путь {path} зарезервирован системой")
        elif path in used_paths:
            errors.append(f"Путь {path} используется несколькими маршрутами")
        else:
            used_paths.add(path)
        routes.append({
            "id": rid, "path": path, "title": title, "mode": mode,
            "enabled": enabled, "upstreams": [],
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

    def mut(cfg):
        cfg["sources"] = sources
        cfg["routes"] = routes
        cfg["edges"] = edges
        recompute_upstreams_from_graph(cfg)
    store.update_config(mut)
    return True, []


def migrate_config(store):
    """Привести граф и upstreams к согласованному виду (устойчиво к битому конфигу)."""
    def mut(cfg):
        try:
            _ensure_keys(cfg)
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
