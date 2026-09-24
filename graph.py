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
import uuid
import secrets
import urllib.parse

import subscriptions as subs
import source_checks
from subscriptions import normalize_path

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F-]{8,40}$")

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
GROUP_BUCKETS_MAX = 64
BUCKET_MEMBERS_MAX = 256
ROUTER_RULES_MAX = 64
ROUTER_VALUE_MAX = 256
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


def _is_group_node(source, node_meta):
    """Нода-группа (страна → балансер). Роль выводим из данных, не только из type."""
    sid = source.get("id")
    meta = (node_meta or {}).get(sid) or {}
    if isinstance(meta.get("group"), dict):
        return True
    return source.get("type") == "group"


def _node_group(source, node_meta):
    """Конфиг группы {buckets, params}, если это нода-группа; иначе None."""
    if not _is_group_node(source, node_meta):
        return None
    g = ((node_meta or {}).get(source.get("id")) or {}).get("group")
    return g if isinstance(g, dict) else {"buckets": [], "params": {}}


def _is_autoselect_node(source, node_meta):
    """Нода авто-выбора (все входы → один балансер leastPing)."""
    sid = source.get("id")
    meta = (node_meta or {}).get(sid) or {}
    if isinstance(meta.get("autoselect"), dict):
        return True
    return source.get("type") == "autoselect"


def _node_autoselect(source, node_meta):
    """Конфиг авто-выбора {params}, если это нода авто-выбора; иначе None."""
    if not _is_autoselect_node(source, node_meta):
        return None
    a = ((node_meta or {}).get(source.get("id")) or {}).get("autoselect")
    return a if isinstance(a, dict) else {"params": {}}


def _is_router_node(source, node_meta):
    """Нода-роутер (#05): по правилам geosite/geoip раскидывает трафик по таргетам."""
    sid = source.get("id")
    meta = (node_meta or {}).get(sid) or {}
    if isinstance(meta.get("router"), dict):
        return True
    return source.get("type") == "router"


def _node_router(source, node_meta):
    """Конфиг роутера {rules, default_target, params}, если это роутер; иначе None."""
    if not _is_router_node(source, node_meta):
        return None
    r = ((node_meta or {}).get(source.get("id")) or {}).get("router")
    return r if isinstance(r, dict) else {"rules": [], "default_target": "direct", "params": {}}


def _is_proc_node(source, node_meta):
    """Обрабатывающая нода (группа/авто/роутер): carry, не в upstreams, резолв→spec."""
    return (_is_group_node(source, node_meta) or _is_autoselect_node(source, node_meta)
            or _is_router_node(source, node_meta))


def _is_balancer_proc(source, node_meta):
    """ТОЛЬКО group/auto: их вход — строго source/key (не proc, не router). Для save_graph."""
    return _is_group_node(source, node_meta) or _is_autoselect_node(source, node_meta)


# _is_key_node/_node_keys уже возвращают False/None для группы/авто/роутера (нет
# meta["keys"], type != "key", url == "") — отдельная проверка не нужна.


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
        grp = meta.get("group")
        if isinstance(grp, dict):
            buckets = []
            for b in (grp.get("buckets") or [])[:GROUP_BUCKETS_MAX]:
                if not isinstance(b, dict):
                    continue
                bname = _norm_name(b.get("name"))
                members = []
                for m in (b.get("members") or [])[:BUCKET_MEMBERS_MAX]:
                    if not isinstance(m, dict):
                        continue
                    link = str(m.get("link") or "").strip()[:LINK_MAX]
                    if link:
                        members.append({"link": link})
                    else:
                        maddr = str(m.get("addr") or "").strip()[:LINK_MAX]
                        mnm = str(m.get("name") or "").strip()[:LINK_MAX]
                        if maddr or mnm:
                            members.append({"addr": maddr, "name": mnm})
                if bname or members:
                    buckets.append({"name": bname, "members": members})
            if buckets:
                entry["group"] = {"buckets": buckets,
                                  "params": subs._norm_balancer_params(grp.get("params"))}
        auto = meta.get("autoselect")
        if isinstance(auto, dict):
            entry["autoselect"] = {"params": subs._norm_balancer_params(auto.get("params"))}
        rt = meta.get("router")
        if isinstance(rt, dict):
            def _map_target(t):
                # target — id другой ноды; зеркалим remap рёбер/ключей; неизвестный → direct (GC)
                t = str(t or "").strip()
                if not t or t == "direct":
                    return "direct"
                mapped = id_map.get(t, t)
                return mapped if mapped in valid_ids else "direct"
            rrules = []
            for r in (rt.get("rules") or [])[:ROUTER_RULES_MAX]:
                if not isinstance(r, dict):
                    continue
                m = r.get("match") or {}
                mk = m.get("kind")
                if mk not in ("preset", "domain", "ip"):
                    continue
                mv = str(m.get("value") or "").strip()[:ROUTER_VALUE_MAX]
                if not mv:
                    continue
                rrules.append({"match": {"kind": mk, "value": mv}, "target": _map_target(r.get("target"))})
            entry["router"] = {
                "rules": rrules,
                "default_target": _map_target(rt.get("default_target")),
                "params": subs._norm_balancer_params(rt.get("params")),
            }
            gw = rt.get("gateway")          # серверный режим (узел-gateway): vless-ws на узле
            if isinstance(gw, dict) and gw.get("enabled"):
                uid = str(gw.get("uuid") or "").strip()
                if not _UUID_RE.match(uid):
                    uid = str(uuid.uuid4())   # генерируем один раз, дальше сохраняется
                path = str(gw.get("path") or "").strip() or subs.GATEWAY_WS_PATH
                if not path.startswith("/"):
                    path = "/" + path
                path = re.sub(r"[^A-Za-z0-9_/-]", "", path)[:64] or "/vlessws"
                try:
                    port = int(gw.get("port") or 0)
                except (TypeError, ValueError):
                    port = 0
                if not (1 <= port <= 65535):
                    port = subs.GATEWAY_PORT
                entry["router"]["gateway"] = {
                    "enabled": True, "uuid": uid, "path": path, "port": port,
                    "domain": str(gw.get("domain") or "").strip()[:255],
                }
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
        if s.get("url") and not _is_key_node(s, node_meta) and not _is_proc_node(s, node_meta):
            old_by_url.setdefault(s["url"], s)
    # Сохраняем как есть: ноды-ключи, обрабатывающие ноды (группа/авто) и любой источник,
    # питающий такую ноду (URL-подписка, питающая ТОЛЬКО proc, не появится в upstreams
    # маршрута — иначе классический редактор стёр бы её и её рёбра, P0).
    proc_ids = {s.get("id") for s in cfg.get("sources", [])
                if _is_proc_node(s, node_meta) and s.get("id")}
    feeds_proc = {e.get("from") for e in cfg.get("edges", []) if e.get("to") in proc_ids}
    carry = [dict(s) for s in cfg.get("sources", [])
             if _is_key_node(s, node_meta) or _is_proc_node(s, node_meta)
             or s.get("id") in feeds_proc]
    carry_ids = {s.get("id") for s in carry if s.get("id")}
    route_ids = {r.get("id") for r in cfg["routes"] if r.get("id")}
    # рёбра вне upstreams: (маршрут/ключ/proc/источник-в-proc)→маршрут и любое *→proc
    kept_edges = [e for e in cfg.get("edges", [])
                  if ((e.get("from") in route_ids or e.get("from") in carry_ids) and e.get("to") in route_ids)
                  or (e.get("to") in proc_ids)]
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
                    "unsafe": source_checks.is_unsafe(old or {"url": url}),
                    "type": (old or {}).get("type", "source"),
                    "x": (old or {}).get("x"),
                    "y": (old or {}).get("y"),
                }
                sources.append(node)
                by_url[url] = node
            edges.append({"from": node["id"], "to": rid})
    # источник, питающий группу, мог быть пересоздан выше (если также питает маршрут) —
    # не дублируем его (и его рёбра) из carry/kept.
    rebuilt_ids = {n["id"] for n in sources}
    carry = [s for s in carry if s.get("id") not in rebuilt_ids]
    seen_e = {(e["from"], e["to"]) for e in edges}
    kept_edges = [e for e in kept_edges if (e.get("from"), e.get("to")) not in seen_e]
    cfg["sources"] = sources + carry
    cfg["edges"] = edges + kept_edges
    autolayout(cfg)


def recompute_upstreams_from_graph(cfg):
    _ensure_keys(cfg)
    node_meta = cfg.get("node_meta") or {}
    # В upstreams попадают только URL-подписки (их скачивают); ключи и proc-ноды — нет
    # (группа/авто резолвятся при отдаче через spec["groups"], их ребро proc→route — без url).
    url_by_id = {s.get("id"): (s.get("url") or "")
                 for s in cfg["sources"]
                 if s.get("id") and not _is_key_node(s, node_meta) and not _is_proc_node(s, node_meta)}
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
    groups, seen_groups = [], set()
    routers, seen_routers = [], set()
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
                if _is_router_node(s, node_meta):   # роутер — раньше proc-ветки (он тоже proc)
                    if fid not in seen_routers:
                        seen_routers.add(fid)
                        routers.append(_resolve_router(s, node_meta, incoming, src_by_id, routes_by_id))
                    continue
                if _is_proc_node(s, node_meta):      # теперь = group/auto (роутер отсечён выше)
                    if fid not in seen_groups:
                        seen_groups.add(fid)
                        groups.append(_resolve_proc(s, node_meta, incoming, src_by_id, routes_by_id))
                    continue
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
    spec = {"subs": subs, "keys": keys, "groups": groups, "routers": routers}
    return mark_unsafe(spec, cfg)


def mark_unsafe(spec, cfg):
    unsafe_urls = {s.get("url", "").strip() for s in cfg.get("sources", []) if source_checks.is_unsafe(s)}
    def mark(value):
        if isinstance(value, list):
            return any([mark(x) for x in value])
        if not isinstance(value, dict):
            return False
        unsafe = value.get("url") in unsafe_urls or any([mark(x) for x in value.values()])
        if unsafe and any(key in value for key in ("url", "subs", "targets", "routers")):
            value["unsafe"] = True
            if "url" in value:
                value["renames"] = []  # the country/warning label cannot be hidden
        return unsafe
    mark(spec)
    return spec


def _route_flat_io(rid, routes_by_id, incoming, src_by_id, node_meta):
    """Маршрут на ВХОДЕ proc-ноды → его плоские (subs, keys): рекурсивно собираем
    source/key, питающие этот маршрут (и вложенные маршруты). Вложенные group/auto/router
    маршрута НЕ разворачиваем в члены родителя (их балансировка не плоская) — пропускаем.
    Циклобезопасно (local visited)."""
    subs, keys, sub_by_url, seen_k = [], [], {}, set()
    stack, local_seen = [rid], set()
    while stack:
        cur = stack.pop()
        if cur in local_seen:
            continue
        local_seen.add(cur)
        r = routes_by_id.get(cur)
        if not r or not r.get("enabled", True):
            continue
        for fid in incoming.get(cur, []):
            if fid in routes_by_id:
                stack.append(fid)
                continue
            s = src_by_id.get(fid)
            if s is None or _is_proc_node(s, node_meta):
                continue
            nk = _node_keys(s, node_meta)
            if nk is not None:
                for k in nk:
                    if k["link"] not in seen_k:
                        seen_k.add(k["link"])
                        keys.append(k)
            else:
                url = (s.get("url") or "").strip()
                if url:
                    renames = ((node_meta.get(fid) or {}).get("renames")) or []
                    ex = sub_by_url.get(url)
                    if ex is None:
                        entry = {"url": url, "renames": list(renames)}
                        subs.append(entry)
                        sub_by_url[url] = entry
                    else:
                        ex["renames"].extend(renames)
    return subs, keys


def _resolve_router(router_node, node_meta, incoming, src_by_id, routes_by_id=None):
    """Вход роутера → таргеты по input_id. source/key→link (ключ с N ссылок и source-
    подписка → kind:auto-обёртка); group/auto→_resolve_proc (2-й hop, bounded: их входы
    только source/key); МАРШРУТ→kind:auto из его плоских ссылок. Cycle-safe (роутер не
    принимает router). rules/default_target из node_meta; отсутствующий таргет → direct."""
    routes_by_id = routes_by_id or {}
    rdef = _node_router(router_node, node_meta) or {}
    targets = {}
    for fid in incoming.get(router_node.get("id"), []):
        if fid in routes_by_id:                                     # МАРШРУТ на входе → auto-таргет
            r_subs, r_keys = _route_flat_io(fid, routes_by_id, incoming, src_by_id, node_meta)
            if r_subs or r_keys:
                rt = routes_by_id[fid]
                targets[fid] = {"kind": "auto", "name": rt.get("title") or rt.get("path") or "",
                                "params": {}, "auto": True, "buckets": [], "subs": r_subs, "keys": r_keys}
            continue
        s = src_by_id.get(fid)
        if s is None or _is_router_node(s, node_meta):
            continue
        if _is_balancer_proc(s, node_meta):                         # group/auto → 2-й hop
            res = _resolve_proc(s, node_meta, incoming, src_by_id, routes_by_id)
            res["kind"] = "auto" if _is_autoselect_node(s, node_meta) else "group"
            targets[fid] = res
            continue
        nk = _node_keys(s, node_meta)                               # ключ-нода
        if nk is not None:
            links = [k["link"] for k in nk if (k.get("link") or "").strip()]
            if len(links) == 1:
                targets[fid] = {"kind": "link", "link": links[0]}
            elif links:                                             # >1 ключ → авто-балансер
                targets[fid] = {"kind": "auto", "name": s.get("label") or "", "params": {},
                                "auto": True, "buckets": [], "subs": [],
                                "keys": [{"link": l, "name": ""} for l in links]}
            continue
        url = (s.get("url") or "").strip()                          # source-подписка
        if url:
            renames = ((node_meta.get(fid) or {}).get("renames")) or []
            targets[fid] = {"kind": "auto", "name": s.get("label") or "", "params": {},
                            "auto": True, "buckets": [],
                            "subs": [{"url": url, "renames": list(renames)}], "keys": []}
    valid = set(targets) | {"direct"}
    rules = [{"match": r.get("match"),
              "target": (r.get("target") if r.get("target") in valid else "direct")}
             for r in (rdef.get("rules") or [])]
    dflt = rdef.get("default_target") if rdef.get("default_target") in valid else "direct"
    return {"id": router_node.get("id"), "name": router_node.get("label") or "",
            "params": rdef.get("params") or {}, "rules": rules, "default_target": dflt, "targets": targets}


def _resolve_proc(proc_node, node_meta, incoming, src_by_id, routes_by_id=None):
    """Вход группы/авто-выбора — source/key ИЛИ МАРШРУТ (его плоские ссылки вливаются
    членами). Вложенные group/auto/router-входы не поддерживаем. Авто-выбор →
    {auto:True, без корзин}; группа → {buckets}."""
    routes_by_id = routes_by_id or {}
    g_subs, g_keys, seen_k = [], [], set()
    g_sub_by_url = {}
    for fid in incoming.get(proc_node.get("id"), []):
        if fid in routes_by_id:                       # МАРШРУТ на входе → его плоские ссылки
            r_subs, r_keys = _route_flat_io(fid, routes_by_id, incoming, src_by_id, node_meta)
            for entry in r_subs:
                ex = g_sub_by_url.get(entry["url"])
                if ex is None:
                    e2 = {"url": entry["url"], "renames": list(entry.get("renames") or [])}
                    g_subs.append(e2)
                    g_sub_by_url[entry["url"]] = e2
                else:
                    ex["renames"].extend(entry.get("renames") or [])
            for k in r_keys:
                if k["link"] not in seen_k:
                    seen_k.add(k["link"])
                    g_keys.append(k)
            continue
        s = src_by_id.get(fid)
        if s is None or _is_proc_node(s, node_meta):
            continue  # вложенные proc-ноды не поддерживаем
        nk = _node_keys(s, node_meta)
        if nk is not None:
            for k in nk:
                if k["link"] not in seen_k:
                    seen_k.add(k["link"])
                    g_keys.append(k)
        else:
            url = (s.get("url") or "").strip()
            if url:
                renames = ((node_meta.get(fid) or {}).get("renames")) or []
                ex = g_sub_by_url.get(url)        # один url из двух источников — качаем раз
                if ex is None:
                    entry = {"url": url, "renames": list(renames)}
                    g_subs.append(entry)
                    g_sub_by_url[url] = entry
                else:
                    ex["renames"].extend(renames)
    if _is_autoselect_node(proc_node, node_meta):
        params = (_node_autoselect(proc_node, node_meta) or {}).get("params") or {}
        return {"name": proc_node.get("label") or "", "params": params,
                "auto": True, "buckets": [], "subs": g_subs, "keys": g_keys}
    gdef = _node_group(proc_node, node_meta) or {}
    return {"name": proc_node.get("label") or "", "params": gdef.get("params") or {},
            "buckets": gdef.get("buckets") or [], "subs": g_subs, "keys": g_keys}


def resolve_gateways(store):
    """Роутер-ноды в СЕРВЕРНОМ режиме (gateway) → список для рантайма:
      [{node_id, name, link, config, path, port, uuid, domain}]
    config — серверный xray-конфиг (vless-ws inbound + routing, см.
    subscriptions._wrap_as_server_gateway). link — универсальная клиентская ссылка
    (host = gateway.domain ноды, иначе дефолтный домен подписок). Чистая функция —
    рантайм (gateway.py) её прогоняет и (пере)запускает xray/nfqws."""
    cfg = store.get_config() or {}
    node_meta = cfg.get("node_meta") or {}
    src_by_id = {s.get("id"): s for s in cfg.get("sources", []) if s.get("id")}
    routes_by_id = {r.get("id"): r for r in cfg.get("routes", []) if r.get("id")}
    incoming = {}
    for e in cfg.get("edges", []):
        incoming.setdefault(e.get("to"), []).append(e.get("from"))
    try:
        settings = store.get_settings()
    except AttributeError:
        settings = (cfg.get("settings") or {})
    dd = default_domain(settings)
    default_dom = domain_fqdn(dd) if dd else ""
    out = []
    for nid, s in src_by_id.items():
        if not _is_router_node(s, node_meta):
            continue
        gw = (_node_router(s, node_meta) or {}).get("gateway")
        if not (isinstance(gw, dict) and gw.get("enabled")):
            continue
        rr = mark_unsafe(_resolve_router(s, node_meta, incoming, src_by_id, routes_by_id), cfg)
        if rr.get("unsafe"):
            rr["name"] = subs.unsafe_name(rr.get("name"))
        inbound = {"uuid": gw.get("uuid"), "path": gw.get("path"), "port": gw.get("port")}
        config = subs._wrap_as_server_gateway(rr["targets"], rr["rules"], rr["default_target"],
                                              rr["name"] or "gateway", inbound, rr["params"])
        domain = gw.get("domain") or default_dom
        link = subs._gateway_link(domain, gw.get("uuid"), gw.get("path"),
                                  rr["name"] or "gateway") if domain else ""
        out.append({"node_id": nid, "name": rr["name"], "link": link, "config": config,
                    "path": gw.get("path"), "port": gw.get("port"), "uuid": gw.get("uuid"),
                    "domain": domain})
    return out


# ── чтение ────────────────────────────────────────────────────────────────
def get_graph(store):
    cfg = store.get_config() or {}
    nm = {}
    for nid, meta in (cfg.get("node_meta") or {}).items():
        if isinstance(meta, dict):
            # глубокая копия вложенных list/dict (напр. group.buckets), чтобы редактор
            # не мутировал стор-объекты через ссылку.
            nm[nid] = {k: (json.loads(json.dumps(v)) if isinstance(v, (list, dict)) else v)
                       for k, v in meta.items()}
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
    norm = normalize_path(path).casefold()
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
    exact, fallback = [], []
    for route in cfg.get("routes", []):
        if not route.get("enabled", True) or normalize_path(route.get("path", "")).casefold() != norm:
            continue
        domain = domain_by_id(settings, route.get("domain_id") or "")
        if domain is not None and domain.get("enabled", True):
            if domain.get("id") == serving_id:
                exact.append(route)
        elif default_id == serving_id:
            fallback.append(route)
    matches = exact or fallback
    # Never resolve an old case-only collision to a different person's route.
    return dict(matches[0]) if len(matches) == 1 else None


# ── запись через Store ────────────────────────────────────────────────────
def add_route(store, path, title, upstreams, mode, announce="", domain_id="", access="public"):
    def mut(cfg):
        _ensure_keys(cfg)
        cfg["routes"].append({
            "id": _new_id(), "path": normalize_path(path), "title": title,
            "upstreams": upstreams, "mode": mode, "enabled": True,
            "domain_id": domain_id or "",
            "access": "private" if access == "private" else "public",
            "personal_owner": store.origin if access == "private" else "",
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
                if "access" in fields:
                    r["access"] = "private" if fields["access"] == "private" else "public"
                    if r["access"] == "private" and not r.get("personal_owner"):
                        r["personal_owner"] = store.origin
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


def validate_route_path(store, path, ignore_id=None, domain_id="", access="public"):
    if not path:
        return "Путь не может быть пустым"
    norm = normalize_path(path).casefold()
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
        other_path = normalize_path(r.get("path", "")).casefold()
        if eff(r.get("domain_id") or "") == cand and (
                (r.get("access") == "private" and norm.startswith(other_path + "/")) or
                (access == "private" and other_path.startswith(norm + "/"))):
            return "Подпуть личного маршрута зарезервирован для пользовательских ссылок"
        if other_path != norm:
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
            "unsafe": source_checks.is_unsafe(s),
            "label": str(s.get("label") or "").strip()[:120],
            "type": str(s.get("type") or "source") if str(s.get("type") or "") in ("source", "key", "group", "autoselect", "router") else "source",
            "x": _num(s.get("x"), 80.0), "y": _num(s.get("y"), 80.0),
        })

    current_routes = {r["id"]: r for r in get_routes(store)}
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
        key = (_eff_id(did), path.casefold())
        if not raw_path or path == "/":
            errors.append(f"Маршрут «{label}»: путь не задан")
        elif path.casefold() in RESERVED_PATHS:
            errors.append(f"Путь {path} зарезервирован системой")
        elif key in used_paths:
            errors.append(f"Путь {path} используется несколькими маршрутами на одном домене")
        else:
            used_paths.add(key)
        routes.append({
            "id": rid, "path": path, "title": title, "mode": mode,
            "enabled": enabled, "upstreams": [], "domain_id": did,
            "announce": _norm_announce(r.get("announce")),
            "access": "private" if r.get("access", current_routes.get(rid, {}).get("access")) == "private" else "public",
            "personal_owner": current_routes.get(rid, {}).get("personal_owner") or (store.origin if r.get("access", current_routes.get(rid, {}).get("access")) == "private" else ""),
            "x": _num(r.get("x"), 520.0), "y": _num(r.get("y"), 80.0),
        })

    for parent in routes:
        if parent.get("access") != "private":
            continue
        for child in routes:
            if child["id"] != parent["id"] and _eff_id(child["domain_id"]) == _eff_id(parent["domain_id"]) and child["path"].casefold().startswith(parent["path"].casefold() + "/"):
                errors.append("Подпуть личного маршрута зарезервирован для пользовательских ссылок")
                break
    if errors:
        return False, errors

    # Рёбра. Балансер-ноды (группа/авто) берут только source/key. Роутер берёт
    # source/key И группу/авто (его таргеты). Разрешено: source/key→{bal,router,route};
    # group/auto→{router,route}; router→route; route→route. Запрещено: bal←proc/route,
    # router←router/route, router→{router,bal}, самопетли, циклы.
    bal_proc_ids = {s["id"] for s in sources if s["type"] in ("group", "autoselect")}
    router_ids = {s["id"] for s in sources if s["type"] == "router"}
    proc_ids = bal_proc_ids | router_ids
    plain_src_ids = src_ids - proc_ids
    edges, seen_edge = [], set()
    radj = {}  # обрабатывающая нода (proc/маршрут) -> входы, для проверки циклов
    for e in raw_edges:
        if not isinstance(e, dict):
            continue
        fr = id_map.get(str(e.get("from") or ""), str(e.get("from") or ""))
        to = id_map.get(str(e.get("to") or ""), str(e.get("to") or ""))
        key = (fr, to)
        if fr == to or key in seen_edge:
            continue
        to_route = to in route_ids
        to_bal = to in bal_proc_ids
        to_router = to in router_ids
        if not (to_route or to_bal or to_router):
            continue
        if to_bal:
            # в группу/авто — из источника/ключа ИЛИ из МАРШРУТА (route → вход)
            if fr in plain_src_ids:
                seen_edge.add(key)
                edges.append({"from": fr, "to": to})
            elif fr in route_ids and not _creates_cycle(radj, fr, to):
                radj.setdefault(to, []).append(fr)
                seen_edge.add(key)
                edges.append({"from": fr, "to": to})
            continue
        if to_router:
            # в роутер — из source/key, group/auto (таргеты) ИЛИ МАРШРУТА; не router→router
            if fr in plain_src_ids:
                seen_edge.add(key)
                edges.append({"from": fr, "to": to})
            elif (fr in bal_proc_ids or fr in route_ids) and not _creates_cycle(radj, fr, to):
                radj.setdefault(to, []).append(fr)
                seen_edge.add(key)
                edges.append({"from": fr, "to": to})
            continue
        # to_route:
        if fr in plain_src_ids:                                   # source/key → route
            seen_edge.add(key)
            edges.append({"from": fr, "to": to})
        elif fr in proc_ids and not _creates_cycle(radj, fr, to):   # group/auto/router → route
            radj.setdefault(to, []).append(fr)
            seen_edge.add(key)
            edges.append({"from": fr, "to": to})
        elif fr in route_ids and not _creates_cycle(radj, fr, to):  # route → route
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
