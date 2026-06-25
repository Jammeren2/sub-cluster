#!/usr/bin/env python3
"""
subscriptions.py — извлечение нод и сборка ответов подписки.

Чистые функции без глобального состояния (кроме кэша upstream). Логика та же,
что была в исходном sub_server.py: зеркало (mirror) отдаёт upstream как есть,
слияние (merge) собирает base64-список нод из нескольких upstream с агрегацией
Subscription-Userinfo.
"""

import os
import re
import ssl
import gzip
import json
import time
import base64
import threading
import urllib.request
import urllib.parse

UPSTREAM_TIMEOUT = int(os.environ.get("UPSTREAM_TIMEOUT", "20"))
CACHE_TTL = int(os.environ.get("CACHE_TTL", "60"))

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

PASS_THROUGH_HEADERS = [
    "Content-Type", "Content-Disposition", "Profile-Title",
    "Profile-Update-Interval", "Profile-Web-Page-Url", "Subscription-Userinfo",
    "Announce", "Support-Url", "Use-Progress-Bar", "Pro-Mode",
    "Protocols-Hidden", "Routing",
]

PROXY_LINK_RE = re.compile(
    r'((?:vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic)://[^\s"\'<>]+)',
    re.IGNORECASE,
)


def normalize_path(path):
    p = "/" + (path or "").strip().strip("/")
    return p if p != "/" else "/"


def build_ssl_context():
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


# ── извлечение ссылок ─────────────────────────────────────────────────────
def _vless_from_outbound(outbound, remarks):
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
    text = body_bytes.decode("utf-8", errors="ignore").strip()
    if not text:
        return []
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
    candidate = text
    if "://" not in candidate:
        try:
            padded = candidate + "=" * (-len(candidate) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
            if "://" in decoded:
                candidate = decoded
        except Exception:
            pass
    return PROXY_LINK_RE.findall(candidate)


def _parse_userinfo(value):
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


# ── кэш upstream ──────────────────────────────────────────────────────────
_cache_lock = threading.Lock()
_cache = {}


def fetch_upstream(url):
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
    now = time.time()
    with _cache_lock:
        entry = _cache.get(url)
        if entry and (now - entry["ts"]) < CACHE_TTL:
            return entry["body"], entry["headers"]
    body, headers = fetch_upstream(url)
    with _cache_lock:
        _cache[url] = {"ts": time.time(), "body": body, "headers": headers}
    return body, headers


def _b64_header(text):
    """Текст → 'base64:<b64>' — формат Happ для Profile-Title / Announce."""
    return "base64:" + base64.b64encode(text.encode("utf-8")).decode("ascii")


# ── идентичность ссылок и переименование (rename) ──────────────────────────
# Порт по умолчанию по схеме — чтобы host:port совпадал, даже если порт не указан.
_DEFAULT_PORTS = {"vless": 443, "trojan": 443, "tuic": 443,
                  "hysteria2": 443, "hy2": 443, "hysteria": 443}


def _frag_name(link):
    """Имя (remark) из #fragment ссылки."""
    try:
        frag = urllib.parse.urlsplit(link).fragment
        return urllib.parse.unquote(frag) if frag else ""
    except Exception:
        return ""


def _link_addr(link):
    """host:port ссылки (для матча переименования). '' если не разобрать
    (напр. vmess:// — base64-JSON; тогда матчим по имени)."""
    try:
        u = urllib.parse.urlsplit(link)
        host = (u.hostname or "").lower()
        if not host:
            return ""
        port = u.port or _DEFAULT_PORTS.get((u.scheme or "").lower(), 0)
        return f"{host}:{port}" if port else host
    except Exception:
        return ""


def _outbound_addr(ob):
    """host:port из xray-outbound (vnext)."""
    try:
        vnext = ob["settings"]["vnext"][0]
        return f"{str(vnext['address']).lower()}:{vnext['port']}"
    except Exception:
        return ""


def _apply_name(link, name):
    """Переписать #fragment ссылки на name (пустое name — не трогаем)."""
    if not name or not name.strip():
        return link
    return link.split("#", 1)[0] + "#" + urllib.parse.quote(name.strip())


def _config_addr_name(cfg):
    """(host:port, имя) JSON-конфига: адрес первого vless-outbound + его remarks."""
    addr, name = "", ""
    obs = _find_vless_outbounds(cfg)
    if obs:
        ob, rem = obs[0]
        addr = _outbound_addr(ob)
        name = rem or ""
    if not name and isinstance(cfg, dict) and cfg.get("remarks"):
        name = str(cfg["remarks"])
    return addr, name


def _config_identity(cfg):
    """Ключ дедупа конфига БЕЗ учёта remarks (иначе одинаковые конфиги с разными
    косметическими именами не схлопываются)."""
    try:
        c = {k: v for k, v in cfg.items() if k != "remarks"} if isinstance(cfg, dict) else cfg
        return json.dumps(c, sort_keys=True, ensure_ascii=False)
    except Exception:
        return json.dumps(cfg, sort_keys=True, ensure_ascii=False, default=str)


def _set_config_remarks(cfg, name):
    if isinstance(cfg, dict):
        cfg["remarks"] = name


def _match_rename(addr, orig_name, renames):
    """Гибрид: 1) адрес+имя; 2) адрес (если по нему ровно одно правило);
    3) имя. Иначе None (без порядковых индексов — они ломаются при переупорядочивании)."""
    if not renames:
        return None
    for r in renames:
        if addr and r.get("addr") == addr and r.get("name") == orig_name:
            return r.get("to")
    if addr:
        by_addr = [r for r in renames if r.get("addr") == addr]
        if len(by_addr) == 1:
            return by_addr[0].get("to")
    for r in renames:
        if orig_name and r.get("name") == orig_name:
            return r.get("to")
    return None


def _dedup(seq):
    out, seen = [], set()
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def build_mirror_response(route, url, announce=""):
    body, headers = fetch_upstream_cached(url)
    headers = dict(headers)
    if route.get("title"):
        headers["Profile-Title"] = _b64_header(route["title"])
    if announce and announce.strip():  # свой текст под подпиской перебивает upstream
        headers["Announce"] = _b64_header(announce.strip())
    return body, headers


# Заголовки upstream, которые имеет смысл пробросить в слитую подписку (режим Happ).
_MERGE_PASSTHROUGH = ("Pro-Mode", "Protocols-Hidden", "Use-Progress-Bar",
                      "Support-Url", "Profile-Web-Page-Url")


def _vless_to_outbound(url, tag="proxy"):
    """vless://... → xray-outbound (обратное к _vless_from_outbound). → (outbound, name) или (None,None)."""
    try:
        u = urllib.parse.urlsplit(url)
        if u.scheme.lower() != "vless" or not u.hostname:
            return None, None
        q = urllib.parse.parse_qs(u.query)
        g = lambda k: (q.get(k, [""])[0])
        name = urllib.parse.unquote(u.fragment) if u.fragment else u.hostname
        net = g("type") or "tcp"
        sec = g("security") or "none"
        flow = g("flow")
        stream = {"network": net, "security": sec}
        if sec == "reality":
            stream["realitySettings"] = {"publicKey": g("pbk"), "fingerprint": g("fp") or "chrome",
                                         "serverName": g("sni"), "shortId": g("sid"), "spiderX": g("spx") or "/"}
        elif sec == "tls":
            stream["tlsSettings"] = {"serverName": g("sni"), "fingerprint": g("fp") or "chrome",
                                     "allowInsecure": False}
        if net == "ws":
            stream["wsSettings"] = {"path": g("path") or "/", "headers": {"Host": g("host")}}
        elif net == "grpc":
            stream["grpcSettings"] = {"serviceName": g("serviceName")}
        user = {"id": u.username or "", "encryption": "none"}
        if flow:
            user["flow"] = flow
        ob = {"tag": tag, "protocol": "vless",
              "settings": {"vnext": [{"address": u.hostname, "port": u.port or 443, "users": [user]}]},
              "streamSettings": stream}
        return ob, name
    except Exception:
        return None, None


def _wrap_as_config(outbound, name):
    """Одиночная нода → самодостаточный xray-конфиг (элемент массива Happ)."""
    return {
        "remarks": name,
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": [
            {"tag": "socks", "port": 10808, "listen": "127.0.0.1", "protocol": "socks",
             "settings": {"udp": True}},
            {"tag": "http", "port": 10809, "listen": "127.0.0.1", "protocol": "http"},
        ],
        "outbounds": [outbound,
                      {"protocol": "freedom", "tag": "direct"},
                      {"protocol": "blackhole", "tag": "block"}],
        "routing": {"domainStrategy": "AsIs",
                    "rules": [{"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}]},
    }


def _b64list(links):
    return base64.b64encode(("\n".join(_dedup(links))).encode("utf-8")).decode("ascii").encode("ascii")


def build_merged_response(route, spec, announce=""):
    """Слияние подписок и прямых ключей в один ответ.
       spec = {"subs":[{"url","renames"}], "keys":[{"link","name"}]}.
    Формат (JSON-конфиги Happ vs base64-список) выбираем ТОЛЬКО по подпискам —
    протокол ключа не должен «опускать» весь ответ. Переименования применяем после
    дедупа (гибрид: адрес → имя). Прямые ключи вставляются в выбранном формате."""
    subs = spec.get("subs", []) if isinstance(spec, dict) else []
    keys = spec.get("keys", []) if isinstance(spec, dict) else []

    json_items = []   # [{"cfg","addr","name","renames"}]  (дедуп по identity без remarks)
    seen_cfg = set()
    text_items = []   # [{"link","addr","name","renames"}] (дедуп по строке ссылки)
    seen_link = set()
    infos = []
    passthrough = {}

    for sub in subs:
        url = (sub or {}).get("url")
        if not url:
            continue
        renames = (sub or {}).get("renames") or []
        try:
            body, headers = fetch_upstream_cached(url)
        except Exception as e:
            print(f"[-] upstream {url} недоступен: {e}", flush=True)
            continue
        ui = headers.get("Subscription-Userinfo")
        if ui:
            infos.append(_parse_userinfo(ui))
        for k in _MERGE_PASSTHROUGH:
            if k not in passthrough and headers.get(k):
                passthrough[k] = headers[k]
        text = body.decode("utf-8", errors="ignore").strip()
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            parsed = None
        cfgs = parsed if isinstance(parsed, list) else ([parsed] if isinstance(parsed, dict) else None)
        if cfgs is not None:
            for cfg in cfgs:
                ident = _config_identity(cfg)
                if ident not in seen_cfg:
                    seen_cfg.add(ident)
                    addr, name = _config_addr_name(cfg)
                    json_items.append({"cfg": cfg, "addr": addr, "name": name, "renames": renames})
        else:
            for link in extract_links(body):
                if link not in seen_link:
                    seen_link.add(link)
                    text_items.append({"link": link, "addr": _link_addr(link),
                                       "name": _frag_name(link), "renames": renames})

    # Переименования — отдельным проходом после дедупа (identity дедупа не трогаем).
    for it in json_items:
        new = _match_rename(it["addr"], it["name"], it["renames"])
        if new is not None:
            _set_config_remarks(it["cfg"], new)
    for it in text_items:
        new = _match_rename(it["addr"], it["name"], it["renames"])
        if new is not None:
            it["link"] = _apply_name(it["link"], new)

    # Прямые ключи → строки ссылок с заданным именем.
    key_links = [_apply_name(k["link"], k.get("name") or "") for k in keys if (k.get("link") or "").strip()]

    have_json = bool(json_items)
    have_text = bool(text_items)
    out_configs = [it["cfg"] for it in json_items]
    out_links = [it["link"] for it in text_items]

    def _json_payload(configs):
        h = {"Content-Type": "application/json; charset=utf-8"}
        h.update(passthrough)
        return json.dumps(configs, ensure_ascii=False).encode("utf-8"), h

    if have_json and not have_text:
        # JSON-формат: vless-ключи оборачиваем в конфиги; не-vless обернуть нельзя.
        for link in key_links:
            ob, name = _vless_to_outbound(link)
            if ob:
                out_configs.append(_wrap_as_config(ob, name))
            else:
                print(f"[-] прямой ключ ({link[:32]}…) не vless — пропущен в JSON-маршруте", flush=True)
        payload, out_headers = _json_payload(out_configs)
    elif have_text and not have_json:
        payload = _b64list(out_links + key_links)
        out_headers = {"Content-Type": "text/plain; charset=utf-8"}
    elif have_json and have_text:
        # Смешанные подписки: JSON оставляем сгруппированным, плоские vless-ссылки и
        # ключи оборачиваем в конфиги; если есть не-vless — сводим всё в base64-список.
        wrapped, leftover = [], []
        for link in _dedup(out_links + key_links):
            ob, name = _vless_to_outbound(link)
            (wrapped if ob else leftover).append((link, ob, name))
        if not leftover:
            payload, out_headers = _json_payload(out_configs + [_wrap_as_config(ob, name) for _, ob, name in wrapped])
        else:
            all_links = list(out_links + key_links)
            seen = set(all_links)
            for it in json_items:
                for ob, rem in _find_vless_outbounds(it["cfg"]):
                    link = _vless_from_outbound(ob, rem)
                    if link and link not in seen:
                        seen.add(link)
                        all_links.append(link)
            payload = _b64list(all_links)
            out_headers = {"Content-Type": "text/plain; charset=utf-8"}
    else:
        # Подписок нет (или все недоступны) — отдаём только прямые ключи (или пусто).
        payload = _b64list(key_links)
        out_headers = {"Content-Type": "text/plain; charset=utf-8"}

    out_headers.setdefault("Profile-Update-Interval", "12")
    if route.get("title"):
        out_headers["Profile-Title"] = _b64_header(route["title"])
    if announce and announce.strip():
        out_headers["Announce"] = _b64_header(announce.strip())
    if infos:
        out_headers["Subscription-Userinfo"] = _aggregate_userinfo(infos)
    return payload, out_headers


def build_route_response(route, spec=None, announce=""):
    """spec — разрешённый (транзитивный) набор: {"subs":[{"url","renames"}],
    "keys":[{"link","name"}]}. announce — текст под подпиской (заголовок Announce).
    Если spec=None — строим вырожденный spec из route['upstreams'] (совместимость)."""
    if spec is None:
        spec = {"subs": [{"url": u, "renames": []} for u in route.get("upstreams", [])], "keys": []}
    subs = spec.get("subs", [])
    keys = spec.get("keys", [])
    mode = route.get("mode", "merge")
    has_renames = any((s.get("renames") for s in subs))
    # Зеркало байт-в-байт возможно только без ключей/переименований и с одной подпиской.
    if mode == "mirror" and len(subs) == 1 and not keys and not has_renames:
        return build_mirror_response(route, subs[0]["url"], announce)
    return build_merged_response(route, spec, announce)


def preview_subscription(url, limit=1000):
    """Скачать подписку и вернуть [{name, addr, link}] для UI-переименования.
    Гранулярность совпадает с merge: JSON → по конфигам, текст/base64 → по ссылкам."""
    body, _headers = fetch_upstream_cached(url)
    out, seen = [], set()
    text = body.decode("utf-8", errors="ignore").strip()
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    cfgs = parsed if isinstance(parsed, list) else ([parsed] if isinstance(parsed, dict) else None)
    if cfgs is not None:
        for cfg in cfgs:
            addr, name = _config_addr_name(cfg)
            obs = _find_vless_outbounds(cfg)
            link = _vless_from_outbound(obs[0][0], name) if obs else ""
            ident = (addr, name, link)
            if ident in seen:
                continue
            seen.add(ident)
            out.append({"name": name, "addr": addr, "link": link})
            if len(out) >= limit:
                break
    else:
        for link in extract_links(body):
            if link in seen:
                continue
            seen.add(link)
            out.append({"name": _frag_name(link), "addr": _link_addr(link), "link": link})
            if len(out) >= limit:
                break
    return out
