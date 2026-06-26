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
    """Ключ дедупа конфига — полный JSON (с учётом remarks): два конфига, которые
    различаются только именем, считаем РАЗНЫМИ «нодами» и оба сохраняем (как в
    исходной логике), чтобы не терять именованные группы из подписки."""
    try:
        return json.dumps(cfg, sort_keys=True, ensure_ascii=False)
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


def _maybe_b64(s):
    """Декодировать base64(method:password…) если это base64; иначе вернуть как есть."""
    s = (s or "").strip()
    try:
        dec = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8")
        if ":" in dec:
            return dec
    except Exception:
        pass
    return s


def _split_hostport(hp):
    hp = (hp or "").strip()
    if hp.startswith("["):                         # IPv6 [::1]:port
        host, _, rest = hp[1:].partition("]")
        return host, rest.lstrip(":")
    if ":" in hp:
        host, port = hp.rsplit(":", 1)
        return host, port
    return hp, ""


def _trojan_to_outbound(url, tag="proxy"):
    try:
        u = urllib.parse.urlsplit(url)
        if u.scheme.lower() != "trojan" or not u.hostname:
            return None, None
        q = urllib.parse.parse_qs(u.query)
        g = lambda k: q.get(k, [""])[0]
        name = urllib.parse.unquote(u.fragment) if u.fragment else u.hostname
        net = g("type") or "tcp"
        sec = g("security") or "tls"
        stream = {"network": net, "security": sec}
        if sec in ("tls", "xtls", "reality"):
            stream["tlsSettings"] = {"serverName": g("sni") or g("peer") or u.hostname,
                                     "fingerprint": g("fp") or "chrome",
                                     "allowInsecure": g("allowInsecure") in ("1", "true")}
        if net == "ws":
            stream["wsSettings"] = {"path": g("path") or "/", "headers": {"Host": g("host")}}
        elif net == "grpc":
            stream["grpcSettings"] = {"serviceName": g("serviceName") or g("path")}
        ob = {"tag": tag, "protocol": "trojan",
              "settings": {"servers": [{"address": u.hostname, "port": u.port or 443,
                                        "password": urllib.parse.unquote(u.username or "")}]},
              "streamSettings": stream}
        return ob, name
    except Exception:
        return None, None


def _ss_to_outbound(url, tag="proxy"):
    """ss:// (SIP002 base64(method:pass)@host:port и легаси base64(всё)) → xray-outbound."""
    try:
        raw = url[5:] if url.lower().startswith("ss://") else url
        frag = ""
        if "#" in raw:
            raw, frag = raw.split("#", 1)
        name = urllib.parse.unquote(frag) if frag else ""
        if "?" in raw:                              # plugin-параметры — xray так не настроить, отбросим
            raw = raw.split("?", 1)[0]
        method = password = host = None
        port = ""
        if "@" in raw:                              # SIP002: creds@host:port
            userinfo, hostpart = raw.rsplit("@", 1)
            creds = _maybe_b64(userinfo)
            if ":" in creds:
                method, password = creds.split(":", 1)
            host, port = _split_hostport(hostpart)
        else:                                       # легаси: base64(method:pass@host:port)
            dec = _maybe_b64(raw)
            if "@" in dec:
                creds, hostpart = dec.rsplit("@", 1)
                if ":" in creds:
                    method, password = creds.split(":", 1)
                host, port = _split_hostport(hostpart)
        if not (method and host and port and str(port).isdigit()):
            return None, None
        ob = {"tag": tag, "protocol": "shadowsocks",
              "settings": {"servers": [{"address": host, "port": int(port),
                                        "method": method, "password": password}]}}
        return ob, (name or host)
    except Exception:
        return None, None


def _vmess_to_outbound(url, tag="proxy"):
    try:
        raw = url[8:] if url.lower().startswith("vmess://") else url
        raw = raw.split("#", 1)[0].strip()
        v = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "ignore"))
        host = v.get("add")
        port = int(v.get("port") or 0)
        uid = v.get("id")
        if not (host and port and uid):
            return None, None
        name = v.get("ps") or host
        net = v.get("net") or "tcp"
        sec = "tls" if str(v.get("tls") or "").lower() in ("tls", "reality") else "none"
        stream = {"network": net, "security": sec}
        if sec == "tls":
            stream["tlsSettings"] = {"serverName": v.get("sni") or v.get("host") or host, "allowInsecure": False}
        if net == "ws":
            stream["wsSettings"] = {"path": v.get("path") or "/", "headers": {"Host": v.get("host") or ""}}
        elif net == "grpc":
            stream["grpcSettings"] = {"serviceName": v.get("path") or ""}
        ob = {"tag": tag, "protocol": "vmess",
              "settings": {"vnext": [{"address": host, "port": port,
                                      "users": [{"id": uid, "alterId": int(v.get("aid") or 0),
                                                 "security": v.get("scy") or "auto"}]}]},
              "streamSettings": stream}
        return ob, name
    except Exception:
        return None, None


def _link_to_outbound(url, tag="proxy"):
    """Любая прокси-ссылка → (xray-outbound, name). Поддержка vless/vmess/trojan/ss
    (то, что выражается xray-конфигом). hysteria2/tuic/ssr → (None, None)."""
    scheme = (url.split("://", 1)[0].lower() if "://" in url else "")
    if scheme == "vless":
        return _vless_to_outbound(url, tag)
    if scheme == "trojan":
        return _trojan_to_outbound(url, tag)
    if scheme == "ss":
        return _ss_to_outbound(url, tag)
    if scheme == "vmess":
        return _vmess_to_outbound(url, tag)
    return None, None


def _b64list(links):
    return base64.b64encode(("\n".join(_dedup(links))).encode("utf-8")).decode("ascii").encode("ascii")


# ── нода-группа (страна) → один xray-конфиг с клиентским балансером leastPing ──
# Всё, что специфично для схемы /s/sub «Быстрый», сосредоточено в _wrap_as_balancer
# и _norm_balancer_params — подгонка под реальный экспорт = правка одной функции.
_BALANCER_DEFAULTS = {
    "strategy": "leastPing",                              # routing.balancers[].strategy.type
    "probe_url": "http://www.gstatic.com/generate_204",   # burstObservatory.pingConfig.destination
    "interval": "5m",
    "timeout": "3s",
    "sampling": 2,
    "domain_strategy": "AsIs",                            # routing.domainStrategy
}
_STRATEGY_OK = {"leastPing", "leastLoad", "random", "roundRobin"}
_DOMAINSTRAT_OK = {"AsIs", "IPIfNonMatch", "IPOnDemand"}
_DURATION_RE = re.compile(r"^\d+(ms|s|m|h)$")


def _norm_balancer_params(p):
    """Параметры балансера группы → валидный/обрезанный набор (с дефолтами)."""
    out = dict(_BALANCER_DEFAULTS)
    if not isinstance(p, dict):
        return out
    if p.get("strategy") in _STRATEGY_OK:
        out["strategy"] = p["strategy"]
    if p.get("domain_strategy") in _DOMAINSTRAT_OK:
        out["domain_strategy"] = p["domain_strategy"]
    u = str(p.get("probe_url") or "").strip()
    if u.startswith(("http://", "https://")):
        out["probe_url"] = u[:256]
    for k in ("interval", "timeout"):
        v = str(p.get(k) or "").strip()
        if _DURATION_RE.match(v):
            out[k] = v
    try:
        s = int(p.get("sampling"))
        if 1 <= s <= 8:
            out["sampling"] = s
    except (TypeError, ValueError):
        pass
    return out


def _wrap_as_balancer(member_outbounds, name, params=None):
    """N member-outbound'ов → ОДИН самодостаточный xray-конфиг (элемент Happ-массива)
    с клиентским балансером leastPing + burstObservatory (схема /s/sub «Быстрый»).
    Теги: proxy-0..proxy-(N-1). Selector по префиксу 'proxy-' → direct/block НЕ входят.
    Это же ядро для roadmap/03A (одна корзина = все входы). Чисто структурная функция:
    конвертация ссылок в outbound'ы — у вызывающего."""
    p = _norm_balancer_params(params)
    obs = []
    for i, ob in enumerate(member_outbounds):
        ob = dict(ob)
        ob["tag"] = f"proxy-{i}"            # перетираем тег → уникальный, префиксный
        obs.append(ob)
    obs.append({"protocol": "freedom", "tag": "direct"})
    obs.append({"protocol": "blackhole", "tag": "block"})
    return {
        "remarks": name,
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": [
            {"tag": "socks", "port": 10808, "listen": "127.0.0.1",
             "protocol": "socks", "settings": {"udp": True}},
            {"tag": "http", "port": 10809, "listen": "127.0.0.1", "protocol": "http"},
        ],
        "outbounds": obs,
        "routing": {
            "domainStrategy": p["domain_strategy"],
            "balancers": [{
                "tag": "balancer",
                "selector": ["proxy-"],            # префикс → все proxy-N
                "strategy": {"type": p["strategy"]},
            }],
            "rules": [{
                "type": "field",
                "inboundTag": ["socks", "http"],
                "balancerTag": "balancer",
            }],
        },
        "burstObservatory": {
            "subjectSelector": ["proxy-"],         # наблюдаем только членов балансера
            "pingConfig": {
                "destination": p["probe_url"],
                "interval": p["interval"],
                "timeout": p["timeout"],
                "sampling": p["sampling"],
            },
        },
    }


def _member_match(u, members):
    """u = {"link","addr","name"}; members — члены корзины ({addr,name} | {link}).
    Гибрид как _match_rename: 1) точная ссылка-ключ; 2) addr+имя; 3) уникальный addr; 4) имя."""
    if not members:
        return False
    addr, name, link = u["addr"], u["name"], u["link"]
    for m in members:
        if m.get("link") and m["link"] == link:
            return True
    for m in members:
        if not m.get("link") and m.get("addr") == addr and m.get("name") == name:
            return True
    addr_ms = [m for m in members if not m.get("link") and m.get("addr") == addr]
    if addr and len(addr_ms) == 1:
        return True
    for m in members:
        if not m.get("link") and name and m.get("name") == name:
            return True
    return False


def _dedup_configs(configs):
    out, seen = [], set()
    for c in configs:
        ident = _config_identity(c)
        if ident not in seen:
            seen.add(ident)
            out.append(c)
    return out


def _resolve_group_members(group):
    """group = {name, params, buckets, subs, keys} (из resolve_links_spec). Скачивает
    подписки группы (кэш общий), добавляет её прямые ключи → плоский набор ссылок с
    (addr,name). Порядок Q7: сопоставление с корзиной по (addr,name), ЗАТЕМ переименование
    источника применяется к имени ссылки. Имя корзины → remarks конфига.
    → (configs, leftover_links, skipped_links, infos, passthrough):
      configs       — по одному leastPing-конфигу на НЕпустую корзину;
      leftover_links— конвертируемые ссылки вне корзин → passthrough (как сегодня);
      skipped_links — неконвертируемые в xray (hysteria2/tuic/ssr), даже в корзине → passthrough+лог;
      infos/passthrough — для агрегации Subscription-Userinfo и заголовков."""
    # universe: ИСХОДНАЯ ссылка/addr/имя (для матча корзины) + отложенное переименование
    # ("rename"), которое применяется ТОЛЬКО при passthrough (Q7: сначала группа, потом
    # переименование). У члена балансера имя всё равно затирается тегом proxy-N, а имя
    # корзины становится remarks — поэтому внутри балансера rename не нужен.
    universe, seen = [], set()          # [{"link","addr","name","rename"}]
    infos, passthrough = [], {}
    for sub in group.get("subs", []):
        url = (sub or {}).get("url")
        if not url:
            continue
        renames = (sub or {}).get("renames") or []
        try:
            body, headers = fetch_upstream_cached(url)
        except Exception as e:
            print(f"[-] группа «{group.get('name')}»: апстрим {url} недоступен: {e}", flush=True)
            continue
        ui = headers.get("Subscription-Userinfo")
        if ui:
            infos.append(_parse_userinfo(ui))
        for k in _MERGE_PASSTHROUGH:
            if k not in passthrough and headers.get(k):
                passthrough[k] = headers[k]
        for link in extract_links(body):
            if link in seen:
                continue
            seen.add(link)
            addr, nm = _link_addr(link), _frag_name(link)
            universe.append({"link": link, "addr": addr, "name": nm,
                             "rename": _match_rename(addr, nm, renames)})  # НЕ применяем до матча
    for k in group.get("keys", []):
        raw = (k.get("link") or "").strip()
        if not raw or raw in seen:
            continue
        seen.add(raw)
        # имя ключа применяем только при passthrough; для матча корзины — исходная ссылка
        universe.append({"link": raw, "addr": _link_addr(raw),
                         "name": k.get("name") or _frag_name(raw), "rename": (k.get("name") or None)})

    def _emit(u):  # ссылка для passthrough — с применённым переименованием/именем
        return _apply_name(u["link"], u["rename"]) if u.get("rename") is not None else u["link"]

    # авто-режим (нода авто-выбора, roadmap/03A): ВСЕ конвертируемые ссылки → ОДИН
    # балансер leastPing (клиент сам выберет быстрейший по пингу); неконвертируемые →
    # отдельными записями. Корзины не используются.
    if group.get("auto"):
        obs, skipped = [], []
        for u in universe:
            ob, _name = _link_to_outbound(u["link"])
            if ob is None:
                skipped.append(_emit(u))
            else:
                obs.append(ob)
        configs = [_wrap_as_balancer(obs, group.get("name") or "", group.get("params"))] if obs else []
        if skipped:
            schemes = _dedup([l.split("://", 1)[0] for l in skipped if "://" in l])
            print(f"[-] авто-выбор «{group.get('name')}»: {len(skipped)} ссыл. неконвертируемого "
                  f"протокола ({', '.join(schemes)}) → отдаю отдельными записями", flush=True)
        return configs, [], skipped, infos, passthrough

    buckets = group.get("buckets", [])
    members_of = {i: [] for i in range(len(buckets))}
    skipped, leftover, assigned = [], [], set()
    for idx, b in enumerate(buckets):
        for u in universe:
            if u["link"] in assigned:
                continue
            if _member_match(u, b.get("members", [])):   # матч по ИСХОДНОЙ идентичности
                assigned.add(u["link"])
                ob, _name = _link_to_outbound(u["link"])
                if ob is None:
                    skipped.append(_emit(u))        # в корзине, но не xray → passthrough
                else:
                    members_of[idx].append(ob)
    for u in universe:
        if u["link"] not in assigned:
            leftover.append(_emit(u))               # вне корзин → passthrough

    configs = []
    for idx, b in enumerate(buckets):
        obs = members_of[idx]
        if obs:                                      # пустую корзину НЕ эмитим
            configs.append(_wrap_as_balancer(obs, b.get("name") or "", group.get("params")))
    if skipped:
        schemes = _dedup([l.split("://", 1)[0] for l in skipped if "://" in l])
        print(f"[-] группа «{group.get('name')}»: {len(skipped)} ссыл. неконвертируемого "
              f"протокола ({', '.join(schemes)}) в корзинах → отдаю отдельными записями", flush=True)
    return configs, leftover, skipped, infos, passthrough


# ── нода-роутер (#05, Фаза A): клиентский xray-конфиг с routing.rules ─────────
# Пресеты: geosite/geoip-категории, понятные xray + штатной geosite.dat (бандлит Happ).
ROUTER_PRESETS = {
    "telegram":   {"label": "Telegram",         "domain": ["geosite:telegram"],   "ip": ["geoip:telegram"]},
    "youtube":    {"label": "YouTube",          "domain": ["geosite:youtube"],    "ip": []},
    "google":     {"label": "Google",           "domain": ["geosite:google"],     "ip": ["geoip:google"]},
    "discord":    {"label": "Discord",          "domain": ["geosite:discord"],    "ip": []},
    "whatsapp":   {"label": "WhatsApp",         "domain": ["geosite:whatsapp"],   "ip": ["geoip:whatsapp"]},
    "meta":       {"label": "Meta (FB/IG)",     "domain": ["geosite:facebook", "geosite:instagram"], "ip": ["geoip:facebook"]},
    "netflix":    {"label": "Netflix",          "domain": ["geosite:netflix"],    "ip": ["geoip:netflix"]},
    "twitch":     {"label": "Twitch",           "domain": ["geosite:twitch"],     "ip": []},
    "spotify":    {"label": "Spotify",          "domain": ["geosite:spotify"],    "ip": []},
    "twitter":    {"label": "Twitter / X",      "domain": ["geosite:twitter"],    "ip": ["geoip:twitter"]},
    "tiktok":     {"label": "TikTok",           "domain": ["geosite:tiktok"],     "ip": []},
    "cloudflare": {"label": "Cloudflare",       "domain": ["geosite:cloudflare"], "ip": ["geoip:cloudflare"]},
    "openai":     {"label": "OpenAI / ChatGPT", "domain": ["geosite:openai"],     "ip": []},
    "ru_inside":  {"label": "Рунет (внутри)",   "domain": ["geosite:category-ru", "geosite:private"], "ip": ["geoip:ru", "geoip:private"]},
}


def _materialize_target_outbounds(tinfo):
    """Таргет роутера → список xray-outbound'ов (БЕЗ тега; тег ставит вызывающий).
    link→1; group/auto→все конвертируемые члены; direct/неизвестно→[]."""
    kind = (tinfo or {}).get("kind")
    if kind == "link":
        ob, _ = _link_to_outbound(tinfo.get("link") or "")
        return [ob] if ob else []
    if kind in ("group", "auto"):
        cfgs, _leftover, _skipped, _infos, _pass = _resolve_group_members(tinfo)
        obs = []
        for c in cfgs:
            for o in c.get("outbounds", []):
                if str(o.get("tag", "")).startswith("proxy-"):
                    obs.append({k: v for k, v in o.items() if k != "tag"})
        return obs
    return []   # direct / неизвестно


def _wrap_as_router(targets_resolved, rules, default_target, name, params=None):
    """Правила (geosite/geoip → target) → ОДИН клиентский xray-конфиг (Фаза A).
    Каждый таргет → proxy-<tidx>-N; таргет с >1 outbound получает balancer-<tidx>
    (selector ['proxy-<tidx>-']); 1 outbound → прямой outboundTag. routing.rules в
    порядке первого совпадения; финал — default. Неконвертируемые/пустой/пропавший/
    zapret таргет → direct (warn). Структурная функция, как _wrap_as_balancer."""
    p = _norm_balancer_params(params)
    outbounds, balancers, observed, skipped_total = [], [], False, 0
    tag_for = {}                                  # input_id -> ("outbound"|"balancer", tag) | None

    for tidx, tid in enumerate(targets_resolved.keys()):
        tinfo = targets_resolved[tid]
        if (tinfo or {}).get("kind") == "direct":
            continue                              # → штатный freedom 'direct'
        obs = _materialize_target_outbounds(tinfo)
        if not obs:
            skipped_total += 1
            tag_for[tid] = None                   # → direct
            continue
        tagged = []
        for j, ob in enumerate(obs):
            ob = dict(ob)
            ob["tag"] = f"proxy-{tidx}-{j}"
            outbounds.append(ob)
            tagged.append(ob["tag"])
        if len(tagged) == 1:
            tag_for[tid] = ("outbound", tagged[0])
        else:
            btag = f"balancer-{tidx}"
            balancers.append({"tag": btag, "selector": [f"proxy-{tidx}-"],
                              "strategy": {"type": p["strategy"]}})
            tag_for[tid] = ("balancer", btag)
        observed = True

    outbounds.append({"protocol": "freedom", "tag": "direct"})
    outbounds.append({"protocol": "blackhole", "tag": "block"})

    def _dest(tid):
        if tid == "direct" or tid not in tag_for or tag_for[tid] is None:
            return {"outboundTag": "direct"}
        kind, val = tag_for[tid]
        return {"balancerTag": val} if kind == "balancer" else {"outboundTag": val}

    rrules = []
    for rule in rules:
        m = rule.get("match") or {}
        mk, mv = m.get("kind"), m.get("value")
        if mk == "preset":
            pr = ROUTER_PRESETS.get(mv)
            if not pr:
                continue
            doms, ips = list(pr.get("domain") or []), list(pr.get("ip") or [])
        elif mk == "domain":
            doms, ips = ([mv] if mv else []), []
        elif mk == "ip":
            doms, ips = [], ([mv] if mv else [])
        else:
            continue
        if not doms and not ips:
            continue
        r = {"type": "field"}
        if doms:
            r["domain"] = doms
        if ips:
            r["ip"] = ips
        r.update(_dest(rule.get("target")))
        rrules.append(r)
    dflt = {"type": "field", "network": "tcp,udp"}
    dflt.update(_dest(default_target))
    rrules.append(dflt)

    if skipped_total:
        print(f"[-] роутер «{name}»: {skipped_total} таргет(ов) без конвертируемых "
              f"outbound'ов → их трафик уходит в direct", flush=True)

    cfg = {
        "remarks": name,
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": [
            {"tag": "socks", "port": 10808, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}},
            {"tag": "http", "port": 10809, "listen": "127.0.0.1", "protocol": "http"},
        ],
        "outbounds": outbounds,
        "routing": {"domainStrategy": p["domain_strategy"], "rules": rrules},
    }
    if balancers:
        cfg["routing"]["balancers"] = balancers
    if observed:
        cfg["burstObservatory"] = {
            "subjectSelector": ["proxy-"],
            "pingConfig": {"destination": p["probe_url"], "interval": p["interval"],
                           "timeout": p["timeout"], "sampling": p["sampling"]},
        }
    return cfg


def build_merged_response(route, spec, announce=""):
    """Слияние подписок и прямых ключей в один ответ.
       spec = {"subs":[{"url","renames"}], "keys":[{"link","name"}]}.
    Если среди источников есть подписка в формате JSON-конфигов Happ («нода» с
    маршрутизацией/балансировкой) — сохраняем группировку: её конфиги отдаём как есть,
    а плоские ссылки/ключи оборачиваем каждую в отдельный конфиг (vless/vmess/trojan/ss).
    Группы НЕ разворачиваем в плоский список (иначе одна «нода» превратилась бы в десятки
    ссылок). Если JSON-нод нет — отдаём base64-список. Переименования применяем после
    дедупа (гибрид: адрес → имя)."""
    subs = spec.get("subs", []) if isinstance(spec, dict) else []
    keys = spec.get("keys", []) if isinstance(spec, dict) else []
    groups = spec.get("groups", []) if isinstance(spec, dict) else []
    routers = spec.get("routers", []) if isinstance(spec, dict) else []

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

    # Ноды-группы: каждая непустая корзина → один конфиг с балансером; членов вне корзин
    # и неконвертируемых отдаём отдельными ссылками (passthrough), не теряя.
    group_configs, group_pass = [], []
    for g in groups:
        cfgs, leftover, skipped, g_infos, g_pass = _resolve_group_members(g)
        group_configs.extend(cfgs)
        group_pass.extend(leftover)
        group_pass.extend(skipped)
        infos.extend(g_infos)
        for k, v in g_pass.items():
            passthrough.setdefault(k, v)

    # Ноды-роутеры (#05): каждый → один конфиг с routing.rules. Дедуп по id.
    router_configs, seen_router = [], set()
    for rt in routers:
        rid = rt.get("id")
        if rid in seen_router:
            continue
        seen_router.add(rid)
        router_configs.append(_wrap_as_router(
            rt.get("targets") or {}, rt.get("rules") or [],
            rt.get("default_target") or "direct", rt.get("name") or "", rt.get("params")))

    have_json = bool(json_items) or bool(group_configs) or bool(router_configs)   # балансер/роутер форсят JSON
    out_configs = [it["cfg"] for it in json_items]
    out_links = [it["link"] for it in text_items]
    flat = _dedup(out_links + key_links + group_pass)

    if have_json:
        # Есть хотя бы одна подписка-«нода» (JSON-конфиги Happ) — СОХРАНЯЕМ группировку:
        # её конфиги отдаём как есть, а плоские ссылки/ключи оборачиваем каждую в свой
        # конфиг (vless/vmess/trojan/ss). Неконвертируемые в xray (hysteria2/tuic/ssr)
        # пропускаем с логом — НЕ разворачиваем «ноды» в плоский список ради них.
        extra, skipped = [], []
        for link in flat:
            ob, name = _link_to_outbound(link)
            if ob:
                extra.append(_wrap_as_config(ob, name))
            else:
                skipped.append(link)
        if skipped:
            schemes = _dedup([l.split("://", 1)[0] for l in skipped if "://" in l])
            print(f"[-] пропущено {len(skipped)} ссыл. неконвертируемого протокола "
                  f"({', '.join(schemes)}) — группировка JSON-нод сохранена", flush=True)
        out_headers = {"Content-Type": "application/json; charset=utf-8"}
        out_headers.update(passthrough)
        # конфиги-группы (балансеры) идут первыми, затем JSON-ноды источников, затем
        # обёрнутые плоские ссылки; дедуп по полному identity (с remarks).
        payload = json.dumps(_dedup_configs(router_configs + group_configs + out_configs + extra),
                             ensure_ascii=False).encode("utf-8")
    else:
        # Только плоские источники/ключи (или ничего) — base64-список ссылок.
        payload = _b64list(flat)
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
    groups = spec.get("groups", [])
    routers = spec.get("routers", [])
    mode = route.get("mode", "merge")
    has_renames = any((s.get("renames") for s in subs))
    # Зеркало байт-в-байт возможно только без ключей/групп/роутеров/переименований и с одной подпиской.
    if mode == "mirror" and len(subs) == 1 and not keys and not groups and not routers and not has_renames:
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
