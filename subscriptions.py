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
import uuid
import base64
import threading
import urllib.request
from urllib.parse import quote as _urlquote, urlencode as _urlencode
import urllib.parse

UPSTREAM_TIMEOUT = int(os.environ.get("UPSTREAM_TIMEOUT", "20"))
# Не позволяем старому .env с CACHE_TTL=60 снова устроить шквал запросов после обновления.
# Значение можно увеличить, но не уменьшить ниже трёх часов.
CACHE_TTL = max(10800, int(os.environ.get("CACHE_TTL", "10800")))

# HWID/device — НЕ хардкодим реальный отпечаток. По умолчанию генерируем случайный
# (стабильный в пределах запуска); для стабильности между рестартами задай HAPP_HWID.
_DEFAULT_HWID = str(uuid.uuid4())

UPSTREAM_HEADERS = {
    "User-Agent": os.environ.get("HAPP_UA", "Happ/2.16.2/Windows/2605221224603"),
    "X-App-Version": os.environ.get("HAPP_VERSION", "2.16.2"),
    "X-Device-Locale": "RU",
    "X-Device-Os": "Windows",
    "X-Device-Model": os.environ.get("HAPP_DEVICE_MODEL", "DESKTOP-0000000_x86_64"),
    "X-Hwid": os.environ.get("HAPP_HWID") or _DEFAULT_HWID,
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
_cache_inflight = {}


# Injected by the server; unsafe feeds never fall back to unverified upstream data.
checked_source_reader = None


def fetch_source(source):
    if source.get("unsafe"):
        return checked_source_reader(source["url"]) if checked_source_reader else (b"", {})
    return fetch_upstream_cached(source["url"])


def unsafe_name(name):
    return name if str(name).startswith("Небезопасный · ") else "Небезопасный · " + (name or "Группа")


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
    """Общий кэш upstream + single-flight на URL.

    Даже если сотни клиентов одновременно обновятся после истечения TTL, к VPN-
    провайдеру уйдёт один запрос; остальные дождутся его результата из кэша.
    """
    while True:
        now = time.time()
        with _cache_lock:
            entry = _cache.get(url)
            if entry and (now - entry["ts"]) < CACHE_TTL:
                if entry.get("error") is not None:
                    raise entry["error"]
                return entry["body"], entry["headers"]
            event = _cache_inflight.get(url)
            if event is None:
                event = _cache_inflight[url] = threading.Event()
                owner = True
            else:
                owner = False
        if owner:
            try:
                body, headers = fetch_upstream(url)
                with _cache_lock:
                    _cache[url] = {"ts": time.time(), "body": body, "headers": headers}
                return body, headers
            except Exception as exc:
                with _cache_lock:
                    stale = _cache.get(url)
                    if stale and stale.get("body") is not None:
                        # Провайдер временно недоступен: не роняем подписки и не
                        # повторяем запрос для каждого клиента — продлеваем stale.
                        stale["ts"] = time.time()
                        return stale["body"], stale["headers"]
                    # На холодном старте также запоминаем ошибку на TTL: один сбой
                    # не превращается в сотни одинаковых запросов от клиентов.
                    _cache[url] = {"ts": time.time(), "error": exc}
                raise
            finally:
                with _cache_lock:
                    _cache_inflight.pop(url, None)
                    event.set()
        # У владельца сетевой таймаут ограничен UPSTREAM_TIMEOUT. После его ошибки
        # ожидающий сам станет владельцем и попробует снова; вечного ожидания нет.
        event.wait(UPSTREAM_TIMEOUT + 5)


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
    if link.lower().startswith("ssr://"):
        try:
            raw = link[6:].split("#", 1)[0]
            raw = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode()
            head, _, query = raw.partition("/?")
            params = urllib.parse.parse_qs(query)
            params["remarks"] = [base64.urlsafe_b64encode(name.strip().encode()).decode().rstrip("=")]
            raw = head + "/?" + urllib.parse.urlencode(params, doseq=True)
            link = "ssr://" + base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
        except (ValueError, TypeError):
            pass
    if link.lower().startswith("vmess://"):
        try:
            raw = link[8:].split("#", 1)[0]
            value = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
            value["ps"] = name.strip()
            link = "vmess://" + base64.b64encode(json.dumps(value, ensure_ascii=False).encode()).decode()
        except (ValueError, TypeError):
            pass
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
    Это же ядро для авто-выбора (одна корзина = все входы). Чисто структурная функция:
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
            body, headers = fetch_source(sub)
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

    # авто-режим (нода авто-выбора): ВСЕ конвертируемые ссылки → ОДИН
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
        configs = [_wrap_as_balancer(obs, unsafe_name(group.get("name")) if group.get("unsafe") else group.get("name") or "", group.get("params"))] if obs else []
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
            configs.append(_wrap_as_balancer(obs, unsafe_name(b.get("name")) if group.get("unsafe") else b.get("name") or "", group.get("params")))
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


def _router_core(targets_resolved, rules, default_target, p, name):
    """Общее ядро роутера → (outbounds, balancers, rrules, observed, skipped).
    outbounds БЕЗ freedom/blackhole — их добавляет вызывающий (клиент: обычный freedom;
    сервер-gateway: freedom с fwmark). Используется _wrap_as_router и _wrap_as_server_gateway.
    Каждый таргет → proxy-<tidx>-N; >1 outbound → balancer-<tidx>; zapret/пустой/direct → direct."""
    outbounds, balancers, observed, skipped_total = [], [], False, 0
    tag_for = {}                                  # input_id -> ("outbound"|"balancer", tag) | None
    for tidx, tid in enumerate(targets_resolved.keys()):
        tinfo = targets_resolved[tid]
        if (tinfo or {}).get("kind") == "direct":
            continue                              # → штатный freedom 'direct'
        obs = _materialize_target_outbounds(tinfo)
        if not obs:
            skipped_total += 1
            tag_for[tid] = ("outbound", "block") if tinfo.get("unsafe") else None
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
              f"outbound'ов → direct для обычных, block для небезопасных источников", flush=True)
    return outbounds, balancers, rrules, observed, skipped_total


def _wrap_as_router(targets_resolved, rules, default_target, name, params=None):
    """Правила (geosite/geoip → target) → ОДИН КЛИЕНТСКИЙ xray-конфиг (Фаза A):
    socks/http inbound; ядро (outbounds/routing) — общее с серверным gateway."""
    p = _norm_balancer_params(params)
    outbounds, balancers, rrules, observed, _ = _router_core(targets_resolved, rules, default_target, p, name)
    outbounds = outbounds + [{"protocol": "freedom", "tag": "direct"},
                             {"protocol": "blackhole", "tag": "block"}]
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


# ── нода-роутер: СЕРВЕРНЫЙ режим (gateway) ────────────────────────────────────
# Один vless-ws inbound НА УЗЛЕ; xray раскидывает трафик server-side: zapret-таргет →
# freedom 'direct' (egress + nfqws, скоуп по fwmark), остальное → balancer/outbound
# аплинков (лучший VPN). TLS терминирует Caddy/Coolify на 443 → xray получает чистый ws.
GATEWAY_MARK = int(os.environ.get("GATEWAY_FWMARK", "1080"))
GATEWAY_PORT = int(os.environ.get("GATEWAY_PORT", "8084"))
GATEWAY_WS_PATH = os.environ.get("GATEWAY_WS_PATH", "/vlessws")


def _wrap_as_server_gateway(targets_resolved, rules, default_target, name, inbound, params=None):
    """СЕРВЕРНЫЙ xray-конфиг узла-gateway: vless-ws inbound + routing (ядро роутера).
    inbound = {"uuid","path","port"}. freedom 'direct' помечается fwmark — nfqws на egress
    скоупится РОВНО на zapret-таргетный трафик (аплинки идут нетронутыми). sniffing включён,
    иначе server-side geosite/domain-правила не видят SNI."""
    p = _norm_balancer_params(params)
    outbounds, balancers, rrules, observed, _ = _router_core(targets_resolved, rules, default_target, p, name)
    outbounds = outbounds + [
        {"protocol": "freedom", "tag": "direct", "streamSettings": {"sockopt": {"mark": GATEWAY_MARK}}},
        {"protocol": "blackhole", "tag": "block"},
    ]
    uid = (inbound or {}).get("uuid") or ""
    path = (inbound or {}).get("path") or GATEWAY_WS_PATH
    port = int((inbound or {}).get("port") or GATEWAY_PORT)
    cfg = {
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": [{
            "tag": "vless-in", "listen": "0.0.0.0", "port": port, "protocol": "vless",
            "settings": {"clients": [{"id": uid, "email": name or "gateway"}], "decryption": "none"},
            "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": path}},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
        }],
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


def _gateway_link(domain, uuid_str, path=None, name="gateway", port=443):
    """Универсальная клиентская vless-ссылка на gateway (vless + ws + tls через 443)."""
    q = _urlencode({"encryption": "none", "security": "tls", "type": "ws",
                    "host": domain, "path": path or GATEWAY_WS_PATH, "sni": domain})
    return f"vless://{uuid_str}@{domain}:{port}?{q}#{_urlquote(name or 'gateway')}"


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
            body, headers = fetch_source(sub)
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
            rt.get("default_target") or "direct", unsafe_name(rt.get("name")) if rt.get("unsafe") else rt.get("name") or "", rt.get("params")))

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


_CLASH_UA_MARKERS = (
    "koala clash", "koala-clash", "koalaclash",
    "clash-verge", "clash verge", "clash.meta", "clashmeta",
    "mihomo", "clash for windows", "clashforwindows", "clashx",
    "clash/", "stash/",
)


def select_output_format(request_target="", user_agent="", accept=""):
    """Choose the wire format without changing the historical Happ response.

    An explicit ``?format=clash`` is useful for clients that hide or spoof their
    User-Agent.  Known Clash/mihomo clients are detected automatically.  Every
    other client keeps receiving the byte-for-byte legacy format.
    """
    query = urllib.parse.urlsplit(request_target or "").query
    requested = (urllib.parse.parse_qs(query).get("format", [""])[0] or "").strip().lower()
    if requested in ("clash", "clash-meta", "meta", "mihomo", "koala", "yaml", "yml"):
        return "clash"
    if requested in ("happ", "xray", "base64", "raw", "legacy"):
        return "legacy"
    ua = (user_agent or "").lower()
    if any(marker in ua for marker in _CLASH_UA_MARKERS):
        return "clash"
    accepted = (accept or "").lower()
    if "application/yaml" in accepted or "application/x-yaml" in accepted:
        return "clash"
    return "legacy"


def _clash_transport(proxy, stream):
    """Copy Xray transport/TLS settings into their mihomo equivalents."""
    stream = stream if isinstance(stream, dict) else {}
    network = str(stream.get("network") or "tcp").lower()
    security = str(stream.get("security") or "none").lower()
    proxy["udp"] = True
    if security in ("tls", "xtls", "reality"):
        proxy["tls"] = True
        tls = stream.get("realitySettings") if security == "reality" else stream.get("tlsSettings")
        tls = tls if isinstance(tls, dict) else {}
        servername = tls.get("serverName") or tls.get("serverNameToVerify")
        if servername:
            proxy["servername"] = servername
        fingerprint = tls.get("fingerprint")
        if fingerprint:
            proxy["client-fingerprint"] = fingerprint
        if tls.get("allowInsecure"):
            proxy["skip-cert-verify"] = True
        if security == "reality":
            reality = {}
            if tls.get("publicKey"):
                reality["public-key"] = tls["publicKey"]
            if tls.get("shortId"):
                reality["short-id"] = tls["shortId"]
            if reality:
                proxy["reality-opts"] = reality
    if network == "ws":
        ws = stream.get("wsSettings") if isinstance(stream.get("wsSettings"), dict) else {}
        proxy["network"] = "ws"
        opts = {"path": ws.get("path") or "/"}
        headers = ws.get("headers")
        if isinstance(headers, dict) and any(str(v) for v in headers.values()):
            opts["headers"] = headers
        proxy["ws-opts"] = opts
    elif network == "grpc":
        grpc = stream.get("grpcSettings") if isinstance(stream.get("grpcSettings"), dict) else {}
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {"grpc-service-name": grpc.get("serviceName") or ""}
    elif network in ("http", "h2"):
        http = stream.get("httpSettings") if isinstance(stream.get("httpSettings"), dict) else {}
        proxy["network"] = "h2"
        proxy["h2-opts"] = {"path": http.get("path") or "/", "host": http.get("host") or []}


def _xray_outbound_to_clash(outbound, name):
    """Convert the common Xray outbounds emitted/accepted by this project."""
    if not isinstance(outbound, dict):
        return None
    protocol = str(outbound.get("protocol") or "").lower()
    settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
    stream = outbound.get("streamSettings")
    try:
        if protocol in ("vless", "vmess"):
            vnext = settings["vnext"][0]
            user = vnext["users"][0]
            proxy = {"name": name, "type": protocol, "server": vnext["address"],
                     "port": int(vnext["port"]), "uuid": user["id"]}
            if protocol == "vless":
                proxy["flow"] = user.get("flow") or ""
                proxy["encryption"] = user.get("encryption") or ""
            else:
                proxy["alterId"] = int(user.get("alterId") or 0)
                proxy["cipher"] = user.get("security") or "auto"
            _clash_transport(proxy, stream)
            return proxy
        if protocol == "trojan":
            server = settings["servers"][0]
            proxy = {"name": name, "type": "trojan", "server": server["address"],
                     "port": int(server["port"]), "password": server["password"]}
            _clash_transport(proxy, stream)
            return proxy
        if protocol in ("shadowsocks", "ss"):
            server = settings["servers"][0]
            return {"name": name, "type": "ss", "server": server["address"],
                    "port": int(server["port"]), "cipher": server["method"],
                    "password": server["password"], "udp": True}
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    return None


def _share_link_to_clash(link, name):
    outbound, parsed_name = _link_to_outbound(link)
    if outbound:
        return _xray_outbound_to_clash(outbound, name or parsed_name or "Proxy")
    try:
        u = urllib.parse.urlsplit(link)
        q = urllib.parse.parse_qs(u.query)
        one = lambda key, default="": q.get(key, [default])[0]
        scheme = u.scheme.lower()
        if scheme in ("hysteria2", "hy2") and u.hostname:
            proxy = {"name": name or urllib.parse.unquote(u.fragment) or u.hostname,
                     "type": "hysteria2", "server": u.hostname, "port": u.port or 443,
                     "password": urllib.parse.unquote(u.username or "")}
            if one("sni") or one("peer"):
                proxy["sni"] = one("sni") or one("peer")
            if one("insecure") in ("1", "true"):
                proxy["skip-cert-verify"] = True
            if one("obfs"):
                proxy["obfs"] = one("obfs")
            if one("obfs-password") or one("obfsParam"):
                proxy["obfs-password"] = one("obfs-password") or one("obfsParam")
            return proxy
        if scheme == "tuic" and u.hostname:
            proxy = {"name": name or urllib.parse.unquote(u.fragment) or u.hostname,
                     "type": "tuic", "server": u.hostname, "port": u.port or 443,
                     "uuid": urllib.parse.unquote(u.username or ""),
                     "password": urllib.parse.unquote(u.password or "")}
            if one("sni"):
                proxy["sni"] = one("sni")
            if one("congestion_control") or one("congestion-controller"):
                proxy["congestion-controller"] = one("congestion_control") or one("congestion-controller")
            proxy["udp-relay-mode"] = one("udp_relay_mode") or "native"
            return proxy
    except (TypeError, ValueError):
        pass
    return None


def _unique_clash_name(preferred, used):
    base = str(preferred or "Proxy").strip() or "Proxy"
    candidate, n = base, 2
    while candidate in used:
        candidate = f"{base} #{n}"
        n += 1
    used.add(candidate)
    return candidate


def _render_clash_yaml(proxies, groups, rules):
    """Emit dependency-free YAML; JSON flow mappings are valid YAML 1.2."""
    compact = lambda value: json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    lines = ["# Generated by sub-cluster for Clash/mihomo clients",
             "mixed-port: 7890", "allow-lan: false", "mode: rule",
             "log-level: info", "ipv6: false"]
    lines.append("proxies:" if proxies else "proxies: []")
    lines.extend("  - " + compact(proxy) for proxy in proxies)
    lines.append("proxy-groups:" if groups else "proxy-groups: []")
    lines.extend("  - " + compact(group) for group in groups)
    lines.append("rules:" if rules else "rules: []")
    lines.extend("  - " + compact(rule) for rule in rules)
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_clash_response(body, headers, title=""):
    """Convert a legacy Happ/base64 response to one runnable mihomo profile."""
    text = body.decode("utf-8", errors="ignore").lstrip("\ufeff\r\n \t")
    # A mirror may already be a native Clash subscription. Preserve its rules verbatim.
    if re.search(r"(?m)^\s*proxies\s*:", text) and re.search(r"(?m)^\s*(proxy-groups|rules)\s*:", text):
        out_headers = dict(headers or {})
        out_headers["Content-Type"] = "application/yaml; charset=utf-8"
        return body, out_headers

    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    configs = parsed if isinstance(parsed, list) else ([parsed] if isinstance(parsed, dict) else [])
    proxies, groups, profile_targets, used = [], [], [], set()

    for index, cfg in enumerate(configs, 1):
        if not isinstance(cfg, dict):
            continue
        base = str(cfg.get("remarks") or f"Profile {index}")
        converted = []
        candidates = [ob for ob in (cfg.get("outbounds") or [])
                      if isinstance(ob, dict) and ob.get("protocol") not in ("freedom", "blackhole", "loopback", "dns")]
        for ob in candidates:
            raw_name = base if len(candidates) == 1 else f"{base} · {ob.get('tag') or len(converted) + 1}"
            proxy_name = _unique_clash_name(raw_name, used)
            proxy = _xray_outbound_to_clash(ob, proxy_name)
            if proxy:
                proxies.append(proxy)
                converted.append(proxy_name)
            else:
                used.discard(proxy_name)
        if not converted:
            continue
        if len(converted) == 1:
            profile_targets.append(converted[0])
        else:
            group_name = _unique_clash_name(base, used)
            auto = bool(((cfg.get("routing") or {}).get("balancers") or []))
            group = {"name": group_name, "type": "url-test" if auto else "select", "proxies": converted}
            if auto:
                group.update({"url": "http://www.gstatic.com/generate_204", "interval": 300})
            groups.append(group)
            profile_targets.append(group_name)

    if not configs:
        for index, link in enumerate(extract_links(body), 1):
            raw_name = _frag_name(link) or f"Proxy {index}"
            proxy_name = _unique_clash_name(raw_name, used)
            proxy = _share_link_to_clash(link, proxy_name)
            if proxy:
                proxies.append(proxy)
                profile_targets.append(proxy_name)
            else:
                used.discard(proxy_name)

    proxy_names = [proxy["name"] for proxy in proxies]
    if proxy_names:
        auto_name = _unique_clash_name("♻️ Auto", used)
        groups.append({"name": auto_name, "type": "url-test", "proxies": proxy_names,
                       "url": "http://www.gstatic.com/generate_204", "interval": 300})
        main_name = _unique_clash_name(title or "🚀 Proxy", used)
        choices = _dedup(profile_targets + [auto_name, "DIRECT"])
        groups.append({"name": main_name, "type": "select", "proxies": choices})
        rules = [f"MATCH,{main_name}"]
    else:
        rules = ["MATCH,DIRECT"]

    out_headers = dict(headers or {})
    out_headers["Content-Type"] = "application/yaml; charset=utf-8"
    out_headers["Content-Disposition"] = "attachment; filename=subscription.yaml"
    return _render_clash_yaml(proxies, groups, rules), out_headers


_BLOCKED_MESSAGE = "Вы были заблокированы. Обратитесь в Telegram @Jammeren2"
_BLOCKED_NAME = "Заблокирован"
_BLOCKED_HOST = "blocked.invalid"  # зарезервированная DNS-зона, соединение невозможно
_BLOCKED_UUID = "00000000-0000-4000-8000-000000000000"


def build_blocked_response(output_format="legacy"):
    """Валидная, но заведомо нерабочая подписка, заменяющая старые серверы клиента."""
    common_headers = {
        "Cache-Control": "no-store",
        "Profile-Title": _b64_header(_BLOCKED_MESSAGE),
        "Announce": _b64_header(_BLOCKED_MESSAGE),
        "Subscription-Userinfo": "upload=0; download=0; total=0",
    }
    if output_format == "clash":
        proxy = {"name": _BLOCKED_NAME, "type": "vless", "server": _BLOCKED_HOST,
                 "port": 1, "uuid": _BLOCKED_UUID, "udp": False}
        group_name = "VPN"
        body = _render_clash_yaml(
            [proxy], [{"name": group_name, "type": "select", "proxies": [_BLOCKED_NAME]}],
            [f"MATCH,{group_name}"])
        headers = dict(common_headers)
        headers.update({"Content-Type": "application/yaml; charset=utf-8",
                        "Content-Disposition": "attachment; filename=subscription.yaml"})
        return body, headers

    params = _urlencode({"encryption": "none", "security": "none", "type": "tcp"})
    link = (f"vless://{_BLOCKED_UUID}@{_BLOCKED_HOST}:1?{params}#"
            f"{_urlquote(_BLOCKED_NAME)}")
    headers = dict(common_headers)
    headers["Content-Type"] = "text/plain; charset=utf-8"
    return _b64list([link]), headers


def build_route_response(route, spec=None, announce="", output_format="legacy"):
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
    if mode == "mirror" and len(subs) == 1 and not keys and not groups and not routers and not has_renames and not spec.get("unsafe"):
        body, headers = build_mirror_response(route, subs[0]["url"], announce)
    else:
        body, headers = build_merged_response(route, spec, announce)
    if output_format == "clash":
        return build_clash_response(body, headers, route.get("title") or "")
    return body, headers


def preview_subscription(url, limit=1000, body=None):
    """Скачать подписку и вернуть [{name, addr, link}] для UI-переименования.
    Гранулярность совпадает с merge: JSON → по конфигам, текст/base64 → по ссылкам."""
    if body is None:
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
