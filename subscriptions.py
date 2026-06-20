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


def build_merged_response(route, urls, announce=""):
    """Слияние нескольких ключей в один. Если upstream'ы отдают JSON-конфиги
    (формат Happ/xray с routing/балансерами) — СКЛЕИВАЕМ массивы конфигов, сохраняя
    формат (как /s/sub). Если base64/текст-списки — отдаём base64-список ссылок."""
    json_configs = []
    seen_cfg = set()
    text_links = []
    seen_link = set()
    infos = []
    passthrough = {}
    for url in urls:
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
        if isinstance(parsed, list):
            cfgs = parsed
        elif isinstance(parsed, dict):
            cfgs = [parsed]
        else:
            cfgs = None
        if cfgs is not None:
            for cfg in cfgs:
                key = json.dumps(cfg, sort_keys=True, ensure_ascii=False)
                if key not in seen_cfg:
                    seen_cfg.add(key)
                    json_configs.append(cfg)
        else:
            for link in extract_links(body):
                if link not in seen_link:
                    seen_link.add(link)
                    text_links.append(link)

    if json_configs and not text_links:
        # все источники — JSON-конфиги: склеиваем массивы (сохраняем формат Happ)
        payload = json.dumps(json_configs, ensure_ascii=False).encode("utf-8")
        out_headers = {"Content-Type": "application/json; charset=utf-8"}
        out_headers.update(passthrough)
    elif text_links and not json_configs:
        payload = base64.b64encode(("\n".join(text_links)).encode("utf-8")).decode("ascii").encode("ascii")
        out_headers = {"Content-Type": "text/plain; charset=utf-8"}
    elif json_configs and text_links:
        # смешанные источники: JSON-конфиги оставляем сгруппированными, а плоские
        # vless-ссылки оборачиваем в отдельные конфиги (чтобы группировка JSON не терялась).
        wrapped, leftover = [], []
        for link in text_links:
            ob, name = _vless_to_outbound(link)
            if ob:
                wrapped.append(_wrap_as_config(ob, name))
            else:
                leftover.append(link)
        if not leftover:
            payload = json.dumps(json_configs + wrapped, ensure_ascii=False).encode("utf-8")
            out_headers = {"Content-Type": "application/json; charset=utf-8"}
            out_headers.update(passthrough)
        else:
            # есть не-vless ссылки, которые так не обернуть — сводим всё к base64-списку
            all_links = list(text_links)
            seen = set(text_links)
            for cfg in json_configs:
                for ob, rem in _find_vless_outbounds(cfg):
                    link = _vless_from_outbound(ob, rem)
                    if link and link not in seen:
                        seen.add(link)
                        all_links.append(link)
            payload = base64.b64encode(("\n".join(all_links)).encode("utf-8")).decode("ascii").encode("ascii")
            out_headers = {"Content-Type": "text/plain; charset=utf-8"}
    else:
        # ничего не нашли
        payload = base64.b64encode(b"").decode("ascii").encode("ascii")
        out_headers = {"Content-Type": "text/plain; charset=utf-8"}

    out_headers.setdefault("Profile-Update-Interval", "12")
    if route.get("title"):
        out_headers["Profile-Title"] = _b64_header(route["title"])
    if announce and announce.strip():
        out_headers["Announce"] = _b64_header(announce.strip())
    if infos:
        out_headers["Subscription-Userinfo"] = _aggregate_userinfo(infos)
    return payload, out_headers


def build_route_response(route, urls=None, announce=""):
    """urls — разрешённый (транзитивный) набор источников. announce — текст под
    подпиской (заголовок Announce). Если urls=None, берём route['upstreams']."""
    if urls is None:
        urls = route.get("upstreams", [])
    mode = route.get("mode", "merge")
    if mode == "mirror" and len(urls) == 1:
        return build_mirror_response(route, urls[0], announce)
    return build_merged_response(route, urls, announce)
