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


def _profile_title_header(title):
    encoded = base64.b64encode(title.encode("utf-8")).decode("ascii")
    return "base64:" + encoded


def build_mirror_response(route, url):
    body, headers = fetch_upstream_cached(url)
    headers = dict(headers)
    if route.get("title"):
        headers["Profile-Title"] = _profile_title_header(route["title"])
    return body, headers


def build_merged_response(route, urls, custom_text=""):
    all_links = []
    seen = set()
    infos = []
    for url in urls:
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
    # свой sub-текст маршрута (и транзитивно — из подключённых маршрутов)
    if custom_text and custom_text.strip():
        for link in extract_links(custom_text.encode("utf-8")):
            if link not in seen:
                seen.add(link)
                all_links.append(link)
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


def build_route_response(route, urls=None, custom_text=""):
    """urls/custom_text — разрешённый (транзитивный) набор. Если urls=None,
    берём route['upstreams'] (обратная совместимость)."""
    if urls is None:
        urls = route.get("upstreams", [])
    mode = route.get("mode", "merge")
    if mode == "mirror" and len(urls) == 1 and not (custom_text or "").strip():
        return build_mirror_response(route, urls[0])
    return build_merged_response(route, urls, custom_text)
