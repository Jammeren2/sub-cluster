#!/usr/bin/env python3
"""
cluster.py — кластер узлов: опрос живости, синхронизация конфига, DNS-фейловер.

Каждый узел:
  • периодически пингует остальных (HMAC-подпись через CLUSTER_SECRET);
  • тянет и сливает их config/failover (LWW) — конфиг расходится по кластеру;
  • вычисляет, кто должен быть активным (самый живой по приоритету), и при
    необходимости переписывает A-записи обоих доменов на себя через DNS-провайдера.

Защита от split-brain: авто-захват DNS происходит только если узел — самый
приоритетный среди живых И кворум (большинство участников) согласен, что текущий
активный мёртв. Меньшинство в разрыве сети не перетянет DNS на себя.
"""

import os
import time
import json
import hmac
import socket
import hashlib
import ssl
import secrets
import threading
import urllib.request
import urllib.error

import secretbox
import dns_providers


def _build_ssl_context():
    """CA-контекст для https-запросов к пирам (admin-домены, серты Let's Encrypt).
    На slim-образах системного CA-бандла может не быть — берём certifi."""
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


_SSL_CTX = _build_ssl_context()

# ── идентичность узла из окружения ─────────────────────────────────────────
NODE_ID = os.environ.get("NODE_ID") or socket.gethostname() or "node"
NODE_LABEL = os.environ.get("NODE_LABEL") or NODE_ID
NODE_PUBLIC_IP = os.environ.get("NODE_PUBLIC_IP", "").strip()
NODE_PRIORITY = int(os.environ.get("NODE_PRIORITY", "100"))
CLUSTER_PORT = int(os.environ.get("CLUSTER_PORT", "8083"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8080"))
SUB_PORT = int(os.environ.get("SUB_PORT", "8081"))
CLUSTER_SECRET = os.environ.get("CLUSTER_SECRET", "")
CLUSTER_SCHEME = os.environ.get("CLUSTER_SCHEME", "http")  # схема для фолбэка ip:port
# Публичный адрес ЭТОГО узла для пиров — статичный admin-домен по 443, напр.
# https://admin1.example.net. Тогда узлы ходят друг к другу через прокси (443),
# и проброс портов 1753/8083 не нужен (NAT-узлы работают через уже открытый 443).
CLUSTER_URL = os.environ.get("CLUSTER_URL", "").strip().rstrip("/")
HTTP_TIMEOUT = int(os.environ.get("CLUSTER_HTTP_TIMEOUT", "6"))
# Окно валидности подписи peer-запроса. Узкое, т.к. peer-API теперь доступен и по
# 443 (через admin-домен) — каждый запрос ещё и одноразовый (nonce), см. verify().
TS_SKEW = int(os.environ.get("CLUSTER_TS_SKEW", "30"))


def _seed_bases():
    """PEERS=ip:port,ip:port — стартовые адреса для бутстрапа (до синка конфига)."""
    out = []
    for part in os.environ.get("PEERS", "").split(","):
        part = part.strip()
        if not part:
            continue
        if "://" not in part:
            part = f"{CLUSTER_SCHEME}://{part}"
        out.append(part.rstrip("/"))
    return out


class Cluster:
    def __init__(self, store, identity=None):
        ident = identity or {}
        self.store = store
        self.id = ident.get("id", NODE_ID)
        self.label = ident.get("label", NODE_LABEL if ident.get("id") is None else ident["id"])
        self.public_ip = ident.get("public_ip", NODE_PUBLIC_IP)
        self.priority = int(ident.get("priority", NODE_PRIORITY))
        self.cluster_port = int(ident.get("cluster_port", CLUSTER_PORT))
        self.admin_port = int(ident.get("admin_port", ADMIN_PORT))
        self.sub_port = int(ident.get("sub_port", SUB_PORT))
        self.secret = ident.get("secret", CLUSTER_SECRET)
        self.scheme = ident.get("scheme", CLUSTER_SCHEME)
        self.cluster_url = ident.get("cluster_url", CLUSTER_URL)
        self.http_timeout = int(ident.get("http_timeout", HTTP_TIMEOUT))
        self.seeds = ident.get("seeds", _seed_bases())
        self._lock = threading.Lock()
        # id -> {alive,last_ok,fails,latency,view(list),active,ts}
        self.liveness = {}
        self._nonce_seen = {}  # nonce -> expiry (защита от повторного проигрывания)
        self._stop = threading.Event()
        self._thread = None

    # ── участники кластера ────────────────────────────────────────────────
    def get_nodes(self):
        """Включённые участники (список dict)."""
        return [dict(e) for e in self.store.get_members().values() if e.get("enabled", True)]

    def all_nodes(self):
        return [dict(e) for e in self.store.get_members().values()]

    def find_node(self, node_id):
        return self.store.get_members().get(node_id)

    def ensure_self_registered(self):
        """Гарантирует свою запись в members. Инфра-поля (ip/порты) берём из env;
        UI-поля (priority/label/enabled) задаются один раз и далее правятся в UI."""
        members = self.store.get_members(include_deleted=True)
        me = members.get(self.id)
        # Узел удалён администратором (тумбстоун) — не воскрешаем себя.
        if me is not None and me.get("_deleted"):
            return
        fields = {}
        # инфра-поля: env авторитетен
        for field, val in (("public_ip", self.public_ip), ("cluster_port", self.cluster_port),
                           ("admin_port", self.admin_port), ("sub_port", self.sub_port),
                           ("cluster_url", self.cluster_url)):
            if val and (me is None or me.get(field) != val):
                fields[field] = val
        # UI-поля: только если узла ещё нет или поле отсутствует
        if me is None or "priority" not in me:
            fields["priority"] = self.priority
        if me is None or "label" not in me:
            fields["label"] = self.label
        if me is None or "enabled" not in me:
            fields["enabled"] = True
        if me is None or fields:
            self.store.upsert_member(self.id, fields, self.id)

    # ── HMAC ──────────────────────────────────────────────────────────────
    def _sign(self, ts, nonce, path, body):
        msg = ts.encode() + b"\n" + nonce.encode() + b"\n" + path.encode() + b"\n" + body
        return hmac.new(self.secret.encode(), msg, hashlib.sha256).hexdigest()

    def auth_headers(self, path, body=b""):
        ts = str(int(time.time()))
        nonce = secrets.token_hex(16)
        return {
            "X-Cl-Ts": ts,
            "X-Cl-Node": self.id,
            "X-Cl-Nonce": nonce,
            "X-Cl-Sig": self._sign(ts, nonce, path, body),
        }

    def verify(self, headers_get, path, body):
        """headers_get: callable(name)->value. Подпись HMAC + одноразовый nonce
        в узком окне TS_SKEW — перехваченный запрос нельзя проиграть повторно."""
        if not self.secret:
            return False
        ts = headers_get("X-Cl-Ts") or ""
        nonce = headers_get("X-Cl-Nonce") or ""
        sig = headers_get("X-Cl-Sig") or ""
        if not ts or not nonce or not sig:
            return False
        try:
            if abs(time.time() - int(ts)) > TS_SKEW:
                return False
        except ValueError:
            return False
        if not hmac.compare_digest(self._sign(ts, nonce, path, body), sig):
            return False
        now = time.time()
        with self._lock:
            for k in [k for k, exp in self._nonce_seen.items() if exp < now]:
                self._nonce_seen.pop(k, None)
            if nonce in self._nonce_seen:
                return False  # повтор
            self._nonce_seen[nonce] = now + TS_SKEW
        return True

    # ── peer client ───────────────────────────────────────────────────────
    def _peer_base(self, node):
        # приоритет — статичный admin-домен пира по 443 (через прокси, без проброса портов)
        url = (node.get("cluster_url") or "").strip().rstrip("/")
        if url:
            return url
        ip = node.get("public_ip")
        port = node.get("cluster_port", self.cluster_port)
        if not ip:
            return None
        return f"{self.scheme}://{ip}:{port}"

    def _http(self, base, path, method="GET", payload=None):
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        url = base + path
        req = urllib.request.Request(url, data=(body if method != "GET" else None), method=method)
        for k, v in self.auth_headers(path, body).items():
            req.add_header(k, v)
        if method != "GET":
            req.add_header("Content-Type", "application/json")
        ctx = _SSL_CTX if url.lower().startswith("https") else None
        with urllib.request.urlopen(req, timeout=self.http_timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        return json.loads(raw) if raw else {}

    def ping_peer(self, node):
        nid = node.get("id")
        base = self._peer_base(node)
        if not base or not nid:
            return None
        t0 = time.time()
        try:
            data = self._http(base, "/cluster/ping")
            latency = time.time() - t0
            with self._lock:
                self.liveness[nid] = {
                    "alive": True, "last_ok": time.time(), "fails": 0,
                    "latency": latency, "view": data.get("alive", []),
                    "active": data.get("active"), "ts": time.time(),
                }
            return data
        except Exception:
            with self._lock:
                lv = self.liveness.get(nid, {"fails": 0})
                fails = lv.get("fails", 0) + 1
                self.liveness[nid] = {
                    "alive": False, "last_ok": lv.get("last_ok", 0), "fails": fails,
                    "latency": None, "view": lv.get("view", []),
                    "active": lv.get("active"), "ts": time.time(),
                }
            return None

    def pull_peer(self, base):
        if not base:
            return
        # config — LWW на весь документ
        try:
            meta = self._http(base, "/cluster/state/config")
            if meta and "data" in meta:
                self.store.merge_remote("config", meta)
        except Exception:
            pass
        # failover — поэлементное слияние (active/dns_ip vs pinned/history не затирают друг друга)
        try:
            meta = self._http(base, "/cluster/state/failover")
            if meta and "data" in meta:
                self.store.merge_failover(meta)
        except Exception:
            pass
        # members — поэлементное слияние
        try:
            doc = self._http(base, "/cluster/members")
            if doc and isinstance(doc.get("nodes"), dict):
                self.store.merge_members(doc["nodes"])
        except Exception:
            pass

    # ── живость / выбор активного ─────────────────────────────────────────
    def _self_enabled(self):
        me = self.find_node(self.id)
        return bool(me and me.get("enabled", True))

    def alive_ids(self, nodes=None, fail_threshold=3):
        if nodes is None:
            nodes = self.get_nodes()
        ids = set()
        # себя считаем живым только если мы — включённый участник
        if self._self_enabled():
            ids.add(self.id)
        with self._lock:
            for n in nodes:
                nid = n.get("id")
                if nid == self.id:
                    continue
                lv = self.liveness.get(nid)
                if lv and lv.get("fails", 99) < fail_threshold and lv.get("last_ok", 0) > 0:
                    ids.add(nid)
        return ids

    def best_alive(self, nodes, alive, blocked=None):
        blocked = blocked or set()
        cand = [n for n in nodes if n.get("id") in alive and n.get("id") not in blocked]
        if not cand:
            # все живые заблокированы (DNS не применяется) — пробуем хоть кого-то
            cand = [n for n in nodes if n.get("id") in alive]
        if not cand:
            return self.id if self._self_enabled() else None
        cand.sort(key=lambda n: (int(n.get("priority", 100)), str(n.get("id"))))
        return cand[0]["id"]

    def _has_alive_majority(self, nodes, alive):
        total = len(nodes) or 1
        alive_count = sum(1 for n in nodes if n.get("id") in alive)
        return alive_count >= (total // 2 + 1)

    def _blocked_nodes(self, fo, settings):
        """Узлы, у которых reg.ru-применение DNS подряд падает — временно уступают
        черёд следующему по приоритету (счётчик протухает, чтобы узел вернулся)."""
        limit = int(settings.get("seize_fail_limit", 3))
        window = max(float(settings.get("cooldown", 60)) * 5, 300.0)
        now = time.time()
        blocked = set()
        for nid, rec in (fo.get("fail_counts") or {}).items():
            if isinstance(rec, list) and rec[0] >= limit and (now - float(rec[1])) < window:
                blocked.add(nid)
        return blocked

    def _quorum_active_dead(self, active, nodes, alive):
        total = len(nodes) or 1
        majority = total // 2 + 1
        agree = 0
        if active not in alive:  # наше мнение
            agree += 1
        with self._lock:
            for n in nodes:
                nid = n.get("id")
                if nid == self.id:
                    continue
                lv = self.liveness.get(nid)
                if lv and lv.get("alive") and active not in (lv.get("view") or []):
                    agree += 1
        return agree >= majority

    # ── переключение DNS ──────────────────────────────────────────────────
    def _apply_dns(self, ip):
        """Переключаем на активный узел ТОЛЬКО домен подписок. Admin-домены у
        каждого узла свои (статичные) и reg.ru их не трогает."""
        settings = self.store.get_settings()
        prov, err = dns_providers.provider_from_settings(settings, secretbox.decrypt)
        if err or not prov:
            return False, (err or "нет DNS-провайдера"), []
        d = (settings.get("dns") or {}).get("sub") or {}
        if not d.get("zone") or not d.get("subdomain"):
            return False, "не настроен домен подписок", []
        r = prov.set_a_record(d["zone"], d["subdomain"], ip)
        return bool(r.ok), f"sub:{r.message}", [("sub", bool(r.ok), r.message)]

    def _record_failover(self, node_id, ip, by, ok, msg, pin=None, pin_set=False):
        now = time.time()

        def mut(fo):
            # active/dns_ip обновляем ТОЛЬКО при успешной смене DNS, иначе
            # пометили бы себя активным без реальной записи и не повторяли бы.
            if ok:
                fo["active"] = node_id
                fo["dns_ip"] = ip
            fo["last_ts"] = now
            # счётчик неудач применить DNS: чтобы вечно-падающий узел уступил черёд
            fc = fo.setdefault("fail_counts", {})
            if ok:
                fc.pop(node_id, None)
            else:
                rec = fc.get(node_id) if isinstance(fc.get(node_id), list) else [0, 0]
                fc[node_id] = [rec[0] + 1, now]
            if pin_set:
                fo["pinned"] = pin
                fo["pinned_ts"] = now
            hist = fo.setdefault("history", [])
            hist.insert(0, {"ts": now, "node": node_id, "ip": ip,
                            "by": by, "ok": ok, "msg": msg})
            del hist[20:]
        self.store.update_failover(mut)

    def seize(self, by="auto"):
        if not self.public_ip:
            print("[cluster] не задан NODE_PUBLIC_IP — не могу взять DNS", flush=True)
            return False
        ok, msg, _ = self._apply_dns(self.public_ip)
        self._record_failover(self.id, self.public_ip, by, ok, msg)
        print(f"[cluster] seize by={by} ok={ok} ip={self.public_ip} {msg}", flush=True)
        return ok

    def set_active_to(self, node_id, by="manual", pin=True):
        """Ручное переключение DNS на узел node_id."""
        node = self.find_node(node_id)
        if not node:
            return False, "узел не найден"
        ip = node.get("public_ip")
        if not ip:
            return False, "у узла не задан public_ip"
        ok, msg, _ = self._apply_dns(ip)
        self._record_failover(node_id, ip, by, ok, msg,
                              pin=(node_id if pin else None), pin_set=True)
        return ok, msg

    def clear_pin(self):
        def mut(fo):
            fo["pinned"] = None
            fo["pinned_ts"] = time.time()
        self.store.update_failover(mut)

    # ── управление участниками из UI ──────────────────────────────────────
    def members_doc(self):
        return self.store.members_doc()

    def set_node(self, node_id, fields):
        """UI-правка записи узла (label/priority/enabled/public_ip/порты)."""
        clean = {}
        for k in ("label", "public_ip", "cluster_url", "priority", "cluster_port", "admin_port", "sub_port", "enabled"):
            if k in fields:
                clean[k] = fields[k]
        if clean:
            self.store.upsert_member(node_id, clean, self.id)

    def add_node(self, fields):
        import secrets as _s
        nid = fields.get("id") or _s.token_hex(6)
        entry = {
            "label": fields.get("label") or nid,
            "public_ip": fields.get("public_ip", ""),
            "cluster_url": (fields.get("cluster_url") or "").strip().rstrip("/"),
            "priority": int(fields.get("priority", 100)),
            "cluster_port": int(fields.get("cluster_port", self.cluster_port)),
            "admin_port": int(fields.get("admin_port", self.admin_port)),
            "sub_port": int(fields.get("sub_port", self.sub_port)),
            "enabled": bool(fields.get("enabled", True)),
        }
        self.store.upsert_member(nid, entry, self.id)
        return nid

    def remove_node(self, node_id):
        if node_id == self.id:
            return False, "нельзя удалить текущий узел"
        self.store.remove_member(node_id, self.id)
        return True, "ok"

    # ── основной цикл ─────────────────────────────────────────────────────
    def poll_once(self):
        settings = self.store.get_settings()
        fail_threshold = int(settings.get("fail_threshold", 3))
        self.ensure_self_registered()

        nodes = self.get_nodes()
        # пинг известных узлов
        for n in nodes:
            if n.get("id") != self.id:
                self.ping_peer(n)
        # синк конфига/состояния с пиров и сидов
        bases = set(self.seeds)
        for n in nodes:
            if n.get("id") != self.id:
                b = self._peer_base(n)
                if b:
                    bases.add(b)
        for b in bases:
            self.pull_peer(b)

        # пересчёт после слияний
        settings = self.store.get_settings()
        nodes = self.get_nodes()
        fo = self.store.get_failover()

        # этот узел выключен администратором — не участвуем в захвате DNS
        if not self._self_enabled():
            return

        alive = self.alive_ids(nodes, fail_threshold)
        blocked = self._blocked_nodes(fo, settings)
        cand = self.best_alive(nodes, alive, blocked)
        active = fo.get("active")
        pinned = fo.get("pinned")

        if not settings.get("failover_enabled", True):
            return
        # без настроенного DNS-провайдера авто-фейловер невозможен — не дёргаем reg.ru
        _prov, _prov_err = dns_providers.provider_from_settings(settings, secretbox.decrypt)
        if _prov_err:
            return
        desired = pinned if (pinned and pinned in alive) else cand
        if desired != self.id or active == self.id:
            return
        if not self.public_ip:
            return

        node_ids = {n.get("id") for n in nodes}
        active_valid = active is not None and active in node_ids
        active_alive = active in alive
        cooldown_ok = time.time() - float(fo.get("last_ts", 0)) >= float(settings.get("cooldown", 60))

        if pinned == self.id:
            # ручной пин на нас — берём DNS себе (без кворума)
            if cooldown_ok:
                self.seize(by="auto-pin")
            return

        if not active_valid:
            # активный не задан/неизвестен — заявляемся. Но кворум обязателен:
            # меньшинство в разрыве сети не должно перетягивать «ничей» DNS.
            if len(nodes) > 1 and settings.get("require_quorum", True) \
                    and not self._has_alive_majority(nodes, alive):
                return
            if cooldown_ok:
                self.seize(by="auto")
            return

        if not active_alive:
            # активный мёртв — фейловер с защитой от split-brain (кворум)
            if settings.get("require_quorum", True) and not self._quorum_active_dead(active, nodes, alive):
                return
            if cooldown_ok:
                self.seize(by="auto")
            return

        # активный жив, но мы предпочтительнее по приоритету — failback (preempt)
        if settings.get("preempt", True):
            active_node = self.find_node(active)
            active_prio = int(active_node.get("priority", 100)) if active_node else 100
            if self.priority < active_prio and cooldown_ok:
                self.seize(by="auto-failback")

    # ── агрегированная статистика по кластеру ─────────────────────────────
    def stats_doc(self):
        """Статистика этого узла для пиров."""
        return {"node": self.id, "rows": self.store.get_stats_rows()}

    def reset_stats_cluster(self, route_id=None):
        """Сбросить статистику локально и разослать сброс живым узлам."""
        self.store.reset_stats(route_id)
        settings = self.store.get_settings()
        alive = self.alive_ids(self.get_nodes(), int(settings.get("fail_threshold", 3)))
        for n in self.get_nodes():
            nid = n.get("id")
            if nid == self.id or nid not in alive:
                continue
            base = self._peer_base(n)
            if not base:
                continue
            try:
                self._http(base, "/cluster/reset-stats", method="POST",
                           payload=({"route": route_id} if route_id else {}))
            except Exception:
                pass

    def cluster_stats(self):
        """Суммирует статистику со всех живых узлов (read-time, без синка счётчиков).
        → {route_id: {requests, devices:[{...,nodes:[...]}]}}"""
        settings = self.store.get_settings()
        nodes = self.get_nodes()
        alive = self.alive_ids(nodes, int(settings.get("fail_threshold", 3)))
        sources = [(self.id, self.store.get_stats_rows())]
        for n in nodes:
            nid = n.get("id")
            if nid == self.id or nid not in alive:
                continue
            base = self._peer_base(n)
            if not base:
                continue
            try:
                data = self._http(base, "/cluster/stats")
                sources.append((data.get("node") or nid, data.get("rows") or []))
            except Exception:
                pass
        agg = {}
        for node_id, rows in sources:
            for r in rows:
                key = (r.get("route_id"), r.get("device"))
                e = agg.get(key)
                if e is None:
                    e = {"route_id": r.get("route_id"), "device": r.get("device"),
                         "hwid": r.get("hwid"), "model": r.get("model"), "app": r.get("app"),
                         "ip": r.get("ip"), "cnt": 0, "last_ts": 0,
                         "first_ts": r.get("first_ts") or 0, "nodes": set()}
                    agg[key] = e
                e["cnt"] += int(r.get("cnt") or 0)
                lt = float(r.get("last_ts") or 0)
                if lt > e["last_ts"]:
                    e["last_ts"] = lt
                    e["model"], e["app"], e["ip"], e["hwid"] = r.get("model"), r.get("app"), r.get("ip"), r.get("hwid")
                ft = float(r.get("first_ts") or 0)
                if ft and (not e["first_ts"] or ft < e["first_ts"]):
                    e["first_ts"] = ft
                e["nodes"].add(node_id)
        out = {}
        for e in agg.values():
            ro = out.setdefault(e["route_id"], {"requests": 0, "devices": []})
            ro["requests"] += e["cnt"]
            e["nodes"] = sorted(e["nodes"])
            ro["devices"].append(e)
        for ro in out.values():
            ro["devices"].sort(key=lambda d: d.get("last_ts") or 0, reverse=True)
        return out

    # ── статус для UI / API ───────────────────────────────────────────────
    def ping_view(self):
        settings = self.store.get_settings()
        alive = self.alive_ids(self.get_nodes(), int(settings.get("fail_threshold", 3)))
        fo = self.store.get_failover()
        return {
            "node_id": self.id,
            "priority": self.priority,
            "ts": time.time(),
            "alive": sorted(alive),
            "active": fo.get("active"),
        }

    def status(self):
        settings = self.store.get_settings()
        fail_threshold = int(settings.get("fail_threshold", 3))
        alive = self.alive_ids(self.get_nodes(), fail_threshold)
        fo = self.store.get_failover()
        out_nodes = []
        for n in sorted(self.all_nodes(), key=lambda x: (int(x.get("priority", 100)), str(x.get("id")))):
            nid = n.get("id")
            lv = self.liveness.get(nid, {})
            out_nodes.append({
                "id": nid, "label": n.get("label") or nid,
                "public_ip": n.get("public_ip", ""),
                "cluster_url": n.get("cluster_url", ""),
                "priority": n.get("priority", 100),
                "enabled": n.get("enabled", True),
                "cluster_port": n.get("cluster_port", self.cluster_port),
                "admin_port": n.get("admin_port", self.admin_port),
                "sub_port": n.get("sub_port", self.sub_port),
                "is_self": nid == self.id,
                "alive": (nid in alive),
                "last_ok": lv.get("last_ok", 0) if nid != self.id else time.time(),
                "latency": lv.get("latency"),
                "is_active": nid == fo.get("active"),
                "is_pinned": nid == fo.get("pinned"),
            })
        return {
            "self_id": self.id,
            "active": fo.get("active"),
            "pinned": fo.get("pinned"),
            "dns_ip": fo.get("dns_ip"),
            "failover_enabled": settings.get("failover_enabled", True),
            "require_quorum": settings.get("require_quorum", True),
            "nodes": out_nodes,
            "history": fo.get("history", [])[:10],
        }

    # ── жизненный цикл ────────────────────────────────────────────────────
    def run(self):
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as e:
                print(f"[cluster] poll error: {e}", flush=True)
            interval = int((self.store.get_settings() or {}).get("poll_interval", 10))
            self._stop.wait(max(2, interval))

    def start(self):
        self.ensure_self_registered()
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
