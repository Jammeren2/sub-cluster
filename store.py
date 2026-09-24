#!/usr/bin/env python3
"""
store.py — локальное хранилище конфигурации на SQLite с LWW-синхронизацией.

Каждый узел кластера держит свою SQLite-БД. Документы («config» и «failover»)
версионируются и синхронизируются между узлами по принципу last-write-wins:
выигрывает версия с большим кортежем (version, updated_at, origin).

  • config   — маршруты/источники/рёбра подписок, список узлов кластера,
               настройки (reg.ru, домены, фейловер). Меняется редко (правки в UI).
  • failover — оперативное состояние: активный узел, ручной пин, время и IP
               последнего переключения DNS. Меняется при фейловере/переключении.

Так конфиг расходится по узлам в течение poll_interval, а частое изменение
оперативного состояния не дёргает весь конфиг.
"""

import os
import json
import time
import sqlite3
import threading

DB_FILE = os.environ.get("DB_FILE", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "cluster.db"))

# Версия времени берётся из реального времени; на разных узлах часы могут
# слегка расходиться — поэтому в кортеже сравнения первым идёт version (Lamport),
# затем updated_at, затем origin (детерминированный тай-брейк по id узла).

DEFAULT_CONFIG = {
    "routes": [],
    "sources": [],
    "edges": [],
    # Ручные блокировки подписок. Синхронизируются как часть config по кластеру.
    # device = X-Hwid, а для клиентов без HWID — "ip:<адрес>".
    "blocked_devices": [],
    "settings": {
        "require_device_hwid": True,  # HWID без IP; версия клиента не требуется
        "failover_enabled": True,
        "require_quorum": True,   # авто-захват мёртвого активного — только при кворуме
        "preempt": True,          # узел с лучшим приоритетом возвращает себе DNS (failback)
        "poll_interval": 10,      # сек между опросами кластера
        "fail_threshold": 3,      # подряд неудач, чтобы счесть узел мёртвым
        "cooldown": 60,           # сек между авто-переключениями DNS
        "seize_fail_limit": 3,    # после стольких неудач применить DNS узел уступает черёд
        "sub_public_base": "",    # для показа готовых ссылок (напр. https://happ.example.com)
        "dns": {
            "provider": "regru",
            # Легаси-поля одного домена (миграция → domains[0]; зеркало дефолтного
            # домена для старых узлов). Не удаляем. Домены задаёт пользователь в
            # /settings — здесь без хардкода инфраструктуры.
            "regru_username": "",
            "regru_password_enc": "",   # шифр (secretbox)
            "sub": {"zone": "", "subdomain": ""},
            # Несколько доменов подписок, у каждого свой аккаунт reg.ru. Каждый
            # фейловерится отдельно (на свой активный узел). См. graph.domain_*.
            "domains": [],
        },
        # zapret (обход DPI): список стратегий + активная. Логи теста —
        # эфемерные (в памяти узла, не синкаются). См. zapret.py.
        "zapret": {"strategies": [], "active_id": ""},
    },
}

DEFAULT_FAILOVER = {
    # Верхнеуровневая сводка = зеркало ДЕФОЛТНОГО домена (для старых узлов и UI).
    "active": None,       # id узла, на который указывает DNS дефолтного домена
    "pinned": None,       # id узла, закреплённого вручную глобально (или None = авто)
    "pinned_ts": 0.0,     # штамп изменения pinned (для слияния)
    "last_ts": 0.0,       # время последнего переключения DNS дефолтного домена
    "dns_ip": None,       # IP, установленный в DNS дефолтного домена
    "history": [],        # последние события [{ts, domain, node, ip, by, ok, msg}]
    "fail_counts": {},    # node_id -> [подряд неудач применить DNS, ts] (дефолтный домен)
    # Состояние на каждый домен подписок (фейловер per-domain).
    "domains": {},        # domain_id -> {active, dns_ip, last_ts, fail_counts:{node:[n,ts]}}
}

# Участники кластера — отдельный документ с поэлементным (CRDT-подобным) слиянием:
# каждый узел владеет своей записью, поэтому одновременная саморегистрация узлов
# не затирает друг друга (в отличие от LWW на весь документ). Каждая запись несёт
# свои _v (версия), _t (время), _o (origin) для разрешения конфликтов.
DEFAULT_MEMBERS = {"nodes": {}}  # id -> {id,label,public_ip,priority,...,enabled,_v,_t,_o,_deleted?}


class Store:
    def __init__(self, db_file=DB_FILE, origin="node"):
        self.db_file = db_file
        self.origin = origin
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(db_file) or ".", exist_ok=True)
        self._conn = sqlite3.connect(db_file, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS kv ("
            " key TEXT PRIMARY KEY, data TEXT NOT NULL,"
            " version INTEGER NOT NULL, updated_at REAL NOT NULL, origin TEXT NOT NULL)"
        )
        # Статистика по устройствам на маршрутах — ЛОКАЛЬНАЯ (не синкается между
        # узлами): каждый узел считает запросы, что пришли к нему.
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS device_seen ("
            " route_id TEXT NOT NULL, device TEXT NOT NULL, hwid TEXT, model TEXT,"
            " app TEXT, ip TEXT, cnt INTEGER NOT NULL DEFAULT 0,"
            " first_ts REAL, last_ts REAL, PRIMARY KEY(route_id, device))"
        )
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(device_seen)")}
        if "personal_name" not in columns:
            self._conn.execute("ALTER TABLE device_seen ADD COLUMN personal_name TEXT NOT NULL DEFAULT ''")
        self._conn.commit()
        self._ensure("config", DEFAULT_CONFIG)
        self._ensure("failover", DEFAULT_FAILOVER)
        self._ensure("members", DEFAULT_MEMBERS)
        # high-water mark версий (Lamport-часы): наибольшая версия, которую узел
        # когда-либо видел — локально или принятая от пира. Запись делаем от неё,
        # чтобы конкурентные правки не сталкивались на одном номере и причинно
        # более поздняя правка всегда побеждала на поле version (а не по часам).
        self._hw = {}
        for k in ("config", "failover", "members"):
            m = self.get_meta(k)
            if m:
                self._hw[k] = m["version"]

    def _next_version(self, key, local_version):
        nv = max(self._hw.get(key, 0), local_version) + 1
        self._hw[key] = nv
        return nv

    def _seen(self, key, version):
        self._hw[key] = max(self._hw.get(key, 0), int(version or 0))

    # ── низкоуровневое ────────────────────────────────────────────────────
    def _ensure(self, key, default):
        with self._lock:
            row = self._conn.execute("SELECT key FROM kv WHERE key=?", (key,)).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO kv(key,data,version,updated_at,origin) VALUES(?,?,?,?,?)",
                    (key, json.dumps(default, ensure_ascii=False), 0, 0.0, self.origin),
                )
                self._conn.commit()

    def get_meta(self, key):
        """→ {data, version, updated_at, origin} (копия)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT data,version,updated_at,origin FROM kv WHERE key=?", (key,)
            ).fetchone()
        if row is None:
            return None
        return {
            "data": json.loads(row[0]),
            "version": row[1],
            "updated_at": row[2],
            "origin": row[3],
        }

    def get(self, key):
        m = self.get_meta(key)
        return m["data"] if m else None

    def _write(self, key, data, version, updated_at, origin):
        self._conn.execute(
            "INSERT INTO kv(key,data,version,updated_at,origin) VALUES(?,?,?,?,?)"
            " ON CONFLICT(key) DO UPDATE SET data=excluded.data, version=excluded.version,"
            " updated_at=excluded.updated_at, origin=excluded.origin",
            (key, json.dumps(data, ensure_ascii=False), version, updated_at, origin),
        )
        self._conn.commit()

    # ── публичное ─────────────────────────────────────────────────────────
    def update(self, key, mutator, skip_if_unchanged=False):
        """Атомарно: data = mutator(data); версия инкрементируется. → новая data.
        skip_if_unchanged=True: если мутатор ничего не изменил — не бампим версию
        (чтобы перезапуск со старым конфигом не «омолаживал» его и не затирал
        более свежий конфиг кластера)."""
        with self._lock:
            m = self.get_meta(key)
            data = m["data"] if m else {}
            before = json.dumps(data, ensure_ascii=False, sort_keys=True) if skip_if_unchanged else None
            mutator(data)
            if skip_if_unchanged and m is not None and \
                    json.dumps(data, ensure_ascii=False, sort_keys=True) == before:
                return data
            new_version = self._next_version(key, m["version"] if m else 0)
            self._write(key, data, new_version, time.time(), self.origin)
            return data

    def put(self, key, data):
        with self._lock:
            m = self.get_meta(key)
            new_version = self._next_version(key, m["version"] if m else 0)
            self._write(key, data, new_version, time.time(), self.origin)
            return data

    def merge_remote(self, key, remote):
        """Принять удалённую версию, если она «новее» по (version,updated_at,origin).
        remote = {data,version,updated_at,origin}. → True если приняли."""
        if not remote or "data" not in remote:
            return False
        with self._lock:
            self._seen(key, remote.get("version", 0))
            local = self.get_meta(key)
            lt = (local["version"], local["updated_at"], local["origin"]) if local else (-1, -1, "")
            rt = (int(remote.get("version", 0)), float(remote.get("updated_at", 0)),
                  str(remote.get("origin", "")))
            if rt > lt:
                self._write(key, remote["data"], rt[0], rt[1], rt[2])
                return True
        return False

    # ── удобные обёртки ───────────────────────────────────────────────────
    def get_config(self):
        return self.get("config")

    def update_config(self, mutator, skip_if_unchanged=False):
        return self.update("config", mutator, skip_if_unchanged=skip_if_unchanged)

    def get_settings(self):
        cfg = self.get_config() or {}
        s = dict(DEFAULT_CONFIG["settings"])
        s.update(cfg.get("settings") or {})
        # гарантируем вложенный dns
        dns = dict(DEFAULT_CONFIG["settings"]["dns"])
        dns.update((cfg.get("settings") or {}).get("dns") or {})
        if not isinstance(dns.get("domains"), list):
            dns["domains"] = []
        s["dns"] = dns
        z = dict(DEFAULT_CONFIG["settings"]["zapret"])
        z.update((cfg.get("settings") or {}).get("zapret") or {})
        if not isinstance(z.get("strategies"), list):
            z["strategies"] = []
        z["active_id"] = str(z.get("active_id") or "")
        s["zapret"] = z
        return s

    def get_failover(self):
        fo = self.get("failover") or {}
        out = dict(DEFAULT_FAILOVER)
        out.update(fo)
        if not isinstance(out.get("domains"), dict):
            out["domains"] = {}
        return out

    def get_domain_failover(self, fo, domain_id):
        """Срез оперативного состояния одного домена (active/dns_ip/last_ts/fail_counts)."""
        d = (fo.get("domains") or {}).get(domain_id)
        if not isinstance(d, dict):
            return {"active": None, "dns_ip": None, "last_ts": 0.0, "fail_counts": {}}
        return {"active": d.get("active"), "dns_ip": d.get("dns_ip"),
                "last_ts": float(d.get("last_ts", 0)), "fail_counts": d.get("fail_counts") or {}}

    def default_domain_id(self):
        """id дефолтного домена (явный флаг default, иначе первый). Инлайн — store
        не импортирует graph, чтобы остаться без зависимостей в merge_failover."""
        doms = ((self.get_settings().get("dns") or {}).get("domains")) or []
        for d in doms:
            if isinstance(d, dict) and d.get("default"):
                return d.get("id")
        return doms[0].get("id") if doms and isinstance(doms[0], dict) else None

    def update_failover(self, mutator):
        return self.update("failover", mutator)

    def merge_failover(self, remote_meta):
        """Поэлементное слияние failover, чтобы конкурентные записи разных узлов
        (и разных доменов) не затирали друг друга:
        - domains[did] — поэлементно по своему last_ts (per-domain переключения);
        - старый узел (без domains, только плоские поля) — вливаем во ВКЛАД дефолтного
          домена, если свежее (смешанный кластер во время раскатки);
        - верхнеуровневая сводка active/dns_ip/last_ts — по верхнему last_ts;
        - pinned — по своему штампу pinned_ts;
        - history — объединяем по (ts,node,domain), новейшие сверху, до 20.
        Инвариант (как у node_meta): старый узел мутирует только известные поля и
        НИКОГДА не удаляет domains, поэтому per-domain записи новых узлов выживают."""
        if not remote_meta or "data" not in remote_meta:
            return False
        rd = remote_meta["data"] or {}
        with self._lock:
            m = self.get_meta("failover")
            local = m["data"] if m else dict(DEFAULT_FAILOVER)
            local.setdefault("domains", {})
            changed = False

            # per-domain поэлементно — каждый домен по своему last_ts
            for did, rdom in (rd.get("domains") or {}).items():
                if not isinstance(rdom, dict):
                    continue
                ldom = local["domains"].get(did)
                l_ts = float(ldom.get("last_ts", 0)) if isinstance(ldom, dict) else -1.0
                if float(rdom.get("last_ts", 0)) > l_ts:
                    local["domains"][did] = {
                        "active": rdom.get("active"), "dns_ip": rdom.get("dns_ip"),
                        "last_ts": float(rdom.get("last_ts", 0)),
                        "fail_counts": rdom.get("fail_counts") or {},
                    }
                    changed = True

            # back-compat: старый узел шлёт только плоские поля (нет domains).
            # Вливаем его состояние в срез ДЕФОЛТНОГО домена, если свежее.
            if not rd.get("domains") and (rd.get("active") is not None or float(rd.get("last_ts", 0)) > 0):
                did = self.default_domain_id()
                if did:
                    ldom = local["domains"].get(did)
                    l_ts = float(ldom.get("last_ts", 0)) if isinstance(ldom, dict) else -1.0
                    if float(rd.get("last_ts", 0)) > l_ts:
                        local["domains"][did] = {
                            "active": rd.get("active"), "dns_ip": rd.get("dns_ip"),
                            "last_ts": float(rd.get("last_ts", 0)),
                            "fail_counts": rd.get("fail_counts") or {},
                        }
                        changed = True

            # верхнеуровневая сводка (дефолтный домен / старые узлы)
            if float(rd.get("last_ts", 0)) > float(local.get("last_ts", 0)):
                local["active"] = rd.get("active")
                local["dns_ip"] = rd.get("dns_ip")
                local["last_ts"] = float(rd.get("last_ts", 0))
                local["fail_counts"] = rd.get("fail_counts", local.get("fail_counts", {}))
                changed = True

            if float(rd.get("pinned_ts", 0)) > float(local.get("pinned_ts", 0)):
                local["pinned"] = rd.get("pinned")
                local["pinned_ts"] = float(rd.get("pinned_ts", 0))
                changed = True

            def hk(h):
                return (h.get("ts"), h.get("node"), h.get("domain"))
            merged = {hk(h): h for h in local.get("history", [])}
            for h in rd.get("history", []):
                merged.setdefault(hk(h), h)
            newhist = sorted(merged.values(), key=lambda h: h.get("ts", 0), reverse=True)[:20]
            if newhist != local.get("history", []):
                local["history"] = newhist
                changed = True

            if changed:
                nv = self._next_version("failover", m["version"] if m else 0)
                self._write("failover", local, nv, time.time(), self.origin)
            return changed

    # ── участники кластера (поэлементный LWW) ─────────────────────────────
    def get_members(self, include_deleted=False):
        """→ {id: entry} живых участников (по умолчанию без удалённых)."""
        data = self.get("members") or {"nodes": {}}
        nodes = data.get("nodes", {}) or {}
        if include_deleted:
            return dict(nodes)
        return {mid: dict(e) for mid, e in nodes.items() if not e.get("_deleted")}

    def upsert_member(self, mid, fields, origin):
        """Создать/обновить запись участника mid; бампит её версию."""
        with self._lock:
            data = self.get("members") or {"nodes": {}}
            nodes = data.setdefault("nodes", {})
            e = dict(nodes.get(mid, {}))
            e.update(fields)
            e["id"] = mid
            e["_v"] = int(e.get("_v", 0)) + 1
            e["_t"] = time.time()
            e["_o"] = origin
            e.pop("_deleted", None)
            nodes[mid] = e
            m = self.get_meta("members")
            self._write("members", data, self._next_version("members", m["version"] if m else 0), time.time(), origin)
            return e

    def remove_member(self, mid, origin):
        """Тумбстоун: помечает участника удалённым (чтобы удаление разошлось)."""
        with self._lock:
            data = self.get("members") or {"nodes": {}}
            nodes = data.setdefault("nodes", {})
            e = dict(nodes.get(mid, {"id": mid}))
            e["_deleted"] = True
            e["_v"] = int(e.get("_v", 0)) + 1
            e["_t"] = time.time()
            e["_o"] = origin
            nodes[mid] = e
            m = self.get_meta("members")
            self._write("members", data, self._next_version("members", m["version"] if m else 0), time.time(), origin)

    def merge_members(self, remote_nodes):
        """Слить удалённые записи участников поэлементно (адоптим более новые)."""
        if not isinstance(remote_nodes, dict):
            return False
        with self._lock:
            data = self.get("members") or {"nodes": {}}
            nodes = data.setdefault("nodes", {})
            changed = False
            for mid, re in remote_nodes.items():
                if not isinstance(re, dict):
                    continue
                le = nodes.get(mid)
                lt = (int(le.get("_v", -1)), float(le.get("_t", -1)), str(le.get("_o", ""))) if le else (-1, -1.0, "")
                rt = (int(re.get("_v", 0)), float(re.get("_t", 0)), str(re.get("_o", "")))
                if rt > lt:
                    nodes[mid] = re
                    changed = True
            if changed:
                m = self.get_meta("members")
                self._write("members", data, self._next_version("members", m["version"] if m else 0), time.time(), self.origin)
            return changed

    def members_doc(self):
        """Полный документ участников (для отдачи пирам)."""
        return self.get("members") or {"nodes": {}}

    # ── статистика устройств/маршрутов (локальная) ────────────────────────
    def record_device(self, route_id, hwid, model, app, ip, max_per_route=2000, personal_name=""):
        """Засчитать обращение устройства к маршруту. Поля приходят из заголовков
        неаутентифицированного клиента — ограничиваем длину и число строк (LRU),
        чтобы X-Hwid со случайными значениями не раздул БД (disk-fill DoS)."""
        hwid = (hwid or "")[:128]
        model = (model or "")[:64]
        app = (app or "")[:64]
        ip = (ip or "")[:64]
        device = self.device_key(hwid, ip)
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO device_seen(route_id,device,hwid,model,app,ip,cnt,first_ts,last_ts,personal_name)"
                " VALUES(?,?,?,?,?,?,1,?,?,?)"
                " ON CONFLICT(route_id,device) DO UPDATE SET cnt=cnt+1, last_ts=?,"
                " model=excluded.model, app=excluded.app, ip=excluded.ip,"
                " personal_name=CASE WHEN excluded.personal_name != '' THEN excluded.personal_name ELSE device_seen.personal_name END",
                (route_id, device, hwid, model, app, ip, now, now, str(personal_name or "")[:80], now),
            )
            # держим не более N последних устройств на маршрут
            self._conn.execute(
                "DELETE FROM device_seen WHERE route_id=? AND device NOT IN ("
                " SELECT device FROM device_seen WHERE route_id=? ORDER BY last_ts DESC LIMIT ?)",
                (route_id, route_id, max_per_route),
            )
            self._conn.commit()

    @staticmethod
    def device_key(hwid, ip):
        """Та же идентичность, что используется статистикой и блокировкой."""
        return ((hwid or "").strip() or ("ip:" + (ip or "?")))[:128]

    def get_blocked_devices(self):
        cfg = self.get_config() or {}
        rows = cfg.get("blocked_devices")
        if not isinstance(rows, list):
            return []
        out = []
        for row in rows[:5000]:
            if not isinstance(row, dict):
                continue
            route_id = str(row.get("route_id") or "")[:64]
            device = str(row.get("device") or "")[:128]
            if route_id and device:
                try:
                    blocked_at = float(row.get("blocked_at") or 0)
                except (TypeError, ValueError):
                    blocked_at = 0.0
                out.append({"route_id": route_id, "device": device,
                            "blocked_at": blocked_at})
        return out

    def is_device_blocked(self, route_id, hwid="", ip="", device=None):
        key = (device if device is not None else self.device_key(hwid, ip))[:128]
        return any(row["route_id"] == route_id and row["device"] == key
                   for row in self.get_blocked_devices())

    def set_device_blocked(self, route_id, device, blocked=True):
        """Заблокировать/разблокировать устройство на одном маршруте подписки."""
        route_id = str(route_id or "")[:64]
        device = str(device or "")[:128]
        if not route_id or not device:
            return False

        def mut(cfg):
            rows = cfg.get("blocked_devices")
            if not isinstance(rows, list):
                rows = []
            rows = [r for r in rows if not (isinstance(r, dict)
                    and str(r.get("route_id") or "") == route_id
                    and str(r.get("device") or "") == device)]
            if blocked:
                rows.append({"route_id": route_id, "device": device,
                             "blocked_at": time.time()})
            cfg["blocked_devices"] = rows[-5000:]

        self.update_config(mut, skip_if_unchanged=True)
        return True

    def get_stats(self):
        """→ {route_id: {requests, devices:[{device,hwid,model,app,ip,cnt,last_ts,first_ts}]}}"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT route_id,device,hwid,model,app,ip,cnt,first_ts,last_ts,personal_name FROM device_seen"
                " ORDER BY last_ts DESC LIMIT 5000"
            ).fetchall()
        out = {}
        for r in rows:
            rid = r[0]
            d = {"device": r[1], "hwid": r[2], "model": r[3], "app": r[4],
                 "ip": r[5], "cnt": r[6], "first_ts": r[7], "last_ts": r[8], "personal_name": r[9]}
            e = out.setdefault(rid, {"requests": 0, "devices": []})
            e["requests"] += r[6]
            e["devices"].append(d)
        return out

    def get_stats_rows(self):
        """Сырые строки статистики этого узла (для отдачи пирам)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT route_id,device,hwid,model,app,ip,cnt,first_ts,last_ts,personal_name FROM device_seen"
                " ORDER BY last_ts DESC LIMIT 5000"
            ).fetchall()
        return [{"route_id": r[0], "device": r[1], "hwid": r[2], "model": r[3], "app": r[4],
                 "ip": r[5], "cnt": r[6], "first_ts": r[7], "last_ts": r[8], "personal_name": r[9]} for r in rows]

    def reset_stats(self, route_id=None):
        with self._lock:
            if route_id:
                self._conn.execute("DELETE FROM device_seen WHERE route_id=?", (route_id,))
            else:
                self._conn.execute("DELETE FROM device_seen")
            self._conn.commit()

    def close(self):
        with self._lock:
            self._conn.close()
