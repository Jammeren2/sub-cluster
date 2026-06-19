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
    "settings": {
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
            "regru_username": "",
            "regru_password_enc": "",   # шифр (secretbox)
            "admin": {"zone": "example.net", "subdomain": "admin"},
            "sub": {"zone": "example.com", "subdomain": "happ"},
        },
    },
}

DEFAULT_FAILOVER = {
    "active": None,       # id узла, на который сейчас указывает DNS
    "pinned": None,       # id узла, закреплённого вручную (или None = авто)
    "pinned_ts": 0.0,     # штамп изменения pinned (для слияния)
    "last_ts": 0.0,       # время последнего переключения DNS
    "dns_ip": None,       # IP, установленный в DNS
    "history": [],        # последние события [{ts, node, ip, by, ok, msg}]
    "fail_counts": {},    # node_id -> [подряд неудач применить DNS, ts]
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
        s["dns"] = dns
        return s

    def get_failover(self):
        fo = self.get("failover") or {}
        out = dict(DEFAULT_FAILOVER)
        out.update(fo)
        return out

    def update_failover(self, mutator):
        return self.update("failover", mutator)

    def merge_failover(self, remote_meta):
        """Поэлементное слияние failover, чтобы конкурентные записи active/dns_ip
        (с активного узла) и pinned/history (с другого) не затирали друг друга.
        - active/dns_ip/last_ts — берём с большим last_ts (свежее реальное переключение);
        - pinned — по своему штампу pinned_ts;
        - history — объединяем по (ts,node), новейшие сверху, до 20;
        - fail_counts — берём бóльшие счётчики (свежесть по ts)."""
        if not remote_meta or "data" not in remote_meta:
            return False
        rd = remote_meta["data"] or {}
        with self._lock:
            m = self.get_meta("failover")
            local = m["data"] if m else dict(DEFAULT_FAILOVER)
            changed = False
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
            merged = {(h.get("ts"), h.get("node")): h for h in local.get("history", [])}
            for h in rd.get("history", []):
                merged.setdefault((h.get("ts"), h.get("node")), h)
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

    def close(self):
        with self._lock:
            self._conn.close()
