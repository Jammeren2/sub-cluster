#!/usr/bin/env python3
"""selftest.py — автономные проверки прямых ключей, переименования ссылок и
sync-safety (без тест-фреймворка). Запуск: python3 selftest.py

Монкипатчит subscriptions.fetch_upstream_cached фейковыми апстримами и работает
с временными SQLite-Store. Покрывает регрессии из ревью (P0/P1) и инвариант
синхронизации конфига между узлами разных версий."""

import os
import json
import base64
import tempfile
import urllib.parse

TMP = tempfile.mkdtemp(prefix="subcluster-selftest-")
os.environ["DB_FILE"] = os.path.join(TMP, "default.db")
os.environ.setdefault("CLUSTER_SECRET", "x")

import store as storemod          # noqa: E402
import graph                      # noqa: E402
import subscriptions as subs      # noqa: E402
import dns_providers              # noqa: E402
import cluster as clustermod      # noqa: E402
import zapret                     # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {name}")
    else:
        FAIL += 1
        print(f"FAIL  {name}  {extra}")


_n = [0]


def new_store():
    _n[0] += 1
    return storemod.Store(db_file=os.path.join(TMP, f"s{_n[0]}.db"), origin=f"node{_n[0]}")


# ── фейковые апстримы ──────────────────────────────────────────────────────
FAKE = {}


def fake_fetch(url):
    if url not in FAKE:
        raise Exception(f"upstream not found: {url}")
    return FAKE[url]


subs.fetch_upstream_cached = fake_fetch


def b64(s):
    return base64.b64encode(s.encode()).decode().encode("ascii")


def json_config(link):
    ob, name = subs._vless_to_outbound(link)
    return subs._wrap_as_config(ob, name)


def names_from_json(payload):
    return [c.get("remarks") for c in json.loads(payload.decode())]


def links_from_b64(payload):
    text = base64.b64decode(payload).decode()
    return [l for l in text.split("\n") if l]


def frag(link):
    f = urllib.parse.urlsplit(link).fragment
    return urllib.parse.unquote(f) if f else ""


VLESS_J = "vless://uid1@host1:443?type=tcp&security=none#Srv1"
VLESS_T = "vless://uid2@host2:443?type=tcp&security=none#Srv2"
FAKE["https://json/sub"] = (json.dumps([json_config(VLESS_J)]).encode(), {"Content-Type": "application/json"})
FAKE["https://text/sub"] = (b64(VLESS_T), {"Content-Type": "text/plain"})
FAKE["https://mirror/sub"] = (b"RAW-MIRROR-BYTES", {"Content-Type": "text/plain", "Profile-Title": "up"})
# для нод-групп
FAKE["https://de/sub"] = (b64("vless://d1@de1:443?type=tcp#DE-1\nvless://d2@de2:443?type=tcp#DE-2"), {})
FAKE["https://mix/sub"] = (b64("vless://v@h1:443?type=tcp#V\nss://YWVzLTI1Ni1nY206cHc@h2:8388#S\nhysteria2://p@h3:443#HY"), {})
FAKE["https://hy/sub"] = (b64("hysteria2://p@h9:443#HY1\ntuic://u@h8:443#TU1"), {})
FAKE["https://dup/sub"] = (b64("vless://a@dup:443?type=tcp#A1\nvless://b@dup:443?type=tcp#A2"), {})
FAKE["https://deui/sub"] = (b64("vless://d1@de1:443?type=tcp#DE-1"), {"Subscription-Userinfo": "upload=0; download=0; total=1000"})


def base_graph(st, extra_meta=None):
    """Граф: ключ k1 + подписка s1 → маршрут r1."""
    data = {
        "sources": [
            {"id": "k1aaaaaa", "type": "key", "url": "", "x": 80, "y": 60},
            {"id": "s1bbbbbb", "type": "source", "url": "https://json/sub", "x": 80, "y": 220},
        ],
        "routes": [{"id": "r1cccccc", "path": "/x", "title": "X", "mode": "merge",
                    "enabled": True, "x": 520, "y": 60}],
        "edges": [{"from": "k1aaaaaa", "to": "r1cccccc"}, {"from": "s1bbbbbb", "to": "r1cccccc"}],
        "node_meta": {
            "k1aaaaaa": {"keys": [{"link": "vless://kid@hk:443?type=tcp#Orig", "name": "Alpha"}]},
            "s1bbbbbb": {"renames": [{"addr": "host1:443", "name": "Srv1", "to": "Renamed1"}]},
        },
    }
    if extra_meta:
        data["node_meta"].update(extra_meta)
    return graph.save_graph(st, data)


def get_route(st, rid="r1cccccc"):
    return next(r for r in st.get_config()["routes"] if r["id"] == rid)


# ── 1. sync-safety ─────────────────────────────────────────────────────────
def t_sync_safety():
    print("\n[1] sync-safety")
    st = new_store()
    ok, errs = base_graph(st)
    check("save_graph ok", ok, errs)
    check("node_meta.keys сохранён", st.get_config().get("node_meta", {}).get("k1aaaaaa", {}).get("keys"))

    # старый код пишет конфиг (только sources/routes/edges, не знает про node_meta)
    def old_mut(cfg):
        cfg["sources"] = [dict(s) for s in cfg["sources"]]
        cfg["routes"] = [dict(r) for r in cfg["routes"]]
        cfg["edges"] = [dict(e) for e in cfg["edges"]]
    st.update_config(old_mut)
    check("node_meta пережил запись старого узла", bool(st.get_config().get("node_meta", {}).get("k1aaaaaa")))

    # антикейс/инвариант: если доку без node_meta дать выиграть LWW — он теряется
    m = st.get_meta("config")
    remote = {"data": {k: v for k, v in m["data"].items() if k != "node_meta"},
              "version": m["version"] + 5, "updated_at": m["updated_at"] + 5, "origin": "zzz"}
    st.merge_remote("config", remote)
    check("merge_remote без node_meta затирает его (инвариант: писатели обязаны его сохранять)",
          not st.get_config().get("node_meta"))


# ── 2. sync_graph_from_routes сохраняет ноды-ключи (P0) ────────────────────
def t_classic_preserves_keys():
    print("\n[2] классический путь сохраняет ноды-ключи")
    st = new_store()
    base_graph(st)
    graph.add_route(st, "/y", "Y", ["https://text/sub"], "merge")  # → sync_graph_from_routes
    cfg = st.get_config()
    sids = {s["id"] for s in cfg["sources"]}
    check("ключ k1 не стёрт после add_route", "k1aaaaaa" in sids)
    check("ребро ключ→маршрут сохранено",
          any(e["from"] == "k1aaaaaa" and e["to"] == "r1cccccc" for e in cfg["edges"]))
    r1 = get_route(st)
    check("прямая ссылка ключа не попала в upstreams",
          all(not graph._is_direct_link(u) for u in r1["upstreams"]))
    check("node_meta ключа цел", cfg.get("node_meta", {}).get("k1aaaaaa", {}).get("keys"))


# ── 3. id-remap ────────────────────────────────────────────────────────────
def t_id_remap():
    print("\n[3] id-remap node_meta")
    st = new_store()
    data = {
        "sources": [{"id": "bad id!", "type": "key", "url": ""}],
        "routes": [{"id": "r1cccccc", "path": "/z", "mode": "merge", "enabled": True}],
        "edges": [{"from": "bad id!", "to": "r1cccccc"}],
        "node_meta": {"bad id!": {"keys": [{"link": "vless://x@h:443#K", "name": "Kk"}]}},
    }
    ok, errs = graph.save_graph(st, data)
    check("save_graph ok", ok, errs)
    cfg = st.get_config()
    src = cfg["sources"][0]
    check("id переназначен", src["id"] != "bad id!")
    check("node_meta перенесён на новый id", bool(cfg["node_meta"].get(src["id"], {}).get("keys")))
    check("ребро перенесено на новый id",
          any(e["from"] == src["id"] for e in cfg["edges"]))


# ── 4. GC node_meta ────────────────────────────────────────────────────────
def t_gc():
    print("\n[4] GC node_meta при удалении ноды")
    st = new_store()
    base_graph(st)
    # сохраняем граф без s1, но с node_meta для s1 → запись s1 должна отвалиться
    data = {
        "sources": [{"id": "k1aaaaaa", "type": "key", "url": ""}],
        "routes": [{"id": "r1cccccc", "path": "/x", "mode": "merge", "enabled": True}],
        "edges": [{"from": "k1aaaaaa", "to": "r1cccccc"}],
        "node_meta": {
            "k1aaaaaa": {"keys": [{"link": "vless://kid@hk:443#K", "name": "A"}]},
            "s1bbbbbb": {"renames": [{"addr": "host1:443", "name": "Srv1", "to": "X"}]},
        },
    }
    graph.save_graph(st, data)
    nm = st.get_config().get("node_meta", {})
    check("запись удалённой ноды s1 вычищена (GC)", "s1bbbbbb" not in nm)
    check("запись существующей ноды k1 цела", "k1aaaaaa" in nm)


# ── 5. resolve spec ────────────────────────────────────────────────────────
def t_resolve():
    print("\n[5] resolve_links_spec: транзитивность / выключенный / цикл")
    st = new_store()
    # r1 (sub+key) → r2 (через ребро r1→r2)
    data = {
        "sources": [
            {"id": "k1aaaaaa", "type": "key", "url": ""},
            {"id": "s1bbbbbb", "type": "source", "url": "https://json/sub"},
        ],
        "routes": [
            {"id": "r1cccccc", "path": "/a", "mode": "merge", "enabled": True},
            {"id": "r2dddddd", "path": "/b", "mode": "merge", "enabled": True},
        ],
        "edges": [
            {"from": "k1aaaaaa", "to": "r1cccccc"},
            {"from": "s1bbbbbb", "to": "r1cccccc"},
            {"from": "r1cccccc", "to": "r2dddddd"},
        ],
        "node_meta": {"k1aaaaaa": {"keys": [{"link": "vless://kid@hk:443#K", "name": "A"}]}},
    }
    graph.save_graph(st, data)
    spec = graph.resolve_links_spec(st, get_route(st, "r2dddddd"))
    check("транзитивно собраны подписки", any(s["url"] == "https://json/sub" for s in spec["subs"]))
    check("транзитивно собраны ключи", any(k["link"].startswith("vless://kid@hk") for k in spec["keys"]))

    # выключим r1 → r2 ничего не получает
    graph.update_route(st, "r1cccccc", enabled=False)
    spec2 = graph.resolve_links_spec(st, get_route(st, "r2dddddd"))
    check("выключенный вход не отдаёт ничего", not spec2["subs"] and not spec2["keys"])

    # цикл r2→r1 (плюс уже есть r1→r2) — save_graph не должен дать замкнуть, resolve не виснет
    graph.update_route(st, "r1cccccc", enabled=True)
    spec3 = graph.resolve_links_spec(st, get_route(st, "r1cccccc"))
    check("resolve по r1 не виснет и собирает свои входы",
          any(s["url"] == "https://json/sub" for s in spec3["subs"]))


# ── 6. формат: ключ не «опускает» формат подписки ──────────────────────────
def t_format():
    print("\n[6] выбор формата по подпискам, не по ключу")
    route = {"id": "r", "title": "T", "mode": "merge"}

    # JSON-подписка + vless-ключ → остаётся JSON, ключ обёрнут в конфиг
    spec = {"subs": [{"url": "https://json/sub", "renames": []}],
            "keys": [{"link": "vless://kid@hk:443?type=tcp", "name": "MyKey"}]}
    payload, h = subs.build_merged_response(route, spec)
    check("JSON-sub + vless-ключ → JSON", "application/json" in h.get("Content-Type", ""))
    names = names_from_json(payload)
    check("JSON содержит и подписку, и ключ", "Srv1" in names and "MyKey" in names, names)

    # JSON-подписка + ss-ключ → остаётся JSON, ss оборачивается в конфиг (не теряется)
    spec = {"subs": [{"url": "https://json/sub", "renames": []}],
            "keys": [{"link": "ss://YWVzLTI1Ni1nY206cHc@hs:8388", "name": "SSKey"}]}
    payload, h = subs.build_merged_response(route, spec)
    check("JSON-sub + ss-ключ → формат остаётся JSON", "application/json" in h.get("Content-Type", ""))
    check("ss-ключ обёрнут в конфиг (не потерян, группа цела)",
          names_from_json(payload) == ["Srv1", "SSKey"], names_from_json(payload))

    # JSON-подписка + неконвертируемый ключ (hysteria2) → JSON цел, ключ пропущен (не разворачиваем группу)
    spec = {"subs": [{"url": "https://json/sub", "renames": []}],
            "keys": [{"link": "hysteria2://pw@hh:443", "name": "Hy"}]}
    payload, h = subs.build_merged_response(route, spec)
    check("hysteria2-ключ пропущен, JSON-группа не развёрнута", names_from_json(payload) == ["Srv1"])

    # РЕАЛЬНЫЙ БАГ: JSON-«нода» (group) + плоский список с ss → группа сохраняется (не взрывается)
    group = {"remarks": "Европа (Быстрый)", "outbounds": [
        subs._vless_to_outbound("vless://a@h1:443?type=tcp#n1")[0],
        subs._vless_to_outbound("vless://b@h2:443?type=tcp#n2")[0],
        {"protocol": "freedom", "tag": "direct"}]}
    FAKE["https://group/sub"] = (json.dumps([group]).encode(), {"Content-Type": "application/json"})
    FAKE["https://flat/sub"] = (b64("vless://c@h3:443#F1\nss://YWVzLTI1Ni1nY206cHc@h4:8388#F2"), {})
    spec = {"subs": [{"url": "https://group/sub", "renames": []}, {"url": "https://flat/sub", "renames": []}], "keys": []}
    payload, h = subs.build_merged_response(route, spec)
    names = names_from_json(payload)
    check("микс JSON-группы + плоского списка с ss → остаётся JSON", "application/json" in h.get("Content-Type", ""))
    check("группа НЕ развёрнута в отдельные ссылки (1 группа + 2 плоские)",
          names == ["Европа (Быстрый)", "F1", "F2"], names)
    grp = json.loads(payload.decode())[0]
    check("у группы сохранены её внутренние outbounds (балансер/роутинг)",
          len(grp.get("outbounds", [])) == 3, len(grp.get("outbounds", [])))

    # text-подписка + ключи → base64-список с переименованным #fragment
    spec = {"subs": [{"url": "https://text/sub", "renames": []}],
            "keys": [{"link": "vless://kid@hk:443#orig", "name": "Renamed"}]}
    payload, h = subs.build_merged_response(route, spec)
    links = links_from_b64(payload)
    check("text-sub → base64", "text/plain" in h.get("Content-Type", ""))
    check("ключ присутствует с новым именем", any(frag(l) == "Renamed" for l in links), links)
    check("ссылка подписки присутствует", any("host2:443" in l for l in links), links)

    # только ключи (нет подписок) → base64-список ключей
    spec = {"subs": [], "keys": [{"link": "vless://kid@hk:443", "name": "OnlyKey"}]}
    payload, h = subs.build_merged_response(route, spec)
    check("только ключи → base64 со ссылкой", any("hk:443" in l for l in links_from_b64(payload)))


# ── 7. гибрид-матч и дедуп ─────────────────────────────────────────────────
def t_rename_match():
    print("\n[7] гибрид-матч переименования и дедуп")
    route = {"id": "r", "mode": "merge"}

    # апстрим переименовал ссылку (имя сменилось), но адрес тот же → матч по адресу
    FAKE["https://renamed/sub"] = (b64("vless://uid2@host2:443?type=tcp#BrandNewName"), {})
    spec = {"subs": [{"url": "https://renamed/sub",
                      "renames": [{"addr": "host2:443", "name": "OldName", "to": "Custom"}]}], "keys": []}
    payload, h = subs.build_merged_response(route, spec)
    check("addr-матч переживает смену имени апстримом",
          any(frag(l) == "Custom" for l in links_from_b64(payload)))

    # неоднозначность: два правила на один адрес, имя не совпадает → без падения, имя не меняем
    spec = {"subs": [{"url": "https://renamed/sub", "renames": [
        {"addr": "host2:443", "name": "n1", "to": "t1"},
        {"addr": "host2:443", "name": "n2", "to": "t2"}]}], "keys": []}
    payload, h = subs.build_merged_response(route, spec)
    check("неоднозначный addr → имя не тронуто, без падения",
          any(frag(l) == "BrandNewName" for l in links_from_b64(payload)))

    # дедуп: полностью идентичный конфиг (включая remarks) из двух подписок → один
    FAKE["https://dupA"] = (json.dumps([json_config("vless://u@hh:443?type=tcp#Same")]).encode(), {})
    FAKE["https://dupB"] = (json.dumps([json_config("vless://u@hh:443?type=tcp#Same")]).encode(), {})
    spec = {"subs": [{"url": "https://dupA", "renames": []}, {"url": "https://dupB", "renames": []}], "keys": []}
    check("идентичные конфиги (вкл. remarks) схлопнуты в один",
          names_from_json(subs.build_merged_response(route, spec)[0]) == ["Same"])
    # конфиги, отличающиеся ТОЛЬКО именем → разные ноды, сохраняем оба (как у источника)
    FAKE["https://difA"] = (json.dumps([json_config("vless://u@hh:443?type=tcp#NameA")]).encode(), {})
    FAKE["https://difB"] = (json.dumps([json_config("vless://u@hh:443?type=tcp#NameB")]).encode(), {})
    spec = {"subs": [{"url": "https://difA", "renames": []}, {"url": "https://difB", "renames": []}], "keys": []}
    check("разные имена → обе ноды сохранены",
          sorted(names_from_json(subs.build_merged_response(route, spec)[0])) == ["NameA", "NameB"])


# ── 8. зеркало ─────────────────────────────────────────────────────────────
def t_mirror():
    print("\n[8] зеркало: байт-в-байт только без ключей/переименований")
    route = {"id": "r", "title": "T", "mode": "mirror"}
    spec = {"subs": [{"url": "https://mirror/sub", "renames": []}], "keys": []}
    payload, h = subs.build_route_response(route, spec)
    check("зеркало 1 sub/0 keys/0 renames → байт-в-байт", payload == b"RAW-MIRROR-BYTES")

    spec = {"subs": [{"url": "https://mirror/sub", "renames": [{"addr": "x:1", "name": "a", "to": "b"}]}], "keys": []}
    payload, h = subs.build_route_response(route, spec)
    check("зеркало + rename → уходит в merge (не байт-в-байт)", payload != b"RAW-MIRROR-BYTES")

    # spec=None → вырожденный spec из upstreams (легаси-совместимость)
    route2 = {"id": "r2", "mode": "merge", "upstreams": ["https://text/sub"]}
    payload, h = subs.build_route_response(route2, None)
    check("spec=None строит spec из upstreams", any("host2:443" in l for l in links_from_b64(payload)))


# ── 9. preview ─────────────────────────────────────────────────────────────
def t_preview():
    print("\n[9] preview_subscription")
    rows = subs.preview_subscription("https://json/sub")
    check("preview JSON: имя+addr", rows and rows[0]["name"] == "Srv1" and rows[0]["addr"] == "host1:443", rows)
    rows = subs.preview_subscription("https://text/sub")
    check("preview text: имя+addr", rows and rows[0]["name"] == "Srv2" and rows[0]["addr"] == "host2:443", rows)


# ── мультидомен: миграция, host-aware, per-domain фейловер ─────────────────
def set_domains(st, domains, **extra):
    def mut(cfg):
        s = cfg.setdefault("settings", {})
        dns = s.setdefault("dns", {})
        dns["domains"] = domains
        for k, v in extra.items():
            s[k] = v
    st.update_config(mut)


def t_migrate_domains():
    print("\n[10] миграция легаси-домена → domains[0]")
    st = new_store()

    def seed(cfg):
        s = cfg.setdefault("settings", {})
        dns = s.setdefault("dns", {})
        dns["sub"] = {"zone": "z.ru", "subdomain": "hh"}
        dns["regru_username"] = "user1"
        dns["regru_password_enc"] = "enc:xxx"
        s["sub_public_base"] = "https://hh.z.ru"
        dns["domains"] = []
    st.update_config(seed)
    graph.migrate_config(st)
    doms = (st.get_settings().get("dns") or {}).get("domains")
    check("один домен создан", len(doms) == 1, doms)
    d = doms[0]
    check("id = 'default'", d["id"] == "default", d)
    check("default = True", d["default"] is True)
    check("зона/поддомен перенесены", d["zone"] == "z.ru" and d["subdomain"] == "hh", d)
    check("логин/пароль reg.ru перенесены",
          d["regru_username"] == "user1" and d["regru_password_enc"] == "enc:xxx")
    check("public_base перенесён", d["public_base"] == "https://hh.z.ru", d)


def t_migrate_idempotent():
    print("\n[11] миграция идемпотентна (без бампа версии)")
    st = new_store()
    graph.migrate_config(st)
    v1 = st.get_meta("config")["version"]
    graph.migrate_config(st)
    v2 = st.get_meta("config")["version"]
    check("повторная миграция не бампит версию", v1 == v2, (v1, v2))
    check("id остаётся 'default'", st.get_settings()["dns"]["domains"][0]["id"] == "default")


def t_migrate_deterministic():
    print("\n[12] миграция детерминирована (узлы сходятся)")
    stores = []
    for _ in range(2):
        st = new_store()

        def seed(cfg):
            dns = cfg.setdefault("settings", {}).setdefault("dns", {})
            dns["sub"] = {"zone": "q.ru", "subdomain": "p"}
            dns["regru_username"] = "u"
            dns["regru_password_enc"] = "enc:k"
            dns["domains"] = []
        st.update_config(seed)
        graph.migrate_config(st)
        stores.append(st)
    da = stores[0].get_settings()["dns"]["domains"][0]
    db = stores[1].get_settings()["dns"]["domains"][0]
    check("два узла дают идентичный дефолтный домен", da == db, (da, db))


def t_domain_id_carried():
    print("\n[13] domain_id сохраняется и переживает запись старого узла")
    st = new_store()
    set_domains(st, [{"id": "dom_a", "zone": "a.ru", "subdomain": "x", "enabled": True, "default": True}])
    data = {
        "sources": [{"id": "s1bbbbbb", "type": "source", "url": "https://json/sub"}],
        "routes": [{"id": "r1cccccc", "path": "/x", "mode": "merge", "enabled": True, "domain_id": "dom_a"}],
        "edges": [{"from": "s1bbbbbb", "to": "r1cccccc"}],
    }
    ok, errs = graph.save_graph(st, data)
    check("save_graph ok", ok, errs)
    check("domain_id сохранён", get_route(st)["domain_id"] == "dom_a", get_route(st))
    st.update_config(lambda cfg: cfg.__setitem__("routes", [dict(r) for r in cfg["routes"]]))
    check("domain_id пережил запись старого узла", get_route(st)["domain_id"] == "dom_a")


def t_domain_unknown_blanks():
    print("\n[14] неизвестный domain_id → ''")
    st = new_store()
    set_domains(st, [{"id": "dom_a", "zone": "a.ru", "subdomain": "x", "enabled": True, "default": True}])
    graph.save_graph(st, {"sources": [], "edges": [], "routes": [
        {"id": "r1cccccc", "path": "/x", "mode": "merge", "enabled": True, "domain_id": "ghost"}]})
    check("чужой domain_id обнулён", get_route(st)["domain_id"] == "")


def t_perdomain_path_uniqueness():
    print("\n[15] уникальность пути per-domain")
    st = new_store()
    set_domains(st, [
        {"id": "dom_a", "zone": "a.ru", "subdomain": "x", "enabled": True, "default": True},
        {"id": "dom_b", "zone": "b.ru", "subdomain": "y", "enabled": True, "default": False},
    ])
    ok, errs = graph.save_graph(st, {"sources": [], "edges": [], "routes": [
        {"id": "r1cccccc", "path": "/x", "mode": "merge", "enabled": True, "domain_id": "dom_a"},
        {"id": "r2dddddd", "path": "/x", "mode": "merge", "enabled": True, "domain_id": "dom_b"}]})
    check("/x на A и /x на B — оба сохраняются", ok, errs)
    ok2, errs2 = graph.save_graph(st, {"sources": [], "edges": [], "routes": [
        {"id": "r1cccccc", "path": "/x", "mode": "merge", "enabled": True, "domain_id": "dom_a"},
        {"id": "r2dddddd", "path": "/x", "mode": "merge", "enabled": True, "domain_id": "dom_a"}]})
    check("/x дважды на одном домене — ошибка", not ok2, errs2)


def t_find_route_host():
    print("\n[16] host-aware find_route")
    st = new_store()
    set_domains(st, [
        {"id": "dom_a", "zone": "a.ru", "subdomain": "x", "enabled": True, "default": True},
        {"id": "dom_b", "zone": "b.ru", "subdomain": "y", "enabled": True, "default": False},
    ])
    graph.save_graph(st, {"sources": [], "edges": [], "routes": [
        {"id": "ra000000", "path": "/p", "mode": "merge", "enabled": True, "domain_id": "dom_a"},
        {"id": "rb000000", "path": "/p", "mode": "merge", "enabled": True, "domain_id": "dom_b"}]})
    check("host A → маршрут A", (graph.find_route(st, "/p", host="x.a.ru") or {}).get("id") == "ra000000")
    check("host B → маршрут B", (graph.find_route(st, "/p", host="y.b.ru") or {}).get("id") == "rb000000")
    check("host=None → дефолтный (A)", (graph.find_route(st, "/p", host=None) or {}).get("id") == "ra000000")
    check("неизвестный host → дефолтный (A)",
          (graph.find_route(st, "/p", host="1.2.3.4") or {}).get("id") == "ra000000")


def t_effective_domain_fallback():
    print("\n[17] маршрут на выключенном домене → дефолтный")
    st = new_store()
    set_domains(st, [
        {"id": "dom_a", "zone": "a.ru", "subdomain": "x", "enabled": True, "default": True},
        {"id": "dom_b", "zone": "b.ru", "subdomain": "y", "enabled": False, "default": False},
    ])
    graph.save_graph(st, {"sources": [], "edges": [], "routes": [
        {"id": "rq000000", "path": "/q", "mode": "merge", "enabled": True, "domain_id": "dom_b"}]})
    settings = st.get_settings()
    eff = graph.effective_domain(settings, get_route(st, "rq000000"))
    check("effective_domain выключенного → дефолтный", eff and eff["id"] == "dom_a", eff)
    check("отдаётся на дефолтном host",
          (graph.find_route(st, "/q", host="x.a.ru") or {}).get("id") == "rq000000")
    check("на host выключенного домена не находится", graph.find_route(st, "/q", host="y.b.ru") is None)


def t_host_norm():
    print("\n[18] _host_norm")
    check("host:port → host, lower", graph._host_norm("Happ.example.com:443") == "happ.example.com")
    check("IPv6 [::1]:8081 → ::1", graph._host_norm("[::1]:8081") == "::1")
    check("trailing dot убран", graph._host_norm("x.y.") == "x.y")


def t_provider_from_domain():
    print("\n[19] provider_from_domain")
    dec = lambda s: s
    p, err = dns_providers.provider_from_domain({"regru_username": "u", "regru_password_enc": "pw"}, dec)
    check("с кредами → RegRuProvider", err is None and isinstance(p, dns_providers.RegRuProvider))
    p2, err2 = dns_providers.provider_from_domain({"regru_username": "", "regru_password_enc": ""}, dec)
    check("без кредов → ошибка", p2 is None and bool(err2))
    os.environ["DNS_MOCK"] = "1"
    try:
        p3, err3 = dns_providers.provider_from_domain({}, dec)
        check("DNS_MOCK=1 → MockProvider", err3 is None and isinstance(p3, dns_providers.MockProvider))
    finally:
        os.environ.pop("DNS_MOCK", None)


def t_normalize_domains():
    print("\n[20] normalize_domains: валидация")
    enc = lambda s: "enc:" + s
    # дубль FQDN
    parsed, errs = graph.normalize_domains(
        [{"id": "a", "zone": "z.ru", "subdomain": "h"}, {"id": "b", "zone": "z.ru", "subdomain": "h"}], {}, enc)
    check("дубль FQDN отклонён", any("FQDN" in e for e in errs), errs)
    # включённый без поддомена
    _, errs2 = graph.normalize_domains([{"id": "a", "zone": "z.ru", "subdomain": "", "enabled": True}], {}, enc)
    check("включённый без поддомена — ошибка", bool(errs2), errs2)
    # ноль default → первый назначается
    parsed3, _ = graph.normalize_domains(
        [{"id": "a", "zone": "z.ru", "subdomain": "h"}, {"id": "b", "zone": "z.ru", "subdomain": "g"}], {}, enc)
    check("ноль default → первый default", parsed3[0]["default"] and not parsed3[1]["default"], parsed3)
    # >1 default → остаётся первый
    parsed4, _ = graph.normalize_domains(
        [{"id": "a", "zone": "z.ru", "subdomain": "h", "default": True},
         {"id": "b", "zone": "z.ru", "subdomain": "g", "default": True}], {}, enc)
    check(">1 default → только первый", parsed4[0]["default"] and not parsed4[1]["default"], parsed4)
    # пустой пароль → сохраняется прежний по id
    parsed5, _ = graph.normalize_domains([{"id": "a", "zone": "z.ru", "subdomain": "h"}],
                                         {"a": {"regru_password_enc": "enc:old"}}, enc)
    check("пустой пароль → прежний сохранён", parsed5[0]["regru_password_enc"] == "enc:old")
    # новый пароль шифруется
    parsed6, _ = graph.normalize_domains([{"id": "a", "zone": "z.ru", "subdomain": "h", "regru_password": "new"}], {}, enc)
    check("новый пароль зашифрован", parsed6[0]["regru_password_enc"] == "enc:new")


def t_merge_failover_per_domain():
    print("\n[21] merge_failover поэлементно по доменам")
    st = new_store()
    st.update_failover(lambda fo: fo.setdefault("domains", {}).__setitem__(
        "A", {"active": "n1", "dns_ip": "1.1.1.1", "last_ts": 10.0, "fail_counts": {}}))
    st.merge_failover({"data": {"domains": {"B": {"active": "n2", "dns_ip": "2.2.2.2", "last_ts": 5.0}}}})
    fo = st.get_failover()
    check("домен A не тронут", fo["domains"]["A"]["active"] == "n1")
    check("домен B добавлен", fo["domains"]["B"]["active"] == "n2")
    st.merge_failover({"data": {"domains": {"B": {"active": "n3", "dns_ip": "3.3.3.3", "last_ts": 20.0}}}})
    check("свежий B (last_ts 20) переопределяет", st.get_failover()["domains"]["B"]["active"] == "n3")
    st.merge_failover({"data": {"domains": {"B": {"active": "nX", "last_ts": 3.0}}}})
    check("устаревший B (last_ts 3) игнорируется", st.get_failover()["domains"]["B"]["active"] == "n3")


def t_failover_oldnode_compat():
    print("\n[22] back-compat failover со старым узлом")
    st = new_store()
    set_domains(st, [{"id": "default", "zone": "z.ru", "subdomain": "s", "enabled": True, "default": True}])
    st.merge_failover({"data": {"active": "nX", "dns_ip": "9.9.9.9", "last_ts": 100.0}})
    fo = st.get_failover()
    check("плоское состояние влито в дефолтный домен", fo["domains"].get("default", {}).get("active") == "nX")
    check("верхнеуровневая сводка обновлена", fo["active"] == "nX")
    st2 = new_store()
    st2.merge_failover({"data": {"domains": {"d1": {"active": "n5", "last_ts": 7.0}}}})
    check("новый формат влит в стартовый старый док без падений",
          st2.get_failover()["domains"]["d1"]["active"] == "n5")


def t_failover_summary_mirror():
    print("\n[23] _record_failover: зеркало сводки только для дефолта")
    st = new_store()
    cl = clustermod.Cluster(st, identity={"id": "n1", "public_ip": "10.0.0.1", "secret": "x"})
    cl._record_failover("default", True, "n1", "10.0.0.1", "manual", True, "ok")
    fo = st.get_failover()
    check("дефолтный домен active", fo["domains"]["default"]["active"] == "n1")
    check("верхнеуровневый active зеркалится", fo["active"] == "n1")
    cl._record_failover("dom_b", False, "n2", "10.0.0.2", "manual", True, "ok")
    fo = st.get_failover()
    check("недефолтный домен active", fo["domains"]["dom_b"]["active"] == "n2")
    check("верхнеуровневый active НЕ изменён недефолтным", fo["active"] == "n1")


def t_per_domain_active():
    print("\n[24] per-domain активный по node_priority + seize (mock DNS)")
    os.environ["DNS_MOCK"] = "1"
    try:
        st = new_store()
        set_domains(st, [{"id": "dA", "zone": "a.ru", "subdomain": "x", "enabled": True,
                          "default": True, "node_priority": ["n2"],
                          "regru_username": "u", "regru_password_enc": "e"}])
        cl = clustermod.Cluster(st, identity={"id": "n1", "public_ip": "10.0.0.1", "secret": "x"})
        nodes = [{"id": "n1", "priority": 1}, {"id": "n2", "priority": 2}]
        domain = graph.enabled_domains(st.get_settings())[0]
        check("node_priority выводит n2 вперёд n1",
              cl.best_alive_for_domain(domain, nodes, {"n1", "n2"}) == "n2")
        check("n2 мёртв → откат на глобальный (n1)",
              cl.best_alive_for_domain(domain, nodes, {"n1"}) == "n1")
        ok = cl.seize_domain(domain, True, by="auto")
        check("seize_domain mock ok", ok)
        fo = st.get_failover()
        check("домен dA: active = self (n1)", fo["domains"]["dA"]["active"] == "n1")
        check("сводка зеркалит дефолтный домен", fo["active"] == "n1")
    finally:
        os.environ.pop("DNS_MOCK", None)


def t_disabled_default_repair():
    print("\n[25] дефолтный домен всегда включённый")
    enc = lambda s: "enc:" + s
    # админ пометил выключенный домен дефолтным → default переносится на включённый
    parsed, _ = graph.normalize_domains([
        {"id": "a", "zone": "a.ru", "subdomain": "x", "enabled": False, "default": True},
        {"id": "b", "zone": "b.ru", "subdomain": "y", "enabled": True, "default": False},
    ], {}, enc)
    check("default перенесён на включённый домен",
          next(d for d in parsed if d["default"])["id"] == "b", parsed)
    check("выключенный домен не default", not parsed[0]["default"])
    # default_domain игнорирует выключенный помеченный default (защита от старых данных)
    st = new_store()
    set_domains(st, [
        {"id": "a", "zone": "a.ru", "subdomain": "x", "enabled": False, "default": True},
        {"id": "b", "zone": "b.ru", "subdomain": "y", "enabled": True, "default": False},
    ])
    dd = graph.default_domain(st.get_settings())
    check("default_domain возвращает включённый (b)", dd and dd["id"] == "b", dd)
    graph.save_graph(st, {"sources": [], "edges": [], "routes": [
        {"id": "r0000000", "path": "/p", "mode": "merge", "enabled": True, "domain_id": ""}]})
    check("маршрут без домена отдаётся на включённом дефолте (host b)",
          (graph.find_route(st, "/p", host="y.b.ru") or {}).get("id") == "r0000000")
    check("на host выключенного помеченного-дефолта (a) — ничего",
          graph.find_route(st, "/p", host="x.a.ru") is None)


def t_find_route_exact_wins():
    print("\n[26] точный домен маршрута приоритетнее осиротевшего")
    st = new_store()
    set_domains(st, [
        {"id": "dom_a", "zone": "a.ru", "subdomain": "x", "enabled": True, "default": True},
        {"id": "dom_b", "zone": "b.ru", "subdomain": "y", "enabled": True, "default": False},
    ])
    # rb записан ПЕРВЫМ, ra вторым — порядок не должен решать исход
    graph.save_graph(st, {"sources": [], "edges": [], "routes": [
        {"id": "rb000000", "path": "/p", "mode": "merge", "enabled": True, "domain_id": "dom_b"},
        {"id": "ra000000", "path": "/p", "mode": "merge", "enabled": True, "domain_id": "dom_a"}]})
    # выключаем dom_b → rb «осиротел» и падает в дефолт dom_a, где уже есть ra
    set_domains(st, [
        {"id": "dom_a", "zone": "a.ru", "subdomain": "x", "enabled": True, "default": True},
        {"id": "dom_b", "zone": "b.ru", "subdomain": "y", "enabled": False, "default": False},
    ])
    got = graph.find_route(st, "/p", host="x.a.ru")
    check("точный dom_a выигрывает у осиротевшего dom_b (детерминированно)",
          got and got["id"] == "ra000000", got)


def t_fourth_level_domain():
    print("\n[27] домены 4-го уровня (многоуровневый поддомен)")
    enc = lambda s: "enc:" + s
    parsed, errs = graph.normalize_domains([
        {"id": "d4", "zone": "example.com", "subdomain": "happ.region", "enabled": True, "default": True},
        {"id": "d5", "zone": "example.com", "subdomain": "a.b.c", "enabled": True, "default": False},
    ], {}, enc)
    check("4-й/5-й уровень принят без ошибок", not errs, errs)
    check("FQDN 4-го уровня = happ.region.example.com", graph.domain_fqdn(parsed[0]) == "happ.region.example.com")
    check("FQDN 5-го уровня = a.b.c.example.com", graph.domain_fqdn(parsed[1]) == "a.b.c.example.com")
    check("_host_norm 4-го уровня с портом",
          graph._host_norm("Happ.Region.example.com:8081") == "happ.region.example.com")
    st = new_store()
    set_domains(st, [
        {"id": "d4", "zone": "example.com", "subdomain": "happ.region", "enabled": True, "default": True},
        {"id": "d3", "zone": "example.com", "subdomain": "happ", "enabled": True, "default": False},
    ])
    graph.save_graph(st, {"sources": [], "edges": [], "routes": [
        {"id": "r4000000", "path": "/p", "mode": "merge", "enabled": True, "domain_id": "d4"},
        {"id": "r3000000", "path": "/p", "mode": "merge", "enabled": True, "domain_id": "d3"}]})
    check("host 4-го уровня → свой маршрут",
          (graph.find_route(st, "/p", host="happ.region.example.com") or {}).get("id") == "r4000000")
    check("host 3-го уровня → свой (не путается с 4-м под той же зоной)",
          (graph.find_route(st, "/p", host="happ.example.com") or {}).get("id") == "r3000000")


# ── ноды-группы (страна → JSON-конфиг с балансером leastPing) ───────────────
def _group_spec(name, members, subs_list, params=None, keys_list=None):
    return {"subs": [], "keys": [], "groups": [{
        "name": name, "params": params or {},
        "buckets": [{"name": name, "members": members}],
        "subs": subs_list, "keys": keys_list or []}]}


def t_group_balancer_emit():
    print("\n[28] группа → один конфиг с балансером leastPing")
    route = {"id": "r", "title": "T", "mode": "merge"}
    spec = _group_spec("🇩🇪 Германия",
                       [{"addr": "de1:443", "name": "DE-1"}, {"addr": "de2:443", "name": "DE-2"}],
                       [{"url": "https://de/sub", "renames": []}], {"strategy": "leastPing"})
    payload, h = subs.build_merged_response(route, spec)
    check("Content-Type JSON", "application/json" in h.get("Content-Type", ""))
    cfgs = json.loads(payload.decode())
    check("один конфиг группы", len(cfgs) == 1, len(cfgs))
    c = cfgs[0]
    check("remarks = имя корзины", c.get("remarks") == "🇩🇪 Германия", c.get("remarks"))
    tags = [o.get("tag") for o in c.get("outbounds", [])]
    check("теги proxy-0/proxy-1/direct/block", tags == ["proxy-0", "proxy-1", "direct", "block"], tags)
    bal = c["routing"]["balancers"][0]
    check("balancer selector proxy-", bal["selector"] == ["proxy-"])
    check("strategy leastPing", bal["strategy"]["type"] == "leastPing")
    check("routing rule balancerTag", c["routing"]["rules"][0]["balancerTag"] == "balancer")
    check("burstObservatory subjectSelector proxy-", c["burstObservatory"]["subjectSelector"] == ["proxy-"])
    check("pingConfig destination задан", bool(c["burstObservatory"]["pingConfig"]["destination"]))


def t_group_mixed_protocol():
    print("\n[29] группа: vless+ss в балансере, hysteria2 не входит")
    route = {"id": "r", "mode": "merge"}
    spec = _group_spec("Микс",
                       [{"addr": "h1:443", "name": "V"}, {"addr": "h2:8388", "name": "S"},
                        {"addr": "h3:443", "name": "HY"}],
                       [{"url": "https://mix/sub", "renames": []}])
    payload, h = subs.build_merged_response(route, spec)
    cfgs = json.loads(payload.decode())
    bal = next((c for c in cfgs if c.get("remarks") == "Микс"), None)
    check("балансер создан", bal is not None)
    members = [o for o in bal["outbounds"] if str(o.get("tag", "")).startswith("proxy-")]
    check("в балансере ровно 2 члена (vless+ss)", len(members) == 2, len(members))
    check("протоколы vless+shadowsocks",
          sorted(o.get("protocol") for o in members) == ["shadowsocks", "vless"])
    check("hysteria2 не в выдаче (JSON форсирован — passthrough hy2 невозможен, лог)",
          "hysteria2" not in payload.decode())


def t_group_only_nonconvertible():
    print("\n[30] группа из только-неконвертируемых → balancer не эмитится, passthrough base64")
    route = {"id": "r", "mode": "merge"}
    spec = _group_spec("HY", [{"addr": "h9:443", "name": "HY1"}, {"addr": "h8:443", "name": "TU1"}],
                       [{"url": "https://hy/sub", "renames": []}])
    payload, h = subs.build_merged_response(route, spec)
    check("нет балансера → base64 (не JSON)", "text/plain" in h.get("Content-Type", ""))
    links = links_from_b64(payload)
    check("hysteria2 отдан отдельной ссылкой (не потерян)", any("h9:443" in l for l in links), links)
    check("tuic отдан отдельной ссылкой", any("h8:443" in l for l in links), links)


def t_group_passthrough_alongside():
    print("\n[31] группа + небукетированная ссылка рядом")
    route = {"id": "r", "mode": "merge"}
    spec = _group_spec("🇩🇪", [{"addr": "de1:443", "name": "DE-1"}],
                       [{"url": "https://de/sub", "renames": []}])
    payload, h = subs.build_merged_response(route, spec)
    cfgs = json.loads(payload.decode())
    check("два конфига (балансер + обёрнутый DE-2)", len(cfgs) == 2, len(cfgs))
    check("балансер первым", cfgs[0].get("remarks") == "🇩🇪")
    bmembers = [o for o in cfgs[0]["outbounds"] if str(o.get("tag", "")).startswith("proxy-")]
    check("в балансере 1 член (DE-1)", len(bmembers) == 1, len(bmembers))
    check("DE-2 отдан отдельным конфигом", any(c.get("remarks") == "DE-2" for c in cfgs))


def t_group_force_json():
    print("\n[32] группа форсирует JSON даже с text-подпиской рядом")
    route = {"id": "r", "mode": "merge"}
    spec = {"subs": [{"url": "https://text/sub", "renames": []}], "keys": [], "groups": [{
        "name": "G", "params": {}, "buckets": [{"name": "G", "members": [{"addr": "de1:443", "name": "DE-1"}]}],
        "subs": [{"url": "https://de/sub", "renames": []}], "keys": []}]}
    payload, h = subs.build_merged_response(route, spec)
    check("формат JSON (не base64)", "application/json" in h.get("Content-Type", ""))
    cfgs = json.loads(payload.decode())
    check("балансер + обёрнутая text-ссылка (host2)", any(c.get("remarks") == "G" for c in cfgs)
          and any("host2" in json.dumps(c) for c in cfgs))


def t_group_resolve():
    print("\n[33] resolve_links_spec: s1 → g1(bucket) → r1")
    st = new_store()
    data = {
        "sources": [
            {"id": "s1bbbbbb", "type": "source", "url": "https://de/sub"},
            {"id": "g1gggggg", "type": "group", "url": "", "label": "🇩🇪 Германия"},
        ],
        "routes": [{"id": "r1cccccc", "path": "/g", "mode": "merge", "enabled": True}],
        "edges": [{"from": "s1bbbbbb", "to": "g1gggggg"}, {"from": "g1gggggg", "to": "r1cccccc"}],
        "node_meta": {"g1gggggg": {"group": {
            "buckets": [{"name": "🇩🇪 Германия", "members": [{"addr": "de1:443", "name": "DE-1"}]}],
            "params": {"strategy": "leastPing"}}}},
    }
    ok, errs = graph.save_graph(st, data)
    check("save_graph ok", ok, errs)
    spec = graph.resolve_links_spec(st, get_route(st, "r1cccccc"))
    check("spec содержит группу", len(spec.get("groups", [])) == 1, spec.get("groups"))
    g = spec["groups"][0]
    check("имя группы из label", g["name"] == "🇩🇪 Германия", g["name"])
    check("подписка группы — de/sub", any(s["url"] == "https://de/sub" for s in g["subs"]))
    check("корзина группы цела", g["buckets"][0]["name"] == "🇩🇪 Германия")
    # сборка ответа материализует de1 в балансер
    payload, h = subs.build_route_response(get_route(st, "r1cccccc"), spec)
    check("отдача — JSON c балансером", "application/json" in h.get("Content-Type", "")
          and any(c.get("remarks") == "🇩🇪 Германия" for c in json.loads(payload.decode())))


def t_group_save_carry():
    print("\n[34] save_graph несёт ноду-группу; classic-путь её не стирает")
    st = new_store()
    data = {
        "sources": [
            {"id": "s1bbbbbb", "type": "source", "url": "https://de/sub"},
            {"id": "g1gggggg", "type": "group", "url": "", "label": "G"},
        ],
        "routes": [{"id": "r1cccccc", "path": "/g", "mode": "merge", "enabled": True}],
        "edges": [{"from": "s1bbbbbb", "to": "g1gggggg"}, {"from": "g1gggggg", "to": "r1cccccc"}],
        "node_meta": {"g1gggggg": {"group": {
            "buckets": [{"name": "G", "members": [{"addr": "de1:443", "name": "DE-1"}]}], "params": {}}}},
    }
    graph.save_graph(st, data)
    cfg = st.get_config()
    g = next((s for s in cfg["sources"] if s["id"] == "g1gggggg"), None)
    check("группа сохранена с type=group", g and g.get("type") == "group", g)
    check("node_meta.group.buckets целы", cfg["node_meta"]["g1gggggg"]["group"]["buckets"][0]["name"] == "G")
    check("ребро group→route цело", any(e["from"] == "g1gggggg" and e["to"] == "r1cccccc" for e in cfg["edges"]))
    check("ребро source→group цело", any(e["from"] == "s1bbbbbb" and e["to"] == "g1gggggg" for e in cfg["edges"]))
    check("upstreams маршрута пусты (группа не идёт в upstreams)", get_route(st)["upstreams"] == [])
    # classic-путь (add_route → sync_graph_from_routes) не должен стереть группу/рёбра
    graph.add_route(st, "/other", "Other", ["https://text/sub"], "merge")
    cfg2 = st.get_config()
    sids = {s["id"] for s in cfg2["sources"]}
    check("группа жива после add_route", "g1gggggg" in sids)
    check("источник группы жив после add_route", "s1bbbbbb" in sids)
    check("рёбра группы живы после add_route",
          any(e["from"] == "s1bbbbbb" and e["to"] == "g1gggggg" for e in cfg2["edges"])
          and any(e["from"] == "g1gggggg" and e["to"] == "r1cccccc" for e in cfg2["edges"]))


def t_group_sync_safety():
    print("\n[35] нода-группа переживает запись старого узла")
    st = new_store()
    graph.save_graph(st, {
        "sources": [{"id": "g1gggggg", "type": "group", "url": "", "label": "G"}],
        "routes": [{"id": "r1cccccc", "path": "/g", "mode": "merge", "enabled": True}],
        "edges": [{"from": "g1gggggg", "to": "r1cccccc"}],
        "node_meta": {"g1gggggg": {"group": {
            "buckets": [{"name": "G", "members": [{"link": "vless://x@h:443#K"}]}], "params": {}}}},
    })
    # старый узел переписывает только sources/routes/edges (как dict-копии)
    st.update_config(lambda cfg: (cfg.__setitem__("sources", [dict(s) for s in cfg["sources"]]),
                                  cfg.__setitem__("edges", [dict(e) for e in cfg["edges"]])))
    cfg = st.get_config()
    check("нода-группа в sources цела", any(s["id"] == "g1gggggg" for s in cfg["sources"]))
    check("node_meta.group пережил запись старого узла",
          bool(cfg.get("node_meta", {}).get("g1gggggg", {}).get("group")))


def t_group_rename_then_group_order():
    print("\n[36] порядок: матч корзины по addr, затем переименование; remarks = имя корзины")
    route = {"id": "r", "mode": "merge"}
    # источник переименовал DE-1 → «Германия-1»; корзина матчит по addr+исходному имени
    spec = {"subs": [], "keys": [], "groups": [{
        "name": "🇩🇪 Германия", "params": {},
        "buckets": [{"name": "🇩🇪 Германия", "members": [{"addr": "de1:443", "name": "DE-1"}]}],
        "subs": [{"url": "https://de/sub",
                  "renames": [{"addr": "de1:443", "name": "DE-1", "to": "Германия-1"}]}], "keys": []}]}
    payload, h = subs.build_merged_response(route, spec)
    cfgs = json.loads(payload.decode())
    bal = next((c for c in cfgs if "Германия" in (c.get("remarks") or "")), None)
    check("корзина собрала член (addr стабилен при переименовании)",
          bal is not None and any(str(o.get("tag", "")).startswith("proxy-") for o in bal["outbounds"]))
    check("remarks конфига = имя корзины, не имя члена", bal.get("remarks") == "🇩🇪 Германия", bal.get("remarks"))


def t_group_rename_match_original():
    print("\n[37] корзина матчит по ИСХОДНОМУ имени; переименование — после (член не теряется)")
    route = {"id": "r", "mode": "merge"}
    # два члена с ОДИНАКОВЫМ addr (tier2 unique-addr не спасёт) + переименование A1 на источнике.
    # До фикса A1 переименовывался ДО матча → tier1 по имени падал → A1 терялся.
    spec = {"subs": [], "keys": [], "groups": [{
        "name": "G", "params": {},
        "buckets": [{"name": "G", "members": [{"addr": "dup:443", "name": "A1"},
                                              {"addr": "dup:443", "name": "A2"}]}],
        "subs": [{"url": "https://dup/sub",
                  "renames": [{"addr": "dup:443", "name": "A1", "to": "RA1"}]}], "keys": []}]}
    payload, h = subs.build_merged_response(route, spec)
    bal = next((c for c in json.loads(payload.decode()) if c.get("remarks") == "G"), None)
    members = [o for o in (bal or {}).get("outbounds", []) if str(o.get("tag", "")).startswith("proxy-")]
    check("оба члена в балансере, несмотря на переименование A1 (матч по исходному имени)",
          len(members) == 2, len(members))


def t_group_nameless_bucket_kept():
    print("\n[38] безымянная корзина с членами сохраняется (сервер ↔ редактор согласованы)")
    st = new_store()
    graph.save_graph(st, {
        "sources": [{"id": "g1gggggg", "type": "group", "url": "", "label": "G"}],
        "routes": [{"id": "r1cccccc", "path": "/g", "mode": "merge", "enabled": True}],
        "edges": [{"from": "g1gggggg", "to": "r1cccccc"}],
        "node_meta": {"g1gggggg": {"group": {
            "buckets": [{"name": "", "members": [{"addr": "de1:443", "name": "DE-1"}]}], "params": {}}}},
    })
    bks = st.get_config()["node_meta"]["g1gggggg"]["group"]["buckets"]
    check("безымянная корзина с членами не выброшена", len(bks) == 1 and bks[0]["members"], bks)


def t_group_resolve_dedup():
    print("\n[39] группа на входе двух маршрутов резолвится один раз (userinfo не задваивается)")
    st = new_store()
    graph.save_graph(st, {
        "sources": [
            {"id": "s1bbbbbb", "type": "source", "url": "https://deui/sub"},
            {"id": "g1gggggg", "type": "group", "url": "", "label": "G"}],
        "routes": [
            {"id": "r1cccccc", "path": "/a", "mode": "merge", "enabled": True},
            {"id": "r2dddddd", "path": "/b", "mode": "merge", "enabled": True}],
        "edges": [
            {"from": "s1bbbbbb", "to": "g1gggggg"},
            {"from": "g1gggggg", "to": "r1cccccc"},
            {"from": "g1gggggg", "to": "r2dddddd"},
            {"from": "r1cccccc", "to": "r2dddddd"}],
        "node_meta": {"g1gggggg": {"group": {
            "buckets": [{"name": "G", "members": [{"addr": "de1:443", "name": "DE-1"}]}], "params": {}}}},
    })
    spec = graph.resolve_links_spec(st, get_route(st, "r2dddddd"))
    check("группа в spec один раз (не задвоена)", len(spec.get("groups", [])) == 1, len(spec.get("groups", [])))
    payload, h = subs.build_route_response(get_route(st, "r2dddddd"), spec)
    check("Subscription-Userinfo не задвоен (total=1000)",
          "total=1000" in (h.get("Subscription-Userinfo") or ""), h.get("Subscription-Userinfo"))


# ── нода авто-выбора (все входы → один балансер leastPing, roadmap/03A) ────
def t_autoselect_emit():
    print("\n[40] авто-выбор: все входы → один балансер")
    route = {"id": "r", "mode": "merge"}
    spec = {"subs": [], "keys": [], "groups": [{
        "name": "⚡ Авто", "params": {"strategy": "leastPing"}, "auto": True, "buckets": [],
        "subs": [{"url": "https://de/sub", "renames": []}], "keys": []}]}
    payload, h = subs.build_merged_response(route, spec)
    check("Content-Type JSON", "application/json" in h.get("Content-Type", ""))
    cfgs = json.loads(payload.decode())
    check("один конфиг", len(cfgs) == 1, len(cfgs))
    c = cfgs[0]
    check("remarks = метка авто", c.get("remarks") == "⚡ Авто", c.get("remarks"))
    members = [o for o in c["outbounds"] if str(o.get("tag", "")).startswith("proxy-")]
    check("оба входа в балансере (DE-1, DE-2)", len(members) == 2, len(members))
    check("balancer leastPing", c["routing"]["balancers"][0]["strategy"]["type"] == "leastPing")


def t_autoselect_nonconvertible():
    print("\n[41] авто-выбор: hysteria2 не в балансере, отдаётся отдельно (passthrough)")
    route = {"id": "r", "mode": "merge"}
    spec = {"subs": [], "keys": [], "groups": [{
        "name": "Auto", "params": {}, "auto": True, "buckets": [],
        "subs": [{"url": "https://mix/sub", "renames": []}], "keys": []}]}
    payload, h = subs.build_merged_response(route, spec)
    cfgs = json.loads(payload.decode())
    bal = next((c for c in cfgs if c.get("remarks") == "Auto"), None)
    members = [o for o in (bal or {}).get("outbounds", []) if str(o.get("tag", "")).startswith("proxy-")]
    check("в балансере 2 члена (vless+ss)", len(members) == 2, len(members))
    check("hysteria2 не в выдаче (JSON форсирован)", "hysteria2" not in payload.decode())


def t_autoselect_resolve_save():
    print("\n[42] авто-выбор: resolve + save_graph carry + classic не стирает")
    st = new_store()
    data = {
        "sources": [
            {"id": "s1bbbbbb", "type": "source", "url": "https://de/sub"},
            {"id": "a1aaaaaa", "type": "autoselect", "url": "", "label": "⚡ Авто"}],
        "routes": [{"id": "r1cccccc", "path": "/auto", "mode": "merge", "enabled": True}],
        "edges": [{"from": "s1bbbbbb", "to": "a1aaaaaa"}, {"from": "a1aaaaaa", "to": "r1cccccc"}],
        "node_meta": {"a1aaaaaa": {"autoselect": {"params": {"strategy": "leastPing"}}}},
    }
    ok, errs = graph.save_graph(st, data)
    check("save_graph ok", ok, errs)
    cfg = st.get_config()
    a = next((s for s in cfg["sources"] if s["id"] == "a1aaaaaa"), None)
    check("нода авто сохранена type=autoselect", a and a.get("type") == "autoselect", a)
    check("node_meta.autoselect.params целы",
          cfg["node_meta"]["a1aaaaaa"]["autoselect"]["params"].get("strategy") == "leastPing")
    spec = graph.resolve_links_spec(st, get_route(st, "r1cccccc"))
    check("spec содержит auto-группу",
          len(spec.get("groups", [])) == 1 and spec["groups"][0].get("auto") is True, spec.get("groups"))
    check("подписка авто — de/sub", any(su["url"] == "https://de/sub" for su in spec["groups"][0]["subs"]))
    payload, h = subs.build_route_response(get_route(st, "r1cccccc"), spec)
    check("отдача — JSON с балансером", "application/json" in h.get("Content-Type", "")
          and any(c.get("remarks") == "⚡ Авто" for c in json.loads(payload.decode())))
    graph.add_route(st, "/x", "X", ["https://text/sub"], "merge")   # classic-путь
    cfg2 = st.get_config()
    sids = {s["id"] for s in cfg2["sources"]}
    check("авто-нода и её источник живы после add_route", "a1aaaaaa" in sids and "s1bbbbbb" in sids)
    check("рёбра авто живы после add_route",
          any(e["from"] == "s1bbbbbb" and e["to"] == "a1aaaaaa" for e in cfg2["edges"])
          and any(e["from"] == "a1aaaaaa" and e["to"] == "r1cccccc" for e in cfg2["edges"]))


def t_autoselect_edges():
    print("\n[43] авто-выбор: запрещённые рёбра отбрасываются (proc→proc, route→proc)")
    st = new_store()
    data = {
        "sources": [
            {"id": "a1aaaaaa", "type": "autoselect", "url": "", "label": "A"},
            {"id": "a2bbbbbb", "type": "autoselect", "url": "", "label": "B"},
            {"id": "g1gggggg", "type": "group", "url": "", "label": "G"}],
        "routes": [{"id": "r1cccccc", "path": "/x", "mode": "merge", "enabled": True}],
        "edges": [
            {"from": "a1aaaaaa", "to": "a2bbbbbb"},   # auto→auto запрещено
            {"from": "r1cccccc", "to": "a1aaaaaa"},   # route→auto запрещено
            {"from": "g1gggggg", "to": "a1aaaaaa"},   # group→auto (proc→proc) запрещено
            {"from": "a1aaaaaa", "to": "r1cccccc"}],  # auto→route ок
        "node_meta": {"a1aaaaaa": {"autoselect": {"params": {}}},
                      "a2bbbbbb": {"autoselect": {"params": {}}},
                      "g1gggggg": {"group": {"buckets": [{"name": "G", "members": [{"link": "vless://x@h:443#K"}]}]}}},
    }
    ok, errs = graph.save_graph(st, data)
    check("save_graph ok", ok, errs)
    edges = st.get_config()["edges"]
    check("auto→auto отброшено", not any(e["from"] == "a1aaaaaa" and e["to"] == "a2bbbbbb" for e in edges))
    check("route→auto отброшено", not any(e["from"] == "r1cccccc" and e["to"] == "a1aaaaaa" for e in edges))
    check("group→auto (proc→proc) отброшено", not any(e["from"] == "g1gggggg" and e["to"] == "a1aaaaaa" for e in edges))
    check("auto→route сохранено", any(e["from"] == "a1aaaaaa" and e["to"] == "r1cccccc" for e in edges))


# ── zapret (обход DPI): валидация, baseline, авто-тест, фоновый прогон, store ──
def t_zapret_validate():
    print("\n[44] zapret.validate_params: белый список флагов nfqws")
    ok, _ = zapret.validate_params("")
    check("пусто = direct (ok)", ok)
    ok, toks = zapret.validate_params("--dpi-desync=fake,split2 --dpi-desync-ttl=1")
    check("валидные флаги приняты", ok and toks, toks)
    ok, _ = zapret.validate_params("--dpi-desync=fake; rm -rf /")
    check("инъекция отклонена", not ok)
    ok, _ = zapret.validate_params("--unknown-flag=1")
    check("флаг не из белого списка отклонён", not ok)
    ok, _ = zapret.validate_params("notaflag")
    check("не-флаг отклонён", not ok)
    ok, _ = zapret.validate_params("x" * 1100)
    check("слишком длинная строка отклонена", not ok)


def t_zapret_baseline():
    print("\n[45] zapret.check_baseline (monkeypatch _probe)")
    orig = zapret._probe
    up = {"discord.com"}
    zapret._probe = lambda host, **kw: host in up
    try:
        res = zapret.check_baseline(["discord", "youtube"])
        check("discord доступен", res["discord"]["up"] is True)
        check("youtube недоступен", res["youtube"]["up"] is False)
    finally:
        zapret._probe = orig


def t_zapret_autotest_best():
    print("\n[46] zapret.run_autotest выбирает лучшую стратегию")
    import threading as _t
    o_apply, o_clear, o_base = zapret.apply_strategy, zapret.clear_strategy, zapret.check_baseline
    cur = {"p": None}
    zapret.apply_strategy = lambda params, log_cb=None: (cur.__setitem__("p", params) or True)
    zapret.clear_strategy = lambda log_cb=None: cur.__setitem__("p", None)
    zapret.check_baseline = lambda keys, log_cb=None, stop_evt=None: \
        {k: {"up": (cur["p"] == "--dpi-desync=fake"), "domains": {}} for k in keys}
    try:
        results, best = zapret.run_autotest(
            [{"id": "a", "label": "Direct", "params": ""},
             {"id": "b", "label": "Fake", "params": "--dpi-desync=fake"}],
            ["discord", "youtube"], None, _t.Event())
        check("лучшая — стратегия с большим числом доступных", best == "b", best)
        check("у лучшей up_count=2", results["b"]["up_count"] == 2, results["b"])
        check("у direct up_count=0", results["a"]["up_count"] == 0)
    finally:
        zapret.apply_strategy, zapret.clear_strategy, zapret.check_baseline = o_apply, o_clear, o_base


def t_zapret_runstate():
    print("\n[47] zapret фоновый прогон: один тест за раз, состояние idle→running→done")
    import time as _tm, threading as _t
    o_run = zapret.run_autotest
    gate = _t.Event()

    def fake_run(strategies, service_keys, log_cb=None, stop_evt=None):
        if log_cb:
            log_cb("старт")
        gate.wait(3)
        return ({"x": {"label": "X", "up_count": 1, "services": {}}}, "x")
    zapret.run_autotest = fake_run
    try:
        check("тест запущен", zapret.start_test([{"id": "x"}], ["discord"]) is True)
        check("повторный старт отклонён (уже идёт)", zapret.start_test([], []) is False)
        check("состояние running", zapret.test_status(0)["state"] == "running")
        gate.set()
        done = False
        for _ in range(40):
            if zapret.test_status(0)["state"] == "done":
                done = True
                break
            _tm.sleep(0.05)
        check("состояние done после завершения", done)
        check("best_id зафиксирован", zapret.test_status(0)["best_id"] == "x")
    finally:
        zapret.run_autotest = o_run
        gate.set()


def t_zapret_store():
    print("\n[48] settings.zapret по умолчанию + коэрция")
    st = new_store()
    z = st.get_settings().get("zapret")
    check("zapret в настройках по умолчанию", isinstance(z, dict)
          and z.get("strategies") == [] and z.get("active_id") == "", z)
    st.update_config(lambda cfg: cfg.setdefault("settings", {}).__setitem__(
        "zapret", {"strategies": "bad", "active_id": 123}))
    z2 = st.get_settings().get("zapret")
    check("strategies коэрцится в список", z2["strategies"] == [], z2)
    check("active_id коэрцится в строку", z2["active_id"] == "123", z2)


def t_zapret_no_run_collision():
    print("\n[49] zapret: привилегированный путь доходит до subprocess (нет коллизии _run)")
    import os as _os
    check("_run_cmd — функция (не затёрта dict-ом _run)", callable(zapret._run_cmd))
    calls = []
    o_run, o_avail, o_path = zapret._run_cmd, zapret.is_available, zapret.nfqws_path
    zapret._run_cmd = lambda cmd, log_cb=None: (calls.append(cmd) or True)
    zapret.is_available = lambda: True
    zapret.nfqws_path = lambda: "/bin/true"
    _os.environ["ZAPRET_ENABLE_APPLY"] = "1"
    try:
        check("can_apply True при включении", zapret.can_apply() is True)
        zapret.clear_strategy(lambda m: None)   # до фикса падало TypeError: dict not callable
        check("clear_strategy дошёл до iptables -D (хелпер вызван, не упал)",
              any("iptables" in c and "-D" in c for c in calls), calls)
    finally:
        zapret._run_cmd, zapret.is_available, zapret.nfqws_path = o_run, o_avail, o_path
        _os.environ.pop("ZAPRET_ENABLE_APPLY", None)
        zapret.clear_strategy(lambda m: None)   # сброс состояния


for t in (t_sync_safety, t_classic_preserves_keys, t_id_remap, t_gc,
          t_resolve, t_format, t_rename_match, t_mirror, t_preview,
          t_migrate_domains, t_migrate_idempotent, t_migrate_deterministic,
          t_domain_id_carried, t_domain_unknown_blanks, t_perdomain_path_uniqueness,
          t_find_route_host, t_effective_domain_fallback, t_host_norm,
          t_provider_from_domain, t_normalize_domains, t_merge_failover_per_domain,
          t_failover_oldnode_compat, t_failover_summary_mirror, t_per_domain_active,
          t_disabled_default_repair, t_find_route_exact_wins, t_fourth_level_domain,
          t_group_balancer_emit, t_group_mixed_protocol, t_group_only_nonconvertible,
          t_group_passthrough_alongside, t_group_force_json, t_group_resolve,
          t_group_save_carry, t_group_sync_safety, t_group_rename_then_group_order,
          t_group_rename_match_original, t_group_nameless_bucket_kept, t_group_resolve_dedup,
          t_autoselect_emit, t_autoselect_nonconvertible, t_autoselect_resolve_save,
          t_autoselect_edges,
          t_zapret_validate, t_zapret_baseline, t_zapret_autotest_best,
          t_zapret_runstate, t_zapret_store, t_zapret_no_run_collision):
    t()

print(f"\n=== PASS={PASS} FAIL={FAIL} ===")
raise SystemExit(1 if FAIL else 0)
