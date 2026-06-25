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

    # JSON-подписка + ss-ключ → остаётся JSON (ss обернуть нельзя — пропущен), формат цел
    spec = {"subs": [{"url": "https://json/sub", "renames": []}],
            "keys": [{"link": "ss://YWVzOnB3@hs:8388", "name": "SSKey"}]}
    payload, h = subs.build_merged_response(route, spec)
    check("JSON-sub + ss-ключ → формат остаётся JSON", "application/json" in h.get("Content-Type", ""))
    check("не-vless ключ пропущен, подписка не деградировала", names_from_json(payload) == ["Srv1"])

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

    # дедуп конфигов без учёта remarks: два sub'а с одинаковым конфигом, разные имена → один
    FAKE["https://dupA"] = (json.dumps([json_config("vless://u@hh:443?type=tcp#A")]).encode(), {})
    FAKE["https://dupB"] = (json.dumps([json_config("vless://u@hh:443?type=tcp#B")]).encode(), {})
    spec = {"subs": [{"url": "https://dupA", "renames": []}, {"url": "https://dupB", "renames": []}], "keys": []}
    payload, h = subs.build_merged_response(route, spec)
    check("одинаковые конфиги с разными remarks схлопнуты", len(names_from_json(payload)) == 1,
          names_from_json(payload))


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


for t in (t_sync_safety, t_classic_preserves_keys, t_id_remap, t_gc,
          t_resolve, t_format, t_rename_match, t_mirror, t_preview):
    t()

print(f"\n=== PASS={PASS} FAIL={FAIL} ===")
raise SystemExit(1 if FAIL else 0)
