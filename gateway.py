#!/usr/bin/env python3
"""
gateway.py — узел-gateway (Группа B): xray-core поднимает ОДИН VLESS-ws inbound и
раскидывает трафик server-side (роутер-нода в серверном режиме). zapret-таргеты идут
во freedom 'direct' (egress), помеченный fwmark — на этот mark вешается nfqws (обход DPI);
остальное — в balancer аплинков (лучший VPN). TLS терминирует Caddy/Coolify на 443 → xray
получает чистый ws по внутреннему порту.

Модель повторяет proxy-zapret-panel: на каждое изменение графа — reconcile (регенерация
config.json + рестарт xray + переустановка nfqws/iptables); на старте — reconcile из стора.

ПРИВИЛЕГИРОВАННАЯ часть (xray SO_MARK, iptables NFQUEUE, nfqws) работает только на Linux с
NET_ADMIN/NET_RAW и при ZAPRET_ENABLE_APPLY. В dev-среде (Windows) не запускается —
изолирована за is_available()/can_apply(). Конфиг генерится чисто (graph.resolve_gateways)
и тестируется юнит-тестами без рантайма.
"""

import os
import sys
import json
import time
import shutil
import threading
import subprocess

import graph
import zapret
import subscriptions as subs

GATEWAY_DIR = os.environ.get("GATEWAY_DIR", "/data/gateway")
GATEWAY_QUEUE = int(os.environ.get("GATEWAY_QUEUE_NUM", "210"))

_lock = threading.Lock()
_xray_proc = None
_nfqws_proc = None
_applied_rules = []          # установленные iptables-правила (для точного снятия)
_state = {"running": False, "link": "", "name": "", "node_id": "", "error": "", "ts": 0.0}


# ── обнаружение xray ─────────────────────────────────────────────────────────
def xray_path():
    p = (os.environ.get("XRAY_BIN") or "").strip()
    if p and os.path.exists(p):
        return p
    w = shutil.which("xray")
    if w:
        return w
    for c in ("/usr/local/bin/xray", "/opt/xray/xray", "/usr/bin/xray"):
        if os.path.exists(c):
            return c
    return None


def is_available():
    """xray можно запустить (Linux + бинарник). Без него gateway = только генерация ссылки."""
    return sys.platform.startswith("linux") and xray_path() is not None


def can_apply():
    """Реально поднимать xray/nfqws на узле — только при явном согласии (как у zapret)."""
    return is_available() and zapret._env_true("ZAPRET_ENABLE_APPLY")


def unavailable_reason():
    if not sys.platform.startswith("linux"):
        return "узел не на Linux (gateway работает только на Linux)"
    if xray_path() is None:
        return "бинарник xray не найден — задай ZAPRET=true в .env и пересобери образ"
    if not zapret._env_true("ZAPRET_ENABLE_APPLY"):
        return "применение выключено — задай ZAPRET=true в .env (cap_add уже в docker-compose)"
    return ""


def _run(cmd, log=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if r.returncode != 0 and log:
            log(f"  ! {' '.join(cmd[:2])}: rc={r.returncode} {(r.stderr or '').strip()[:200]}")
        return r.returncode == 0
    except Exception as e:
        if log:
            log(f"  ! {' '.join(cmd[:2])}: {e}")
        return False


def _active_strategy(store):
    """Активная nfqws-стратегия из настроек (та, что пользователь выбрал/протестировал
    на /zapret). Пусто → без обхода (zapret-таргет уйдёт во freedom без DPI-обхода)."""
    try:
        z = store.get_settings().get("zapret") or {}
    except Exception:
        return ""
    saved = {s.get("id"): s for s in (z.get("strategies") or []) if s.get("id")}
    st = saved.get(z.get("active_id"))
    return (st or {}).get("params") or ""


# ── reconcile: граф → запущенный xray + nfqws ────────────────────────────────
def reconcile(store):
    """Привести рантайм узла к графу: поднять/обновить xray для ПЕРВОЙ серверной
    роутер-ноды (gateway) и nfqws на её fwmark-egress. → state-словарь (см. status())."""
    gws = []
    try:
        gws = graph.resolve_gateways(store)
    except Exception as e:
        print(f"[gateway] resolve_gateways: {e}", flush=True)
    with _lock:
        if not gws:
            _stop_locked()
            _state.update({"running": False, "link": "", "name": "", "node_id": "", "error": "", "ts": time.time()})
            return dict(_state)
        if len(gws) > 1:
            print(f"[gateway] на узле {len(gws)} серверных роутеров — поднимаю первый "
                  f"«{gws[0].get('name')}», остальные игнорирую (v1: один gateway на узел)", flush=True)
        g = gws[0]
        # ссылку отдаём всегда (даже без рантайма — её можно положить в подписку)
        _state.update({"link": g.get("link") or "", "name": g.get("name") or "",
                       "node_id": g.get("node_id") or "", "ts": time.time()})
        if not can_apply():
            _stop_locked()
            _state.update({"running": False, "error": unavailable_reason()})
            return dict(_state)
        _stop_locked()
        err = _start_locked(g, _active_strategy(store))
        _state.update({"running": err == "", "error": err})
        return dict(_state)


def _start_locked(g, strategy):
    """Поднять xray с конфигом gateway + nfqws на fwmark-egress. → '' или текст ошибки."""
    global _xray_proc, _nfqws_proc, _applied_rules
    os.makedirs(GATEWAY_DIR, exist_ok=True)
    cfg_path = os.path.join(GATEWAY_DIR, "xray.json")
    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(g["config"], f, ensure_ascii=False, indent=2)
    except Exception as e:
        return f"запись конфига: {e}"
    xb = xray_path()
    try:
        _xray_proc = subprocess.Popen([xb, "run", "-c", cfg_path],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        return f"запуск xray: {e}"
    time.sleep(0.4)
    if _xray_proc.poll() is not None:
        return f"xray упал сразу (rc={_xray_proc.returncode}) — проверь config.json"

    # nfqws на egress, скоуп по fwmark (freedom 'direct' xray помечает GATEWAY_MARK):
    # NFQUEUE ловит только marked-пакеты → обходом затрагивается ровно zapret-таргетный трафик.
    ok, toks = zapret.validate_params(strategy)
    if ok and toks:
        nf = zapret.nfqws_path()
        if nf:
            try:
                _nfqws_proc = subprocess.Popen([nf, "--qnum", str(GATEWAY_QUEUE)] + toks,
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                print(f"[gateway] nfqws: {e}", flush=True)
            ports = zapret._collect_filter_ports(toks)
            specs = []
            tcp = ports["tcp"] or ["80", "443"]
            specs.append(["-p", "tcp", "-m", "multiport", "--dports", zapret._ports_to_multiport(tcp)])
            if ports["udp"]:
                specs.append(["-p", "udp", "-m", "multiport", "--dports", zapret._ports_to_multiport(ports["udp"])])
            mark = str(subs.GATEWAY_MARK)
            for sp in specs:
                rule = ["-t", "mangle", "-A", "POSTROUTING", "-m", "mark", "--mark", mark] + sp + \
                       ["-j", "NFQUEUE", "--queue-num", str(GATEWAY_QUEUE), "--queue-bypass"]
                if _run(["iptables"] + rule):
                    _applied_rules.append(rule)
    return ""


def _stop_locked():
    global _xray_proc, _nfqws_proc, _applied_rules
    for proc_attr in ("_xray_proc", "_nfqws_proc"):
        p = globals().get(proc_attr)
        if p is not None:
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                pass
            globals()[proc_attr] = None
    for rule in _applied_rules:
        d = list(rule)
        try:
            d[d.index("-A")] = "-D"
            _run(["iptables"] + d)
        except ValueError:
            pass
    _applied_rules = []


def stop():
    with _lock:
        _stop_locked()
        _state.update({"running": False, "ts": time.time()})


def status(store=None):
    """Текущее состояние gateway + ссылка (для UI). Если store задан и рантайма нет —
    подтягиваем ссылку из графа (её можно показать/положить в подписку без запуска)."""
    with _lock:
        out = dict(_state)
    out["available"] = is_available()
    out["can_apply"] = can_apply()
    out["reason"] = unavailable_reason()
    if store is not None and not out.get("link"):
        try:
            gws = graph.resolve_gateways(store)
            if gws:
                out["link"] = gws[0].get("link") or ""
                out["name"] = gws[0].get("name") or ""
        except Exception:
            pass
    return out
