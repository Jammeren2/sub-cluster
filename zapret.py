#!/usr/bin/env python3
"""
zapret.py — каркас ноды zapret (обход DPI) + авто-тест стратегий, roadmap/04 (Фаза A).

ОБЪЁМ (важно): это ДИАГНОСТИКА/выбор стратегии НА УЗЛЕ, а не конечный обход DPI для
твоего трафика. Реальное применение стратегии к трафику телефона требует прокси-шлюза
и роутер-ноды (#05) — отложено. Здесь:
  • check_baseline() — чистый Python TLS-пробник: какие из заблокированных сервисов
    доступны с этого узла ПРЯМО СЕЙЧАС (без привилегий, тестируется везде);
  • run_autotest() — для каждой стратегии (при наличии zapret) применяет обход и
    перепроверяет доступность; выбирает лучшую (макс. доступных сервисов);
  • apply_strategy()/clear_strategy() — ПРИВИЛЕГИРОВАННАЯ часть (nfqws/iptables),
    работает только на Linux с NET_ADMIN и явным согласием (ZAPRET_ENABLE_APPLY=1);
    в моей среде НЕ тестировалась — изолирована за is_available()/can_apply().

Безопасность: nfqws вызывается СПИСКОМ аргументов (без shell); параметры стратегии
валидируются строгим белым списком флагов. Только в контейнере, host не трогаем.
"""

import os
import re
import sys
import time
import shutil
import socket
import ssl
import threading
import subprocess

# ── список заблокированных/троттлящихся сервисов для авто-теста ───────────────
# key — стабильный id; domains — тест-домены (TLS SNI-пробник). Сервис «доступен»,
# если доступен его ПЕРВЫЙ (основной) домен; остальные — для подробностей в логах.
SERVICES = [
    {"key": "discord", "label": "Discord", "domains": ["discord.com", "gateway.discord.gg", "cdn.discordapp.com"]},
    {"key": "youtube", "label": "YouTube", "domains": ["www.youtube.com", "youtubei.googleapis.com"]},
    {"key": "googlevideo", "label": "YouTube CDN", "domains": ["redirector.googlevideo.com", "googlevideo.com"]},
    {"key": "whatsapp", "label": "WhatsApp", "domains": ["web.whatsapp.com", "whatsapp.net"]},
    {"key": "instagram", "label": "Instagram", "domains": ["www.instagram.com"]},
    {"key": "facebook", "label": "Facebook", "domains": ["www.facebook.com"]},
    {"key": "twitter", "label": "X (Twitter)", "domains": ["x.com", "twitter.com"]},
    {"key": "twitch", "label": "Twitch", "domains": ["www.twitch.tv", "gql.twitch.tv"]},
    {"key": "tiktok", "label": "TikTok", "domains": ["www.tiktok.com"]},
    {"key": "telegram", "label": "Telegram", "domains": ["web.telegram.org"]},
    {"key": "signal", "label": "Signal", "domains": ["signal.org", "chat.signal.org"]},
    {"key": "netflix", "label": "Netflix", "domains": ["www.netflix.com"]},
    {"key": "spotify", "label": "Spotify", "domains": ["open.spotify.com"]},
    {"key": "reddit", "label": "Reddit", "domains": ["www.reddit.com"]},
    {"key": "linkedin", "label": "LinkedIn", "domains": ["www.linkedin.com"]},
    {"key": "cloudflare", "label": "Cloudflare", "domains": ["www.cloudflare.com"]},
    {"key": "proton", "label": "Proton", "domains": ["protonvpn.com", "proton.me"]},
    {"key": "soundcloud", "label": "SoundCloud", "domains": ["soundcloud.com"]},
    {"key": "rutracker", "label": "RuTracker", "domains": ["rutracker.org"]},
    {"key": "wikipedia", "label": "Wikipedia", "domains": ["www.wikipedia.org"]},
]
SERVICE_BY_KEY = {s["key"]: s for s in SERVICES}

PROBE_TIMEOUT = float(os.environ.get("ZAPRET_PROBE_TIMEOUT", "4"))

# Белый список флагов nfqws (для валидации пользовательской стратегии перед запуском).
_ALLOWED_FLAGS = {
    "--dpi-desync", "--dpi-desync-ttl", "--dpi-desync-ttl6", "--dpi-desync-fooling",
    "--dpi-desync-split-pos", "--dpi-desync-split-http-req", "--dpi-desync-split-tls",
    "--dpi-desync-repeats", "--dpi-desync-fake-tls", "--dpi-desync-fake-quic",
    "--dpi-desync-fake-http", "--dpi-desync-any-protocol", "--dpi-desync-cutoff",
    "--dpi-desync-badseq-increment", "--dpi-desync-badack-increment", "--dpi-desync-fakedsplit",
    "--dpi-desync-autottl", "--wssize", "--hostlist", "--hostlist-domains",
    "--dpi-desync-start", "--dpi-desync-fake-syndata", "--dpi-desync-fake-unknown",
}
_PARAMS_RE = re.compile(r"^[A-Za-z0-9 =:,.\-_/+@]*$")
_PARAMS_MAX = 1000


def validate_params(params):
    """Параметры стратегии (строка nfqws-флагов) → (ok, tokens|error). Пусто = direct."""
    params = (params or "").strip()
    if not params:
        return True, []
    if len(params) > _PARAMS_MAX:
        return False, "слишком длинная строка стратегии"
    if not _PARAMS_RE.match(params):
        return False, "недопустимые символы в стратегии"
    toks = params.split()
    for t in toks:
        flag = t.split("=", 1)[0]
        if not flag.startswith("--"):
            return False, f"ожидался флаг --xxx, а не «{t}»"
        if flag not in _ALLOWED_FLAGS:
            return False, f"флаг не в белом списке: {flag}"
    return True, toks


# ── обнаружение zapret/привилегий ────────────────────────────────────────────
def nfqws_path():
    p = (os.environ.get("ZAPRET_NFQWS") or "").strip()
    if p and os.path.exists(p):
        return p
    w = shutil.which("nfqws")
    if w:
        return w
    for cand in ("/opt/zapret/binaries/linux-x86_64/nfqws", "/opt/zapret/nfqws"):
        if os.path.exists(cand):
            return cand
    return None


def is_available():
    """zapret вообще можно запустить на этом узле (Linux + бинарник nfqws)."""
    return sys.platform.startswith("linux") and nfqws_path() is not None


def can_apply():
    """Реально применять обход к egress — только при явном согласии (защита от
    случайной правки сети непротестированным кодом). Иначе авто-тест = только baseline."""
    return is_available() and os.environ.get("ZAPRET_ENABLE_APPLY") == "1"


# ── baseline-пробник доступности (чистый Python, без привилегий, тестируемо) ──
def _probe(host, port=443, timeout=PROBE_TIMEOUT):
    """TLS-рукопожатие к host:port c SNI=host. True — дошли до рукопожатия (доступно);
    False — RST/таймаут/ошибка (вероятно блокировка DPI). Серт НЕ валидируем — важен
    сам факт установки TLS (как у blockcheck)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                ss.do_handshake()
        return True
    except Exception:
        return False


def check_baseline(service_keys, log_cb=None, stop_evt=None):
    """Доступность каждого сервиса (по первому домену) → {key: {"up":bool, "domains":{d:bool}}}."""
    out = {}
    for key in service_keys:
        if stop_evt is not None and stop_evt.is_set():
            break
        svc = SERVICE_BY_KEY.get(key)
        if not svc:
            continue
        dres = {}
        for d in svc["domains"]:
            if stop_evt is not None and stop_evt.is_set():
                break
            dres[d] = _probe(d)
        up = bool(dres.get(svc["domains"][0])) if svc["domains"] else False
        out[key] = {"up": up, "domains": dres}
        if log_cb:
            log_cb(f"  {svc['label']}: {'доступен' if up else 'НЕДОСТУПЕН'}")
    return out


# ── ПРИВИЛЕГИРОВАННАЯ часть: применение стратегии к egress (UNTESTED, gated) ──
# Запускается ТОЛЬКО при can_apply(). nfqws вызывается списком аргументов (без shell);
# параметры провалидированы. Только в контейнере. В среде разработки не проверялось.
_apply_lock = threading.Lock()
_nfqws_proc = None
QUEUE_NUM = int(os.environ.get("ZAPRET_QUEUE_NUM", "200"))


def _run_cmd(cmd, log_cb):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if r.returncode != 0 and log_cb:
            log_cb(f"    ! {' '.join(cmd[:2])}: rc={r.returncode} {(r.stderr or '').strip()[:200]}")
        return r.returncode == 0
    except Exception as e:
        if log_cb:
            log_cb(f"    ! {' '.join(cmd[:2])}: {e}")
        return False


def apply_strategy(params, log_cb=None):
    """Поднять nfqws со стратегией params и завернуть egress 80/443 в nfqueue.
    → True если применено. Без can_apply() — no-op с логом (диагностика = baseline)."""
    ok, toks = validate_params(params)
    if not ok:
        if log_cb:
            log_cb(f"  стратегия отклонена: {toks}")
        return False
    if not toks:
        if log_cb:
            log_cb("  стратегия: direct (без обхода)")
        return True
    if not can_apply():
        if log_cb:
            reason = "zapret недоступен (нет nfqws/не Linux)" if not is_available() \
                else "применение выключено (ZAPRET_ENABLE_APPLY!=1)"
            log_cb(f"  обход НЕ применён: {reason} — меряю как есть (baseline)")
        return False
    global _nfqws_proc
    with _apply_lock:
        clear_strategy(log_cb)
        nf = nfqws_path()
        # egress tcp 80/443 → NFQUEUE (контейнерные правила, host не трогаем)
        for proto_args in (["-p", "tcp", "--dport", "80"], ["-p", "tcp", "--dport", "443"]):
            _run_cmd(["iptables", "-t", "mangle", "-A", "POSTROUTING"] + proto_args
                     + ["-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM), "--queue-bypass"], log_cb)
        try:
            _nfqws_proc = subprocess.Popen([nf, "--qnum", str(QUEUE_NUM)] + toks,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if log_cb:
                log_cb(f"  nfqws запущен (qnum={QUEUE_NUM}) со стратегией")
            time.sleep(0.5)
            return True
        except Exception as e:
            if log_cb:
                log_cb(f"  не удалось запустить nfqws: {e}")
            return False


def clear_strategy(log_cb=None):
    """Снять nfqws и iptables-правила (обратное к apply_strategy)."""
    global _nfqws_proc
    if _nfqws_proc is not None:
        try:
            _nfqws_proc.terminate()
            _nfqws_proc.wait(timeout=3)
        except Exception:
            pass
        _nfqws_proc = None
    if not can_apply():
        return
    for proto_args in (["-p", "tcp", "--dport", "80"], ["-p", "tcp", "--dport", "443"]):
        _run_cmd(["iptables", "-t", "mangle", "-D", "POSTROUTING"] + proto_args
                 + ["-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM), "--queue-bypass"], log_cb)


# ── оркестрация авто-теста (тестируемо: monkeypatch apply/clear/check_baseline) ──
def run_autotest(strategies, service_keys, log_cb=None, stop_evt=None):
    """Для каждой стратегии: применить (если можем) → замерить доступность сервисов →
    снять. Выбрать лучшую (макс. доступных). → (results, best_id).
      strategies — [{id,label,params}]; service_keys — какие сервисы тестировать.
      results = {strategy_id: {"label","up_count","services":{key:{up,domains}}}}."""
    def _log(m):
        if log_cb:
            log_cb(m)
    if not strategies:
        strategies = [{"id": "direct", "label": "Прямой (без обхода)", "params": ""}]
    if not service_keys:
        service_keys = [s["key"] for s in SERVICES]
    if not can_apply():
        _log("⚠ zapret не применяется (диагностика без обхода) — реальный обход появится с роутер-нодой (#05).")

    results = {}
    for st in strategies:
        if stop_evt is not None and stop_evt.is_set():
            _log("остановлено.")
            break
        sid = st.get("id") or "?"
        label = st.get("label") or sid
        _log(f"▶ стратегия «{label}»…")
        applied = apply_strategy(st.get("params") or "", _log)
        try:
            svc = check_baseline(service_keys, _log, stop_evt)
        finally:
            if applied and (st.get("params") or "").strip():
                clear_strategy(_log)
        up = sum(1 for v in svc.values() if v.get("up"))
        results[sid] = {"label": label, "up_count": up, "services": svc}
        _log(f"  итог «{label}»: доступно {up}/{len(service_keys)}")

    best_id = None
    if results:
        best_id = max(results.keys(), key=lambda k: results[k]["up_count"])
        _log(f"✔ лучшая стратегия: «{results[best_id]['label']}» ({results[best_id]['up_count']}/{len(service_keys)})")
    return results, best_id


# ── фоновый прогон + буфер логов (один тест за раз; логи эфемерны, не синкаются) ─
_run_lock = threading.Lock()
_run = {"state": "idle", "logs": [], "results": None, "best_id": None,
        "started": 0.0, "thread": None, "stop": None}
LOGS_MAX = 4000


def _push_log(msg):
    with _run_lock:
        _run["logs"].append({"ts": time.time(), "msg": msg})
        if len(_run["logs"]) > LOGS_MAX:
            del _run["logs"][:len(_run["logs"]) - LOGS_MAX]


def start_test(strategies, service_keys, on_done=None):
    """Запустить авто-тест в фоне. → True если запущен, False если уже идёт."""
    with _run_lock:
        if _run["state"] == "running":
            return False
        _run.update({"state": "running", "logs": [], "results": None, "best_id": None,
                     "started": time.time(), "stop": threading.Event()})
        stop = _run["stop"]
        t = threading.Thread(target=_worker, args=(strategies, service_keys, stop, on_done), daemon=True)
        _run["thread"] = t
    t.start()
    return True


def _worker(strategies, service_keys, stop, on_done):
    try:
        results, best_id = run_autotest(strategies, service_keys, _push_log, stop)
        with _run_lock:
            _run["results"] = results
            _run["best_id"] = best_id
            _run["state"] = "done"
        if on_done and not stop.is_set():
            try:
                on_done(results, best_id)
            except Exception as e:
                _push_log(f"on_done: {e}")
    except Exception as e:
        _push_log(f"ошибка теста: {e}")
        with _run_lock:
            _run["state"] = "done"


def test_status(cursor=0):
    """Состояние прогона + новые логи с позиции cursor (для опроса модалкой)."""
    with _run_lock:
        try:
            cursor = max(0, int(cursor))
        except (TypeError, ValueError):
            cursor = 0
        total = len(_run["logs"])
        return {
            "state": _run["state"],
            "available": is_available(),
            "can_apply": can_apply(),
            "logs": _run["logs"][cursor:],
            "cursor": total,
            "results": _run["results"],
            "best_id": _run["best_id"],
        }


def stop_test():
    with _run_lock:
        if _run["stop"] is not None:
            _run["stop"].set()
        return _run["state"] == "running"
