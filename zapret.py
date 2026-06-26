#!/usr/bin/env python3
"""
zapret.py — каркас ноды zapret (обход DPI) + авто-тест стратегий (Фаза A).

ОБЪЁМ (важно): это ДИАГНОСТИКА/выбор стратегии НА УЗЛЕ, а не конечный обход DPI для
твоего трафика. Реальное применение стратегии к трафику телефона требует прокси-шлюза
и роутер-ноды — отложено (отдельная фаза). Здесь:
  • check_baseline() — чистый Python TLS-пробник: какие из заблокированных сервисов
    доступны с этого узла ПРЯМО СЕЙЧАС (без привилегий, тестируется везде);
  • run_autotest() — для каждой стратегии (при наличии zapret) применяет обход и
    перепроверяет доступность; выбирает лучшую (макс. доступных сервисов);
  • apply_strategy()/clear_strategy() — ПРИВИЛЕГИРОВАННАЯ часть (nfqws/iptables),
    работает только на Linux с NET_ADMIN и явным согласием (ZAPRET=true);
    в моей среде НЕ тестировалась — изолирована за is_available()/can_apply().

Безопасность: nfqws вызывается СПИСКОМ аргументов (без shell); валидация стратегии
отсекает shell-метасимволы и мусор (принимает реальные конфиги zapret целиком, в т.ч.
мульти-секционные через --new). Только в контейнере, host не трогаем.
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

# Каталог fake-payload'ов в установленном zapret (bol-van/zapret). Переопределяется env.
ZAPRET_FAKE_DIR = (os.environ.get("ZAPRET_FAKE_DIR") or "/opt/zapret/files/fake").rstrip("/")

# Набор стратегий «по умолчанию» (кнопка «+ набор по умолчанию» в UI). Канонические
# nfqws-стратегии из zapret (bol-van): самодостаточные (без --hostlist, применяются ко
# всему трафику на queued-портах). QUIC-фейки ссылаются на shipped-файлы под ZAPRET_FAKE_DIR.
def _default_strategies():
    q = ZAPRET_FAKE_DIR + "/quic_initial_www_google_com.bin"
    return [
        {"label": "Прямой (baseline)", "params": ""},
        {"label": "TCP fake+split2 ttl=1", "params": "--filter-tcp=80,443 --dpi-desync=fake,split2 --dpi-desync-ttl=1"},
        {"label": "TCP fake+split2 md5sig", "params": "--filter-tcp=80,443 --dpi-desync=fake,split2 --dpi-desync-fooling=md5sig"},
        {"label": "TCP fake+disorder2 badseq", "params": "--filter-tcp=80,443 --dpi-desync=fake,disorder2 --dpi-desync-fooling=badseq"},
        {"label": "TCP fakedsplit pos=1", "params": "--filter-tcp=80,443 --dpi-desync=fakedsplit --dpi-desync-split-pos=1 --dpi-desync-ttl=1"},
        {"label": "TCP multisplit", "params": "--filter-tcp=80,443 --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld"},
        {"label": "TCP syndata", "params": "--filter-tcp=80,443 --dpi-desync=syndata"},
        {"label": "QUIC/UDP 443 fake", "params": f"--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic={q}"},
        {"label": "Комбо TCP+QUIC", "params": f"--filter-tcp=80,443 --dpi-desync=fake,split2 --dpi-desync-ttl=1 --new --filter-udp=443 --dpi-desync=fake --dpi-desync-fake-quic={q}"},
    ]


DEFAULT_STRATEGIES = _default_strategies()


# «Комьюнити»-стратегии: популярные мульти-секционные рецепты (QUIC google + Discord/STUN +
# general с hostfakesplit и т.п.), адаптированные под РЕАЛЬНЫЕ пути bol-van/zapret
# (fake-payload'ы из ZAPRET_FAKE_DIR — проверено по релизу v72.12). Все режимы/флаги
# (hostfakesplit, multisplit, fakedsplit, fakeddisorder, filter-l7, fake-discord/stun)
# поддерживаются nfqws v72.12. Применяются по портам (без --hostlist — файлов-листов в
# образе нет; если нужны листы, положи их в образ и добавь --hostlist=… в свою стратегию).
def _community_strategies():
    f = ZAPRET_FAKE_DIR
    q = f + "/quic_initial_www_google_com.bin"
    return [
        {"label": "Comm: комбо QUIC+Discord+general", "params":
            f"--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic={q} --new "
            f"--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake "
            f"--dpi-desync-fake-discord={f}/discord-ip-discovery-with-port.bin "
            f"--dpi-desync-fake-stun={f}/stun.bin --dpi-desync-repeats=6 --new "
            "--filter-tcp=80,443 --dpi-desync=hostfakesplit --dpi-desync-repeats=4 "
            "--dpi-desync-fooling=ts --dpi-desync-hostfakesplit-mod=host=www.google.com"},
        {"label": "Comm: fakedsplit + QUIC", "params":
            "--filter-tcp=80,443 --dpi-desync=fakedsplit --dpi-desync-split-pos=1 --dpi-desync-ttl=2 --new "
            f"--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic={q}"},
        {"label": "Comm: multisplit + QUIC", "params":
            "--filter-tcp=80,443 --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq --new "
            f"--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic={q}"},
        {"label": "Comm: hostfakesplit ts+md5sig", "params":
            "--filter-tcp=80,443 --dpi-desync=hostfakesplit --dpi-desync-repeats=4 "
            "--dpi-desync-fooling=ts,md5sig --dpi-desync-hostfakesplit-mod=host=www.google.com --new "
            f"--filter-udp=443 --dpi-desync=fake --dpi-desync-fake-quic={q}"},
        {"label": "Comm: fakeddisorder + QUIC", "params":
            "--filter-tcp=80,443 --dpi-desync=fakeddisorder --dpi-desync-split-pos=1 --dpi-desync-fooling=md5sig --new "
            f"--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic={q}"},
    ]


COMMUNITY_STRATEGIES = _community_strategies()

# Валидация стратегии nfqws. Аргументы уходят в subprocess СПИСКОМ (без shell),
# поэтому инъекция шелл-команд невозможна в принципе; задача валидации — отсечь
# мусор и shell-метасимволы. Белый список конкретных флагов НЕ ведём (у zapret их
# десятки и они меняются от версии к версии): принимаем любой корректный флаг
# `--xxx[=value]` и разделитель секций `--new` (мульти-стратегии zapret), запрещая
# опасные символы в значениях. Так нода принимает реальные конфиги zapret as-is,
# включая `--filter-tcp/udp`, `--hostlist=/opt/...`, `--ipset=...`, `--dpi-desync-*`.
_PARAMS_MAX = 8000           # мульти-секционные стратегии длинные
_PARAMS_MAX_TOKENS = 400
_FLAG_RE = re.compile(r"^--[a-z0-9][a-z0-9\-]{0,48}$")
# значение после первого '=': пути (/opt/...), домены, числа, диапазоны (19294-19344),
# списки (80,443), host=www.google.com (вложенный '='), фулинги ts,md5sig.
_VALUE_RE = re.compile(r"^[A-Za-z0-9=:,.\-_/+@]*$")


def validate_params(params):
    """Строка nfqws-стратегии → (ok, tokens|error). Пусто = direct. Поддержка
    мульти-секций (`--new`). Токены идут в subprocess СПИСКОМ (без shell)."""
    params = (params or "").strip()
    if not params:
        return True, []
    if len(params) > _PARAMS_MAX:
        return False, "слишком длинная строка стратегии"
    toks = params.split()
    if len(toks) > _PARAMS_MAX_TOKENS:
        return False, "слишком много аргументов в стратегии"
    for t in toks:
        if t == "--new":             # разделитель секций мульти-стратегии
            continue
        flag, sep, val = t.partition("=")
        if not _FLAG_RE.match(flag):
            return False, f"недопустимый флаг: «{t[:48]}»"
        if sep and not _VALUE_RE.match(val):
            return False, f"недопустимое значение во флаге {flag}"
    return True, toks


def _collect_filter_ports(toks):
    """Из токенов стратегии собрать порты/диапазоны `--filter-tcp`/`--filter-udp`
    (по всем секциям) для построения NFQUEUE-правил. → {"tcp":[...], "udp":[...]}.
    Значения вида '80,443' и '19294-19344' сохраняются как есть (дедуп по порядку)."""
    tcp, udp = [], []
    for t in toks:
        flag, sep, val = t.partition("=")
        if not sep or not val:
            continue
        if flag == "--filter-tcp":
            tcp.extend(p for p in val.split(",") if p)
        elif flag == "--filter-udp":
            udp.extend(p for p in val.split(",") if p)
    return {"tcp": list(dict.fromkeys(tcp)), "udp": list(dict.fromkeys(udp))}


def _ports_to_multiport(ports):
    """['80','443','19294-19344'] → '80,443,19294:19344' (формат iptables multiport)."""
    return ",".join(p.replace("-", ":") for p in ports)


# ── обнаружение zapret/привилегий ────────────────────────────────────────────
def nfqws_path():
    p = (os.environ.get("ZAPRET_NFQWS") or "").strip()
    if p and os.path.exists(p):
        return p
    w = shutil.which("nfqws")
    if w:
        return w
    for cand in ("/opt/zapret/binaries/linux-x86_64/nfqws",
                 "/opt/zapret/binaries/linux-aarch64/nfqws",
                 "/opt/zapret/binaries/linux-arm/nfqws",
                 "/opt/zapret/nfqws", "/opt/zapret/bin/nfqws",
                 "/usr/local/bin/nfqws", "/usr/bin/nfqws"):
        if os.path.exists(cand):
            return cand
    return None


def is_available():
    """zapret вообще можно запустить на этом узле (Linux + бинарник nfqws)."""
    return sys.platform.startswith("linux") and nfqws_path() is not None


def _env_true(name):
    """Булев env: принимает 1/true/yes/on (без регистра). Удобно для ZAPRET=true в .env."""
    return (os.environ.get(name) or "").strip().lower() in ("1", "true", "yes", "on")


def can_apply():
    """Реально применять обход к egress — только при явном согласии (защита от случайной
    правки сети непротестированным кодом). Включается ZAPRET=true (ZAPRET_ENABLE_APPLY).
    Иначе авто-тест = только baseline."""
    return is_available() and _env_true("ZAPRET_ENABLE_APPLY")


def unavailable_reason():
    """Почему обход не применяется (точная причина для UI). '' = всё ок, можно применять."""
    if not sys.platform.startswith("linux"):
        return "узел не на Linux (nfqws работает только на Linux)"
    if nfqws_path() is None:
        return ("бинарник nfqws не найден — пересобери образ (docker compose up -d --build); "
                "nfqws ставится по умолчанию (если не задан INSTALL_ZAPRET=0)")
    if not _env_true("ZAPRET_ENABLE_APPLY"):
        return "применение выключено — задай ZAPRET=true в .env (cap_add уже в docker-compose)"
    return ""


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
_applied_rules = []          # установленные iptables-правила (для точного снятия)
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
            log_cb(f"  обход НЕ применён: {unavailable_reason()} — меряю как есть (baseline)")
        return False
    global _nfqws_proc, _applied_rules
    with _apply_lock:
        clear_strategy(log_cb)
        nf = nfqws_path()
        # NFQUEUE-правила строим из портов стратегии (--filter-tcp/--filter-udp по всем
        # секциям); если портов нет — дефолт tcp 80/443. Контейнерные правила, host не трогаем.
        ports = _collect_filter_ports(toks)
        specs = []
        tcp_ports = ports["tcp"] or ["80", "443"]
        specs.append(["-p", "tcp", "-m", "multiport", "--dports", _ports_to_multiport(tcp_ports)])
        if ports["udp"]:
            specs.append(["-p", "udp", "-m", "multiport", "--dports", _ports_to_multiport(ports["udp"])])
        for sp in specs:
            if _run_cmd(["iptables", "-t", "mangle", "-A", "POSTROUTING"] + sp
                        + ["-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM), "--queue-bypass"], log_cb):
                _applied_rules.append(sp)
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
    global _nfqws_proc, _applied_rules
    if _nfqws_proc is not None:
        try:
            _nfqws_proc.terminate()
            _nfqws_proc.wait(timeout=3)
        except Exception:
            pass
        _nfqws_proc = None
    if not can_apply():
        _applied_rules = []
        return
    for sp in _applied_rules:
        _run_cmd(["iptables", "-t", "mangle", "-D", "POSTROUTING"] + sp
                 + ["-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM), "--queue-bypass"], log_cb)
    _applied_rules = []


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
        _log(f"⚠ zapret не применяется (диагностика без обхода): {unavailable_reason()}")

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
            "reason": unavailable_reason(),
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
