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
import json
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

# Бандл flowseal/zapret-discord-youtube: рабочие стратегии + hostlists + fake-payload'ы
# (assets/zapret/{strategies,lists,bin} в репо → /opt/zapret/{lists,bin} в образе).
# Это РЕАЛЬНО РАБОТАЮЩИЙ набор (как в proxy-zapret-panel): стратегии ссылаются на
# /opt/zapret/lists/*.txt и /opt/zapret/bin/*.bin, поэтому без этих файлов они не дают
# эффекта. Provision/Dockerfile кладут файлы на место.
_ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "zapret")


def _assets_posix():
    """Каталог бандла в POSIX-форме (forward slashes) — пути идут в nfqws на Linux."""
    return _ASSETS_DIR.replace(os.sep, "/")


def _fix_asset_paths(params):
    """Стратегии flowseal хардкодят /opt/zapret/{lists,bin}; направляем их на РЕАЛЬНО
    лежащие в образе бандл-файлы (/app/assets/zapret/{lists,bin}). Так обход не зависит от
    того, разложил ли Dockerfile/Coolify данные в /opt (а он мог и не разложить — отсюда
    'cannot access hostlist file'). Файлы там точно есть: из них же грузятся стратегии."""
    base = _assets_posix()
    return (params.replace("/opt/zapret/lists/", base + "/lists/")
                  .replace("/opt/zapret/bin/", base + "/bin/"))


def _load_flowseal():
    """Стратегии flowseal из assets/zapret/strategies/manifest.json → [{label, params}].
    Пути к листам/фейкам направлены на бандл (см. _fix_asset_paths)."""
    out, mdir = [], os.path.join(_ASSETS_DIR, "strategies")
    try:
        with open(os.path.join(mdir, "manifest.json"), encoding="utf-8") as f:
            metas = json.load(f)
    except Exception:
        return out
    for m in metas:
        try:
            with open(os.path.join(mdir, m.get("file", "")), encoding="utf-8") as f:
                params = f.read().strip()
        except Exception:
            continue
        if params:
            out.append({"label": m.get("name") or m.get("id") or "", "params": _fix_asset_paths(params)})
    return out


def _default_strategies():
    """«+ набор по умолчанию»: baseline + рабочие flowseal-стратегии + простой фолбэк
    без листов. Flowseal — первыми (их и надо пробовать; «General ⭐» — топ)."""
    q = _assets_posix() + "/bin/quic_initial_www_google_com.bin"   # бандл-фейк (точно есть)
    base = [{"label": "Прямой (baseline)", "params": ""}]
    fs = _load_flowseal()
    fallback = [
        {"label": "Simple fake+multisplit (без листов)",
         "params": "--filter-tcp=80,443 --dpi-desync=fake,multisplit --dpi-desync-ttl=4 --dpi-desync-autottl=2"},
        {"label": "Simple QUIC/UDP 443",
         "params": f"--filter-udp=443 --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic={q}"},
    ]
    return base + fs + fallback


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
# списки (80,443), host=www.google.com (вложенный '='), фулинги ts,md5sig, hex 0x00,
# '!' (nfqws-маркер «встроенный fake»). Все безопасны: аргументы уходят списком, без shell.
_VALUE_RE = re.compile(r"^[A-Za-z0-9=:,.\-_/+@!]*$")


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
                 "/data/zapret/binaries/linux-x86_64/nfqws",   # рантайм-доустановка (provision.py)
                 "/data/zapret/binaries/linux-aarch64/nfqws",
                 "/data/zapret/nfqws",
                 "/usr/local/bin/nfqws", "/usr/bin/nfqws"):
        if os.path.exists(cand):
            return cand
    return None


def refresh_defaults():
    """Пересобрать наборы стратегий (после рантайм-доустановки zapret, когда
    ZAPRET_FAKE_DIR мог измениться на /data/zapret/files/fake)."""
    global ZAPRET_FAKE_DIR, DEFAULT_STRATEGIES, COMMUNITY_STRATEGIES
    ZAPRET_FAKE_DIR = (os.environ.get("ZAPRET_FAKE_DIR") or "/opt/zapret/files/fake").rstrip("/")
    DEFAULT_STRATEGIES = _default_strategies()
    COMMUNITY_STRATEGIES = _community_strategies()


def is_available():
    """zapret вообще можно запустить на этом узле (Linux + бинарник nfqws)."""
    return sys.platform.startswith("linux") and nfqws_path() is not None


def _env_true(name):
    """Булев env: принимает 1/true/yes/on (без регистра). Удобно для ZAPRET=true в .env."""
    return (os.environ.get(name) or "").strip().lower() in ("1", "true", "yes", "on")


def apply_enabled():
    """Главный рантайм-переключатель обхода/gateway. Читаем И ZAPRET (так его задаёт
    пользователь в .env/Coolify), И ZAPRET_ENABLE_APPLY (его прокидывает compose) — чтобы
    работало даже когда compose-маппинг не применился (Coolify/Nixpacks билд)."""
    return _env_true("ZAPRET") or _env_true("ZAPRET_ENABLE_APPLY")


def can_apply():
    """Реально применять обход к egress — только при явном согласии (защита от случайной
    правки сети непротестированным кодом). Включается ZAPRET=true (ZAPRET_ENABLE_APPLY).
    Иначе авто-тест = только baseline."""
    return is_available() and apply_enabled()


def has_net_admin():
    """Есть ли у контейнера CAP_NET_ADMIN (нужен для iptables/NFQUEUE). False → права не
    выданы при создании контейнера (рантаймом не добавить): нужен cap_add NET_ADMIN/NET_RAW.
    Даже root в обычном docker-контейнере НЕ имеет NET_ADMIN по умолчанию."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << 12))   # CAP_NET_ADMIN = 12
    except Exception:
        pass
    return False


def unavailable_reason():
    """Почему обход не применяется (точная причина для UI). '' = всё ок, можно применять."""
    if not sys.platform.startswith("linux"):
        return "узел не на Linux (nfqws работает только на Linux)"
    if nfqws_path() is None:
        if apply_enabled():
            return ("nfqws доустанавливается в фоне (скачивается с GitHub) — обнови страницу "
                    "через ~1 мин; если не появилось, смотри логи контейнера")
        return ("nfqws не найден — задай ZAPRET=true в .env (узел сам доустановит nfqws/xray "
                "на старте) и перезапусти контейнер")
    if not apply_enabled():
        return "применение выключено — задай ZAPRET=true в .env (cap_add уже в docker-compose)"
    if not has_net_admin():
        return ("контейнеру НЕ выдан NET_ADMIN — обход/NFQUEUE не заработают. Добавь "
                "cap_add: [NET_ADMIN, NET_RAW] в docker-compose (или в Coolify) и сделай "
                "redeploy (не restart — права назначаются при пересоздании контейнера)")
    if shutil.which("iptables") is None:
        return "iptables нет в контейнере — доустанавливается в фоне; обнови через ~1 мин"
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
            err = (r.stderr or "").strip()
            log_cb(f"    ! {' '.join(cmd[:2])}: rc={r.returncode} {err[:200]}")
            if any(s in err.lower() for s in ("permitted", "denied", "permission")):
                log_cb("      ↳ нет прав на iptables/NFQUEUE: дай контейнеру NET_ADMIN/NET_RAW "
                       "(Coolify → Custom Docker Options: --cap-add=NET_ADMIN --cap-add=NET_RAW)")
        return r.returncode == 0
    except FileNotFoundError:
        if log_cb:
            log_cb(f"    ! {cmd[0]} не найден в контейнере (образ собран без него; см. /zapret-баннер)")
        return False
    except Exception as e:
        if log_cb:
            log_cb(f"    ! {' '.join(cmd[:2])}: {e}")
        return False


def _run_dir():
    d = os.environ.get("ZAPRET_RUN_DIR") or "/tmp/zapret-run"
    try:
        os.makedirs(d, exist_ok=True)
        return d
    except Exception:
        return "/tmp"


def _read_tail(path, n=12):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().strip().splitlines()
        return " | ".join(lines[-n:])
    except Exception:
        return ""


def apply_strategy(params, log_cb=None):
    """Поднять nfqws со стратегией params и завернуть egress в nfqueue.
    → True если применено. Без can_apply() — no-op с логом (диагностика = baseline).

    Порядок и форма — КАК В proxy-zapret-panel (рабочий референс): nfqws стартует
    ПЕРВЫМ из @-конфига (--qnum=N + стратегия), его вывод ЛОВИМ и проверяем, что он не
    упал сразу (иначе обход тихо деградирует до baseline — это и был баг), и только потом
    ставим NFQUEUE-правила."""
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
        # 1) nfqws ПЕРВЫМ из @-конфига; вывод → файл (чтобы видеть ошибки, а не DEVNULL).
        conf = os.path.join(_run_dir(), "nfqws.conf")
        nlog = os.path.join(_run_dir(), "nfqws.log")
        try:
            with open(conf, "w", encoding="utf-8") as f:
                f.write(f"--qnum={QUEUE_NUM}\n{params.strip()}\n")
        except Exception as e:
            if log_cb:
                log_cb(f"  не удалось записать конфиг nfqws: {e}")
            return False
        try:
            logf = open(nlog, "w", encoding="utf-8")
            _nfqws_proc = subprocess.Popen([nf, "@" + conf], stdout=logf, stderr=logf)
            logf.close()
        except Exception as e:
            if log_cb:
                log_cb(f"  не удалось запустить nfqws: {e}")
            return False
        time.sleep(0.6)
        if _nfqws_proc.poll() is not None:        # упал сразу — покажем ПОЧЕМУ
            rc = _nfqws_proc.returncode
            _nfqws_proc = None
            if log_cb:
                log_cb(f"  ✗ nfqws упал сразу (rc={rc}): {_read_tail(nlog) or 'нет вывода'}")
            return False
        # 2) iptables ПОСЛЕ (nfqws жив): порты стратегии (--filter-tcp/udp) → NFQUEUE.
        ports = _collect_filter_ports(toks)
        if shutil.which("iptables") is None and log_cb:
            log_cb("  ⚠ iptables нет в контейнере — NFQUEUE-правила не поставить (трафик в очередь "
                   "не пойдёт). Узел доустановит iptables на старте при ZAPRET=true (перезапусти).")
        specs = []
        tcp_ports = ports["tcp"] or ["80", "443"]
        specs.append(["-p", "tcp", "-m", "multiport", "--dports", _ports_to_multiport(tcp_ports)])
        if ports["udp"]:
            specs.append(["-p", "udp", "-m", "multiport", "--dports", _ports_to_multiport(ports["udp"])])
        for sp in specs:
            if _run_cmd(["iptables", "-t", "mangle", "-A", "POSTROUTING"] + sp
                        + ["-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM), "--queue-bypass"], log_cb):
                _applied_rules.append(sp)
        if log_cb:
            log_cb(f"  nfqws запущен (qnum={QUEUE_NUM}); порты tcp={','.join(tcp_ports)} "
                   f"udp={','.join(ports['udp']) or '—'}")
        return True


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
