# -*- coding: utf-8 -*-
"""
webui.py — рендеринг веб-панели администратора.

Страницы (на admin-сервере, в корне):
  /          — нодовый редактор подписок (граф)
  /classic   — те же маршруты списком форм
  /cluster   — узлы кластера, живость, активный, ручное переключение DNS
  /settings  — reg.ru, домены, параметры фейловера
"""

import json
import time

from ui_assets import EDITOR_CSS, EDITOR_JS, PAGE_CSS


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def js_embed(obj):
    s = json.dumps(obj, ensure_ascii=False)
    bs = chr(92)
    s = s.replace("<", bs + "u003c").replace(">", bs + "u003e").replace("&", bs + "u0026")
    s = s.replace(chr(0x2028), bs + "u2028").replace(chr(0x2029), bs + "u2029")
    return s


NAV_ITEMS = [("/", "Граф"), ("/classic", "Список"), ("/cluster", "Кластер"), ("/settings", "Настройки")]


def nav_links(active):
    out = []
    for href, label in NAV_ITEMS:
        cls = "navlink active" if href == active else "navlink"
        out.append(f'<a class="{cls}" href="{href}">{esc(label)}</a>')
    out.append('<form class="inline" method="post" action="/logout">'
               '<button class="btn ghost" type="submit">Выйти</button></form>')
    return "".join(out)


EXTRA_CSS = """
.navlink{display:inline-block;padding:7px 11px;border-radius:6px;color:#cfd3da;text-decoration:none;font-size:13px}
.navlink:hover{background:#23262d}
.navlink.active{background:#2f6feb;color:#fff}
form.inline{display:inline}
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th,.tbl td{text-align:left;padding:8px 10px;border-bottom:1px solid #232833}
.tbl th{color:#8a93a2;font-weight:600;font-size:12px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:middle}
.dot.up{background:#3fb950}.dot.down{background:#f85149}
.badge{font-size:11px;padding:2px 8px;border-radius:999px;margin-left:5px}
.badge.active{background:#16321f;color:#7ee787}
.badge.pin{background:#3a2d16;color:#ffd479}
.badge.self{background:#1d2c3a;color:#79c0ff}
.mono{font-family:ui-monospace,Consolas,monospace}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.help{color:#8a93a2;font-size:12px;margin-top:4px}
fieldset{border:1px solid #232833;border-radius:10px;padding:14px 16px;margin:0 0 16px}
legend{color:#cfd3da;font-size:13px;padding:0 6px}
"""


# ── вход ───────────────────────────────────────────────────────────────────
def render_login(error=""):
    err = f'<div class="flash err">{esc(error)}</div>' if error else ""
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Вход — Sub Cluster</title><style>{PAGE_CSS}{EXTRA_CSS}</style></head>
<body><div class="wrap"><div class="card login-box">
<h1>Панель кластера подписок</h1><div class="sub">Войдите для управления</div>
{err}
<form method="post" action="/login">
<label>Логин</label><input name="user" autocomplete="username" autofocus>
<label>Пароль</label><input name="password" type="password" autocomplete="current-password">
<div style="margin-top:16px"><button class="btn" type="submit">Войти</button></div>
</form></div></div></body></html>"""


# ── нодовый редактор ───────────────────────────────────────────────────────
def render_editor(graph, sub_base, csrf, banner=""):
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Граф — Sub Cluster</title><style>{EDITOR_CSS}{EXTRA_CSS}</style></head>
<body>
<div id="top">
  <span class="title">Подписки — граф</span>
  {nav_links("/")}
  <span style="width:14px"></span>
  <button class="btn" id="addSrc">+ Источник</button>
  <button class="btn" id="addRoute">+ Маршрут</button>
  <button class="btn gray" id="reset">Сбросить вид</button>
  <span class="spacer"></span>
  <button class="btn" id="save">Сохранить</button>
</div>
{banner}
<div id="editor">
  <svg id="wires" xmlns="http://www.w3.org/2000/svg"></svg>
  <div id="world"></div>
  <div id="hint">Пусто. Добавь «<b>+ Источник</b>» и «<b>+ Маршрут</b>», протяни связь и «<b>Сохранить</b>».<br>
    <span style="opacity:.7">Колесо — зум, перетаскивание фона — панорама.</span></div>
</div>
<div id="toast"></div>
<script>window.__GRAPH__={js_embed(graph)};window.__ADMIN__="";window.__CSRF__={js_embed(csrf)};window.__BASE__={js_embed(sub_base)};</script>
<script>{EDITOR_JS}</script>
</body></html>"""


# ── классический список ────────────────────────────────────────────────────
def render_route_card(route, sub_base):
    rid = esc(route.get("id", ""))
    path = esc(route.get("path", ""))
    title = esc(route.get("title", ""))
    mode = route.get("mode", "merge")
    enabled = route.get("enabled", True)
    upstreams = route.get("upstreams", [])
    ups_text = esc("\n".join(upstreams))
    full_url = esc(sub_base.rstrip("/") + (route.get("path", "") or ""))
    state = '<span class="tag on">включён</span>' if enabled else '<span class="tag off">выключен</span>'
    mode_label = "слияние" if mode != "mirror" else "зеркало"
    return f"""
<div class="card">
  <div class="route-head"><div>
    <div class="route-title">{title or '(без названия)'} {state} <span class="tag">{esc(mode_label)}</span></div>
    <div class="path">{path}</div></div></div>
  <div class="muted" style="margin-top:6px">Публичная ссылка: <span class="path">{full_url}</span></div>
  <details style="margin-top:10px"><summary class="muted" style="cursor:pointer">Редактировать ({len(upstreams)} upstream)</summary>
  <form method="post" action="/routes/{rid}/update">
    <label>Название</label><input name="title" value="{title}">
    <label>Путь подписки</label><input name="path" value="{path}">
    <label>Режим</label>
    <select name="mode">
      <option value="merge"{' selected' if mode != 'mirror' else ''}>Слияние</option>
      <option value="mirror"{' selected' if mode == 'mirror' else ''}>Зеркало</option>
    </select>
    <label>Upstream-ссылки (по одной в строке)</label><textarea name="upstreams">{ups_text}</textarea>
    <label class="row" style="margin-top:10px"><input type="checkbox" name="enabled" value="1" style="width:auto"{' checked' if enabled else ''}> <span>Включён</span></label>
    <div class="row" style="margin-top:12px"><button class="btn small" type="submit">Сохранить</button></div>
  </form>
  <form class="inline" method="post" action="/routes/{rid}/delete" onsubmit="return confirm('Удалить этот маршрут?')">
    <div style="margin-top:8px"><button class="btn small red" type="submit">Удалить</button></div>
  </form>
  </details>
</div>"""


def render_classic(routes, sub_base, flash="", flash_err=False):
    cards = "".join(render_route_card(r, sub_base) for r in routes) or \
        '<div class="card muted">Маршрутов пока нет.</div>'
    flash_html = f'<div class="flash {"err" if flash_err else ""}">{esc(flash)}</div>' if flash else ""
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Список — Sub Cluster</title><style>{PAGE_CSS}{EXTRA_CSS}</style></head>
<body><div class="wrap">
<div class="route-head"><div><h1>Маршруты (список)</h1>
<div class="sub">Слияние подписок, переименование, свои пути</div></div></div>
<div style="margin-bottom:16px">{nav_links("/classic")}</div>
{flash_html}{cards}<hr>
<div class="card"><div class="route-title">Новый маршрут</div>
<form method="post" action="/routes/create">
  <label>Название</label><input name="title" placeholder="Моя подписка">
  <label>Путь подписки</label><input name="path" placeholder="/custom/custom" required>
  <label>Режим</label><select name="mode"><option value="merge">Слияние</option><option value="mirror">Зеркало</option></select>
  <label>Upstream-ссылки (по одной в строке)</label><textarea name="upstreams"></textarea>
  <div style="margin-top:12px"><button class="btn" type="submit">Создать</button></div>
</form></div>
</div></body></html>"""


# ── кластер ────────────────────────────────────────────────────────────────
def _ago(ts):
    if not ts:
        return "—"
    d = max(0, int(time.time() - ts))
    if d < 60:
        return f"{d}с назад"
    if d < 3600:
        return f"{d // 60}м назад"
    return f"{d // 3600}ч назад"


def render_cluster(status, sub_base, flash="", flash_err=False):
    flash_html = f'<div class="flash {"err" if flash_err else ""}">{esc(flash)}</div>' if flash else ""
    rows = []
    for n in status["nodes"]:
        dot = '<span class="dot up"></span>' if n["alive"] else '<span class="dot down"></span>'
        badges = ""
        if n["is_active"]:
            badges += '<span class="badge active">активный (DNS)</span>'
        if n["is_pinned"]:
            badges += '<span class="badge pin">пин</span>'
        if n["is_self"]:
            badges += '<span class="badge self">этот узел</span>'
        lat = f'{int(n["latency"]*1000)} мс' if n.get("latency") else "—"
        seen = "сейчас" if n["is_self"] else _ago(n.get("last_ok"))
        actions = ""
        if not n["is_active"]:
            actions += (f'<form class="inline" method="post" action="/cluster/switch">'
                        f'<input type="hidden" name="node" value="{esc(n["id"])}">'
                        f'<button class="btn small" type="submit">Сделать активным</button></form> ')
        actions += (f'<details style="display:inline-block"><summary class="muted" style="cursor:pointer;display:inline">изм.</summary>'
                    f'<form method="post" action="/cluster/nodes/{esc(n["id"])}/update" style="margin-top:6px">'
                    f'<input name="label" value="{esc(n["label"])}" placeholder="метка">'
                    f'<input name="public_ip" value="{esc(n["public_ip"])}" placeholder="IP" class="mono">'
                    f'<input name="priority" value="{esc(n["priority"])}" placeholder="приоритет" type="number">'
                    f'<input name="cluster_port" value="{esc(n["cluster_port"])}" placeholder="cluster-порт" type="number">'
                    f'<label class="row" style="margin-top:6px"><input type="checkbox" name="enabled" value="1" style="width:auto"{" checked" if n["enabled"] else ""}> <span>включён</span></label>'
                    f'<div style="margin-top:6px"><button class="btn small" type="submit">Сохранить</button></div></form>')
        if not n["is_self"]:
            actions += (f'<form class="inline" method="post" action="/cluster/nodes/{esc(n["id"])}/delete" '
                        f'onsubmit="return confirm(\'Удалить узел?\')"><button class="btn small red" type="submit">×</button></form>')
        actions += "</details>"
        rows.append(
            f'<tr><td>{dot}<b>{esc(n["label"])}</b> {badges}<div class="muted mono">{esc(n["id"])}</div></td>'
            f'<td class="mono">{esc(n["public_ip"]) or "—"}</td><td>{esc(n["priority"])}</td>'
            f'<td>{"да" if n["alive"] else "нет"}<div class="muted">{esc(seen)} · {esc(lat)}</div></td>'
            f'<td>{actions}</td></tr>'
        )
    active = status.get("active") or "—"
    dns_ip = status.get("dns_ip") or "—"
    fo_on = status.get("failover_enabled")
    pinned = status.get("pinned")
    pin_html = ""
    if pinned:
        pin_html = (f'<form class="inline" method="post" action="/cluster/pin/clear">'
                    f'<button class="btn small gray" type="submit">Снять пин ({esc(pinned)}) → авто</button></form>')
    hist = ""
    for h in status.get("history", []):
        ok = "✓" if h.get("ok") else "✗"
        hist += (f'<div class="muted" style="font-size:12px">{esc(_ago(h.get("ts")))} · {ok} '
                 f'{esc(h.get("node"))} → {esc(h.get("ip"))} ({esc(h.get("by"))}) {esc(h.get("msg",""))}</div>')
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Кластер — Sub Cluster</title><style>{PAGE_CSS}{EXTRA_CSS}</style></head>
<body><div class="wrap">
<h1>Кластер и фейловер</h1>
<div style="margin:8px 0 16px">{nav_links("/cluster")}</div>
{flash_html}
<div class="card">
  <div class="grid2">
    <div><div class="muted">Активный узел (держит DNS)</div><div class="route-title">{esc(active)}</div></div>
    <div><div class="muted">IP в DNS</div><div class="route-title mono">{esc(dns_ip)}</div></div>
  </div>
  <div style="margin-top:10px">Авто-фейловер: <b>{"включён" if fo_on else "выключен"}</b> {pin_html}</div>
</div>
<div class="card">
  <table class="tbl"><thead><tr><th>Узел</th><th>IP</th><th>Приоритет</th><th>Живость</th><th>Действия</th></tr></thead>
  <tbody>{''.join(rows)}</tbody></table>
</div>
<div class="card"><div class="route-title">Добавить узел</div>
<form method="post" action="/cluster/nodes/add" class="grid2" style="margin-top:8px">
  <div><label>Метка</label><input name="label" placeholder="node-2"></div>
  <div><label>Public IP</label><input name="public_ip" class="mono" placeholder="203.0.113.10"></div>
  <div><label>Приоритет (меньше = важнее)</label><input name="priority" type="number" value="100"></div>
  <div><label>Cluster-порт</label><input name="cluster_port" type="number" value="8083"></div>
  <div style="grid-column:1/3"><button class="btn" type="submit">Добавить</button></div>
</form>
<div class="help">Новый узел сам зарегистрируется, когда запустится с этим NODE_ID и увидит кластер; запись тут — чтобы остальные знали его адрес заранее.</div>
</div>
<div class="card"><div class="route-title">Журнал переключений</div><div style="margin-top:8px">{hist or '<span class="muted">пусто</span>'}</div></div>
</div></body></html>"""


# ── настройки ──────────────────────────────────────────────────────────────
def render_settings(settings, sub_base, flash="", flash_err=False, crypto_ok=True, has_regru_pw=False):
    flash_html = f'<div class="flash {"err" if flash_err else ""}">{esc(flash)}</div>' if flash else ""
    dns = settings.get("dns", {})
    admin_d = dns.get("admin", {})
    sub_d = dns.get("sub", {})
    crypto_warn = "" if crypto_ok else (
        '<div class="flash err">SECRET_KEY не задан или нет cryptography — секреты хранятся в открытом виде. '
        'Задай переменную окружения SECRET_KEY (одинаковую на всех узлах).</div>')
    chk = lambda v: " checked" if v else ""
    pw_ph = "пароль задан — оставь пустым, чтобы не менять" if has_regru_pw else "пароль reg.ru или API-пароль"
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Настройки — Sub Cluster</title><style>{PAGE_CSS}{EXTRA_CSS}</style></head>
<body><div class="wrap">
<h1>Настройки</h1>
<div style="margin:8px 0 16px">{nav_links("/settings")}</div>
{crypto_warn}{flash_html}
<form method="post" action="/settings/save">
<fieldset><legend>reg.ru (DNS)</legend>
  <label>Логин reg.ru</label><input name="regru_username" value="{esc(dns.get('regru_username',''))}">
  <label>Пароль reg.ru</label><input name="regru_password" type="password" placeholder="{esc(pw_ph)}">
  <div class="help">IP всех узлов должны быть в белом списке API в настройках аккаунта reg.ru, иначе запросы отклоняются.</div>
</fieldset>
<fieldset><legend>Домены (A-записи переключаются на активный узел)</legend>
  <div class="grid2">
    <div><label>Admin: зона</label><input name="admin_zone" value="{esc(admin_d.get('zone',''))}" class="mono"></div>
    <div><label>Admin: поддомен</label><input name="admin_subdomain" value="{esc(admin_d.get('subdomain',''))}" class="mono"></div>
    <div><label>Подписки: зона</label><input name="sub_zone" value="{esc(sub_d.get('zone',''))}" class="mono"></div>
    <div><label>Подписки: поддомен</label><input name="sub_subdomain" value="{esc(sub_d.get('subdomain',''))}" class="mono"></div>
  </div>
  <label>Публичная база ссылок подписок</label>
  <input name="sub_public_base" value="{esc(settings.get('sub_public_base',''))}" class="mono" placeholder="https://happ.example.com">
  <div class="help">Используется только для показа готовых ссылок в панели.</div>
</fieldset>
<fieldset><legend>Фейловер</legend>
  <label class="row"><input type="checkbox" name="failover_enabled" value="1" style="width:auto"{chk(settings.get('failover_enabled'))}> <span>Авто-фейловер включён</span></label>
  <label class="row" style="margin-top:8px"><input type="checkbox" name="require_quorum" value="1" style="width:auto"{chk(settings.get('require_quorum'))}> <span>Требовать кворум для захвата мёртвого активного (защита от split-brain)</span></label>
  <label class="row" style="margin-top:8px"><input type="checkbox" name="preempt" value="1" style="width:auto"{chk(settings.get('preempt'))}> <span>Возвращать DNS самому приоритетному живому узлу (failback)</span></label>
  <div class="grid2" style="margin-top:8px">
    <div><label>Интервал опроса, сек</label><input name="poll_interval" type="number" value="{esc(settings.get('poll_interval',10))}"></div>
    <div><label>Порог недоступности (подряд неудач)</label><input name="fail_threshold" type="number" value="{esc(settings.get('fail_threshold',3))}"></div>
    <div><label>Кулдаун переключений, сек</label><input name="cooldown" type="number" value="{esc(settings.get('cooldown',60))}"></div>
  </div>
</fieldset>
<button class="btn" type="submit">Сохранить настройки</button>
</form>
</div></body></html>"""
