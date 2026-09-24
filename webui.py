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

import subscriptions
from ui_assets import EDITOR_CSS, EDITOR_JS, PAGE_CSS, SHELL_CSS, SHELL_JS


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def js_embed(obj):
    s = json.dumps(obj, ensure_ascii=False)
    bs = chr(92)
    s = s.replace("<", bs + "u003c").replace(">", bs + "u003e").replace("&", bs + "u0026")
    s = s.replace(chr(0x2028), bs + "u2028").replace(chr(0x2029), bs + "u2029")
    return s


NAV_ITEMS = [("/", "Граф"), ("/classic", "Список"), ("/cluster", "Кластер"),
             ("/stats", "Статистика"), ("/zapret", "zapret"), ("/settings", "Настройки")]


NAV_ICONS = {
    "/": '<rect x="3" y="3" width="6" height="6" rx="1.5"/><rect x="15" y="15" width="6" height="6" rx="1.5"/><path d="M6 9v9h9M9 6h9v9"/>',
    "/classic": '<path d="M9 6h12M9 12h12M9 18h12M3 6h1M3 12h1M3 18h1"/>',
    "/cluster": '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M16 6.5h2M16 17.5h2"/>',
    "/stats": '<path d="M4 20h17M7 16v-5M12 16V4M17 16V8"/>',
    "/zapret": '<path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6Z"/><path d="m8 12 3 3 5-6"/>',
    "/settings": '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="10" cy="18" r="2"/>',
}
PAGE_DESCRIPTIONS = {
    "/classic": "Ваши подписки, источники и публичные ссылки — в одном месте.",
    "/cluster": "Состояние серверов, домены и автоматическое переключение.",
    "/stats": "Активность подписок и управление доступом устройств.",
    "/zapret": "Проверка доступности сервисов и настройка стратегий обхода.",
    "/settings": "Домены подписок, параметры синхронизации и фейловера.",
}


def nav_links(active):
    links = []
    for href, label in NAV_ITEMS:
        label = {"/": "Редактор", "/classic": "Подписки", "/zapret": "Диагностика"}.get(href, label)
        current = ' aria-current="page"' if href == active else ""
        links.append(f'<a class="navlink{" active" if href == active else ""}" href="{href}"{current}>'
                     f'<svg viewBox="0 0 24 24" aria-hidden="true">{NAV_ICONS[href]}</svg>{esc(label)}</a>')
    description = PAGE_DESCRIPTIONS.get(active, "")
    return ( '<a class="skip-link" href="#editor">К рабочей области</a>' if active == "/" else
             '<a class="skip-link" href="#main-content">К содержимому</a>') + f"""
<button class="mobile-menu btn" type="button" aria-label="Открыть меню" aria-expanded="false" aria-controls="sidebar">☰ <span>Sub Cluster</span></button>
<button class="nav-backdrop" type="button" aria-label="Закрыть меню" tabindex="-1"></button>
<aside class="sidebar" id="sidebar">
  <a class="brand" href="/"><span class="brand-mark">s<span>c</span></span><span>Sub Cluster<small>ПАНЕЛЬ УПРАВЛЕНИЯ</small></span></a>
  <div class="nav-caption">РАБОЧЕЕ ПРОСТРАНСТВО</div>
  <nav aria-label="Основная навигация">{''.join(links)}</nav>
  <div class="sidebar-bottom"><div class="workspace-note"><span class="workspace-dot"></span><div>Ваш кластер<small>Подписки под контролем</small></div></div>
  <form method="post" action="/logout"><button class="logout-btn" type="submit">Выйти из аккаунта <span aria-hidden="true">↗</span></button></form></div>
</aside>
{f'<p class="page-description">{description}</p>' if description else ''}
"""


def metrics(items):
    return '<div class="metrics">' + ''.join(
        f'<div class="metric"><span>{esc(label)}</span><strong>{esc(value)}</strong><small>{esc(note)}</small></div>'
        for label, value, note in items) + '</div>'


def route_search():
    return '<div class="search-bar"><label for="route-search">Найти подписку</label><input id="route-search" type="search" placeholder="Название или путь…" autocomplete="off"><span id="search-count" class="muted" aria-live="polite"></span></div><div id="search-empty" class="empty-state" hidden>Ничего не найдено. Попробуйте другое название или путь.</div>'


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
.chk{display:flex;align-items:center;gap:8px;margin-top:8px;font-size:13px;color:#cfd3da}
.switch{position:relative;display:inline-block;width:34px;height:18px;flex:none}
.switch input{opacity:0;width:0;height:0;position:absolute}
.switch .slider{position:absolute;inset:0;background:#2b313d;border-radius:999px;transition:.15s;cursor:pointer}
.switch .slider:before{content:'';position:absolute;width:14px;height:14px;left:2px;top:2px;background:#cfcfd6;border-radius:50%;transition:.15s}
.switch input:checked + .slider{background:#2f8f86}
.switch input:checked + .slider:before{transform:translateX(16px);background:#fff}
fieldset{border:1px solid #232833;border-radius:10px;padding:14px 16px;margin:0 0 16px}
legend{color:#cfd3da;font-size:13px;padding:0 6px}
.domcard{background:#12151b;border:1px solid #232833;border-radius:10px;padding:12px 14px;margin-bottom:12px}
.npri{border:1px dashed #2b313d;border-radius:8px;padding:8px;margin-top:4px}
.npri-row{display:flex;align-items:center;gap:8px;margin-bottom:4px}
.npri-pos{color:#8a93a2;font-size:12px;width:20px}
.npri-name{flex:1;font-size:13px}
.npri-add{margin-top:6px}
.domtbl{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}
.domtbl th,.domtbl td{text-align:left;padding:7px 9px;border-bottom:1px solid #232833}
.domtbl th{color:#8a93a2;font-weight:600;font-size:12px}
/* zapret */
.zcard{background:#12151b;border:1px solid #232833;border-radius:10px;padding:12px 14px;margin-bottom:10px}
.zsvcs{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.zchk{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:#cfd3da;background:#1c1f27;border:1px solid #2b313d;border-radius:6px;padding:3px 8px;cursor:pointer}
.zmodal{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;z-index:200}
.zmodal.show{display:flex}
.zbox{background:#171a21;border:1px solid #2b313d;border-radius:12px;width:min(820px,94vw);max-height:88vh;display:flex;flex-direction:column}
.zbox .zhd{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 16px;border-bottom:1px solid #232833}
.zlog{flex:1;overflow:auto;padding:10px 14px;font-family:ui-monospace,Consolas,monospace;font-size:12px;white-space:pre-wrap;line-height:1.45;background:#0f1115;color:#cfd3da;min-height:180px}
.zgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:6px;padding:10px 14px;border-top:1px solid #232833}
.zsvc{display:flex;align-items:center;gap:7px;font-size:12px;padding:4px 8px;border:1px solid #232833;border-radius:6px}
.zdot{width:9px;height:9px;border-radius:50%;flex:none;background:#43454e}
.zdot.up{background:#3fb950}.zdot.down{background:#f85149}
"""


# JS-редактор списка доменов на /settings (литеральные {} — обычная строка, не f-string).
SETTINGS_JS = r"""
(function(){
  var DOMS = Array.isArray(window.__SDOMAINS__) ? window.__SDOMAINS__.map(function(d){return Object.assign({},d);}) : [];
  var NODES = Array.isArray(window.__SNODES__) ? window.__SNODES__ : [];
  var SUB_PORT = window.__SUB_PORT__ || 8081;
  var list = document.getElementById('domlist');
  var hidden = document.getElementById('domains_json');
  var form = document.getElementById('setform');
  var addBtn = document.getElementById('addDom');
  function fqdnOf(d){ var s=(d.subdomain||'').trim().toLowerCase(), z=(d.zone||'').trim().toLowerCase(); return (s&&z)?(s+'.'+z):''; }
  function coolifyStr(d){ var fq=fqdnOf(d); return fq?('https://'+fq+':'+SUB_PORT):''; }
  function refreshSummary(){
    var box=document.getElementById('coolify'); if(!box) return; box.textContent='';
    var parts=DOMS.filter(function(d){ return d.enabled!==false && fqdnOf(d); }).map(coolifyStr);
    box.appendChild(el('label',null,'Coolify «Domains» для сервиса (подписки → порт '+SUB_PORT+')'));
    if(!parts.length){ box.appendChild(el('div','help','Добавь домен с зоной и поддоменом.')); return; }
    var ta=el('textarea'); ta.readOnly=true; ta.value=parts.join(',\n'); ta.rows=Math.min(6,parts.length); ta.className='mono'; box.appendChild(ta);
    var copy=el('button','btn small','Копировать'); copy.type='button';
    copy.addEventListener('click',function(){ if(navigator.clipboard)navigator.clipboard.writeText(parts.join(',')); copy.textContent='Скопировано ✓'; setTimeout(function(){copy.textContent='Копировать';},1500); });
    box.appendChild(copy);
    box.appendChild(el('div','help','Вставь в поле «Domains» сервиса app в Coolify (через запятую). Admin-домен узла добавь отдельно к его порту.'));
  }
  function nodeLabel(id){ var n=NODES.find(function(x){return x.id===id;}); return n?(n.label||n.id):id; }
  function el(tag,cls,txt){ var e=document.createElement(tag); if(cls)e.className=cls; if(txt!=null)e.textContent=txt; return e; }

  function field(label,d,key,ph,mono,cb){
    var w=el('div'); w.appendChild(el('label',null,label));
    var inp=el('input'); inp.value=d[key]||''; inp.placeholder=ph||''; if(mono)inp.className='mono';
    inp.addEventListener('input',function(){ d[key]=inp.value; if(cb)cb(); });
    w.appendChild(inp); return w;
  }
  function pwfield(d){
    var w=el('div'); w.appendChild(el('label',null,'Пароль reg.ru'));
    var inp=el('input'); inp.type='password';
    inp.placeholder=d.has_pw?'пароль задан — пусто = не менять':'пароль reg.ru / API-пароль';
    inp.addEventListener('input',function(){ d.__pw=inp.value; });
    w.appendChild(inp); return w;
  }
  function renderNpri(d, host){
    host.textContent='';
    var cur = Array.isArray(d.node_priority)?d.node_priority.slice():[];
    if(!cur.length){ host.appendChild(el('div','help','Глобальный приоритет (по умолчанию). Добавь узлы, чтобы задать свой порядок для этого домена.')); }
    cur.forEach(function(nid,idx){
      var row=el('div','npri-row');
      row.appendChild(el('span','npri-pos',(idx+1)+'.'));
      row.appendChild(el('span','npri-name',nodeLabel(nid)));
      var up=el('button','btn small gray','↑'); up.type='button'; up.disabled=idx===0;
      up.addEventListener('click',function(){ var a=d.node_priority; var t=a[idx-1]; a[idx-1]=a[idx]; a[idx]=t; renderNpri(d,host); });
      var dn=el('button','btn small gray','↓'); dn.type='button'; dn.disabled=idx===cur.length-1;
      dn.addEventListener('click',function(){ var a=d.node_priority; var t=a[idx+1]; a[idx+1]=a[idx]; a[idx]=t; renderNpri(d,host); });
      var rm=el('button','btn small red','✕'); rm.type='button';
      rm.addEventListener('click',function(){ d.node_priority.splice(idx,1); if(!d.node_priority.length)d.node_priority=null; renderNpri(d,host); });
      row.appendChild(up); row.appendChild(dn); row.appendChild(rm); host.appendChild(row);
    });
    var avail = NODES.filter(function(n){ return cur.indexOf(n.id)<0; });
    if(avail.length){
      var sel=el('select','npri-add'); sel.appendChild(el('option',null,'+ добавить узел'));
      avail.forEach(function(n){ var o=el('option',null,(n.label||n.id)); o.value=n.id; sel.appendChild(o); });
      sel.addEventListener('change',function(){ if(!sel.value)return; d.node_priority=d.node_priority||[]; d.node_priority.push(sel.value); renderNpri(d,host); });
      host.appendChild(sel);
    }
  }
  function render(){
    list.textContent='';
    DOMS.forEach(function(d,i){
      var card=el('div','card domcard');
      var head=el('div','row');
      var star=el('label','chk');
      var rad=el('input'); rad.type='radio'; rad.name='__default__'; rad.checked=!!d.default; rad.style.width='auto';
      rad.addEventListener('change',function(){ DOMS.forEach(function(x){x.default=false;}); d.default=true; });
      star.appendChild(rad); star.appendChild(el('span',null,'домен по умолчанию'));
      head.appendChild(star);
      var sp=el('span'); sp.style.flex='1'; head.appendChild(sp);
      var del=el('button','btn small red','Удалить'); del.type='button';
      del.addEventListener('click',function(){ DOMS.splice(i,1); render(); });
      head.appendChild(del); card.appendChild(head);
      var cf=el('div','help'); cf.style.marginTop='6px';
      function updCard(){ var c=coolifyStr(d); cf.textContent = c ? ('Coolify: привязать к порту '+SUB_PORT+' → '+c) : ('Coolify: укажи зону и поддомен (порт '+SUB_PORT+')'); refreshSummary(); }
      var g=el('div','grid2'); g.style.marginTop='8px';
      g.appendChild(field('Зона', d, 'zone', 'example.com', true, updCard));
      g.appendChild(field('Поддомен', d, 'subdomain', 'happ', true, updCard));
      g.appendChild(field('Логин reg.ru', d, 'regru_username', '', false));
      g.appendChild(pwfield(d));
      card.appendChild(g);
      card.appendChild(cf);
      card.appendChild(field('Публичная база (необязательно)', d, 'public_base', 'https://happ.example.com', true));
      card.appendChild(field('Заметка', d, 'note', '', false));
      var en=el('label','chk'); en.style.marginTop='8px';
      var cb=el('input'); cb.type='checkbox'; cb.checked=d.enabled!==false; cb.style.width='auto';
      cb.addEventListener('change',function(){ d.enabled=cb.checked; refreshSummary(); });
      en.appendChild(cb); en.appendChild(el('span',null,'включён')); card.appendChild(en);
      card.appendChild(el('label',null,'Приоритет узлов для этого домена'));
      var np=el('div','npri'); card.appendChild(np); renderNpri(d,np);
      list.appendChild(card);
      updCard();
    });
    if(!DOMS.length){ list.appendChild(el('div','help','Доменов пока нет — добавь хотя бы один.')); }
    refreshSummary();
  }
  addBtn.addEventListener('click',function(){
    DOMS.push({id:'',zone:'',subdomain:'',regru_username:'',enabled:true,default:DOMS.length===0,note:'',public_base:'',node_priority:null,has_pw:false});
    render();
  });
  form.addEventListener('submit',function(){
    var out=DOMS.map(function(d){
      var o={id:d.id||'',zone:(d.zone||'').trim(),subdomain:(d.subdomain||'').trim(),regru_username:(d.regru_username||'').trim(),
        enabled:d.enabled!==false,default:!!d.default,note:d.note||'',public_base:(d.public_base||'').trim(),
        node_priority:(Array.isArray(d.node_priority)&&d.node_priority.length)?d.node_priority:null};
      if(d.__pw) o.regru_password=d.__pw;
      return o;
    });
    hidden.value=JSON.stringify(out);
  });
  render();
})();
"""


# ── вход ───────────────────────────────────────────────────────────────────
def render_login(error=""):
    err = f'<div class="flash err">{esc(error)}</div>' if error else ""
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Вход — Sub Cluster</title><style>{PAGE_CSS}{EXTRA_CSS}{SHELL_CSS}</style></head>
<body class="login-page"><div class="login-layout"><div class="login-story"><a class="brand" href="/"><span class="brand-mark">s<span>c</span></span><span>Sub Cluster</span></a><div class="login-pitch"><div class="eyebrow">ВАША СЕТЬ. ВАШИ ПРАВИЛА.</div><h2>Все подключения. <br>Один центр <br><em>управления.</em></h2><p>Подписки, маршруты и серверы.<br>Всё, что нужно вашему кластеру.</p><div class="login-orbit" aria-hidden="true"><span>Источники</span><i></i><b>sc</b><i></i><span>Подписки</span></div></div><div class="login-foot">Пространство для вашей инфраструктуры</div></div><div class="card login-box">
<div class="eyebrow">ДОБРО ПОЖАЛОВАТЬ</div><h1>Войти в панель</h1><div class="sub">Управляйте своим кластером из одного места.</div>
{err}
<form method="post" action="/login">
<label for="login-user">Логин</label><input id="login-user" name="user" autocomplete="username" placeholder="Ваш логин" required autofocus>
<label for="login-password">Пароль</label><input id="login-password" name="password" type="password" autocomplete="current-password" placeholder="Введите пароль" required>
<div style="margin-top:16px"><button class="btn primary" type="submit">Войти в панель <span aria-hidden="true">→</span></button></div>
</form></div></div><script>{SHELL_JS}</script></body></html>"""


# ── нодовый редактор ───────────────────────────────────────────────────────
def render_editor(graph, sub_base, csrf, banner="", domains=None):
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Граф — Sub Cluster</title><style>{EDITOR_CSS}{EXTRA_CSS}{SHELL_CSS}</style></head>
<body class="editor-page">
{nav_links("/")}
<div id="top" role="toolbar" aria-label="Инструменты графа">
  <div class="tool-group tool-create" role="group" aria-label="Добавить ноду">
  <button class="btn" id="addSrc">+ Источник</button>
  <button class="btn" id="addKey">+ Ключ</button>
  <button class="btn" id="addGroup">+ Группа</button>
  <button class="btn" id="addAuto">+ Авто-выбор</button>
  <button class="btn" id="addRouter">+ Роутер</button>
  <button class="btn" id="addRoute">+ Маршрут</button>
  </div><div class="tool-group tool-actions"><button class="btn gray" id="reset">Сбросить вид</button>
  <button class="btn gray" id="blurToggle">Показать ссылки</button>
  <button class="btn" id="autosaveToggle">Автосейв: вкл</button>
  <span class="spacer"></span>
  <span id="savestat"></span>
  <button class="btn primary" id="save">Сохранить</button></div>
</div>
{banner}
<div id="editor" tabindex="-1" aria-label="Граф подписок">
  <svg id="wires" xmlns="http://www.w3.org/2000/svg"></svg>
  <div id="world"></div>
  <div id="hint">Пусто. Добавь «<b>+ Источник</b>» или «<b>+ Ключ</b>», потом «<b>+ Маршрут</b>», протяни связь и «<b>Сохранить</b>».<br>
    <span style="opacity:.7">Колесо — зум, перетаскивание фона — панорама.</span></div>
</div>
<div id="toast"></div>
<script>window.__GRAPH__={js_embed(graph)};window.__ADMIN__="";window.__CSRF__={js_embed(csrf)};window.__BASE__={js_embed(sub_base)};window.__DOMAINS__={js_embed(domains or [])};window.__BAL_DEFAULTS__={js_embed(subscriptions._BALANCER_DEFAULTS)};window.__PRESETS__={js_embed(subscriptions.ROUTER_PRESETS)};</script>
<script>{EDITOR_JS}</script>
<script>{SHELL_JS}</script></body></html>"""


# ── классический список ────────────────────────────────────────────────────
def _domain_options(domains, selected):
    selected = selected or ""
    out = [f'<option value=""{"" if selected else " selected"}>(по умолчанию)</option>']
    for d in (domains or []):
        did = d.get("id") or ""
        label = d.get("fqdn") or did
        if not d.get("enabled", True):
            label += " (выключен)"
        elif d.get("default"):
            label += " ★"
        sel = " selected" if did == selected else ""
        out.append(f'<option value="{esc(did)}"{sel}>{esc(label)}</option>')
    return "".join(out)


def _domain_base(domains, domain_id):
    """База публичной ссылки маршрута: его домен (если включён), иначе дефолтный.
    Дефолтный выбираем так же, как сервер (graph.default_domain) и редактор: сначала
    включённый помеченный default, затем первый включённый, затем любой."""
    by_id = {d.get("id"): d for d in (domains or [])}
    d = by_id.get(domain_id) if domain_id else None
    if d is None or not d.get("enabled", True):
        d = (next((x for x in (domains or []) if x.get("default") and x.get("enabled", True)), None)
             or next((x for x in (domains or []) if x.get("enabled", True)), None)
             or next((x for x in (domains or [])), None))
    return (d.get("base") or "") if d else ""


def render_route_card(route, sub_base, domains=None):
    rid = esc(route.get("id", ""))
    path = esc(route.get("path", ""))
    title = esc(route.get("title", ""))
    mode = route.get("mode", "merge")
    enabled = route.get("enabled", True)
    domain_id = route.get("domain_id", "") or ""
    upstreams = route.get("upstreams", [])
    ups_text = esc("\n".join(upstreams))
    announce = esc(route.get("announce", "") or "")
    base = _domain_base(domains, domain_id) or sub_base
    full_url = esc(base.rstrip("/") + (route.get("path", "") or ""))
    state = '<span class="tag on">включён</span>' if enabled else '<span class="tag off">выключен</span>'
    mode_label = "слияние" if mode != "mirror" else "зеркало"
    # предупреждение: домен маршрута удалён/выключен → отдаётся на дефолтном
    by_id = {d.get("id"): d for d in (domains or [])}
    dom_warn = ""
    if domain_id and (domain_id not in by_id or not by_id[domain_id].get("enabled", True)):
        dom_warn = ('<div class="muted" style="margin-top:6px;color:#ffb86b">⚠ выбранный домен '
                    'отсутствует/выключен — маршрут отдаётся на домене по умолчанию.</div>')
    return f"""
<div class="card">
  <div class="route-head"><div>
    <div class="route-title">{title or '(без названия)'} {state} <span class="tag">{esc(mode_label)}</span></div>
    <div class="path blur">{path}</div></div></div>
  <div class="muted" style="margin-top:6px">Публичная ссылка: <span class="path blur">{full_url}</span></div>
  {dom_warn}
  <details style="margin-top:10px"><summary class="muted" style="cursor:pointer">Редактировать ({len(upstreams)} upstream)</summary>
  <form method="post" action="/routes/{rid}/update">
    <label>Название</label><input name="title" value="{title}">
    <label>Путь подписки</label><input name="path" value="{path}" class="blur">
    <label>Домен (на каком отдаётся)</label>
    <select name="domain_id">{_domain_options(domains, domain_id)}</select>
    <label>Доступ к подписке</label><select name="access"><option value="public">Общественная</option><option value="private"{' selected' if route.get("access") == "private" else ''}>Личная · 1 устройство</option></select>
    <div class="help">Личный режим: 1 ссылка = 1 HWID. Владелец: {esc(route.get("personal_owner") or "текущий узел")}. Нужны доступный владелец и настроенный Turnstile.</div>
    <label>Режим</label>
    <select name="mode">
      <option value="merge"{' selected' if mode != 'mirror' else ''}>Слияние</option>
      <option value="mirror"{' selected' if mode == 'mirror' else ''}>Зеркало</option>
    </select>
    <label>Upstream-ссылки (по одной в строке)</label><textarea name="upstreams" class="blur">{ups_text}</textarea>
    <label>Текст под подпиской (announce — показывается в клиенте)</label><textarea name="announce" placeholder="Бот — @mybot&#10;Поддержка — https://...">{announce}</textarea>
    <label class="row" style="margin-top:10px"><input type="checkbox" name="enabled" value="1" style="width:auto"{' checked' if enabled else ''}> <span>Включён</span></label>
    <div class="row" style="margin-top:12px"><button class="btn small primary" type="submit">Сохранить</button></div>
  </form>
  <form class="inline" method="post" action="/routes/{rid}/delete" onsubmit="return confirm('Удалить этот маршрут?')">
    <div style="margin-top:8px"><button class="btn small red" type="submit">Удалить</button></div>
  </form>
  </details>
</div>"""


def render_classic(routes, sub_base, flash="", flash_err=False, domains=None):
    cards = "".join(render_route_card(r, sub_base, domains) for r in routes) or \
        '<div class="card muted">Маршрутов пока нет.</div>'
    flash_html = f'<div class="flash {"err" if flash_err else ""}">{esc(flash)}</div>' if flash else ""
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Список — Sub Cluster</title><style>{PAGE_CSS}{EXTRA_CSS}{SHELL_CSS}</style></head>
<body class="app-page"><div class="wrap" id="main-content" tabindex="-1">
<div class="route-head"><div><h1>Подписки</h1>
<div class="eyebrow">УПРАВЛЕНИЕ МАРШРУТАМИ</div></div>
<button class="btn small gray" onclick="document.body.classList.toggle('unblur')">Показать/скрыть ссылки</button></div>
<div style="margin-bottom:16px">{nav_links("/classic")}</div>
{metrics([("Подписки", len(routes), "Всего маршрутов"), ("Включены", sum(r.get("enabled", True) for r in routes), "Доступны клиентам"), ("Домены", len(domains or []), "Домены подписок")])}
{route_search()}
{flash_html}<div id="route-results">{cards}</div><hr>
<div class="card"><div class="route-title">Новый маршрут</div>
<form method="post" action="/routes/create">
  <label>Название</label><input name="title" placeholder="Моя подписка">
  <label>Путь подписки</label><input name="path" placeholder="/custom/custom" required>
  <label>Домен (на каком отдаётся)</label>
  <select name="domain_id">{_domain_options(domains, "")}</select>
  <label>Доступ к подписке</label><select name="access"><option value="public">Общественная</option><option value="private">Личная · 1 устройство</option></select>
  <label>Режим</label><select name="mode"><option value="merge">Слияние</option><option value="mirror">Зеркало</option></select>
  <label>Upstream-ссылки (по одной в строке)</label><textarea name="upstreams"></textarea>
  <label>Текст под подпиской (announce)</label><textarea name="announce" placeholder="Бот — @mybot&#10;Поддержка — https://..."></textarea>
  <div style="margin-top:12px"><button class="btn primary" type="submit">Создать</button></div>
</form></div>
</div><script>{SHELL_JS}</script></body></html>"""


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
                        f'<button class="btn small" type="submit">Сделать активным (все домены)</button></form> ')
        if n.get("redeploy_url"):
            actions += (f'<form class="inline" method="post" action="/cluster/nodes/{esc(n["id"])}/redeploy" '
                        f'onsubmit="return confirm(\'Запустить редеплой узла {esc(n["label"])}?\')">'
                        f'<button class="btn small" type="submit">Редеплой</button></form> ')
        token_ph = "токен задан — пусто = не менять" if n.get("has_redeploy_token") else "токен (Coolify Bearer и т.п.)"
        actions += (f'<details style="display:inline-block"><summary class="muted" style="cursor:pointer;display:inline">изм.</summary>'
                    f'<form method="post" action="/cluster/nodes/{esc(n["id"])}/update" style="margin-top:6px">'
                    f'<input name="label" value="{esc(n["label"])}" placeholder="метка">'
                    f'<input name="public_ip" value="{esc(n["public_ip"])}" placeholder="публичный IP (для DNS подписок)" class="mono">'
                    f'<input name="cluster_url" value="{esc(n.get("cluster_url",""))}" placeholder="https://adminN.домен (адрес для пиров)" class="mono">'
                    f'<input name="redeploy_url" value="{esc(n.get("redeploy_url",""))}" placeholder="redeploy-вебхук (Coolify deploy-webhook / агент)" class="mono">'
                    f'<input name="redeploy_token" type="password" placeholder="{esc(token_ph)}">'
                    f'<input name="priority" value="{esc(n["priority"])}" placeholder="приоритет" type="number">'
                    f'<input name="cluster_port" value="{esc(n["cluster_port"])}" placeholder="cluster-порт (фолбэк по IP)" type="number">'
                    f'<label class="chk"><span class="switch"><input type="checkbox" name="enabled" value="1"{" checked" if n["enabled"] else ""}><span class="slider"></span></span> <span>включён</span></label>'
                    f'<div style="margin-top:6px"><button class="btn small primary" type="submit">Сохранить</button></div></form>')
        if not n["is_self"]:
            actions += (f'<form class="inline" method="post" action="/cluster/nodes/{esc(n["id"])}/delete" '
                        f'onsubmit="return confirm(\'Удалить узел?\')"><button class="btn small red" type="submit">×</button></form>')
        actions += "</details>"
        addr = esc(n.get("cluster_url") or (f'{n["public_ip"]}:{n["cluster_port"]}' if n["public_ip"] else "—"))
        rows.append(
            f'<tr><td>{dot}<b>{esc(n["label"])}</b> {badges}<div class="muted mono">{esc(n["id"])}</div></td>'
            f'<td class="mono">{esc(n["public_ip"]) or "—"}<div class="muted mono">{addr}</div></td><td>{esc(n["priority"])}</td>'
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
        dom_tag = f' · <span class="mono">{esc(h.get("domain"))}</span>' if h.get("domain") else ""
        hist += (f'<div class="muted" style="font-size:12px">{esc(_ago(h.get("ts")))} · {ok} '
                 f'{esc(h.get("node"))} → {esc(h.get("ip"))} ({esc(h.get("by"))}){dom_tag} {esc(h.get("msg",""))}</div>')
    # таблица per-domain (активный узел и IP по каждому домену подписок)
    label_by_id = {n["id"]: n["label"] for n in status["nodes"]}
    drows = []
    for d in status.get("domains", []):
        star = ' <span class="badge active">по умолч.</span>' if d.get("is_default") else ""
        off = '' if d.get("enabled", True) else ' <span class="tag off">выключен</span>'
        nocreds = '' if d.get("has_creds") else ' <span class="tag off">нет reg.ru</span>'
        npri = ' <span class="badge pin">свой приоритет</span>' if d.get("node_priority") else ""
        act = d.get("active")
        act_label = (esc(label_by_id.get(act, act)) if act else "—")
        drows.append(
            f'<tr><td><span class="mono">{esc(d.get("fqdn"))}</span>{star}{off}{nocreds}{npri}</td>'
            f'<td>{act_label}</td><td class="mono">{esc(d.get("dns_ip") or "—")}</td></tr>')
    dom_table = (
        '<div class="card"><div class="route-title">Домены подписок (фейловер на домен)</div>'
        '<table class="domtbl"><thead><tr><th>Домен</th><th>Активный узел (DNS)</th><th>IP в DNS</th></tr></thead>'
        f'<tbody>{"".join(drows)}</tbody></table>'
        '<div class="help">У каждого домена свой активный узел: его A-запись переписывается на этот узел его '
        'аккаунтом reg.ru. «Свой приоритет» — для домена задан собственный порядок узлов (переопределяет глобальный).</div></div>'
    ) if status.get("domains") else ""
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Кластер — Sub Cluster</title><style>{PAGE_CSS}{EXTRA_CSS}{SHELL_CSS}</style></head>
<body class="app-page"><div class="wrap" id="main-content" tabindex="-1">
<h1>Кластер</h1>
<div style="margin:8px 0 16px">{nav_links("/cluster")}</div>
{metrics([("Серверы", len(status["nodes"]), "Узлов в кластере"), ("На связи", sum(n["alive"] for n in status["nodes"]), "Доступны сейчас"), ("Домены", len(status.get("domains", [])), "Под управлением DNS")])}
{flash_html}
<div class="card">
  <div class="grid2">
    <div><div class="muted">Активный узел (домен по умолчанию)</div><div class="route-title">{esc(active)}</div></div>
    <div><div class="muted">IP в DNS (домен по умолчанию)</div><div class="route-title mono">{esc(dns_ip)}</div></div>
  </div>
  <div style="margin-top:10px">Авто-фейловер: <b>{"включён" if fo_on else "выключен"}</b> {pin_html}</div>
</div>
{dom_table}
<div class="card">
  <table class="tbl"><thead><tr><th>Узел / адрес для пиров</th><th>Public IP</th><th>Приоритет</th><th>Живость</th><th>Действия</th></tr></thead>
  <tbody>{''.join(rows)}</tbody></table>
  <div class="help">«Адрес для пиров» — статичный admin-домен узла (https://adminN.домен) по 443: узлы ходят туда друг к другу, проброс портов не нужен. Public IP используется только для DNS подписок при фейловере.</div>
</div>
<div class="card"><div class="route-title">Добавить узел</div>
<form method="post" action="/cluster/nodes/add" class="grid2" style="margin-top:8px">
  <div><label>Метка</label><input name="label" placeholder="node-2"></div>
  <div><label>Public IP (для DNS подписок)</label><input name="public_ip" class="mono" placeholder="203.0.113.10"></div>
  <div style="grid-column:1/3"><label>Адрес для пиров (статичный admin-домен)</label><input name="cluster_url" class="mono" placeholder="https://admin2.example.net"></div>
  <div><label>Приоритет (меньше = важнее)</label><input name="priority" type="number" value="100"></div>
  <div><label>Cluster-порт (фолбэк по IP)</label><input name="cluster_port" type="number" value="8083"></div>
  <div style="grid-column:1/3"><label>Redeploy-вебхук (необязательно)</label><input name="redeploy_url" class="mono" placeholder="Coolify deploy-webhook или http://host.docker.internal:9090/redeploy"></div>
  <div style="grid-column:1/3"><label>Redeploy-токен (необязательно)</label><input name="redeploy_token" type="password" placeholder="Bearer-токен / секрет агента"></div>
  <div style="grid-column:1/3"><button class="btn primary" type="submit">Добавить</button></div>
</form>
<div class="help">Узел и сам зарегистрируется, когда запустится с этим NODE_ID и CLUSTER_URL и увидит кластер; запись тут — чтобы остальные знали его адрес заранее.
Redeploy-вебхук: Coolify — его deploy-webhook (сам делает git pull+build); standalone — агент redeploy-agent.py на хосте.</div>
</div>
<div class="card"><div class="route-title">Журнал переключений</div><div style="margin-top:8px">{hist or '<span class="muted">пусто</span>'}</div></div>
</div><script>{SHELL_JS}</script></body></html>"""


# ── настройки ──────────────────────────────────────────────────────────────
def render_settings(settings, nodes, flash="", flash_err=False, crypto_ok=True,
                    sub_port=8081, admin_port=8080):
    flash_html = f'<div class="flash {"err" if flash_err else ""}">{esc(flash)}</div>' if flash else ""
    dns = settings.get("dns", {})
    doms = dns.get("domains") or []
    domains_ui = [{
        "id": d.get("id", ""), "zone": d.get("zone", ""), "subdomain": d.get("subdomain", ""),
        "regru_username": d.get("regru_username", ""), "enabled": d.get("enabled", True),
        "default": bool(d.get("default")), "note": d.get("note", ""),
        "public_base": d.get("public_base", ""), "node_priority": d.get("node_priority"),
        "has_pw": bool(d.get("regru_password_enc")),
    } for d in doms if isinstance(d, dict)]
    nodes_ui = [{"id": n.get("id"), "label": n.get("label") or n.get("id")} for n in (nodes or [])]
    crypto_warn = "" if crypto_ok else (
        '<div class="flash err">SECRET_KEY не задан или нет cryptography — секреты хранятся в открытом виде. '
        'Задай переменную окружения SECRET_KEY (одинаковую на всех узлах).</div>')
    chk = lambda v: " checked" if v else ""
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Настройки — Sub Cluster</title><style>{PAGE_CSS}{EXTRA_CSS}{SHELL_CSS}</style></head>
<body class="app-page"><div class="wrap" id="main-content" tabindex="-1">
<h1>Настройки</h1>
<div style="margin:8px 0 16px">{nav_links("/settings")}</div>
{crypto_warn}{flash_html}
<form method="post" action="/settings/save" id="setform">
<fieldset><legend>Домены подписок (у каждого свой аккаунт reg.ru)</legend>
  <details class="setup-help"><summary>Как настроить домены и прокси</summary><div class="help" style="margin-bottom:10px">Каждый домен фейловерится отдельно: его A-запись
  переписывается на свой активный узел его аккаунтом reg.ru. IP всех узлов должны быть в белом списке
  API в настройках соответствующего аккаунта reg.ru. «Домен по умолчанию» отдаёт маршруты без явно
  выбранного домена. Admin-домены узлов статичные — reg.ru их не трогает.
  <br><b>Зона</b> — зарегистрированный в reg.ru домен (напр. <code>example.com</code>); <b>поддомен</b>
  может быть многоуровневым (напр. <code>happ.region</code> → домен 4-го уровня
  <code>happ.region.example.com</code>). Зону на 3-й уровень дробить не нужно — её ведёт reg.ru.
  <br><b>Coolify/прокси:</b> привяжи КАЖДЫЙ домен подписок к порту подписок
  <b>{esc(sub_port)}</b> (SUB_PORT), а admin-домен узла — к порту <b>{esc(admin_port)}</b> (ADMIN_PORT).
  Готовая строка для поля «Domains» — ниже.</div></details>
  <div id="domlist"></div>
  <button class="btn small" type="button" id="addDom">+ Добавить домен</button>
  <div id="coolify" style="margin-top:12px"></div>
</fieldset>
<fieldset><legend>Защита подписок</legend>
  <label class="row"><input type="checkbox" name="require_device_hwid" value="1" style="width:auto"{chk(settings.get('require_device_hwid', True))}> <span>Требовать HWID устройства без IP</span></label>
  <div class="help">По умолчанию включено. Клиент должен передавать X-Hwid без IP-адресов и текста «ip». Версия приложения не проверяется. Исключения: публичные IP всех узлов кластера, 37.193.168.134 и 90.189.209.31. Настройка синхронизируется между узлами. Привязка личных ссылок к одному устройству остаётся отдельной проверкой.</div>
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
<input type="hidden" name="domains_json" id="domains_json">
<button class="btn primary" type="submit">Сохранить настройки</button>
</form>
<script>window.__SDOMAINS__={js_embed(domains_ui)};window.__SNODES__={js_embed(nodes_ui)};window.__SUB_PORT__={js_embed(sub_port)};</script>
<script>{SETTINGS_JS}</script>
</div><script>{SHELL_JS}</script></body></html>"""


# ── статистика ─────────────────────────────────────────────────────────────
def render_stats(stats, routes, node_id, sub_base, blocked_devices=None, csrf=""):
    title_by_id = {r.get("id"): (r.get("title") or r.get("path") or r.get("id")) for r in routes}
    path_by_id = {r.get("id"): r.get("path", "") for r in routes}
    blocked = {(str(x.get("route_id") or ""), str(x.get("device") or ""))
               for x in (blocked_devices or []) if isinstance(x, dict)}
    blocks = []
    # маршруты с трафиком — по числу запросов
    items = sorted(stats.items(), key=lambda kv: kv[1].get("requests", 0), reverse=True)
    for rid, st in items:
        name = esc(title_by_id.get(rid, rid))
        path = esc(path_by_id.get(rid, ""))
        rows = []
        for d in st.get("devices", []):
            label = esc(d.get("hwid") or d.get("device") or "—")
            nodes = esc(", ".join(d.get("nodes", []))) or "—"
            device = str(d.get("device") or "")
            is_blocked = (str(rid), device) in blocked
            action = "unblock" if is_blocked else "block"
            button = "Разблокировать" if is_blocked else "Заблокировать"
            badge = '<span class="badge" style="background:#3b1d22;color:#ff9b9b">заблокирован</span>' if is_blocked else ""
            warn = " (по IP)" if device.startswith("ip:") else ""
            rows.append(
                f'<tr><td>{esc(d.get("personal_name") or "—")}</td><td><span class="mono">{label[:20]}</span>{badge}</td>'
                f'<td>{esc(d.get("model") or "—")}</td><td>{esc(d.get("app") or "—")}</td>'
                f'<td class="mono">{esc(d.get("ip") or "—")}</td><td>{esc(d.get("cnt"))}</td>'
                f'<td class="muted">{nodes}</td>'
                f'<td class="muted">{esc(_ago(d.get("last_ts")))}</td>'
                f'<td><form class="inline" method="post" action="/stats/block">'
                f'<input type="hidden" name="route" value="{esc(rid)}">'
                f'<input type="hidden" name="device" value="{esc(device)}">'
                f'<input type="hidden" name="action" value="{action}">'
                f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                f'<button class="btn small {"gray" if is_blocked else "ghost"}" type="submit" '
                f'onclick="return confirm(\'{button} устройство{warn}?\')">{button}</button>'
                f'</form></td></tr>')
        blocks.append(
            f'<div class="card"><div class="route-head"><div>'
            f'<div class="route-title">{name or "(без названия)"}</div>'
            f'<div class="path blur">{path}</div></div>'
            f'<div style="text-align:right"><div class="route-title">{esc(st.get("requests",0))}</div>'
            f'<div class="muted">запросов · устройств: {len(st.get("devices",[]))}</div></div></div>'
            f'<details style="margin-top:10px"><summary class="muted" style="cursor:pointer">Устройства</summary>'
            f'<table class="tbl" style="margin-top:8px"><thead><tr><th>Имя</th><th>HWID</th><th>Модель</th><th>Клиент</th><th>IP</th><th>Запр.</th><th>Узлы</th><th>Активность</th><th>Доступ</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></details>'
            f'<form class="inline" method="post" action="/stats/reset" style="margin-top:8px">'
            f'<input type="hidden" name="route" value="{esc(rid)}">'
            f'<button class="btn small ghost" type="submit">Сбросить по кластеру</button></form></div>')
    body = "".join(blocks) or '<div class="card muted">Пока нет обращений к маршрутам в кластере.</div>'
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Статистика — Sub Cluster</title><style>{PAGE_CSS}{EXTRA_CSS}{SHELL_CSS}</style></head>
<body class="app-page"><div class="wrap" id="main-content" tabindex="-1">
<h1>Статистика</h1>
<div style="margin:8px 0 16px">{nav_links("/stats")}</div>
{metrics([("Запросы", sum(st.get("requests", 0) for st in stats.values()), "Обращения к подпискам"), ("Подписки с активностью", len(stats), "За период сбора"), ("Блокировки", len(blocked), "Устройство × подписка")])}
<details class="setup-help"><summary>Как собирается статистика и работают блокировки</summary><div class="muted" style="margin-bottom:12px">Сводно по <b>всему кластеру</b>: запросы клиентов
к подпискам со всех живых узлов (опрашиваются на лету). Столбец «Узлы» — на каких узлах
видели устройство. Этот узел: <b>{esc(node_id)}</b>. Сброс рассылается на все живые
  узлы (узел, который сейчас офлайн, обнулится только когда вернётся — вручную).
  Блокировка действует на устройство только в выбранной подписке и синхронизируется по
  кластеру. Если HWID отсутствует, используется IP — за общим IP могут находиться другие люди.
</div></details><button class="btn small gray" style="margin-bottom:20px" onclick="document.body.classList.toggle('unblur')">Показать/скрыть пути</button>
{body}
<form class="inline" method="post" action="/stats/reset" style="margin-top:8px">
  <button class="btn small ghost" type="submit" onclick="return confirm('Сбросить статистику по всему кластеру?')">Сбросить всё (по кластеру)</button></form>
</div><script>{SHELL_JS}</script></body></html>"""


# ── zapret (обход DPI): стратегии + авто-тест ───────────────────────────────
def render_zapret(z, services, available, can_apply, node_id, csrf, reason="", defaults=None, community=None):
    z_ui = {
        "strategies": [{"id": s.get("id", ""), "label": s.get("label", ""), "params": s.get("params", "")}
                       for s in (z.get("strategies") or [])],
        "active_id": z.get("active_id") or "",
        "services": [{"key": s["key"], "label": s["label"]} for s in services],
        "available": bool(available), "can_apply": bool(can_apply), "node": node_id,
        "defaults": [{"label": d.get("label", ""), "params": d.get("params", "")} for d in (defaults or [])],
        "community": [{"label": d.get("label", ""), "params": d.get("params", "")} for d in (community or [])],
    }
    why = f' <b>Причина:</b> {esc(reason)}' if reason else ''
    if not available:
        banner = ('<div class="flash err">zapret недоступен — авто-тест покажет ТОЛЬКО базовую '
                  'доступность сервисов <b>без обхода</b>.' + why + '</div>')
    elif not can_apply:
        banner = ('<div class="flash">zapret найден, но применение обхода выключено — задай '
                  '<span class="mono">ZAPRET=true</span> в .env, чтобы авто-тест реально применял стратегии.'
                  + why + ' Сейчас — только baseline (доступность без обхода).</div>')
    elif reason:
        banner = ('<div class="flash err">zapret включён, но <b>обход НЕ применится</b>:' + why
                  + '</div>')
    else:
        banner = ('<div class="flash">zapret активен: авто-тест применяет стратегии к egress контейнера и меряет '
                  'доступность.</div>')
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>zapret — Sub Cluster</title><style>{PAGE_CSS}{EXTRA_CSS}{SHELL_CSS}</style></head>
<body class="app-page"><div class="wrap" id="main-content" tabindex="-1">
<h1>Диагностика</h1>
<div style="margin:8px 0 16px">{nav_links("/zapret")}</div>
<div class="muted" style="margin-bottom:12px">Узел: <b>{esc(node_id)}</b>. Это <b>выбор стратегии и проверка
доступности НА УЗЛЕ</b> — авто-тест меряет, какие из заблокированных сервисов доступны (с обходом и без).
Конечное применение обхода к трафику клиента появится с узлом-прокси-шлюзом (отдельная фаза).</div>
{banner}
<div class="card"><div class="route-title">Стратегии</div>
  <details class="setup-help"><summary>Формат стратегий и параметры</summary><div class="help" style="margin:4px 0 10px">Параметры — флаги <span class="mono">nfqws</span>, можно
  <b>вставить готовый конфиг zapret целиком</b>, в т.ч. мульти-секционный через
  <span class="mono">--new</span> (напр. <span class="mono">--filter-udp=443 --dpi-desync=fake
  --dpi-desync-fake-quic=/opt/zapret/bin/quic.bin --new --filter-tcp=80,443
  --dpi-desync=hostfakesplit …</span>). Пути к листам/бинам (<span class="mono">--hostlist=…</span>,
  <span class="mono">--ipset=…</span>) берутся как есть. Пусто = «direct» (без обхода).
  «Активная» — что применяется (авто-тест сам ставит лучшую, можно сменить).</div></details>
  <div id="zlist"></div>
  <button class="btn small" type="button" id="zadd">+ стратегия</button>
  <button class="btn small gray" type="button" id="zdirect">+ direct</button>
  <button class="btn small gray" type="button" id="zdefaults">+ набор по умолчанию</button>
  <button class="btn small gray" type="button" id="zcommunity">+ комьюнити</button>
  <button class="btn small primary" type="button" id="zsave">Сохранить стратегии</button>
</div>
<div class="card"><div class="route-title">Сервисы для теста</div>
  <div class="zsvcs" id="zsvcs"></div>
  <div style="margin-top:12px"><button class="btn primary" type="button" id="zrun">Запустить авто-тест</button></div>
</div>
<div class="zmodal" id="zmodal"><div class="zbox">
  <div class="zhd"><b>Авто-тест zapret</b><span id="zbest" class="muted"></span>
    <span class="spacer" style="flex:1"></span>
    <button class="btn small red" type="button" id="zstop">Стоп</button>
    <button class="btn small gray" type="button" id="zclose">Свернуть</button></div>
  <div class="zlog" id="zlog"></div>
  <div class="zgrid" id="zgrid"></div>
</div></div>
<div id="ztoast" style="position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#2c2c30;border:1px solid #444;padding:10px 16px;border-radius:9px;z-index:300;display:none;font-size:13px"></div>
<script>window.__ZAP__={js_embed(z_ui)};window.__ZCSRF__={js_embed(csrf)};</script>
<script>{ZAPRET_JS}</script>
</div><script>{SHELL_JS}</script></body></html>"""


ZAPRET_JS = r"""
(function(){
  var Z = window.__ZAP__ || {strategies:[],active_id:'',services:[],available:false,can_apply:false,node:''};
  var CSRF = window.__ZCSRF__ || '';
  var list=document.getElementById('zlist'), svcBox=document.getElementById('zsvcs');
  var modal=document.getElementById('zmodal'), logEl=document.getElementById('zlog');
  var gridEl=document.getElementById('zgrid'), bestEl=document.getElementById('zbest');
  function el(t,c,x){ var e=document.createElement(t); if(c)e.className=c; if(x!=null)e.textContent=x; return e; }
  function toast(m){ var t=document.getElementById('ztoast'); if(!t)return; t.textContent=m; t.style.display='block'; setTimeout(function(){t.style.display='none';},2500); }
  function genId(){ try{var a=new Uint8Array(6);crypto.getRandomValues(a);return Array.from(a,function(b){return b.toString(16).padStart(2,'0');}).join('');}catch(e){return 'id'+Math.floor(Math.random()*1e9).toString(16);} }

  function render(){
    list.textContent='';
    Z.strategies.forEach(function(s,i){
      var c=el('div','zcard'), row=el('div','row');
      var rad=el('input'); rad.type='radio'; rad.name='zactive'; rad.checked=(Z.active_id===s.id); rad.style.width='auto';
      rad.addEventListener('change',function(){ Z.active_id=s.id; });
      var lr=el('label','chk'); lr.appendChild(rad); lr.appendChild(el('span',null,'активная')); row.appendChild(lr);
      var sp=el('span'); sp.style.flex='1'; row.appendChild(sp);
      var del=el('button','btn small red','Удалить'); del.type='button';
      del.addEventListener('click',function(){ Z.strategies.splice(i,1); if(Z.active_id===s.id)Z.active_id=''; render(); });
      row.appendChild(del); c.appendChild(row);
      c.appendChild(el('label',null,'Название'));
      var li=el('input'); li.value=s.label||''; li.placeholder='split2 / fake / direct'; li.addEventListener('input',function(){ s.label=li.value; }); c.appendChild(li);
      c.appendChild(el('label',null,'Параметры nfqws (пусто = direct)'));
      var pi=el('textarea'); pi.className='mono'; pi.rows=4; pi.value=s.params||''; pi.placeholder='Вставь конфиг zapret целиком (секции через --new), напр.:\n--filter-udp=443 --dpi-desync=fake --dpi-desync-fake-quic=/opt/zapret/bin/quic.bin --new\n--filter-tcp=80,443 --dpi-desync=hostfakesplit --dpi-desync-fooling=ts'; pi.addEventListener('input',function(){ s.params=pi.value; }); c.appendChild(pi);
      list.appendChild(c);
    });
    if(!Z.strategies.length) list.appendChild(el('div','help','Стратегий нет. Жми «+ набор по умолчанию» или «+ direct».'));
  }
  document.getElementById('zadd').addEventListener('click',function(){ Z.strategies.push({id:genId(),label:'',params:''}); render(); });
  document.getElementById('zdirect').addEventListener('click',function(){ Z.strategies.push({id:genId(),label:'Прямой (без обхода)',params:''}); render(); });
  function addSet(arr,emptyMsg){
    var have={}; Z.strategies.forEach(function(s){ have[(s.params||'').trim()]=1; });
    var added=0;
    (arr||[]).forEach(function(d){ var p=(d.params||'').trim(); if(have[p])return; have[p]=1;
      Z.strategies.push({id:genId(),label:d.label||'',params:d.params||''}); added++; });
    if(!added && !(arr||[]).length) alert(emptyMsg);
    render();
  }
  document.getElementById('zdefaults').addEventListener('click',function(){ addSet(Z.defaults,'Набор по умолчанию пуст.'); });
  document.getElementById('zcommunity').addEventListener('click',function(){ addSet(Z.community,'Комьюнити-набор пуст.'); });

  Z.services.forEach(function(sv){
    var lab=el('label','zchk'); var cb=el('input'); cb.type='checkbox'; cb.checked=true; cb.dataset.k=sv.key; cb.style.width='auto';
    lab.appendChild(cb); lab.appendChild(el('span',null,sv.label)); svcBox.appendChild(lab);
  });
  function selectedServices(){ return Array.prototype.slice.call(svcBox.querySelectorAll('input:checked')).map(function(c){return c.dataset.k;}); }

  function post(url,body){ return fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(body||{})}).then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});}); }
  document.getElementById('zsave').addEventListener('click',function(){
    post('/zapret/save',{strategies:Z.strategies,active_id:Z.active_id})
      .then(function(r){ toast(r.j&&r.j.ok?'Сохранено ✓':('Ошибка: '+((r.j&&r.j.error)||''))); })
      .catch(function(){ toast('Сервер недоступен'); });
  });

  var poll=null, cursor=0;
  function closeModal(){ modal.classList.remove('show'); if(poll){clearInterval(poll);poll=null;} }
  document.getElementById('zclose').addEventListener('click',closeModal);
  document.getElementById('zstop').addEventListener('click',function(){ post('/zapret/test/stop',{}); });
  function appendLogs(rows){ rows.forEach(function(r){ logEl.appendChild(document.createTextNode((r.msg||'')+'\n')); }); logEl.scrollTop=logEl.scrollHeight; }
  function renderResults(st){
    if(!st.results){ return; }
    var res=st.results, best=st.best_id;
    bestEl.textContent = (best && res[best]) ? ('лучшая: '+res[best].label+' — '+res[best].up_count) : '';
    var shown = (best && res[best]) ? res[best].services : (Object.keys(res).length?res[Object.keys(res)[0]].services:{});
    gridEl.textContent='';
    Object.keys(shown||{}).forEach(function(k){
      var v=shown[k]||{}; var d=el('div','zsvc');
      d.appendChild(el('span','zdot'+(v.up?' up':' down')));
      d.appendChild(el('span',null,k)); gridEl.appendChild(d);
    });
  }
  function tick(){
    fetch('/zapret/test/status?cursor='+cursor).then(function(r){return r.json();}).then(function(st){
      if(st.logs&&st.logs.length){ appendLogs(st.logs); cursor=st.cursor; }
      renderResults(st);
      if(st.state!=='running'){ if(poll){clearInterval(poll);poll=null;} document.getElementById('zstop').disabled=true; }
    }).catch(function(){});
  }
  document.getElementById('zrun').addEventListener('click',function(){
    logEl.textContent=''; gridEl.textContent=''; bestEl.textContent=''; cursor=0;
    document.getElementById('zstop').disabled=false; modal.classList.add('show');
    post('/zapret/test/start',{strategy_ids:Z.strategies.map(function(s){return s.id;}),service_keys:selectedServices()})
      .then(function(r){
        if(!r.j||!r.j.ok){ appendLogs([{msg:'Не запущено: '+((r.j&&r.j.error)||'ошибка')}]); document.getElementById('zstop').disabled=true; return; }
        if(poll)clearInterval(poll); poll=setInterval(tick,1000); tick();
      }).catch(function(){ appendLogs([{msg:'Сервер недоступен'}]); });
  });

  render();
})();
"""
