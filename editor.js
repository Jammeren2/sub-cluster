(function(){
  const G = window.__GRAPH__ || {sources:[],routes:[],edges:[]};
  const ADMIN = (typeof window.__ADMIN__ === 'string') ? window.__ADMIN__ : '/admin';
  const CSRF = window.__CSRF__ || '';
  const BASE = window.__BASE__ || '';
  const DOMAINS = Array.isArray(window.__DOMAINS__) ? window.__DOMAINS__ : [];
  G.sources = G.sources || []; G.routes = G.routes || []; G.edges = G.edges || []; G.node_meta = G.node_meta || {};

  function domainById(id){ return DOMAINS.find(d=>d.id===id); }
  function defaultDomain(){ return DOMAINS.find(d=>d.default && d.enabled) || DOMAINS.find(d=>d.enabled) || DOMAINS[0] || null; }
  function effDomain(r){ const d=domainById(r.domain_id); return (d && d.enabled) ? d : defaultDomain(); }
  function baseFor(r){ const d=effDomain(r); return d ? (d.base || ('https://'+(d.fqdn||''))) : (BASE||''); }

  const NODE_W = 240, SOCK_Y = 28;
  const editor = document.getElementById('editor');
  const world = document.getElementById('world');
  const svg = document.getElementById('wires');
  const toast = document.getElementById('toast');
  const hint = document.getElementById('hint');
  const stat = document.getElementById('savestat');
  const nodeEls = {};
  let view = {panX:60, panY:60, zoom:1};
  let connecting = null, tempPath = null, hoverIn = null;
  let autosave = true, saveTimer = null, saving = false, pendingSave = false, pendingSilent = true;

  function genId(){ try{ const a=new Uint8Array(8); crypto.getRandomValues(a); return Array.from(a,b=>b.toString(16).padStart(2,'0')).join(''); }catch(e){ let s=''; for(let i=0;i<16;i++) s+=Math.floor(Math.random()*16).toString(16); return s; } }
  function num(v,d){ v=parseFloat(v); return isFinite(v)?v:d; }
  function rect(){ return editor.getBoundingClientRect(); }
  function el(tag,cls,txt){ const e=document.createElement(tag); if(cls)e.className=cls; if(txt!=null)e.textContent=txt; return e; }
  function normPath(p){ p=(p||'').trim().replace(/^\/+|\/+$/g,''); return p?('/'+p):'/'; }
  function findAny(id){ return G.sources.find(x=>x.id===id) || G.routes.find(x=>x.id===id); }
  function isRoute(n){ return G.routes.indexOf(n)>=0; }
  function isGroup(n){ return !!(n && n.type==='group'); }
  function isAuto(n){ return !!(n && n.type==='autoselect'); }
  function isRouter(n){ return !!(n && n.type==='router'); }
  function isBalProc(n){ return isGroup(n) || isAuto(n); }
  function isProc(n){ return isGroup(n) || isAuto(n) || isRouter(n); }
  function isDirectLink(u){ return /^(vless|vmess|trojan|ss|ssr|hysteria2?|hy2|tuic):\/\//i.test((u||'').trim()); }
  const BAL_DEFAULTS = window.__BAL_DEFAULTS__ || {strategy:'leastPing',probe_url:'http://www.gstatic.com/generate_204',interval:'5m',timeout:'3s',sampling:2,domain_strategy:'AsIs'};
  const PRESETS = window.__PRESETS__ || {};
  const _DEF_PORTS = {vless:443,trojan:443,tuic:443,hysteria2:443,hy2:443,hysteria:443};
  function linkAddr(url){ try{ const u=new URL((url||'').trim()); const host=(u.hostname||'').toLowerCase(); if(!host) return ''; let port=u.port; if(!port){ port=_DEF_PORTS[(u.protocol||'').replace(':','').toLowerCase()]||''; } return port?(host+':'+port):host; }catch(e){ return ''; } }

  // Гидрация ключей/групп/переименований из node_meta (роль ноды выводим из данных, не только из type)
  G.sources.forEach(s=>{
    const meta = G.node_meta[s.id] || {};
    if(meta.router || s.type==='router'){
      s.type='router';
      s.rules = ((meta.router&&meta.router.rules)||[]).map(r=>({
        match:{kind:(r.match&&r.match.kind)||'preset', value:(r.match&&r.match.value)||''}, target:r.target||'direct'}));
      s.default_target = (meta.router&&meta.router.default_target) || 'direct';
      s.gparams = Object.assign({}, (meta.router&&meta.router.params)||{});
      s.rules = s.rules||[]; s.gparams = s.gparams||{};
      return;  // роутер не гидрируется как ключ/группа
    }
    if(meta.autoselect || s.type==='autoselect'){
      s.type='autoselect';
      s.gparams = Object.assign({}, (meta.autoselect&&meta.autoselect.params)||{});
      s.gparams = s.gparams||{};
      return;  // авто-выбор не гидрируется как ключ/источник
    }
    if(meta.group || s.type==='group'){
      s.type='group';
      s.buckets = ((meta.group&&meta.group.buckets)||[]).map(b=>({name:b.name||'',
          members:(b.members||[]).map(m=>m.link?{link:m.link}:{addr:m.addr||'',name:m.name||''})}));
      s.gparams = Object.assign({}, (meta.group&&meta.group.params)||{});
      s.buckets = s.buckets||[]; s.gparams = s.gparams||{};
      return;  // группа не гидрируется как ключ/источник
    }
    if(Array.isArray(meta.keys)){ s.type='key'; s.keys = meta.keys.map(k=>({link:k.link||'', name:k.name||''})); }
    else if(s.type==='key'){ s.keys = s.keys||[]; }
    else if(isDirectLink(s.url)){ s.type='key'; s.keys=[{link:s.url, name:s.label||''}]; s.url=''; }  // легаси прямой ключ
    if(Array.isArray(meta.renames)) s.renames = meta.renames.map(r=>({addr:r.addr||'', name:r.name||'', to:r.to||''}));
    s.keys = s.keys||[]; s.renames = s.renames||[];
  });

  // auto-position nodes missing coords
  let sy=60; G.sources.forEach(s=>{ s.x=num(s.x,80); if(!isFinite(parseFloat(s.y))){ s.y=sy; sy+=130; } else { s.y=num(s.y,sy); } });
  let ry=60; G.routes.forEach(r=>{ r.x=num(r.x,520); if(!isFinite(parseFloat(r.y))){ r.y=ry; ry+=200; } else { r.y=num(r.y,ry); } });

  function applyTransform(){ world.style.transform='translate('+view.panX+'px,'+view.panY+'px) scale('+view.zoom+')'; }
  function w2s(p){ return {x:p.x*view.zoom+view.panX, y:p.y*view.zoom+view.panY}; }
  function sockPos(n,kind){ return kind==='out' ? {x:n.x+NODE_W, y:n.y+SOCK_Y} : {x:n.x, y:n.y+SOCK_Y}; }
  function curve(a,b){ const dx=Math.max(40,Math.abs(b.x-a.x)*0.5); return 'M '+a.x+' '+a.y+' C '+(a.x+dx)+' '+a.y+' '+(b.x-dx)+' '+b.y+' '+b.x+' '+b.y; }

  function redrawWires(){
    while(svg.firstChild) svg.removeChild(svg.firstChild);
    G.edges.forEach(e=>{
      const s=findAny(e.from), r=findAny(e.to);   // цель — маршрут ИЛИ группа
      if(!s||!r) return;
      const a=w2s(sockPos(s,'out')), b=w2s(sockPos(r,'in'));
      const p=document.createElementNS('http://www.w3.org/2000/svg','path');
      p.setAttribute('d',curve(a,b)); p.setAttribute('class', isRoute(s)?'wire rwire':'wire');
      p.addEventListener('click',ev=>{ ev.stopPropagation(); const i=G.edges.indexOf(e); if(i>=0)G.edges.splice(i,1); redrawWires(); refreshCounts(); markDirty(); refreshRouterTargets(); });
      svg.appendChild(p);
    });
    if(connecting && tempPath) svg.appendChild(tempPath);
    hint.style.display=(G.sources.length||G.routes.length)?'none':'block';
  }

  function refreshCounts(){
    document.querySelectorAll('.cnt').forEach(c=>{ const rid=c.dataset.rid; c.textContent='входов подключено: '+G.edges.filter(e=>e.to===rid).length; });
  }

  // ── размытие ссылок/путей ──
  function mask(input){ input.classList.add('blur'); }
  function maskSpan(span){
    span.classList.add('blur');
    span.addEventListener('click',ev=>{ if(document.body.classList.contains('unblur'))return; ev.stopPropagation(); span.classList.toggle('show'); });
  }

  // ── автосейв ──
  function setStat(text,cls){ if(stat){ stat.textContent=text; stat.className=cls||''; } }
  function markDirty(){
    setStat('● не сохранено','dirty');
    if(autosave){ clearTimeout(saveTimer); saveTimer=setTimeout(()=>save(true), 900); }
  }

  function dragHeader(handle,node,nEl){
    handle.addEventListener('mousedown',ev=>{
      if(ev.target.classList.contains('x')) return;
      ev.stopPropagation(); ev.preventDefault();
      let lx=ev.clientX, ly=ev.clientY, moved=false; nEl.classList.add('sel');
      function mm(e){ moved=true; node.x+=(e.clientX-lx)/view.zoom; node.y+=(e.clientY-ly)/view.zoom; lx=e.clientX; ly=e.clientY; nEl.style.left=node.x+'px'; nEl.style.top=node.y+'px'; redrawWires(); }
      function mu(){ document.removeEventListener('mousemove',mm); document.removeEventListener('mouseup',mu); nEl.classList.remove('sel'); if(moved)markDirty(); }
      document.addEventListener('mousemove',mm); document.addEventListener('mouseup',mu);
    });
  }

  function deleteBtn(x,node){
    x.addEventListener('mousedown',e=>e.stopPropagation());
    x.addEventListener('click',e=>{
      e.stopPropagation();
      const arr=isRoute(node)?G.routes:G.sources; const i=arr.indexOf(node); if(i>=0)arr.splice(i,1);
      G.edges=G.edges.filter(ed=>ed.from!==node.id && ed.to!==node.id);
      const dom=nodeEls[node.id]; if(dom)dom.remove(); delete nodeEls[node.id];
      redrawWires(); refreshCounts(); markDirty(); refreshRouterTargets();
    });
  }

  function startConnect(ev,src){
    ev.stopPropagation(); ev.preventDefault();
    connecting={from:src.id};
    tempPath=document.createElementNS('http://www.w3.org/2000/svg','path'); tempPath.setAttribute('class','temp');
    function mm(e){ const r=rect(); const a=w2s(sockPos(src,'out')); tempPath.setAttribute('d',curve(a,{x:e.clientX-r.left,y:e.clientY-r.top})); redrawWires(); }
    function mu(){ document.removeEventListener('mousemove',mm); document.removeEventListener('mouseup',mu); finishConnect(hoverIn); }
    document.addEventListener('mousemove',mm); document.addEventListener('mouseup',mu);
  }
  function wouldCycle(fr,to){
    // зеркалит серверную проверку: ребро маршрут→маршрут не должно замыкать цикл
    const radj={};
    G.edges.forEach(e=>{ if(G.routes.some(r=>r.id===e.from) && G.routes.some(r=>r.id===e.to)) (radj[e.to]||(radj[e.to]=[])).push(e.from); });
    const stack=[fr], seen=new Set();
    while(stack.length){ const n=stack.pop(); if(n===to) return true; if(seen.has(n)) continue; seen.add(n); (radj[n]||[]).forEach(x=>stack.push(x)); }
    return false;
  }
  function finishConnect(target){
    if(!connecting) return;  // второй (всплывший) mouseup — ничего не делаем
    if(target){
      const f=connecting.from, t=target.id, fromNode=findAny(f);
      if(f!==t && !G.edges.some(e=>e.from===f && e.to===t)){
        if(isRouter(target)){
          // в роутер — из источника/ключа/группы/авто (не router/route)
          if(isRouter(fromNode) || isRoute(fromNode)) showToast('В роутер — из источника/ключа/группы/авто',true);
          else { G.edges.push({from:f,to:t}); markDirty(); }
        } else if(isBalProc(target)){
          // в группу/авто — только из источника/ключа
          if(isProc(fromNode) || isRoute(fromNode)) showToast('В группу/авто — только из источника/ключа',true);
          else { G.edges.push({from:f,to:t}); markDirty(); }
        } else if(isRoute(fromNode) && wouldCycle(f,t)){ showToast('Нельзя замкнуть цикл маршрутов',true); }
        else { G.edges.push({from:f,to:t}); markDirty(); }
      }
    }
    connecting=null; tempPath=null; hoverIn=null; redrawWires(); refreshCounts(); refreshRouterTargets();
  }

  function outSocket(node){ const out=el('div','sock out'); out.title='Тяни в маршрут/группу'; out.addEventListener('mousedown',ev=>startConnect(ev,node)); return out; }
  function inSocket(target){
    const inp=el('div','sock in'); inp.title='Вход';
    inp.addEventListener('mouseenter',()=>hoverIn=target); inp.addEventListener('mouseleave',()=>{ if(hoverIn===target)hoverIn=null; });
    inp.addEventListener('mouseup',()=>finishConnect(target));
    return inp;
  }

  function makeSource(s){
    s.type = s.type || 'source';
    const n=el('div','node src'); n.style.left=s.x+'px'; n.style.top=s.y+'px';
    const hd=el('div','hd'); hd.appendChild(el('span',null,'Источник')); const x=el('span','x','✕'); hd.appendChild(x); n.appendChild(hd);
    const bd=el('div','bd');
    bd.appendChild(el('label',null,'Метка'));
    const lab=el('input'); lab.value=s.label||''; lab.placeholder='необязательно'; lab.addEventListener('input',()=>{ s.label=lab.value; markDirty(); }); bd.appendChild(lab);
    bd.appendChild(el('label',null,'Ссылка-подписка (upstream)'));
    const url=el('input','mono'); url.value=s.url||''; url.placeholder='https://сервер/sub/xxxx'; mask(url); url.addEventListener('input',()=>{ s.url=url.value; markDirty(); }); bd.appendChild(url);
    // переименование отдельных ссылок внутри подписки
    const det=el('details'); det.appendChild(el('summary',null,'Переименовать ссылки'));
    const box=el('div','linkbox');
    const btn=el('button','loadlinks', (s.renames&&s.renames.length)?'Обновить ссылки':'Загрузить ссылки'); btn.type='button';
    btn.addEventListener('mousedown',e=>e.stopPropagation());
    btn.addEventListener('click',e=>{ e.stopPropagation(); loadLinks(s,box,btn); });
    det.appendChild(btn); det.appendChild(box); bd.appendChild(det);
    n.appendChild(bd);
    dragHeader(hd,s,n); deleteBtn(x,s); n.appendChild(outSocket(s));
    nodeEls[s.id]=n; world.appendChild(n);
  }

  function makeKey(s){
    s.type='key'; s.keys=s.keys||[]; if(!s.keys.length) s.keys.push({link:'',name:''});
    const n=el('div','node key'); n.style.left=s.x+'px'; n.style.top=s.y+'px';
    const hd=el('div','hd'); hd.appendChild(el('span',null,'Ключи')); const x=el('span','x','✕'); hd.appendChild(x); n.appendChild(hd);
    const bd=el('div','bd');
    bd.appendChild(el('label',null,'Прямые ссылки (vless://… и т.п.) и их имена'));
    const list=el('div','keylist'); bd.appendChild(list);
    function addRow(k){
      const row=el('div','keyrow');
      const link=el('input','mono'); link.value=k.link||''; link.placeholder='vless://…'; mask(link);
      link.addEventListener('input',()=>{ k.link=link.value; markDirty(); });
      const r2=el('div','krow2');
      const nm=el('input','kname'); nm.value=k.name||''; nm.placeholder='имя (необязательно)';
      nm.addEventListener('input',()=>{ k.name=nm.value; markDirty(); });
      const rm=el('span','krm','✕'); rm.title='Удалить ключ';
      rm.addEventListener('mousedown',e=>e.stopPropagation());
      rm.addEventListener('click',e=>{ e.stopPropagation(); const i=s.keys.indexOf(k); if(i>=0)s.keys.splice(i,1); row.remove();
        if(!s.keys.length){ const nk={link:'',name:''}; s.keys.push(nk); addRow(nk); } markDirty(); });
      r2.appendChild(nm); r2.appendChild(rm); row.appendChild(link); row.appendChild(r2); list.appendChild(row);
    }
    s.keys.forEach(addRow);
    const add=el('button','addkey','+ ключ'); add.type='button'; add.addEventListener('mousedown',e=>e.stopPropagation());
    add.addEventListener('click',e=>{ e.stopPropagation(); const k={link:'',name:''}; s.keys.push(k); addRow(k); markDirty(); });
    bd.appendChild(add);
    n.appendChild(bd);
    dragHeader(hd,s,n); deleteBtn(x,s); n.appendChild(outSocket(s));
    nodeEls[s.id]=n; world.appendChild(n);
  }

  // ── балансер: общий блок параметров (группа и авто-выбор) ──
  function balancerParamsDetails(s){
    s.gparams=s.gparams||{};
    const pdet=el('details'); pdet.appendChild(el('summary',null,'Параметры балансера'));
    const pbox=el('div','bparams');
    function pfield(label,key,ph){ const w=el('div'); w.appendChild(el('label',null,label));
      const inp=el('input'); inp.value=(s.gparams[key]!=null?s.gparams[key]:(BAL_DEFAULTS[key]!=null?BAL_DEFAULTS[key]:'')); inp.placeholder=ph||'';
      inp.addEventListener('input',()=>{ s.gparams[key]=inp.value; markDirty(); }); w.appendChild(inp); return w; }
    function psel(label,key,opts){ const w=el('div'); w.appendChild(el('label',null,label)); const sel=el('select');
      opts.forEach(o=>{ const op=el('option',null,o); op.value=o; if((s.gparams[key]||BAL_DEFAULTS[key])===o)op.selected=true; sel.appendChild(op); });
      sel.addEventListener('change',()=>{ s.gparams[key]=sel.value; markDirty(); }); w.appendChild(sel); return w; }
    pbox.appendChild(psel('Стратегия','strategy',['leastPing','leastLoad','random','roundRobin']));
    pbox.appendChild(pfield('Probe URL','probe_url','http://www.gstatic.com/generate_204'));
    const grow=el('div','grow2'); grow.appendChild(pfield('Интервал','interval','5m')); grow.appendChild(pfield('Таймаут','timeout','3s')); pbox.appendChild(grow);
    const grow2=el('div','grow2'); grow2.appendChild(pfield('Sampling','sampling','2')); grow2.appendChild(psel('domainStrategy','domain_strategy',['AsIs','IPIfNonMatch','IPOnDemand'])); pbox.appendChild(grow2);
    pdet.appendChild(pbox); return pdet;
  }

  // ── нода-группа (страна → балансер) ──
  function memberMatchesRow(m,row){ return m.link ? (m.link===row.link) : (m.addr===row.addr && m.name===row.name); }
  function rowToMember(row){ return row.key ? {link:row.link} : {addr:row.addr, name:row.name}; }
  function findRowBucket(s,row){ for(let i=0;i<s.buckets.length;i++){ if((s.buckets[i].members||[]).some(m=>memberMatchesRow(m,row))) return i; } return -1; }
  function assignRow(s,row,bi){
    s.buckets.forEach(b=>{ b.members=(b.members||[]).filter(m=>!memberMatchesRow(m,row)); });
    if(bi>=0 && bi<s.buckets.length){ s.buckets[bi].members=s.buckets[bi].members||[]; s.buckets[bi].members.push(rowToMember(row)); }
  }
  function incomingNodes(g){ const froms=G.edges.filter(e=>e.to===g.id).map(e=>e.from); return G.sources.filter(x=>froms.indexOf(x.id)>=0); }
  function dedupRows(rows){ const out=[],seen=new Set(); rows.forEach(r=>{ const k=r.key?('L:'+r.link):('A:'+r.addr+'|'+r.name); if(!seen.has(k)){ seen.add(k); out.push(r); } }); return out; }
  function loadGroupLinks(g, btn, cb){
    const ins=incomingNodes(g);
    const keyRows=[];
    ins.filter(x=>x.type==='key').forEach(x=>(x.keys||[]).forEach(k=>{ if((k.link||'').trim()) keyRows.push({name:k.name||'', addr:linkAddr(k.link), link:k.link.trim(), key:true}); }));
    const subNodes=ins.filter(x=>x.type!=='key' && x.type!=='group' && (x.url||'').trim());
    if(btn){ btn.disabled=true; btn.textContent='Загрузка…'; }
    Promise.all(subNodes.map(x=>fetch(ADMIN+'/graph/preview',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify({url:x.url})})
        .then(r=>r.json()).then(j=>(j&&j.ok)?(j.links||[]):[]).catch(()=>[])))
      .then(per=>{ const subRows=[].concat.apply([],per).map(l=>({name:l.name||'', addr:l.addr||'', link:l.link||'', key:false}));
        if(btn){ btn.disabled=false; btn.textContent='Обновить ссылки группы'; }
        cb(dedupRows(keyRows.concat(subRows))); })
      .catch(()=>{ if(btn){ btn.disabled=false; btn.textContent='Обновить ссылки группы'; } showToast('Не удалось загрузить ссылки',true); });
  }
  function renderGroupRows(s, box, rows, renderBuckets){
    box.textContent='';
    if(!rows.length){ box.appendChild(el('div','muted2','Нет входящих ссылок. Подключи источники/ключи в группу и нажми «Загрузить».')); return; }
    rows.forEach(row=>{
      const r=el('div','glrow');
      const nm=el('div','gln'); nm.textContent=(row.name||'(без имени)')+(row.addr?(' · '+row.addr):''); nm.title=row.link||''; r.appendChild(nm);
      const sel=el('select'); const o0=el('option',null,'(не в группе)'); o0.value='-1'; sel.appendChild(o0);
      s.buckets.forEach((b,bi)=>{ const o=el('option',null,(b.name||('Корзина '+(bi+1)))); o.value=String(bi); sel.appendChild(o); });
      sel.value=String(findRowBucket(s,row));
      sel.addEventListener('change',()=>{ assignRow(s,row,parseInt(sel.value,10)); renderBuckets(); markDirty(); });
      r.appendChild(sel); box.appendChild(r);
    });
  }
  function bucketEl(s,b,renderBuckets){
    const wrap=el('div','bucket');
    const hdb=el('div','bhd');
    const nm=el('input','bname'); nm.value=b.name||''; nm.placeholder='🇩🇪 Германия';
    nm.addEventListener('input',()=>{ b.name=nm.value; markDirty(); });
    const rm=el('span','brm','✕'); rm.title='Удалить корзину'; rm.addEventListener('mousedown',e=>e.stopPropagation());
    rm.addEventListener('click',e=>{ e.stopPropagation(); const i=s.buckets.indexOf(b); if(i>=0)s.buckets.splice(i,1); renderBuckets(); markDirty(); });
    hdb.appendChild(nm); hdb.appendChild(rm); wrap.appendChild(hdb);
    const chips=el('div','bchips');
    (b.members||[]).forEach(m=>{
      const chip=el('div','memchip'); chip.appendChild(el('span',null, m.link?m.link:(m.name||m.addr||'?')));
      const cx=el('span','cx','✕'); cx.addEventListener('mousedown',e=>e.stopPropagation());
      cx.addEventListener('click',e=>{ e.stopPropagation(); const i=b.members.indexOf(m); if(i>=0)b.members.splice(i,1); renderBuckets(); markDirty(); });
      chip.appendChild(cx); chips.appendChild(chip);
    });
    if(!(b.members||[]).length) chips.appendChild(el('div','muted2','выбери ссылки ниже'));
    wrap.appendChild(chips);
    return wrap;
  }

  function makeGroup(s){
    s.type='group'; s.buckets=s.buckets||[]; s.gparams=s.gparams||{};
    const n=el('div','node group'); n.style.left=s.x+'px'; n.style.top=s.y+'px';
    const hd=el('div','hd'); hd.appendChild(el('span',null,'Группа')); const x=el('span','x','✕'); hd.appendChild(x); n.appendChild(hd);
    const bd=el('div','bd');
    bd.appendChild(el('label',null,'Метка / флаг группы (видна в клиенте)'));
    const lab=el('input'); lab.value=s.label||''; lab.placeholder='🇩🇪 Германия'; lab.addEventListener('input',()=>{ s.label=lab.value; markDirty(); }); bd.appendChild(lab);

    bd.appendChild(balancerParamsDetails(s));   // параметры балансера

    // корзины + распределение входящих ссылок
    let glRows = null;
    bd.appendChild(el('label',null,'Корзины (страны)'));
    const blist=el('div'); bd.appendChild(blist);
    function refreshGL(){ if(glRows!==null) renderGroupRows(s, glbox, glRows, renderBuckets); }
    function renderBuckets(){ blist.textContent=''; s.buckets.forEach(b=>blist.appendChild(bucketEl(s,b,renderBuckets))); refreshGL(); }
    const addB=el('button','addkey','+ корзина'); addB.type='button'; addB.addEventListener('mousedown',e=>e.stopPropagation());
    addB.addEventListener('click',e=>{ e.stopPropagation(); s.buckets.push({name:'',members:[]}); renderBuckets(); markDirty(); }); bd.appendChild(addB);

    const det=el('details'); det.appendChild(el('summary',null,'Распределить входящие ссылки'));
    const lbtn=el('button','loadlinks', (s.buckets.some(b=>(b.members||[]).length)?'Обновить ссылки группы':'Загрузить ссылки группы')); lbtn.type='button';
    lbtn.addEventListener('mousedown',e=>e.stopPropagation());
    lbtn.addEventListener('click',e=>{ e.stopPropagation(); loadGroupLinks(s, lbtn, rows=>{ glRows=rows; refreshGL(); }); });
    const glbox=el('div','grouplinks');
    det.appendChild(lbtn); det.appendChild(glbox); bd.appendChild(det);

    const cnt=el('div','cnt'); cnt.dataset.rid=s.id; bd.appendChild(cnt);
    n.appendChild(bd);
    dragHeader(hd,s,n); deleteBtn(x,s);
    n.appendChild(inSocket(s)); n.appendChild(outSocket(s));
    nodeEls[s.id]=n; world.appendChild(n);
    renderBuckets();
  }

  // ── нода авто-выбора (все входы → один балансер leastPing, roadmap/03A) ──
  function makeAuto(s){
    s.type='autoselect'; s.gparams=s.gparams||{};
    const n=el('div','node autoselect'); n.style.left=s.x+'px'; n.style.top=s.y+'px';
    const hd=el('div','hd'); hd.appendChild(el('span',null,'Авто-выбор')); const x=el('span','x','✕'); hd.appendChild(x); n.appendChild(hd);
    const bd=el('div','bd');
    bd.appendChild(el('label',null,'Метка / имя записи (видна в клиенте)'));
    const lab=el('input'); lab.value=s.label||''; lab.placeholder='⚡ Авто (быстрейший)'; lab.addEventListener('input',()=>{ s.label=lab.value; markDirty(); }); bd.appendChild(lab);
    const info=el('div','muted2'); info.textContent='Все входящие ключи/ссылки → одна запись с балансером по пингу (клиент сам выберет быстрейший).'; bd.appendChild(info);
    bd.appendChild(balancerParamsDetails(s));
    const cnt=el('div','cnt'); cnt.dataset.rid=s.id; bd.appendChild(cnt);
    n.appendChild(bd);
    dragHeader(hd,s,n); deleteBtn(x,s);
    n.appendChild(inSocket(s)); n.appendChild(outSocket(s));
    nodeEls[s.id]=n; world.appendChild(n);
  }

  // ── нода-роутер (#05): правила geosite/geoip → таргеты ──
  function refreshRouterTargets(){ G.sources.forEach(s=>{ if(isRouter(s) && s._refreshTargets) s._refreshTargets(); }); }
  function routerTargets(s){
    const froms=G.edges.filter(e=>e.to===s.id).map(e=>e.from);
    const ins=G.sources.filter(x=>froms.indexOf(x.id)>=0 && !isRouter(x));
    const opts=[{value:'direct', label:'direct (напрямую)'}];
    ins.forEach(x=>{ const kind=isGroup(x)?'группа':isAuto(x)?'авто':(x.type==='key'?'ключи':'источник');
      opts.push({value:x.id, label:((x.label||'').trim()||x.id.slice(0,6))+' ['+kind+']'}); });
    return opts;
  }
  function targetSelect(s,getv,setv){
    const sel=el('select'), opts=routerTargets(s), cur=getv();
    let has=false;
    opts.forEach(o=>{ const op=el('option',null,o.label); op.value=o.value; if(o.value===cur){op.selected=true;has=true;} sel.appendChild(op); });
    if(!has && cur && cur!=='direct'){ const op=el('option',null,'(отключённый вход '+cur.slice(0,6)+')'); op.value=cur; op.selected=true; sel.appendChild(op); }
    sel.addEventListener('change',()=>{ setv(sel.value); markDirty(); });
    return sel;
  }
  function makeRouter(s){
    s.type='router'; s.rules=s.rules||[]; s.gparams=s.gparams||{}; s.default_target=s.default_target||'direct';
    const n=el('div','node router'); n.style.left=s.x+'px'; n.style.top=s.y+'px';
    const hd=el('div','hd'); hd.appendChild(el('span',null,'Роутер')); const x=el('span','x','✕'); hd.appendChild(x); n.appendChild(hd);
    const bd=el('div','bd');
    bd.appendChild(el('label',null,'Метка / имя записи (видна в клиенте)'));
    const lab=el('input'); lab.value=s.label||''; lab.placeholder='Роутер'; lab.addEventListener('input',()=>{ s.label=lab.value; markDirty(); }); bd.appendChild(lab);
    const info=el('div','muted2'); info.textContent='Правила geosite/geoip → таргеты (вход-ссылка/группа/авто/direct). Порядок = первое совпадение; «остальное» → default. В клиенте одна запись с per-app routing.'; bd.appendChild(info);
    bd.appendChild(balancerParamsDetails(s));
    bd.appendChild(el('label',null,'Правила (matcher → таргет)'));
    const rlist=el('div','rrules'); bd.appendChild(rlist);
    function renderRules(){
      rlist.textContent='';
      s.rules.forEach((r,i)=>{
        r.match=r.match||{kind:'preset',value:''};
        const row=el('div','rrow');
        const ks=el('select'); [['preset','пресет'],['domain','домен'],['ip','IP']].forEach(k=>{ const o=el('option',null,k[1]); o.value=k[0]; if(r.match.kind===k[0])o.selected=true; ks.appendChild(o); });
        const valWrap=el('div','rval');
        function renderVal(){
          valWrap.textContent='';
          if(r.match.kind==='preset'){
            const ps=el('select'); Object.keys(PRESETS).forEach(pk=>{ const o=el('option',null,(PRESETS[pk].label||pk)); o.value=pk; if(r.match.value===pk)o.selected=true; ps.appendChild(o); });
            if(!r.match.value && Object.keys(PRESETS).length){ r.match.value=ps.value; }
            ps.addEventListener('change',()=>{ r.match.value=ps.value; markDirty(); }); valWrap.appendChild(ps);
          } else {
            const ti=el('input'); ti.value=r.match.value||''; ti.placeholder=(r.match.kind==='ip'?'8.8.8.8/32 или geoip:ru':'example.com или geosite:google');
            ti.addEventListener('input',()=>{ r.match.value=ti.value; markDirty(); }); valWrap.appendChild(ti);
          }
        }
        ks.addEventListener('change',()=>{ r.match.kind=ks.value; r.match.value=''; renderVal(); markDirty(); });
        const ts=targetSelect(s, ()=>r.target, v=>{ r.target=v; });
        const rm=el('span','rrm','✕'); rm.addEventListener('mousedown',e=>e.stopPropagation());
        rm.addEventListener('click',()=>{ s.rules.splice(i,1); renderRules(); markDirty(); });
        row.appendChild(ks); row.appendChild(valWrap); row.appendChild(el('span','rarrow','→')); row.appendChild(ts); row.appendChild(rm);
        rlist.appendChild(row); renderVal();
      });
      if(!s.rules.length) rlist.appendChild(el('div','muted2','Правил нет. Жми пресет ниже или «+ правило».'));
    }
    const quick=el('div','rquick');
    Object.keys(PRESETS).forEach(pk=>{ const b=el('button','rqbtn',PRESETS[pk].label||pk); b.type='button';
      b.addEventListener('mousedown',e=>e.stopPropagation());
      b.addEventListener('click',e=>{ e.stopPropagation(); s.rules.push({match:{kind:'preset',value:pk},target:'direct'}); renderRules(); markDirty(); }); quick.appendChild(b); });
    bd.appendChild(quick);
    const addR=el('button','addkey','+ правило'); addR.type='button'; addR.addEventListener('mousedown',e=>e.stopPropagation());
    addR.addEventListener('click',e=>{ e.stopPropagation(); s.rules.push({match:{kind:'preset',value:Object.keys(PRESETS)[0]||''},target:'direct'}); renderRules(); markDirty(); });
    bd.appendChild(addR);
    bd.appendChild(el('label',null,'Остальное (по умолчанию) →'));
    const defWrap=el('div'); bd.appendChild(defWrap);
    function renderDefault(){ defWrap.textContent=''; defWrap.appendChild(targetSelect(s, ()=>s.default_target, v=>{ s.default_target=v; })); }
    const cnt=el('div','cnt'); cnt.dataset.rid=s.id; bd.appendChild(cnt);
    n.appendChild(bd);
    dragHeader(hd,s,n); deleteBtn(x,s);
    n.appendChild(inSocket(s)); n.appendChild(outSocket(s));
    nodeEls[s.id]=n; world.appendChild(n);
    s._refreshTargets=()=>{ renderRules(); renderDefault(); };
    renderRules(); renderDefault();
  }

  // ── переименование ссылок внутри подписки ──
  function getRename(s,addr,name){ const r=(s.renames||[]).find(r=>r.addr===addr && r.name===name); return r?r.to:''; }
  function setRename(s,addr,name,to){
    s.renames=s.renames||[]; to=(to||'').trim();
    const i=s.renames.findIndex(r=>r.addr===addr && r.name===name);
    if(!to){ if(i>=0)s.renames.splice(i,1); }
    else if(i>=0){ s.renames[i].to=to; }
    else { s.renames.push({addr:addr,name:name,to:to}); }
  }
  function renderRenameRows(s,box,links){
    box.textContent='';
    if(!links.length){ box.appendChild(el('div','muted2','Ссылок не найдено')); return; }
    links.forEach(l=>{
      const addr=l.addr||'', name=l.name||'';
      const row=el('div','renrow');
      const orig=el('div','origname'); orig.textContent=(name||'(без имени)')+(addr?(' · '+addr):''); orig.title=l.link||'';
      const inp=el('input','rni'); inp.placeholder='новое имя'; inp.value=getRename(s,addr,name);
      inp.addEventListener('input',()=>{ setRename(s,addr,name,inp.value); markDirty(); });
      row.appendChild(orig); row.appendChild(inp); box.appendChild(row);
    });
  }
  function loadLinks(s,box,btn){
    if(!(s.url||'').trim()){ showToast('Сначала укажи ссылку-подписку',true); return; }
    btn.disabled=true; const prev=btn.textContent; btn.textContent='Загрузка…';
    fetch(ADMIN+'/graph/preview',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify({url:s.url})})
      .then(r=>r.json().then(j=>({ok:r.ok,j})))
      .then(({ok,j})=>{ btn.disabled=false; btn.textContent='Обновить ссылки';
        if(!j||!j.ok){ btn.textContent=prev; showToast('Не удалось: '+((j&&j.error)||'ошибка'),true); return; }
        renderRenameRows(s,box,j.links||[]); })
      .catch(()=>{ btn.disabled=false; btn.textContent=prev; showToast('Сервер недоступен',true); });
  }

  function makeRoute(r){
    const n=el('div','node route'); n.style.left=r.x+'px'; n.style.top=r.y+'px';
    const hd=el('div','hd'); hd.appendChild(el('span',null,'Маршрут')); const x=el('span','x','✕'); hd.appendChild(x); n.appendChild(hd);
    const bd=el('div','bd');
    bd.appendChild(el('label',null,'Название (видно в клиенте)'));
    const t=el('input'); t.value=r.title||''; t.placeholder='Моя подписка'; t.addEventListener('input',()=>{ r.title=t.value; markDirty(); }); bd.appendChild(t);
    bd.appendChild(el('label',null,'Путь подписки'));
    const p=el('input','mono'); p.value=r.path||''; p.placeholder='/custom/custom'; mask(p); bd.appendChild(p);
    bd.appendChild(el('label',null,'Режим'));
    const sel=el('select'); [['merge','Слияние'],['mirror','Зеркало']].forEach(m=>{ const o=el('option',null,m[1]); o.value=m[0]; if((r.mode||'merge')===m[0])o.selected=true; sel.appendChild(o); }); sel.addEventListener('change',()=>{ r.mode=sel.value; markDirty(); }); bd.appendChild(sel);
    // домен (на каком отдаётся) — показываем, только если домены настроены
    let domWarn=null;
    function updWarn(){ if(!domWarn)return; const bad=r.domain_id && !((domainById(r.domain_id)||{}).enabled); domWarn.textContent=bad?'⚠ домен отсутствует/выключен — отдаётся на домене по умолчанию':''; }
    if(DOMAINS.length){
      bd.appendChild(el('label',null,'Домен (на каком отдаётся)'));
      const ds=el('select');
      const o0=el('option',null,'(по умолчанию)'); o0.value=''; if(!(r.domain_id||''))o0.selected=true; ds.appendChild(o0);
      DOMAINS.forEach(d=>{ const lbl=(d.fqdn||d.id)+(d.enabled?(d.default?' ★':''):' (выключен)'); const o=el('option',null,lbl); o.value=d.id; if((r.domain_id||'')===d.id)o.selected=true; ds.appendChild(o); });
      ds.addEventListener('change',()=>{ r.domain_id=ds.value; updPub(); updWarn(); markDirty(); });
      bd.appendChild(ds);
      domWarn=el('div','muted'); domWarn.style.color='#ffb86b'; domWarn.style.fontSize='12px'; bd.appendChild(domWarn);
    }
    // текст под подпиской (announce — показывается в клиенте)
    const det=el('details'); det.appendChild(el('summary',null,'Текст под подпиской (announce)'));
    const ta=el('textarea'); ta.value=r.announce||''; ta.placeholder='Бот — @mybot\nПоддержка — https://...'; ta.addEventListener('input',()=>{ r.announce=ta.value; markDirty(); }); det.appendChild(ta); bd.appendChild(det);
    // тумблер включён
    const chk=el('label','chk'); const sw=el('span','switch'); const cb=el('input'); cb.type='checkbox'; cb.checked=r.enabled!==false;
    const sl=el('span','slider'); sw.appendChild(cb); sw.appendChild(sl); cb.addEventListener('change',()=>{ r.enabled=cb.checked; markDirty(); });
    chk.appendChild(sw); chk.appendChild(el('span',null,'Включён')); bd.appendChild(chk);
    // публичная ссылка
    const pub=el('div','pub'); const pubSpan=el('span',null,''); maskSpan(pubSpan);
    const pubCopy=el('span','copy','копировать'); pubCopy.addEventListener('click',()=>{ if(navigator.clipboard)navigator.clipboard.writeText(pubSpan.textContent); showToast('Ссылка скопирована',false); });
    pub.appendChild(pubSpan); pub.appendChild(pubCopy);
    function updPub(){ r.path=p.value; pubSpan.textContent=baseFor(r).replace(/\/$/,'')+normPath(p.value); }
    p.addEventListener('input',()=>{ updPub(); markDirty(); }); updPub(); updWarn(); bd.appendChild(pub);
    const cnt=el('div','cnt'); cnt.dataset.rid=r.id; bd.appendChild(cnt);
    n.appendChild(bd);
    dragHeader(hd,r,n); deleteBtn(x,r);
    n.appendChild(inSocket(r)); n.appendChild(outSocket(r));  // маршрут можно подключать в другой маршрут
    nodeEls[r.id]=n; world.appendChild(n);
  }

  // pan
  editor.addEventListener('mousedown',e=>{
    if(e.target!==editor && e.target!==world && e.target!==hint) return;
    e.preventDefault(); editor.classList.add('panning');
    let lx=e.clientX, ly=e.clientY;
    function mm(ev){ view.panX+=ev.clientX-lx; view.panY+=ev.clientY-ly; lx=ev.clientX; ly=ev.clientY; applyTransform(); redrawWires(); }
    function mu(){ document.removeEventListener('mousemove',mm); document.removeEventListener('mouseup',mu); editor.classList.remove('panning'); }
    document.addEventListener('mousemove',mm); document.addEventListener('mouseup',mu);
  });
  // zoom
  editor.addEventListener('wheel',e=>{
    e.preventDefault(); const r=rect(); const mx=e.clientX-r.left, my=e.clientY-r.top;
    const wx=(mx-view.panX)/view.zoom, wy=(my-view.panY)/view.zoom;
    view.zoom=Math.min(2.5,Math.max(0.2, view.zoom*(e.deltaY<0?1.1:1/1.1)));
    view.panX=mx-wx*view.zoom; view.panY=my-wy*view.zoom; applyTransform(); redrawWires();
  },{passive:false});

  function centerWorld(){ const r=rect(); return {x:(r.width/2-view.panX)/view.zoom, y:(r.height/2-view.panY)/view.zoom}; }
  document.getElementById('addSrc').addEventListener('click',()=>{ const c=centerWorld(); const s={id:genId(),url:'',label:'',type:'source',x:c.x-NODE_W/2,y:c.y-40}; G.sources.push(s); makeSource(s); redrawWires(); markDirty(); });
  document.getElementById('addKey').addEventListener('click',()=>{ const c=centerWorld(); const s={id:genId(),url:'',label:'',type:'key',keys:[{link:'',name:''}],renames:[],x:c.x-NODE_W/2,y:c.y-40}; G.sources.push(s); makeKey(s); redrawWires(); markDirty(); });
  const addGroupBtn=document.getElementById('addGroup');
  if(addGroupBtn) addGroupBtn.addEventListener('click',()=>{ const c=centerWorld(); const s={id:genId(),type:'group',url:'',label:'',buckets:[],gparams:{},x:c.x-NODE_W/2,y:c.y-40}; G.sources.push(s); makeGroup(s); redrawWires(); refreshCounts(); markDirty(); });
  const addAutoBtn=document.getElementById('addAuto');
  if(addAutoBtn) addAutoBtn.addEventListener('click',()=>{ const c=centerWorld(); const s={id:genId(),type:'autoselect',url:'',label:'',gparams:{},x:c.x-NODE_W/2,y:c.y-40}; G.sources.push(s); makeAuto(s); redrawWires(); refreshCounts(); markDirty(); });
  const addRouterBtn=document.getElementById('addRouter');
  if(addRouterBtn) addRouterBtn.addEventListener('click',()=>{ const c=centerWorld(); const s={id:genId(),type:'router',url:'',label:'',rules:[],default_target:'direct',gparams:{},x:c.x-NODE_W/2,y:c.y-40}; G.sources.push(s); makeRouter(s); redrawWires(); refreshCounts(); markDirty(); });
  document.getElementById('addRoute').addEventListener('click',()=>{ const c=centerWorld(); const r={id:genId(),title:'',path:'',mode:'merge',enabled:true,announce:'',domain_id:'',x:c.x-NODE_W/2,y:c.y-70}; G.routes.push(r); makeRoute(r); redrawWires(); refreshCounts(); markDirty(); });
  document.getElementById('reset').addEventListener('click',()=>{ view={panX:60,panY:60,zoom:1}; applyTransform(); redrawWires(); });
  document.getElementById('save').addEventListener('click',()=>save(false));

  const blurBtn=document.getElementById('blurToggle');
  blurBtn.addEventListener('click',()=>{ const on=document.body.classList.toggle('unblur'); blurBtn.textContent=on?'Скрыть ссылки':'Показать ссылки'; blurBtn.classList.toggle('on',on); });

  const asBtn=document.getElementById('autosaveToggle');
  function updAsBtn(){ asBtn.textContent='Автосейв: '+(autosave?'вкл':'выкл'); asBtn.classList.toggle('on',autosave); }
  asBtn.addEventListener('click',()=>{ autosave=!autosave; updAsBtn(); if(autosave){ markDirty(); } else { clearTimeout(saveTimer); } }); updAsBtn();

  let toastT=null;
  function showToast(msg,isErr){ toast.textContent=msg; toast.className=isErr?'err':'ok'; toast.style.display='block'; clearTimeout(toastT); toastT=setTimeout(()=>toast.style.display='none', isErr?6500:2200); }

  function save(silent){
    if(saving){ pendingSave=true; pendingSilent=pendingSilent&&silent; return; }
    pendingSave=false; pendingSilent=true;
    saving=true; setStat('… сохранение','dirty');
    const node_meta={};
    G.sources.forEach(s=>{
      const e={};
      if(s.type==='router'){
        const rules=(s.rules||[]).filter(r=>r.match && (''+(r.match.value||'')).trim())
          .map(r=>({match:{kind:r.match.kind,value:(''+r.match.value).trim()},target:r.target||'direct'}));
        const params={};
        ['strategy','probe_url','interval','timeout','sampling','domain_strategy'].forEach(k=>{
          if(s.gparams && s.gparams[k]!=null && s.gparams[k]!=='') params[k]=s.gparams[k]; });
        e.router={rules:rules, default_target:s.default_target||'direct', params:params};   // всегда пишем
      } else if(s.type==='autoselect'){
        const params={};
        ['strategy','probe_url','interval','timeout','sampling','domain_strategy'].forEach(k=>{
          if(s.gparams && s.gparams[k]!=null && s.gparams[k]!=='') params[k]=s.gparams[k]; });
        e.autoselect={params:params};   // авто-выбор: всегда пишем (узнаётся по meta/type)
      } else if(s.type==='group'){
        // как на сервере (_norm_node_meta): держим корзину, если есть имя ИЛИ члены,
        // иначе непоименованная, но заполненная корзина молча терялась бы.
        const buckets=(s.buckets||[]).filter(b=>(b.name||'').trim() || (b.members||[]).length).map(b=>({
          name:(b.name||'').trim(),
          members:(b.members||[]).map(m=>m.link?{link:m.link}:{addr:m.addr||'',name:m.name||''})}));
        const params={};
        ['strategy','probe_url','interval','timeout','sampling','domain_strategy'].forEach(k=>{
          if(s.gparams && s.gparams[k]!=null && s.gparams[k]!=='') params[k]=s.gparams[k]; });
        const g={}; if(buckets.length) g.buckets=buckets; if(Object.keys(params).length) g.params=params;
        if(Object.keys(g).length) e.group=g;
      } else if(s.type==='key'){
        const keys=(s.keys||[]).filter(k=>(k.link||'').trim()).map(k=>({link:k.link.trim(),name:k.name||''}));
        if(keys.length) e.keys=keys;
      } else {
        const ren=(s.renames||[]).filter(r=>(r.to||'').trim()).map(r=>({addr:r.addr||'',name:r.name||'',to:r.to}));
        if(ren.length) e.renames=ren;
      }
      if(Object.keys(e).length) node_meta[s.id]=e;
    });
    const payload={
      sources:G.sources.map(s=>({id:s.id,url:s.url||'',label:s.label||'',type:s.type||'source',x:Math.round(s.x),y:Math.round(s.y)})),
      routes:G.routes.map(r=>({id:r.id,title:r.title||'',path:r.path||'',mode:r.mode||'merge',enabled:r.enabled!==false,announce:r.announce||'',domain_id:r.domain_id||'',x:Math.round(r.x),y:Math.round(r.y)})),
      edges:G.edges.map(e=>({from:e.from,to:e.to})),
      node_meta:node_meta
    };
    fetch(ADMIN+'/graph/save',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':CSRF},body:JSON.stringify(payload)})
      .then(r=>r.json().then(j=>({ok:r.ok,j})))
      .then(({ok,j})=>{
        saving=false;
        if(j&&j.ok){ setStat('✓ сохранено','ok'); if(!silent) showToast('Сохранено ✓',false); }
        else { const errs=((j&&j.errors)||['ошибка']).join('; '); setStat('⚠ '+errs,'err'); if(!silent) showToast('Не сохранено: '+errs,true); }
        if(pendingSave){ const s=pendingSilent; pendingSave=false; pendingSilent=true; save(s); }
      })
      .catch(()=>{ saving=false; setStat('⚠ сервер недоступен','err'); if(!silent) showToast('Сервер недоступен',true);
        if(pendingSave){ const s=pendingSilent; pendingSave=false; pendingSilent=true; save(s); } });
  }

  applyTransform();
  G.sources.forEach(s=>{
    if(s.type==='router' || (G.node_meta[s.id]||{}).router) makeRouter(s);
    else if(s.type==='autoselect' || (G.node_meta[s.id]||{}).autoselect) makeAuto(s);
    else if(s.type==='group' || (G.node_meta[s.id]||{}).group) makeGroup(s);
    else if(s.type==='key' || (s.keys&&s.keys.length)) makeKey(s);
    else makeSource(s);
  });
  G.routes.forEach(makeRoute);
  redrawWires(); refreshCounts(); setStat('', '');
})();
