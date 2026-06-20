(function(){
  const G = window.__GRAPH__ || {sources:[],routes:[],edges:[]};
  const ADMIN = (typeof window.__ADMIN__ === 'string') ? window.__ADMIN__ : '/admin';
  const CSRF = window.__CSRF__ || '';
  const BASE = window.__BASE__ || '';
  G.sources = G.sources || []; G.routes = G.routes || []; G.edges = G.edges || [];

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
      const s=findAny(e.from), r=G.routes.find(x=>x.id===e.to);
      if(!s||!r) return;
      const a=w2s(sockPos(s,'out')), b=w2s(sockPos(r,'in'));
      const p=document.createElementNS('http://www.w3.org/2000/svg','path');
      p.setAttribute('d',curve(a,b)); p.setAttribute('class', isRoute(s)?'wire rwire':'wire');
      p.addEventListener('click',ev=>{ ev.stopPropagation(); const i=G.edges.indexOf(e); if(i>=0)G.edges.splice(i,1); redrawWires(); refreshCounts(); markDirty(); });
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
      redrawWires(); refreshCounts(); markDirty();
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
  function finishConnect(route){
    if(!connecting) return;  // второй (всплывший) mouseup — ничего не делаем
    if(route){
      const f=connecting.from, t=route.id;
      if(f!==t && !G.edges.some(e=>e.from===f && e.to===t)){
        if(G.routes.some(r=>r.id===f) && wouldCycle(f,t)){ showToast('Нельзя замкнуть цикл маршрутов',true); }
        else { G.edges.push({from:f,to:t}); markDirty(); }
      }
    }
    connecting=null; tempPath=null; hoverIn=null; redrawWires(); refreshCounts();
  }

  function outSocket(node){ const out=el('div','sock out'); out.title='Тяни в маршрут'; out.addEventListener('mousedown',ev=>startConnect(ev,node)); return out; }
  function inSocket(route){
    const inp=el('div','sock in'); inp.title='Вход';
    inp.addEventListener('mouseenter',()=>hoverIn=route); inp.addEventListener('mouseleave',()=>{ if(hoverIn===route)hoverIn=null; });
    inp.addEventListener('mouseup',()=>finishConnect(route));
    return inp;
  }

  function makeSource(s){
    const n=el('div','node src'); n.style.left=s.x+'px'; n.style.top=s.y+'px';
    const hd=el('div','hd'); hd.appendChild(el('span',null,'Источник')); const x=el('span','x','✕'); hd.appendChild(x); n.appendChild(hd);
    const bd=el('div','bd');
    bd.appendChild(el('label',null,'Метка'));
    const lab=el('input'); lab.value=s.label||''; lab.placeholder='необязательно'; lab.addEventListener('input',()=>{ s.label=lab.value; markDirty(); }); bd.appendChild(lab);
    bd.appendChild(el('label',null,'Ссылка-подписка (upstream)'));
    const url=el('input','mono'); url.value=s.url||''; url.placeholder='https://сервер/sub/xxxx'; mask(url); url.addEventListener('input',()=>{ s.url=url.value; markDirty(); }); bd.appendChild(url);
    n.appendChild(bd);
    dragHeader(hd,s,n); deleteBtn(x,s); n.appendChild(outSocket(s));
    nodeEls[s.id]=n; world.appendChild(n);
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
    function updPub(){ r.path=p.value; pubSpan.textContent=BASE.replace(/\/$/,'')+normPath(p.value); }
    p.addEventListener('input',()=>{ updPub(); markDirty(); }); updPub(); bd.appendChild(pub);
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
  document.getElementById('addSrc').addEventListener('click',()=>{ const c=centerWorld(); const s={id:genId(),url:'',label:'',x:c.x-NODE_W/2,y:c.y-40}; G.sources.push(s); makeSource(s); redrawWires(); markDirty(); });
  document.getElementById('addRoute').addEventListener('click',()=>{ const c=centerWorld(); const r={id:genId(),title:'',path:'',mode:'merge',enabled:true,announce:'',x:c.x-NODE_W/2,y:c.y-70}; G.routes.push(r); makeRoute(r); redrawWires(); refreshCounts(); markDirty(); });
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
    const payload={
      sources:G.sources.map(s=>({id:s.id,url:s.url||'',label:s.label||'',x:Math.round(s.x),y:Math.round(s.y)})),
      routes:G.routes.map(r=>({id:r.id,title:r.title||'',path:r.path||'',mode:r.mode||'merge',enabled:r.enabled!==false,announce:r.announce||'',x:Math.round(r.x),y:Math.round(r.y)})),
      edges:G.edges.map(e=>({from:e.from,to:e.to}))
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
  G.sources.forEach(makeSource); G.routes.forEach(makeRoute);
  redrawWires(); refreshCounts(); setStat('', '');
})();
