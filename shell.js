/* Progressive enhancements shared by the server-rendered admin pages. */
(function () {
  'use strict';
  const menu = document.querySelector('.mobile-menu');
  const sidebar = document.querySelector('.sidebar');
  function setMenu(open) {
    document.body.classList.toggle('nav-open', open);
    if (menu) menu.setAttribute('aria-expanded', String(open));
    if (sidebar) sidebar.inert = !open && window.matchMedia('(max-width: 760px)').matches;
    if (open) sidebar.querySelector('a').focus();
  }
  if (menu) {
    menu.addEventListener('click', () => setMenu(!document.body.classList.contains('nav-open')));
    document.querySelector('.nav-backdrop').addEventListener('click', () => { setMenu(false); menu.focus(); });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && document.body.classList.contains('nav-open')) { setMenu(false); menu.focus(); }
      if (e.key === 'Tab' && document.body.classList.contains('nav-open')) {
        const links = sidebar.querySelectorAll('a, button');
        const first = links[0], last = links[links.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    });
    const mobile = window.matchMedia('(max-width: 760px)');
    mobile.addEventListener('change', () => setMenu(false));
    setMenu(false);
  }
  // Keep wide operational tables scrollable without widening the page.
  document.querySelectorAll('.app-page table').forEach(table => {
    const scroll = document.createElement('div');
    scroll.className = 'table-scroll';
    scroll.tabIndex = 0;
    scroll.setAttribute('role', 'region');
    scroll.setAttribute('aria-label', 'Таблица — прокрутите для просмотра всех столбцов');
    table.before(scroll);
    scroll.appendChild(table);
  });
  // The toolbar may wrap: measure its actual height, not a fixed desktop offset.
  const toolbar = document.getElementById('top');
  const editor = document.getElementById('editor');
  if (toolbar && editor) {
    const layout = () => { editor.style.top = toolbar.getBoundingClientRect().bottom + 'px'; };
    new ResizeObserver(layout).observe(toolbar);
    window.addEventListener('resize', layout);
    layout();
  }
  const search = document.getElementById('route-search');
  if (search) {
    const cards = Array.from(document.querySelectorAll('#route-results > .card'));
    const routes = cards.filter(card => card.querySelector('.route-title'));
    const update = () => {
      const query = search.value.trim().toLocaleLowerCase('ru');
      let count = 0;
      routes.forEach(card => {
        const values = Array.from(card.querySelectorAll('input[name="title"], input[name="path"]')).map(input => input.value);
        const text = [card.querySelector('.route-title').textContent, ...values].join(' ').toLocaleLowerCase('ru');
        card.hidden = !text.includes(query);
        if (!card.hidden) count++;
      });
      document.getElementById('search-count').textContent = count + ' из ' + routes.length;
      document.getElementById('search-empty').hidden = !query || count > 0;
      cards.filter(card => !routes.includes(card)).forEach(card => { card.hidden = !!query; });
    };
    search.addEventListener('input', update);
    update();
  }
  // Associate legacy form labels without changing names or submission contracts.
  let labelId = 0;
  document.querySelectorAll('.app-page label:not([for])').forEach(label => {
    const next = label.nextElementSibling;
    if (next && /^(INPUT|SELECT|TEXTAREA)$/.test(next.tagName)) {
      if (!next.id) next.id = 'field-' + (++labelId);
      label.htmlFor = next.id;
    }
  });
})();
