"""Personal subscription registry. PostgreSQL operations can run on any node.
Legacy SQLite operations run on the fixed owner.

SQLite transactions serialize first-device claims. Never elect a replacement owner
on an outage: doing so without consensus would permit a second device binding.
"""
from contextlib import contextmanager
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import time
import urllib.parse
import urllib.request
import unicodedata
from collections import Counter

import subscriptions as subs
import database
import secretbox

EXEMPT_IPS = {"37.193.168.134", "90.189.209.31"}
HWID_MESSAGE = "Ваш VPN-клиент не передаёт корректный HWID устройства или использует IP вместо него. Используйте другой VPN-клиент, например Happ."
OPEN_MESSAGE = "Откройте ссылку подписки в браузере, чтобы получить личную ссылку для одного устройства."
DEVICE_MESSAGE = "Эта ссылка уже используется на другом устройстве. Откройте основную ссылку в браузере и создайте свою личную подписку."
DEVICE_REQUIRED = "Для личной подписки нужен VPN-клиент, передающий ID устройства (HWID). Используйте, например, Happ."


class PersonalError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def client_ip(peer, headers):
    """Only consume a forwarded chain from configured reverse proxies."""
    cidrs = os.environ.get("TRUSTED_PROXY_CIDRS", "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
    networks = [ipaddress.ip_network(x.strip()) for x in cidrs.split(',') if x.strip()]
    def trusted(value):
        try:
            ip = ipaddress.ip_address(value)
            return any(ip in net for net in networks)
        except ValueError:
            return False
    if not trusted(peer):
        return peer
    chain = [x.strip() for x in headers.get('X-Forwarded-For', '').split(',') if x.strip()]
    # Walk right to left, stopping at the first client outside the trusted network.
    for value in reversed(chain):
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            return peer
        if not trusted(value):
            return value
    return chain[0] if chain else peer


def has_device_hwid(value):
    """Reject empty identifiers, IP fallback markers, and embedded IPv4/IPv6."""
    value = (value or '').strip()
    if not value or len(value) > 256 or 'ip' in value.lower():
        return False
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        return False
    if re.search(r'(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])', value):
        return False
    # Try colon-containing substrings to catch prefixed/bracketed IPv6 addresses.
    for match in re.finditer(r'[0-9a-fA-F:.]+', value):
        text = match.group()
        if ':' not in text:
            continue
        for start in range(len(text)):
            for end in range(start + 2, len(text) + 1):
                candidate = text[start:end]
                if candidate.count(':') < 2:
                    continue
                try:
                    ipaddress.ip_address(candidate)
                    return False
                except ValueError:
                    pass
    return True


def normalized_ip(value):
    try:
        address = ipaddress.ip_address(str(value or '').strip())
        return str(address.ipv4_mapped or address) if isinstance(address, ipaddress.IPv6Address) else str(address)
    except ValueError:
        return None


def exempt_client_ip(ip, nodes, own_ip=''):
    exempt = {normalized_ip(value) for value in EXEMPT_IPS}
    exempt.add(normalized_ip(own_ip))
    exempt.update(normalized_ip(node.get('public_ip')) for node in nodes)
    exempt.discard(None)
    return normalized_ip(ip) in exempt


def notice(name, message, output_format='legacy'):
    body, headers = subs.build_blocked_response(output_format)
    headers['Profile-Title'] = subs._b64_header(message)
    headers['Announce'] = subs._b64_header(message)
    if output_format == 'clash':
        body = subs._render_clash_yaml(
            [{'name': name, 'type': 'vless', 'server': subs._BLOCKED_HOST,
              'port': 1, 'uuid': subs._BLOCKED_UUID, 'udp': False}],
            [{'name': 'VPN', 'type': 'select', 'proxies': [name]}], ['MATCH,VPN'])
    else:
        body = subs._b64list([f'vless://{subs._BLOCKED_UUID}@{subs._BLOCKED_HOST}:1?security=none&type=tcp#{urllib.parse.quote(name)}'])
    return body, headers


def catalog(body, origins=None):
    """Identify complete output entries, keeping routers/balancers indivisible."""
    try:
        parsed = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        parsed = None
    if isinstance(parsed, dict):
        parsed = [parsed]
    items = parsed if isinstance(parsed, list) else subs.extract_links(body)
    result, seen = [], set()
    for item in items:
        if not isinstance(item, (str, dict)):
            continue
        name = (item.get('remarks') or item.get('ps') or 'VPN') if isinstance(item, dict) else subs._frag_name(item)
        if not name and isinstance(item, str) and item.lower().startswith('vmess://'):
            try:
                encoded = item[8:].split('#', 1)[0]
                name = json.loads(base64.b64decode(encoded + '=' * (-len(encoded) % 4))).get('ps') or ''
            except (ValueError, TypeError, AttributeError):
                pass
        raw = json.dumps(item, sort_keys=True, ensure_ascii=False) if isinstance(item, dict) else item
        if isinstance(item, str) and str(name).startswith('Небезопасный · '):
            # Exit-country changes must not invalidate an existing selection.
            raw = subs._apply_name(item, 'Небезопасный').split('#', 1)[0]
            raw = 'unsafe:' + raw
        key = hashlib.sha256(raw.encode()).hexdigest()[:32]
        if key in seen:
            continue
        seen.add(key)
        entry = {'id': key, 'name': str(name or 'VPN')[:200], 'value': item, 'unsafe': str(name).startswith('Небезопасный · ')}
        provenance = (origins or {}).get(subs.selection_value_key(item), [])
        # Open-source lists reuse country labels for unrelated hosts. Never match
        # these, unnamed entries, or ambiguous origins by display name alone.
        normalized = ' '.join(unicodedata.normalize('NFC', str(name or '')).casefold().split())
        if not entry['unsafe'] and len(provenance) == 1 and (normalized not in ('', 'vpn') or provenance[0]['fixed']):
            origin = provenance[0]
            entry['_identity'] = hashlib.sha256(json.dumps(
                [origin['scope'], '' if origin['fixed'] else normalized], ensure_ascii=False).encode()).hexdigest()
        result.append(entry)
    counts = Counter(item.get('_identity') for item in result)
    for item in result:
        if counts[item.get('_identity')] > 1:
            identity = item.pop('_identity', None)
            if identity:
                item['_ambiguous_identity'] = identity
    return result[:1000]


def selected_response(items, selected, headers, output_format, title):
    values = [item['value'] for item in items if item['id'] in set(selected)]
    if not values:
        return notice(title, 'Выбранные серверы временно недоступны. Ваш выбор сохранён: после их возвращения обновите подписку. При желании можно выбрать дополнительные серверы на странице управления.', output_format)
    result_headers = dict(headers)
    result_headers['Cache-Control'] = 'no-store'
    result_headers['Profile-Title'] = subs._b64_header(title)
    if any(isinstance(value, dict) for value in values):
        configs = []
        for value in values:
            if isinstance(value, dict):
                configs.append(value)
            else:
                outbound, name = subs._link_to_outbound(value)
                if outbound:
                    configs.append(subs._wrap_as_config(outbound, name))
        values = configs
        body = json.dumps(values, ensure_ascii=False).encode()
        result_headers['Content-Type'] = 'application/json; charset=utf-8'
    else:
        body = subs._b64list(values)
        result_headers['Content-Type'] = 'text/plain; charset=utf-8'
    if output_format == 'clash':
        return subs.build_clash_response(body, result_headers, title)
    return body, result_headers


def verify_turnstile(token, hostname):
    secret = os.environ.get('TURNSTILE_SECRET_KEY', '')
    if not secret or not os.environ.get('TURNSTILE_SITE_KEY', ''):
        raise PersonalError('Выдача личных ссылок пока не настроена. Обратитесь к администратору.', 503)
    if not isinstance(token, str) or not 1 <= len(token) <= 2048:
        raise PersonalError('Пройдите проверку Cloudflare.')
    data = urllib.parse.urlencode({'secret': secret, 'response': token}).encode()
    try:
        req = urllib.request.Request('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=data)
        with urllib.request.urlopen(req, timeout=10, context=subs.build_ssl_context()) as response:
            result = json.loads(response.read(65536))
    except Exception:
        raise PersonalError('Проверка Cloudflare временно недоступна. Попробуйте позже.', 503)
    if not result.get('success') or result.get('hostname', '').lower() != hostname.lower() or result.get('action') != 'personal_create':
        raise PersonalError('Проверка Cloudflare не пройдена или устарела. Повторите её.', 403)


class Registry:
    def __init__(self, db_file):
        self.db_file = db_file
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS personal_links (route TEXT NOT NULL, slug TEXT NOT NULL, name TEXT NOT NULL, selected TEXT NOT NULL, manage_hash TEXT NOT NULL, device_hash TEXT NOT NULL DEFAULT "", created REAL NOT NULL, PRIMARY KEY(route,slug))')
            columns = {row[1] for row in db.execute("PRAGMA table_info(personal_links)")}
            if "contact" not in columns:
                db.execute("ALTER TABLE personal_links ADD COLUMN contact TEXT NOT NULL DEFAULT ''")
            if "always_all" not in columns:
                db.execute("ALTER TABLE personal_links ADD COLUMN always_all INTEGER NOT NULL DEFAULT 0")
            db.execute('CREATE TABLE IF NOT EXISTS personal_catalog_cache (route TEXT NOT NULL, scope TEXT NOT NULL, choice TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(route,scope,choice))')
            db.execute('CREATE INDEX IF NOT EXISTS personal_slug_nocase ON personal_links(route,slug COLLATE NOCASE)')
            db.execute('CREATE TABLE IF NOT EXISTS personal_limits (bucket TEXT PRIMARY KEY, since REAL NOT NULL, count INTEGER NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS personal_choices (route TEXT NOT NULL, identity TEXT NOT NULL, choice TEXT NOT NULL, PRIMARY KEY(route,identity))')
            db.execute('CREATE TABLE IF NOT EXISTS personal_choice_aliases (route TEXT NOT NULL, old_id TEXT NOT NULL, choice TEXT NOT NULL, PRIMARY KEY(route,old_id))')
            db.execute('CREATE TABLE IF NOT EXISTS personal_ambiguous_choices (route TEXT NOT NULL, identity TEXT NOT NULL, PRIMARY KEY(route,identity))')

    @staticmethod
    def _resolve_selection(db, route, selected):
        aliases = dict(db.execute('SELECT old_id,choice FROM personal_choice_aliases WHERE route=?', (route,)).fetchall())
        return list(dict.fromkeys(aliases.get(key, key) for key in selected))

    def resolve_selection(self, route, selected):
        with self.connect() as db:
            return self._resolve_selection(db, route, selected)

    def stabilize_catalog(self, route, items):
        """Keep the first observed ID for each source/name; remember old content hashes.

        Alias history permits existing selections to migrate when their exact old
        entry is observed. No credentials or full VPN configurations are stored here.
        """
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            choices = dict(db.execute('SELECT identity,choice FROM personal_choices WHERE route=?', (route,)).fetchall())
            aliases = dict(db.execute('SELECT old_id,choice FROM personal_choice_aliases WHERE route=?', (route,)).fetchall())
            blocked = {row[0] for row in db.execute('SELECT identity FROM personal_ambiguous_choices WHERE route=?', (route,))}
            ambiguous = {item['_ambiguous_identity'] for item in items if item.get('_ambiguous_identity')}
            db.executemany('INSERT INTO personal_ambiguous_choices(route,identity) VALUES(?,?) ON CONFLICT(route,identity) DO NOTHING', [(route, identity) for identity in ambiguous - blocked])
            blocked.update(ambiguous)
            new_choices, new_aliases = [], []
            for item in items:
                identity = item.get('_identity')
                if not identity or identity in blocked:
                    continue
                old_id = item['id']
                if identity not in choices:
                    choices[identity] = old_id
                    new_choices.append((route, identity, old_id))
                choice = choices[identity]
                if old_id not in aliases:
                    aliases[old_id] = choice
                    new_aliases.append((route, old_id, choice))
                item['id'] = choice
            db.executemany('INSERT INTO personal_choices(route,identity,choice) VALUES(?,?,?) ON CONFLICT(route,identity) DO NOTHING', new_choices)
            db.executemany('INSERT INTO personal_choice_aliases(route,old_id,choice) VALUES(?,?,?) ON CONFLICT(route,old_id) DO NOTHING', new_aliases)
        return items

    def retained_catalog(self, route, scope, items):
        """Keep last observed trusted entries across partial/empty upstream responses.

        Scope changes when the configured graph changes, so removed sources cannot
        leak back through cached output. Unsafe public proxies are never restored.
        """
        current = {item['id']: item for item in items}
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM personal_catalog_cache WHERE route=? AND scope!=?', (route, scope))
            previous = dict(db.execute('SELECT choice,payload FROM personal_catalog_cache WHERE route=? AND scope=?', (route, scope)).fetchall())
            for item in items:
                if not item.get('unsafe'):
                    raw = json.dumps(item, ensure_ascii=False)
                    if item['id'] in previous and secretbox.decrypt(previous[item['id']]) == raw:
                        continue
                    payload = secretbox.encrypt(raw)
                    db.execute('INSERT INTO personal_catalog_cache(route,scope,choice,payload) VALUES(?,?,?,?) ON CONFLICT(route,scope,choice) DO UPDATE SET payload=excluded.payload', (route,scope,item['id'],payload))
            rows = db.execute('SELECT choice,payload FROM personal_catalog_cache WHERE route=? AND scope=? ORDER BY choice', (route, scope)).fetchall()
            for choice, payload in rows:
                if choice not in current:
                    try:
                        item = json.loads(secretbox.decrypt(payload))
                    except (ValueError, TypeError):
                        continue
                    item['available'] = False
                    current[choice] = item
        return list(current.values())

    @contextmanager
    def connect(self):
        with database.connect(self.db_file, scope='personal') as db:
            yield db

    def limit(self, ip, limit=12):
        bucket = hashlib.sha256(ip.encode()).hexdigest()
        now = time.time()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM personal_limits WHERE since < ?', (now-3600,))
            row = db.execute('SELECT count FROM personal_limits WHERE bucket=?', (bucket,)).fetchone()
            if row and row[0] >= limit:
                raise PersonalError('Слишком много попыток. Попробуйте через час.', 429)
            db.execute('INSERT INTO personal_limits VALUES(?,?,1) ON CONFLICT(bucket) DO UPDATE SET count=count+1', (bucket, now))

    def create(self, route, name, slug, selected, contact="", always_all=False):
        contact = str(contact or '').strip()
        if len(contact) > 160 or any(ord(c) < 32 or ord(c) == 127 for c in contact):
            raise PersonalError('Контакт: до 160 символов, без переносов строк.')
        name = str(name or '').strip()
        slug = str(slug or '').strip() or secrets.token_urlsafe(24)
        if not 1 <= len(name) <= 80:
            raise PersonalError('Введите имя (до 80 символов).')
        if not re.fullmatch(r'[A-Za-z0-9_-]{4,64}', slug):
            raise PersonalError('Название ссылки: 4–64 латинских букв, цифр, дефисов или подчёркиваний.')
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        try:
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                if db.execute('SELECT 1 FROM personal_links WHERE route=? AND slug=? COLLATE NOCASE', (route, slug)).fetchone():
                    raise PersonalError('Это название ссылки уже занято. Выберите другое.', 409)
                count = db.execute('SELECT count(*) FROM personal_links WHERE route=?', (route,)).fetchone()[0]
                if count >= 10000:
                    raise PersonalError('Лимит личных ссылок исчерпан. Обратитесь к администратору.', 409)
                db.execute('INSERT INTO personal_links(route,slug,name,selected,manage_hash,created,contact,always_all) VALUES(?,?,?,?,?,?,?,?)', (route,slug,name,json.dumps(selected),digest,time.time(),contact,int(always_all)))
        except sqlite3.IntegrityError:
            raise PersonalError('Это название ссылки уже занято. Выберите другое.', 409)
        return {'slug': slug, 'token': token, 'name': name, 'contact': contact, 'selected': selected, 'always_all': bool(always_all)}

    def access(self, route, slug, *, token=None, hwid=None, selected=None, claim=True, allow_unauthenticated=False, always_all=None):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            matches = db.execute('SELECT name,selected,manage_hash,device_hash,contact,slug,always_all FROM personal_links WHERE route=? AND slug=? COLLATE NOCASE', (route, slug)).fetchall()
            if len(matches) > 1:
                raise PersonalError('Названия личных ссылок отличаются только регистром. Обратитесь к администратору.', 409)
            row = matches[0] if matches else None
            if row:
                slug = row[5]
            if not row:
                raise PersonalError('Личная ссылка не найдена.', 404)
            if token is not None:
                if not isinstance(token, str) or not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), row[2]):
                    raise PersonalError('Нужна секретная ссылка управления, полученная при создании.', 403)
                if always_all is not None:
                    db.execute('UPDATE personal_links SET always_all=? WHERE route=? AND slug=?', (int(always_all),route,slug))
                if selected is not None:
                    db.execute('UPDATE personal_links SET selected=? WHERE route=? AND slug=?', (json.dumps(selected), route, slug))
                return {'always_all': bool(always_all if token is not None and always_all is not None else row[6]), 'name': row[0], 'contact': row[4], 'selected': self._resolve_selection(db, route, selected if selected is not None else json.loads(row[1])), 'bound': bool(row[3])}
            if allow_unauthenticated:
                return {'always_all': bool(always_all if token is not None and always_all is not None else row[6]), 'name': row[0], 'contact': row[4], 'selected': self._resolve_selection(db, route, json.loads(row[1])), 'bound': bool(row[3])}
            if not hwid or len(hwid) > 256:
                raise PersonalError(DEVICE_REQUIRED, 403)
            digest = hashlib.sha256(hwid.encode()).hexdigest()
            if row[3] and not hmac.compare_digest(row[3], digest):
                raise PersonalError(DEVICE_MESSAGE, 403)
            if not row[3] and claim:
                db.execute('UPDATE personal_links SET device_hash=? WHERE route=? AND slug=? AND device_hash=""', (digest, route, slug))
            return {'always_all': bool(always_all if token is not None and always_all is not None else row[6]), 'name': row[0], 'contact': row[4], 'selected': self._resolve_selection(db, route, json.loads(row[1])), 'bound': bool(row[3]) or claim}
