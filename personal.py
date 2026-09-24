"""Personal subscription registry. All operations run on a route's fixed owner.

SQLite transactions serialize first-device claims. Never elect a replacement owner
on an outage: doing so without consensus would permit a second device binding.
"""
from contextlib import contextmanager
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

import subscriptions as subs

EXEMPT_IPS = {"37.193.168.134", "90.189.209.31"}
VERSION_MESSAGE = "Ваш VPN-клиент не передаёт версию приложения. Используйте другой VPN-клиент, например Happ."
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


def has_version(headers):
    value = headers.get('X-App-Version', '').strip()
    return len(value) <= 120 and bool(re.search(r'\d+(?:\.\d+)+', value))


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


def catalog(body):
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
        raw = json.dumps(item, sort_keys=True, ensure_ascii=False) if isinstance(item, dict) else item
        key = hashlib.sha256(raw.encode()).hexdigest()[:32]
        if key in seen:
            continue
        seen.add(key)
        name = (item.get('remarks') or item.get('ps') or 'VPN') if isinstance(item, dict) else subs._frag_name(item)
        result.append({'id': key, 'name': str(name or 'VPN')[:200], 'value': item})
    return result[:1000]


def selected_response(items, selected, headers, output_format, title):
    values = [item['value'] for item in items if item['id'] in set(selected)]
    if not values:
        return notice('Обновите выбор серверов', 'Выбранные серверы больше недоступны. Откройте личную страницу управления и выберите другие.', output_format)
    result_headers = dict(headers)
    result_headers['Cache-Control'] = 'no-store'
    result_headers['Profile-Title'] = subs._b64_header(title)
    if isinstance(values[0], dict):
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
            db.execute('CREATE TABLE IF NOT EXISTS personal_links (route TEXT NOT NULL, slug TEXT NOT NULL, name TEXT NOT NULL, selected TEXT NOT NULL, manage_hash TEXT NOT NULL, device_hash TEXT NOT NULL DEFAULT "", created REAL NOT NULL, PRIMARY KEY(route,slug))')
            db.execute('CREATE TABLE IF NOT EXISTS personal_limits (bucket TEXT PRIMARY KEY, since REAL NOT NULL, count INTEGER NOT NULL)')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.db_file, timeout=15)
        try:
            with db:
                yield db
        finally:
            db.close()

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

    def create(self, route, name, slug, selected):
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
                count = db.execute('SELECT count(*) FROM personal_links WHERE route=?', (route,)).fetchone()[0]
                if count >= 10000:
                    raise PersonalError('Лимит личных ссылок исчерпан. Обратитесь к администратору.', 409)
                db.execute('INSERT INTO personal_links(route,slug,name,selected,manage_hash,created) VALUES(?,?,?,?,?,?)', (route,slug,name,json.dumps(selected),digest,time.time()))
        except sqlite3.IntegrityError:
            raise PersonalError('Это название ссылки уже занято. Выберите другое.', 409)
        return {'slug': slug, 'token': token, 'name': name, 'selected': selected}

    def access(self, route, slug, *, token=None, hwid=None, selected=None, claim=True):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT name,selected,manage_hash,device_hash FROM personal_links WHERE route=? AND slug=?', (route, slug)).fetchone()
            if not row:
                raise PersonalError('Личная ссылка не найдена.', 404)
            if token is not None:
                if not isinstance(token, str) or not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), row[2]):
                    raise PersonalError('Нужна секретная ссылка управления, полученная при создании.', 403)
                if selected is not None:
                    db.execute('UPDATE personal_links SET selected=? WHERE route=? AND slug=?', (json.dumps(selected), route, slug))
                return {'name': row[0], 'selected': selected if selected is not None else json.loads(row[1]), 'bound': bool(row[3])}
            if not hwid or len(hwid) > 256:
                raise PersonalError(DEVICE_REQUIRED, 403)
            digest = hashlib.sha256(hwid.encode()).hexdigest()
            if row[3] and not hmac.compare_digest(row[3], digest):
                raise PersonalError(DEVICE_MESSAGE, 403)
            if not row[3] and claim:
                db.execute('UPDATE personal_links SET device_hash=? WHERE route=? AND slug=? AND device_hash=""', (digest, route, slug))
            return {'name': row[0], 'selected': json.loads(row[1]), 'bound': bool(row[3]) or claim}
