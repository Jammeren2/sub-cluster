"""Slow, persistent per-node verification of explicitly untrusted subscription feeds.
Only a successful HTTPS request THROUGH the candidate makes it publishable.
No direct fallback; raw feed credentials never go to the portal or checker logs.
"""
import base64
import collections
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request

import subscriptions as subs

PUBLIC_FEED = 'https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt'
PREFIX = 'Небезопасный · '
MAX_BYTES = 32 * 1024 * 1024
MAX_LINKS = 100000
REFRESH = 6 * 3600
TTL = 72 * 3600
WORKERS = max(1, min(16, int(os.environ.get('SOURCE_CHECK_WORKERS', '4'))))
PAUSE = max(0.05, min(60, float(os.environ.get('SOURCE_CHECK_PAUSE', '0.2'))))
LEASE_SECONDS = 120


def is_unsafe(source):
    return bool(source.get('unsafe')) or source.get('url', '').strip() == PUBLIC_FEED


def decode64(value):
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)).decode('utf-8')


def normalize_link(link):
    link = html.unescape(link)
    if link.lower().startswith('ssr://') and link[6:].split('#')[0].count(':') >= 5:
        # Some scraped lists contain decoded SSR URIs; clients expect base64.
        link = 'ssr://' + base64.urlsafe_b64encode(link[6:].split('#')[0].encode()).decode().rstrip('=')
    return link


def proxy_config(link):
    """Parse only proxy fields, never arbitrary remote core configuration."""
    link = normalize_link(link)
    u = urllib.parse.urlsplit(link)
    q = urllib.parse.parse_qs(u.query)
    one = lambda key, default='': q.get(key, [default])[0]
    scheme = u.scheme.lower()
    if scheme == 'ssr':
        raw = link[6:].split('#')[0]
        raw = raw if raw.count(':') >= 5 else decode64(raw)
        head, _, query = raw.partition('/?')
        host, port, protocol, cipher, obfs, password = head.rsplit(':', 5)
        params = urllib.parse.parse_qs(query)
        p = {'name': 'probe', 'type': 'ssr', 'server': host.strip('[]'), 'port': int(port),
             'protocol': protocol, 'cipher': cipher, 'obfs': obfs, 'password': decode64(password)}
        for key, dest in [('obfsparam', 'obfs-param'), ('protoparam', 'protocol-param')]:
            if params.get(key):
                p[dest] = decode64(params[key][0])
        return p
    if scheme == 'hysteria':
        return {'name': 'probe', 'type': 'hysteria', 'server': u.hostname, 'port': u.port or 443,
                'auth-str': one('auth'), 'protocol': one('protocol', 'udp'),
                'up': one('upmbps', '10'), 'down': one('downmbps', '50'),
                'sni': one('peer') or one('sni') or u.hostname,
                'skip-cert-verify': one('insecure') in ('1', 'true'),
                'obfs': one('obfsParam')}
    p = subs._share_link_to_clash(link, 'probe')
    if not p:
        raise ValueError('unsupported')
    # Do not silently test TCP when the original transport is unsupported.
    net = one('type', 'tcp')
    if scheme == 'vmess':
        net = json.loads(decode64(link[8:].split('#')[0])).get('net', 'tcp')
    if scheme in ('vless', 'vmess', 'trojan') and net not in ('tcp', 'ws', 'grpc', 'http', 'h2'):
        raise ValueError('unsupported_transport')
    if p['type'] == 'trojan' and 'servername' in p:
        p['sni'] = p.pop('servername')
    if scheme in ('vless', 'trojan') and net in ('http', 'h2'):
        p['h2-opts'] = {'path': one('path', '/'), 'host': one('host').split(',') if one('host') else []}
    if scheme in ('vless', 'trojan') and net == 'tcp' and one('headerType') not in ('', 'none'):
        # Do not test a transport differing from the URI issued to the user.
        raise ValueError('unsupported_transport')
    if scheme in ('hysteria2', 'hy2') and u.password:
        p['password'] += ':' + urllib.parse.unquote(u.password)
    if scheme in ('hysteria2', 'hy2', 'tuic'):
        p['skip-cert-verify'] = one('insecure') in ('1', 'true') or one('allow_insecure') in ('1', 'true')
        if one('alpn'):
            p['alpn'] = one('alpn').split(',')
    if scheme == 'ss' and one('plugin'):
        plugin, *opts = one('plugin').split(';')
        if plugin not in ('obfs-local', 'simple-obfs', 'v2ray-plugin'):
            raise ValueError('unsupported_plugin')
        p['plugin'] = 'obfs' if plugin in ('obfs-local', 'simple-obfs') else plugin
        options = dict((x.split('=', 1) + [True])[:2] for x in opts if x)
        if p['plugin'] == 'obfs':
            options = {'mode': options.get('obfs', 'http'), 'host': options.get('obfs-host', '')}
        p['plugin-opts'] = options
    return p


def checked_proxy(link):
    p = proxy_config(link)
    host, port = p.get('server'), int(p.get('port') or 0)
    if not host or not 1 <= port <= 65535:
        raise ValueError('invalid_endpoint')
    # Pin a public address so an untrusted feed cannot probe the cluster/private LAN
    # or change a DNS answer between validation and the core's connection.
    addresses = list(dict.fromkeys(x[4][0] for x in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):
        raise ValueError('non_public_endpoint')
    if p.get('tls') or p['type'] in ('trojan', 'hysteria', 'hysteria2', 'tuic'):
        key = 'servername' if p['type'] in ('vless', 'vmess') else 'sni'
        p.setdefault(key, host)
    if p.get('network') == 'ws':
        headers = p.setdefault('ws-opts', {}).setdefault('headers', {})
        if not headers.get('Host'):
            headers['Host'] = host
    p['server'] = next((x for x in addresses if ':' not in x), addresses[0])
    return p


def core_path():
    return shutil.which(os.environ.get('MIHOMO_BIN', '/opt/mihomo/mihomo')) or shutil.which('mihomo')


def probe(link):
    """One isolated core + bounded HTTPS request; returns actual exit IP/country."""
    core = core_path()
    if not core or not shutil.which('curl'):
        raise RuntimeError('checker_unavailable')
    p = checked_proxy(link)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    password = secrets.token_hex(16)
    config = {'mixed-port': port, 'bind-address': '127.0.0.1', 'allow-lan': False,
              'authentication': ['probe:' + password], 'mode': 'rule', 'log-level': 'silent',
              'ipv6': True, 'proxies': [p], 'rules': ['MATCH,probe']}
    with tempfile.TemporaryDirectory(prefix='sub-probe-') as directory:
        path = Path(directory) / 'config.json'
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        process = subprocess.Popen([core, '-d', directory, '-f', str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise ValueError('unsupported_configuration')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise TimeoutError('core_start_timeout')
            result = subprocess.run(['curl', '--silent', '--fail', '--max-time', '15',
                '--max-filesize', '16384', '--noproxy', '', '--proxy', f'http://127.0.0.1:{port}',
                '--proxy-user', 'probe:' + password, 'https://www.cloudflare.com/cdn-cgi/trace'],
                capture_output=True, timeout=20, check=True)
            trace = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
            country, exit_ip = trace.get('loc', ''), trace.get('ip', '')
            if not re.fullmatch('[A-Z]{2}', country) or not ipaddress.ip_address(exit_ip).is_global:
                raise ValueError('invalid_exit_response')
            return {'country': country, 'exit_ip': exit_ip}
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


class Checker:
    def __init__(self, db_file, store):
        self.db_file, self.store = db_file, store
        self.stop = threading.Event()
        self.thread = None
        self.round = 0
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS checked_sources(url TEXT PRIMARY KEY, refreshed REAL NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT "")')
            db.execute('CREATE TABLE IF NOT EXISTS checked_links(url TEXT, key TEXT, link TEXT, position INTEGER, checked REAL NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT "pending", country TEXT NOT NULL DEFAULT "", exit_ip TEXT NOT NULL DEFAULT "", PRIMARY KEY(url,key))')
            columns = {r[1] for r in db.execute('PRAGMA table_info(checked_links)')}
            if 'lease_until' not in columns:
                db.execute('ALTER TABLE checked_links ADD COLUMN lease_until REAL NOT NULL DEFAULT 0')
            db.execute('CREATE INDEX IF NOT EXISTS checked_queue ON checked_links(url,checked,position)')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.db_file, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def ingest(self, url, body):
        links = subs.extract_links(body)
        if len(links) > MAX_LINKS:
            raise ValueError('too_many_links')
        # Interleave protocols, instead of spending days only on VLESS/SS.
        buckets = collections.defaultdict(collections.deque)
        seen = set()
        for link in links:
            link = normalize_link(link)
            raw = link.split('#', 1)[0]
            key = hashlib.sha256(raw.encode()).hexdigest()
            if key not in seen and len(raw) <= 16384:
                seen.add(key)
                buckets[raw.split(':', 1)[0].lower()].append((key, raw))
        ordered = []
        while any(buckets.values()):
            for queue in buckets.values():
                if queue:
                    ordered.append(queue.popleft())
        with self.connect() as db:
            db.execute('CREATE TEMP TABLE current_keys(key TEXT PRIMARY KEY)')
            db.executemany('INSERT INTO current_keys VALUES(?)', [(key,) for key, _ in ordered])
            db.executemany('INSERT INTO checked_links(url,key,link,position) VALUES(?,?,?,?) ON CONFLICT(url,key) DO UPDATE SET position=excluded.position',
                           [(url, key, link, pos) for pos, (key, link) in enumerate(ordered)])
            db.execute('DELETE FROM checked_links WHERE url=? AND key NOT IN (SELECT key FROM current_keys)', (url,))
            db.execute('INSERT INTO checked_sources(url,refreshed,error) VALUES(?,?,"") ON CONFLICT(url) DO UPDATE SET refreshed=excluded.refreshed,error=""', (url, time.time()))

    def refresh(self, url):
        with self.connect() as db:
            row = db.execute('SELECT refreshed FROM checked_sources WHERE url=?', (url,)).fetchone()
        if row and time.time() - row['refreshed'] < REFRESH:
            return
        try:
            if urllib.parse.urlsplit(url).scheme not in ('http', 'https'):
                raise ValueError('invalid_feed')
            # No admin/user HWID is sent to public aggregators.
            req = urllib.request.Request(url, headers={'User-Agent': 'SubCluster-SourceChecker/1', 'Accept-Encoding': 'identity'})
            with urllib.request.urlopen(req, timeout=30) as response:
                body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ValueError('feed_too_large')
            self.ingest(url, body)
        except Exception:
            with self.connect() as db:
                # Retry in ten minutes. Existing successes still expire normally.
                db.execute('INSERT INTO checked_sources(url,refreshed,error) VALUES(?,?,?) ON CONFLICT(url) DO UPDATE SET refreshed=excluded.refreshed,error=excluded.error',
                           (url, time.time() - REFRESH + 600, 'Не удалось обновить список'))

    def next_link(self, url, claim=False):
        with self.connect() as db:
            if claim:
                db.execute("BEGIN IMMEDIATE")
            now = time.time()
            # Every second turn refreshes a working server, so a long first scan
            # cannot leave the published subset unchecked for days.
            row = None
            if self.round % 2:
                row = db.execute('SELECT * FROM checked_links WHERE url=? AND state="ok" AND checked<? AND lease_until<? ORDER BY checked LIMIT 1', (url, now - 3600, now)).fetchone()
            if row is None:
                row = db.execute('SELECT * FROM checked_links WHERE url=? AND checked<? AND lease_until<? ORDER BY checked,position LIMIT 1', (url, now - 3600, now)).fetchone()
            if row is not None and claim:
                db.execute("UPDATE checked_links SET lease_until=? WHERE url=? AND key=?", (now + LEASE_SECONDS, url, row["key"]))
        self.round += 1
        return dict(row) if row else None

    def check_one(self, url):
        row = self.next_link(url, claim=True)
        if row:
            self.check_row(row)

    def check_row(self, row):
        country, exit_ip = '', ''
        try:
            try:
                result = probe(row['link'])
                country, exit_ip, state = result['country'], result['exit_ip'], 'ok'
            except RuntimeError:
                return  # Missing core does not falsely mark all servers as dead.
            except ValueError as exc:
                state = 'unsupported' if str(exc).startswith('unsupported') else 'failed'
            except Exception:
                state = 'failed'
            with self.connect() as db:
                db.execute('UPDATE checked_links SET checked=?,state=?,country=?,exit_ip=? WHERE url=? AND key=?',
                           (time.time(), state, country, exit_ip, row['url'], row['key']))
        finally:
            with self.connect() as db:
                db.execute('UPDATE checked_links SET lease_until=0 WHERE url=? AND key=?', (row['url'], row['key']))

    def body(self, url):
        with self.connect() as db:
            rows = db.execute('SELECT link,country,key FROM checked_links WHERE url=? AND state="ok" AND checked>? ORDER BY position', (url, time.time() - TTL)).fetchall()
        return subs._b64list([subs._apply_name(r['link'], PREFIX + r['country'] + ' · ' + r['key'][:8]) for r in rows]), {}

    def status(self, url):
        with self.connect() as db:
            rows = db.execute('SELECT state,count(*) AS n FROM checked_links WHERE url=? GROUP BY state', (url,)).fetchall()
            fresh = db.execute('SELECT count(*) FROM checked_links WHERE url=? AND state="ok" AND checked>?', (url, time.time() - TTL)).fetchone()[0]
            source = db.execute('SELECT error FROM checked_sources WHERE url=?', (url,)).fetchone()
        counts = {r['state']: r['n'] for r in rows}
        return {'total': sum(counts.values()), 'working': fresh, 'pending': counts.get('pending', 0),
                'unsupported': counts.get('unsupported', 0), 'failed': counts.get('failed', 0),
                'error': ('Нужны mihomo и curl на этом узле' if not core_path() or not shutil.which('curl') else (source['error'] if source else ''))}

    def run(self):
        cursor, refresh_cursor = 0, 0
        # Separate refresh executor: a slow feed download must not stall probes.
        with ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix='vpn-probe') as pool, ThreadPoolExecutor(max_workers=1, thread_name_prefix='feed-refresh') as refresh_pool:
            active, refreshing = set(), None
            while not self.stop.is_set():
                try:
                    for future in list(active):
                        if future.done():
                            active.remove(future)
                            try:
                                future.result()
                            except Exception:
                                pass  # lease expiry recovers transient SQLite failures
                    urls = list(dict.fromkeys(s.get('url', '').strip() for s in self.store.get_config().get('sources', []) if is_unsafe(s) and s.get('url')))
                    if refreshing is None or refreshing.done():
                        if refreshing is not None:
                            finished, refreshing = refreshing, None
                            finished.result()
                        if urls:
                            refreshing = refresh_pool.submit(self.refresh, urls[refresh_cursor % len(urls)])
                            refresh_cursor += 1
                    # Round-robin sources, immediately refill each completed slot.
                    for _ in range(WORKERS - len(active)):
                        row = None
                        for _ in urls:
                            url = urls[cursor % len(urls)]
                            cursor += 1
                            row = self.next_link(url, claim=True)
                            if row:
                                break
                        if not row:
                            break
                        active.add(pool.submit(self.check_row, row))
                    with self.connect() as db:
                        existing = [r[0] for r in db.execute('SELECT url FROM checked_sources')]
                        for old in set(existing) - set(urls):
                            db.execute('DELETE FROM checked_links WHERE url=?', (old,))
                            db.execute('DELETE FROM checked_sources WHERE url=?', (old,))
                except Exception:
                    pass
                self.stop.wait(PAUSE)

    def seed_public_source(self):
        """One-time disconnected source; never changes existing route outputs."""
        def mutate(cfg):
            if cfg.get('public_source_seeded'):
                return
            cfg['public_source_seeded'] = True
            if not any(s.get('url') == PUBLIC_FEED for s in cfg.get('sources', [])):
                cfg.setdefault('sources', []).append({'id': 'public-' + secrets.token_hex(8),
                    'type': 'source', 'label': 'Открытые VPN · проверяемые', 'url': PUBLIC_FEED,
                    'unsafe': True, 'x': 80, 'y': max([s.get('y', 0) or 0 for s in cfg.get('sources', [])] + [0]) + 300})
        if not self.store.get_config().get('public_source_seeded'):
            self.store.update_config(mutate)

    def start(self):
        if not self.thread or not self.thread.is_alive():
            self.thread = threading.Thread(target=self.run, daemon=True, name='source-checker')
            self.thread.start()
