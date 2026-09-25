"""Bounded, persistent per-node verification of explicitly untrusted subscription feeds.
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
import database

PUBLIC_FEED = 'https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt'
PREFIX = 'Небезопасный · '
MAX_BYTES = 32 * 1024 * 1024
MAX_LINKS = 100000
REFRESH = 6 * 3600
TTL = 72 * 3600
CONCURRENCY = max(1, min(256, int(os.environ.get('SOURCE_CHECK_CONCURRENCY', '192'))))
CYCLE = max(60, int(os.environ.get('SOURCE_CHECK_CYCLE_SECONDS', '1800')))
TIMEOUT = max(2, min(30, float(os.environ.get('SOURCE_CHECK_TIMEOUT', '8'))))
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


def validate_proxy(p):
    json.dumps(p, ensure_ascii=False).encode('utf-8')
    if not p.get('server') or not 1 <= int(p.get('port') or 0) <= 65535:
        raise ValueError('unsupported_endpoint')


def checked_proxy(link):
    p = proxy_config(link)
    validate_proxy(p)
    addresses = list(dict.fromkeys(x[4][0] for x in socket.getaddrinfo(p['server'], p['port'], type=socket.SOCK_STREAM)))
    if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):
        raise ValueError('non_public_endpoint')
    return pin_proxy(p, addresses)


def pin_proxy(p, addresses):
    host = p['server']
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
        self.shared = database.shared()
        self.node = store.origin
        self.schema = database.initialize_checker(self.node) if self.shared else 'public'
        self.stop = threading.Event()
        self.thread = None
        self.cluster = None
        self.sync_thread = None
        self.round = 0
        self.engine_error = ""
        self.samples = collections.deque(maxlen=10000)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE IF NOT EXISTS checked_sources(url TEXT PRIMARY KEY, refreshed REAL NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT "")')
            db.execute('CREATE TABLE IF NOT EXISTS checked_links(url TEXT, key TEXT, link TEXT, position INTEGER, checked REAL NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT "pending", country TEXT NOT NULL DEFAULT "", exit_ip TEXT NOT NULL DEFAULT "", PRIMARY KEY(url,key))')
            columns = {r[1] for r in db.execute('PRAGMA table_info(checked_links)')}
            if 'lease_until' not in columns:
                db.execute('ALTER TABLE checked_links ADD COLUMN lease_until REAL NOT NULL DEFAULT 0')
            db.execute('CREATE TABLE IF NOT EXISTS checked_peer_links(node TEXT,url TEXT,key TEXT,link TEXT,checked REAL,country TEXT,PRIMARY KEY(node,url,key))')
            db.execute('CREATE TABLE IF NOT EXISTS checked_peer_snapshots(node TEXT PRIMARY KEY,stamp REAL)')
            db.execute('CREATE INDEX IF NOT EXISTS checked_peer_source ON checked_peer_links(url,checked)')
            db.execute('CREATE INDEX IF NOT EXISTS checked_queue ON checked_links(url,checked,position)')

    @contextmanager
    def connect(self):
        with database.connect(self.db_file, schema=self.schema, scope='checker:' + self.node, mapped=True) as db:
            yield db

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
        unsupported = []
        for key, link in ordered:
            try:
                validate_proxy(proxy_config(link))
            except Exception:
                unsupported.append((time.time(), url, key))
        with self.connect() as db:
            db.execute('CREATE TEMP TABLE current_keys(key TEXT PRIMARY KEY)')
            db.executemany('INSERT INTO current_keys VALUES(?)', [(key,) for key, _ in ordered])
            db.executemany('INSERT INTO checked_links(url,key,link,position) VALUES(?,?,?,?) ON CONFLICT(url,key) DO UPDATE SET position=excluded.position',
                           [(url, key, link, pos) for pos, (key, link) in enumerate(ordered)])
            db.executemany('UPDATE checked_links SET state="unsupported",checked=?,lease_until=0 WHERE url=? AND key=?', unsupported)
            db.execute('DELETE FROM checked_links WHERE url=? AND key NOT IN (SELECT key FROM current_keys)', (url,))
            if self.shared:
                db.execute('DELETE FROM public.source_observations WHERE node=? AND url=? AND key NOT IN (SELECT key FROM checked_links WHERE url=? AND state="ok")', (self.node, url, url))
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
            row = db.execute('SELECT * FROM checked_links WHERE url=? AND state!="unsupported" AND checked<? AND lease_until<? ORDER BY checked,position LIMIT 1', (url, now - CYCLE, now)).fetchone()
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

    def peer_ids(self):
        if self.cluster is None:
            return None
        return {n['id'] for n in self.cluster.get_nodes() if n['id'] != self.cluster.id}

    def combined(self, url):
        cutoff = time.time() - TTL
        with self.connect() as db:
            local = db.execute('SELECT link,country,key,checked FROM checked_links WHERE url=? AND state="ok" AND checked>? ORDER BY position', (url, cutoff)).fetchall()
            table = 'public.source_observations' if self.shared else 'checked_peer_links'
            remote = db.execute('SELECT node,link,country,key,checked FROM ' + table + ' WHERE url=? AND checked>? ORDER BY node,key', (url, cutoff)).fetchall()
        allowed = self.peer_ids()
        merged = {r['key']: dict(r) for r in local}
        for row in remote:
            if allowed is not None and row['node'] not in allowed:
                continue
            old = merged.get(row['key'])
            if old is None or row['checked'] > old['checked']:
                merged[row['key']] = dict(row)
        return list(merged.values())

    def body(self, url):
        rows = self.combined(url)
        return subs._b64list([subs._apply_name(r['link'], PREFIX + r['country'] + ' · ' + r['key'][:8]) for r in rows]), {}

    def snapshot(self):
        # Only our own observations: never re-export imported successes.
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            rows = db.execute('SELECT url,key,link,checked,country FROM checked_links WHERE state="ok" AND checked>? ORDER BY url,key', (time.time() - TTL,)).fetchall()
            stamp = time.time()
        return {'version': 1, 'stamp': stamp, 'links': [dict(r) for r in rows]}

    def merge_snapshot(self, node, doc):
        if doc.get('version') != 1 or not isinstance(doc.get('links'), list):
            raise ValueError('invalid_snapshot')
        stamp = float(doc['stamp'])
        now = time.time()
        if not 0 < stamp <= now + 300:
            raise ValueError('invalid_snapshot_time')
        records = []
        for row in doc['links']:
            link, url, key = row['link'], row['url'], row['key']
            checked = float(row['checked'])
            if not isinstance(url, str) or not isinstance(link, str) or len(link) > 16384:
                raise ValueError('invalid_snapshot_link')
            if hashlib.sha256(link.encode()).hexdigest() != key or not re.fullmatch('[A-Z]{2}', row['country']):
                raise ValueError('invalid_snapshot_link')
            if not 0 < checked <= min(stamp, now + 300):
                raise ValueError('invalid_check_time')
            if checked > now - TTL:
                records.append((node, url, key, link, checked, row['country']))
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT stamp FROM checked_peer_snapshots WHERE node=?', (node,)).fetchone()
            if old and old['stamp'] >= stamp:
                return
            # A failed recheck removes only this node's contribution.
            db.execute('DELETE FROM checked_peer_links WHERE node=?', (node,))
            db.executemany('INSERT INTO checked_peer_links VALUES(?,?,?,?,?,?)', records)
            db.execute('INSERT OR REPLACE INTO checked_peer_snapshots VALUES(?,?)', (node, stamp))

    def sync_once(self):
        if self.cluster is None or self.shared:
            return
        nodes = [n for n in self.cluster.get_nodes() if n['id'] != self.cluster.id]
        for node in nodes:
            if self.stop.is_set():
                return
            try:
                base = self.cluster._peer_base(node)
                if base:
                    self.merge_snapshot(node['id'], self.cluster._http(base, '/cluster/source-checks', timeout=15))
            except Exception:
                # An unreachable/older peer cannot erase its still-fresh results.
                pass
        allowed = {n['id'] for n in nodes}
        with self.connect() as db:
            for row in db.execute('SELECT node FROM checked_peer_snapshots').fetchall():
                if row['node'] not in allowed:
                    db.execute('DELETE FROM checked_peer_links WHERE node=?', (row['node'],))
                    db.execute('DELETE FROM checked_peer_snapshots WHERE node=?', (row['node'],))
            db.execute('DELETE FROM checked_peer_links WHERE checked<?', (time.time() - TTL,))

    def sync_run(self):
        while not self.stop.is_set():
            try:
                self.sync_once()
            except Exception:
                pass
            self.stop.wait(60)

    def status(self, url):
        with self.connect() as db:
            rows = db.execute('SELECT state,count(*) AS n FROM checked_links WHERE url=? GROUP BY state', (url,)).fetchall()
            fresh = db.execute('SELECT count(*) FROM checked_links WHERE url=? AND state="ok" AND checked>?', (url, time.time() - TTL)).fetchone()[0]
            due = db.execute('SELECT count(*) FROM checked_links WHERE url=? AND state!="unsupported" AND checked<?', (url, time.time() - CYCLE)).fetchone()[0]
            source = db.execute('SELECT error FROM checked_sources WHERE url=?', (url,)).fetchone()
        counts = {r['state']: r['n'] for r in rows}
        recent = [t for t, u in list(self.samples) if u == url and t > time.time() - 300]
        rate = (len(recent) - 1) / max(1, time.time() - recent[0]) if len(recent) > 1 else 0
        return {'total': sum(counts.values()), 'working': len(self.combined(url)), 'local_working': fresh, 'pending': counts.get('pending', 0),
                'unsupported': counts.get('unsupported', 0), 'failed': counts.get('failed', 0),
                'due': due, 'cycle_minutes': CYCLE // 60, 'per_minute': round(rate * 60),
                'eta_minutes': round(due / rate / 60) if rate else None,
                'error': self.engine_error or ('Нужен mihomo на этом узле' if not core_path() else (source['error'] if source else ''))}

    def claim_batch(self, urls, limit):
        if not urls:
            return []
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            marks = ','.join('?' for _ in urls)
            now = time.time()
            rows = db.execute(f'SELECT * FROM checked_links WHERE url IN ({marks}) AND state!="unsupported" AND checked<? AND lease_until<? ORDER BY checked,position LIMIT ?', (*urls, now - CYCLE, now, limit)).fetchall()
            db.executemany('UPDATE checked_links SET lease_until=? WHERE url=? AND key=?',
                           [(now + LEASE_SECONDS, r['url'], r['key']) for r in rows])
        return [dict(r) for r in rows]

    def record(self, row, state, result):
        with self.connect() as db:
            db.execute('UPDATE checked_links SET checked=?,state=?,country=?,exit_ip=?,lease_until=0 WHERE url=? AND key=?',
                       (time.time(), state, result.get('country', ''), result.get('exit_ip', ''), row['url'], row['key']))
            if self.shared:
                if state == 'ok':
                    db.execute('INSERT INTO public.source_observations(node,url,key,link,checked,country) VALUES(?,?,?,?,?,?) ON CONFLICT(node,url,key) DO UPDATE SET link=excluded.link,checked=excluded.checked,country=excluded.country', (self.node, row['url'], row['key'], row['link'], time.time(), result['country']))
                else:
                    db.execute('DELETE FROM public.source_observations WHERE node=? AND url=? AND key=?', (self.node, row['url'], row['key']))
        self.samples.append((time.time(), row['url']))

    def run(self):
        from probe_runtime import BatchEngine, EngineUnavailable
        engine, refreshing, cursor = None, None, 0
        try:
            with ThreadPoolExecutor(max_workers=1, thread_name_prefix='feed-refresh') as refresh_pool:
                while not self.stop.is_set():
                    rows = []
                    try:
                        urls = list(dict.fromkeys(s.get('url', '').strip() for s in self.store.get_config().get('sources', []) if is_unsafe(s) and s.get('url')))
                        if refreshing is None or refreshing.done():
                            if refreshing is not None:
                                refreshing.result()
                            refreshing = refresh_pool.submit(self.refresh, urls[cursor % len(urls)]) if urls else None
                            cursor += 1
                        if not core_path():
                            raise EngineUnavailable('Нужен mihomo на этом узле')
                        rows = self.claim_batch(urls, CONCURRENCY)
                        if rows:
                            if engine is None:
                                engine = BatchEngine(core_path(), TIMEOUT)
                            engine.run(rows, self.record, self.stop)
                        self.engine_error = ''
                        with self.connect() as db:
                            existing = [r[0] for r in db.execute('SELECT url FROM checked_sources')]
                            for old in set(existing) - set(urls):
                                db.execute('DELETE FROM checked_links WHERE url=?', (old,))
                                db.execute('DELETE FROM checked_sources WHERE url=?', (old,))
                                if self.shared:
                                    db.execute('DELETE FROM public.source_observations WHERE node=? AND url=?', (self.node, old))
                    except Exception as exc:
                        self.engine_error = str(exc) if isinstance(exc, EngineUnavailable) else 'Сбой проверки; очередь будет повторена'
                        if engine:
                            engine.close()
                            engine = None
                    finally:
                        if rows:
                            try:
                                with self.connect() as db:
                                    db.executemany('UPDATE checked_links SET lease_until=0 WHERE url=? AND key=?', [(r['url'], r['key']) for r in rows])
                            except database.DatabaseUnavailable:
                                pass  # Lease expiry recovers claims when the database returns.
                    self.stop.wait(5 if self.engine_error else (.05 if rows else 1))
        finally:
            if engine:
                engine.close()

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
        if not self.shared and self.cluster is not None and (not self.sync_thread or not self.sync_thread.is_alive()):
            self.sync_thread = threading.Thread(target=self.sync_run, daemon=True, name='source-check-sync')
            self.sync_thread.start()
        if not self.thread or not self.thread.is_alive():
            self.thread = threading.Thread(target=self.run, daemon=True, name='source-checker')
            self.thread.start()
