"""One reusable mihomo process, bounded asynchronous probes, no direct fallback."""
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


class EngineUnavailable(RuntimeError):
    pass


def reserve_port():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    return sock


async def response_body(reader):
    header = await reader.readuntil(b'\r\n\r\n')
    if len(header) > 16384 or header.split(b' ', 2)[1] != b'200':
        raise ValueError('http_status')
    headers = {}
    for line in header.decode('latin1').split('\r\n')[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.lower()] = value.strip()
    if headers.get('transfer-encoding', '').lower() == 'chunked':
        body = bytearray()
        while True:
            size = int((await reader.readline()).split(b';', 1)[0].strip(), 16)
            if not size:
                return bytes(body)
            if size < 0 or len(body) + size > 16384:
                raise ValueError('response_too_large')
            body.extend(await reader.readexactly(size))
            if await reader.readexactly(2) != b'\r\n':
                raise ValueError('bad_chunk')
    if 'content-length' in headers:
        size = int(headers['content-length'])
        if not 0 <= size <= 16384:
            raise ValueError('response_too_large')
        return await reader.readexactly(size)
    body = bytearray()
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            return bytes(body)
        body.extend(chunk)
        if len(body) > 16384:
            raise ValueError('response_too_large')


class BatchEngine:
    def __init__(self, core, timeout=8):
        self.core, self.timeout = core, timeout
        self.directory = tempfile.TemporaryDirectory(prefix='sub-probes-')
        self.secret, self.password = secrets.token_hex(24), secrets.token_hex(24)
        sock = reserve_port()
        self.controller = sock.getsockname()[1]
        sock.close()
        self.process = None
        self.context = ssl.create_default_context()
        self.loop = asyncio.new_event_loop()
        self.dns_pool = ThreadPoolExecutor(max_workers=16, thread_name_prefix='probe-dns')
        self.loop.set_default_executor(self.dns_pool)
        self.dns_cache = {}
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def base_config(self):
        return {'external-controller': f'127.0.0.1:{self.controller}', 'secret': self.secret,
                'allow-lan': False, 'bind-address': '127.0.0.1', 'mode': 'rule',
                'log-level': 'silent', 'ipv6': True, 'rules': ['MATCH,REJECT'],
                'profile': {'store-selected': False, 'store-fake-ip': False}}

    def api(self, method, path, data=None):
        req = urllib.request.Request(f'http://127.0.0.1:{self.controller}' + path,
            data=json.dumps(data).encode() if data is not None else None, method=method,
            headers={'Authorization': 'Bearer ' + self.secret, 'Content-Type': 'application/json'})
        with self.opener.open(req, timeout=5) as response:
            return response.read(65536)

    def start(self):
        if self.process is not None and self.process.poll() is None:
            return
        path = Path(self.directory.name) / 'config.json'
        path.write_text(json.dumps(self.base_config()))
        path.chmod(0o600)
        env = {**os.environ, 'GOMAXPROCS': '2', 'GOMEMLIMIT': '384MiB'}
        self.process = subprocess.Popen([self.core, '-d', self.directory.name, '-f', str(path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                self.api('GET', '/version')
                return
            except (OSError, urllib.error.URLError):
                time.sleep(.05)
        raise EngineUnavailable('Не удалось запустить движок проверки')

    async def resolve(self, host):
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            pass
        entry = self.dns_cache.get(host)
        if entry and entry[0] > time.monotonic():
            return await asyncio.shield(entry[1])
        async def lookup():
            try:
                result = await asyncio.wait_for(self.loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), 3)
                return list(dict.fromkeys(x[4][0] for x in result))
            except Exception:
                return []
        task = asyncio.create_task(lookup())
        self.dns_cache[host] = (time.monotonic() + 300, task)
        if len(self.dns_cache) > 20000:
            self.dns_cache = {h: e for h, e in self.dns_cache.items() if e[0] > time.monotonic()}
        return await asyncio.shield(task)

    async def prepare(self, rows, record):
        import source_checks as checks
        async def one(row):
            try:
                p = checks.proxy_config(row['link'])
                checks.validate_proxy(p)
            except Exception:
                record(row, 'unsupported', {})
                return None
            addresses = await self.resolve(p['server'])
            if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):
                record(row, 'failed', {})
                return None
            return row, checks.pin_proxy(p, addresses)
        return [item for item in await asyncio.gather(*(one(row) for row in rows)) if item is not None]

    def configure(self, prepared, record):
        """Core rejects malformed entries before making any network connections."""
        sockets = [reserve_port() for _ in prepared]
        entries = [(row, dict(proxy), sock.getsockname()[1]) for (row, proxy), sock in zip(prepared, sockets)]
        for sock in sockets:
            sock.close()
        while entries:
            config = self.base_config()
            config['proxies'], config['listeners'] = [], []
            for i, (_, p, port) in enumerate(entries):
                p['name'] = 'probe-' + str(i)
                config['proxies'].append(p)
                config['listeners'].append({'name': 'in-' + str(i), 'type': 'http', 'listen': '127.0.0.1',
                    'port': port, 'proxy': p['name'], 'users': [{'username': 'probe', 'password': self.password}]})
            try:
                self.api('PUT', '/configs?force=true', {'payload': json.dumps(config, ensure_ascii=False)})
                return entries
            except urllib.error.HTTPError as exc:
                # Never log the raw error: it can contain a server/password.
                message = exc.read(65536).decode(errors='replace')
                exc.close()
                match = re.search(r'proxy (\d+):', message)
                if exc.code == 400 and match and int(match[1]) < len(entries):
                    row, _, _ = entries.pop(int(match[1]))
                    record(row, 'unsupported', {})
                    continue
                raise EngineUnavailable('Ошибка настройки движка проверки') from None
            except (OSError, urllib.error.URLError):
                raise EngineUnavailable('Движок проверки недоступен') from None
        return []

    async def request(self, port):
        writer = None
        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', port, limit=32768)
            auth = base64.b64encode(('probe:' + self.password).encode()).decode()
            writer.write(('CONNECT www.cloudflare.com:443 HTTP/1.1\r\nHost: www.cloudflare.com:443\r\n'
                          'Proxy-Authorization: Basic ' + auth + '\r\n\r\n').encode())
            await writer.drain()
            header = await reader.readuntil(b'\r\n\r\n')
            if header.split(b' ', 2)[1] != b'200':
                raise ValueError('proxy_connect_failed')
            await writer.start_tls(self.context, server_hostname='www.cloudflare.com', ssl_handshake_timeout=self.timeout)
            writer.write(b'GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n')
            await writer.drain()
            body = await response_body(reader)
            trace = dict(line.split('=', 1) for line in body.decode().splitlines() if '=' in line)
            country, exit_ip = trace.get('loc', ''), trace.get('ip', '')
            if not re.fullmatch('[A-Z]{2}', country) or not ipaddress.ip_address(exit_ip).is_global:
                raise ValueError('invalid_exit_response')
            return {'country': country, 'exit_ip': exit_ip}
        finally:
            if writer:
                writer.transport.abort()

    async def check_entries(self, entries, record, stop):
        async def one(row, port):
            if stop.is_set():
                return
            try:
                result = await asyncio.wait_for(self.request(port), self.timeout)
            except Exception:
                record(row, 'failed', {})
            else:
                record(row, 'ok', result)
        await asyncio.gather(*(one(row, port) for row, _, port in entries))

    def run(self, rows, record, stop):
        self.start()
        prepared = self.loop.run_until_complete(self.prepare(rows, record))
        if prepared and not stop.is_set():
            entries = self.configure(prepared, record)
            self.loop.run_until_complete(self.check_entries(entries, record, stop))

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        for task in asyncio.all_tasks(self.loop):
            task.cancel()
        self.loop.run_until_complete(asyncio.sleep(0))
        self.loop.close()
        self.dns_pool.shutdown(wait=False, cancel_futures=True)
        self.directory.cleanup()
