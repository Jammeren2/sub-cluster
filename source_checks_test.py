"""No-network tests for queue persistence, filtering and unsafe provenance."""
import base64
import json
import os
from pathlib import Path
import tempfile
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch

import source_checks as checks
import subscriptions as subs
import graph
import personal
import store

VLESS = 'vless://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@vpn.example:443?security=tls#Original'
TROJAN = 'trojan://password@other.example:443#Original'


class SourceChecksTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'db.sqlite')
        self.store = store.Store(db_file=self.path, origin='test')
        self.checker = checks.Checker(self.path, self.store)
        self.url = 'https://public.example/feed'

    def tearDown(self):
        self.store._conn.close()
        self.tmp.cleanup()

    def test_protocols(self):
        b64 = lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip('=')
        vmess = 'vmess://' + b64(json.dumps({'add':'vpn.example','port':443,'id':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','net':'ws','tls':'tls','path':'/ws'}))
        raw_ssr = 'vpn.example:443:auth_sha1_v4:aes-128-cfb:tls1.2_ticket_auth:' + b64('secret') + '/?obfsparam=' + b64('example.com')
        links = [VLESS, TROJAN, vmess, 'ss://' + b64('aes-128-gcm:secret') + '@vpn.example:443',
                 'ssr://' + b64(raw_ssr), 'ssr://' + raw_ssr,
                 'hysteria://vpn.example:443?auth=secret&upmbps=10&downmbps=50',
                 'hy2://secret@vpn.example:443?sni=example.com',
                 'tuic://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa:secret@vpn.example:443']
        self.assertEqual([checks.proxy_config(x)['type'] for x in links],
                         ['vless','trojan','vmess','ss','ssr','ssr','hysteria','hysteria2','tuic'])
        self.assertEqual(checks.proxy_config(VLESS.replace('&', '&amp;'))['type'], 'vless')
        with self.assertRaises(ValueError):
            checks.proxy_config(VLESS.replace('security=tls', 'type=unknown'))

    def test_private_addresses_rejected_and_dns_pinned(self):
        with patch.object(checks.socket, 'getaddrinfo', return_value=[(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaises(ValueError):
                checks.checked_proxy(VLESS)
        with patch.object(checks.socket, 'getaddrinfo', return_value=[(2,1,6,'',('1.1.1.1',443))]):
            p = checks.checked_proxy(VLESS)
            self.assertEqual(p['server'], '1.1.1.1')
            self.assertEqual(p['servername'], 'vpn.example')

    def test_persistent_queue_and_only_successful_fresh_results(self):
        self.checker.ingest(self.url, (VLESS + '\n' + TROJAN).encode())
        self.assertEqual(subs.extract_links(self.checker.body(self.url)[0]), [])
        with patch.object(checks, 'probe', return_value={'country':'NL','exit_ip':'1.1.1.1'}):
            self.checker.check_one(self.url)
        links = subs.extract_links(self.checker.body(self.url)[0])
        self.assertEqual(len(links), 1)
        self.assertTrue(subs._frag_name(links[0]).startswith('Небезопасный · NL'))
        other = checks.Checker(self.path, self.store)
        self.assertEqual(other.next_link(self.url)['link'], TROJAN.split('#')[0])
        with patch.object(checks, 'probe', side_effect=TimeoutError):
            other.check_one(self.url)
        self.assertEqual(len(subs.extract_links(other.body(self.url)[0])), 1)
        with other.connect() as db:
            db.execute('UPDATE checked_links SET checked=?', (time.time() - checks.TTL - 1,))
        self.assertEqual(subs.extract_links(other.body(self.url)[0]), [])
        self.checker.ingest(self.url, TROJAN.encode())
        self.assertEqual(self.checker.status(self.url)['total'], 1)

    def test_protocol_round_robin_and_missing_core(self):
        self.checker.ingest(self.url, ('\n'.join([VLESS, VLESS.replace('vpn.example', 'second.example'), TROJAN])).encode())
        with self.checker.connect() as db:
            rows = db.execute('SELECT link FROM checked_links ORDER BY position').fetchall()
        self.assertTrue(rows[1]['link'].startswith('trojan'))
        with patch.object(checks, 'probe', side_effect=RuntimeError('checker_unavailable')):
            self.checker.check_one(self.url)
        self.assertEqual(self.checker.status(self.url)['pending'], 3)

    def test_graph_provenance_mirror_group_router_and_renames(self):
        data = {'sources':[{'id':'src','url':self.url,'unsafe':True},
                           {'id':'auto','type':'autoselect','label':'Auto'},
                           {'id':'router','type':'router','label':'Router'}],
                'routes':[{'id':'route','path':'/test','mode':'mirror'}],
                'edges':[{'from':'src','to':'route'}], 'node_meta':{'src':{'renames':[{'name':'Original','to':'Hidden'}]}}}
        self.assertTrue(graph.save_graph(self.store, data)[0])
        route = graph.get_routes(self.store)[0]
        body = subs._b64list([subs._apply_name(VLESS, 'Небезопасный · NL · abcd')])
        with patch.object(subs, 'checked_source_reader', return_value=(body, {})), patch.object(subs, 'fetch_upstream_cached', side_effect=AssertionError('raw feed leaked')):
            for edges in ([{'from':'src','to':'route'}],
                          [{'from':'src','to':'auto'},{'from':'auto','to':'route'}],
                          [{'from':'src','to':'router'},{'from':'router','to':'route'}]):
                data['edges'] = edges
                self.assertTrue(graph.save_graph(self.store, data)[0])
                spec = graph.resolve_links_spec(self.store, route)
                self.assertTrue(spec['unsafe'])
                result, _ = subs.build_route_response(route, spec)
                items = personal.catalog(result)
                self.assertTrue(items)
                self.assertTrue(all(x['unsafe'] for x in items))
        graph.update_route(self.store, 'route', title='Edited')
        self.assertTrue(graph.get_graph(self.store)['sources'][0]['unsafe'])

    def test_unsafe_country_changes_preserve_personal_selection(self):
        for link in (VLESS, 'vmess://' + base64.b64encode(json.dumps({'add':'vpn.example','port':443,'id':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','ps':'old'}).encode()).decode()):
            one = personal.catalog(subs._b64list([subs._apply_name(link, 'Небезопасный · NL · 1234')]))[0]
            two = personal.catalog(subs._b64list([subs._apply_name(link, 'Небезопасный · DE · 1234')]))[0]
            self.assertEqual(one['id'], two['id'])
            self.assertTrue(one['unsafe'])

    def test_empty_unsafe_router_target_blocks_instead_of_direct(self):
        with patch.object(subs, 'checked_source_reader', return_value=(b'', {})):
            cfg = subs._wrap_as_router({'src':{'kind':'auto','auto':True,'unsafe':True,
                'subs':[{'url':self.url,'unsafe':True}]}}, [], 'src', 'Unsafe')
        self.assertEqual(cfg['routing']['rules'][-1]['outboundTag'], 'block')

    def test_success_is_removed_on_failed_recheck(self):
        self.checker.ingest(self.url, VLESS.encode())
        with patch.object(checks, 'probe', return_value={'country':'NL','exit_ip':'1.1.1.1'}):
            self.checker.check_one(self.url)
        with self.checker.connect() as db:
            db.execute('UPDATE checked_links SET checked=?', (time.time() - 3700,))
        with patch.object(checks, 'probe', side_effect=TimeoutError):
            self.checker.check_one(self.url)
        self.assertEqual(subs.extract_links(self.checker.body(self.url)[0]), [])

    def test_atomic_claims_and_crash_recovery(self):
        self.checker.ingest(self.url, VLESS.encode())
        with ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(pool.map(lambda _: self.checker.next_link(self.url, claim=True), range(8)))
        self.assertEqual(sum(row is not None for row in rows), 1)
        with self.checker.connect() as db:
            db.execute('UPDATE checked_links SET lease_until=?', (time.time() - 1,))
        self.assertIsNotNone(checks.Checker(self.path, self.store).next_link(self.url, claim=True))

    def test_batch_scheduler_reuses_engine_and_obeys_limit(self):
        links = [VLESS.replace('vpn.example', f'vpn{i}.example') for i in range(7)]
        self.checker.ingest(self.url, '\n'.join(links).encode())
        self.store.update_config(lambda cfg: cfg.update(sources=[{'url':self.url,'unsafe':True}]))
        sizes, seen = [], []
        checker = self.checker
        class Engine:
            def __init__(self, *args):
                self.closed = False
            def run(self, rows, record, stop):
                sizes.append(len(rows))
                for row in rows:
                    seen.append(row['key'])
                    record(row, 'ok', {'country':'NL','exit_ip':'1.1.1.1'})
                if len(seen) == 7:
                    stop.set()
            def close(self):
                self.closed = True
        engine = Engine()
        with patch.object(checks, 'CONCURRENCY', 3), patch.object(checks, 'core_path', return_value='/core'), patch('probe_runtime.BatchEngine', return_value=engine) as factory, patch.object(checker, 'refresh'):
            checker.start()
            checker.thread.join(5)
        self.assertFalse(checker.thread.is_alive())
        factory.assert_called_once()
        self.assertTrue(engine.closed)
        self.assertEqual(sizes, [3, 3, 1])
        self.assertEqual(len(set(seen)), 7)
        self.assertEqual(checker.status(self.url)['working'], 7)

    def test_unsupported_skipped_and_half_hour_cycle(self):
        bad = VLESS.replace('security=tls', 'type=xhttp')
        self.checker.ingest(self.url, (VLESS + '\n' + bad).encode())
        self.assertEqual(self.checker.status(self.url)['unsupported'], 1)
        rows = self.checker.claim_batch([self.url], 192)
        self.assertEqual(len(rows), 1)
        self.checker.record(rows[0], 'ok', {'country':'NL','exit_ip':'1.1.1.1'})
        with self.checker.connect() as db:
            db.execute('UPDATE checked_links SET checked=? WHERE state="ok"', (time.time() - 1790,))
        self.assertEqual(self.checker.claim_batch([self.url], 192), [])
        with self.checker.connect() as db:
            db.execute('UPDATE checked_links SET checked=? WHERE state="ok"', (time.time() - 1801,))
        self.assertEqual(len(self.checker.claim_batch([self.url], 192)), 1)
        # Core-unsupported results stay excluded even when the same feed refreshes.
        self.checker.ingest(self.url, (VLESS + '\n' + bad).encode())
        self.assertEqual(self.checker.status(self.url)['unsupported'], 1)

    def test_async_timeout_is_concurrent_and_private_hosts_never_reach_core(self):
        import asyncio
        from probe_runtime import BatchEngine
        engine = BatchEngine('/unused', .05)
        try:
            result = []
            record = lambda row, state, data: result.append(state)
            async def slow(port):
                await asyncio.sleep(1)
            engine.request = slow
            started = time.monotonic()
            engine.loop.run_until_complete(engine.check_entries([({'key':i}, {}, i) for i in range(192)], record, threading.Event()))
            self.assertLess(time.monotonic() - started, .8)
            self.assertEqual(result, ['failed'] * 192)
            result.clear()
            rows = [{'link':VLESS.replace('vpn.example','127.0.0.1')}]
            prepared = engine.loop.run_until_complete(engine.prepare(rows, record))
            self.assertEqual(prepared, [])
            self.assertEqual(result, ['failed'])
        finally:
            engine.close()

    def test_engine_failure_preserves_pending_and_releases_claims(self):
        from probe_runtime import EngineUnavailable
        self.checker.ingest(self.url, VLESS.encode())
        self.store.update_config(lambda cfg: cfg.update(sources=[{'url':self.url,'unsafe':True}]))
        checker = self.checker
        class BrokenEngine:
            def __init__(self, *args):
                pass
            def run(self, rows, record, stop):
                stop.set()
                raise EngineUnavailable('Unavailable')
            def close(self):
                pass
        with patch.object(checks, 'core_path', return_value='/core'), patch('probe_runtime.BatchEngine', BrokenEngine), patch.object(checker, 'refresh'):
            checker.run()
        self.assertEqual(checker.status(self.url)['pending'], 1)
        self.assertEqual(checker.status(self.url)['failed'], 0)
        self.assertEqual(len(checker.claim_batch([self.url], 192)), 1)

    def test_core_rejects_one_entry_without_poisoning_batch(self):
        import io
        import urllib.error
        from probe_runtime import BatchEngine
        engine = BatchEngine('/unused')
        try:
            recorded, payloads = [], []
            def api(method, path, data):
                payloads.append(data['payload'])
                if len(payloads) == 1:
                    raise urllib.error.HTTPError('http://localhost', 400, 'invalid', {}, io.BytesIO(b'{"message":"proxy 0: unsupported cipher"}'))
            engine.api = api
            p = {'type':'trojan', 'server':'1.1.1.1', 'port':443, 'password':'test-😀'}
            entries = engine.configure([({'key':'bad'}, p), ({'key':'good'}, p)], lambda row, state, data: recorded.append((row['key'], state)))
            self.assertEqual(recorded, [('bad', 'unsupported')])
            self.assertEqual([r['key'] for r, _, _ in entries], ['good'])
            # Go's YAML parser cannot decode JSON surrogate-pair escapes.
            self.assertIn('😀', payloads[-1])
            config = json.loads(payloads[-1])
            self.assertEqual(config['rules'], ['MATCH,REJECT'])
            self.assertEqual(config['listeners'][0]['proxy'], config['proxies'][0]['name'])
            self.assertTrue(config['listeners'][0]['users'][0]['password'])
        finally:
            engine.close()

    def test_cluster_union_failure_isolation_expiry_and_no_echo(self):
        other_path = str(Path(self.tmp.name) / 'other.sqlite')
        other = checks.Checker(other_path, self.store)
        for checker in (self.checker, other):
            checker.ingest(self.url, (VLESS + '\n' + TROJAN).encode())
        local = self.checker.claim_batch([self.url], 2)
        remote = other.claim_batch([self.url], 2)
        result = {'country':'NL','exit_ip':'1.1.1.1'}
        self.checker.record(local[0], 'ok', result)
        self.checker.record(local[1], 'failed', {})
        other.record(remote[0], 'failed', {})
        other.record(remote[1], 'ok', result)
        snapshot = other.snapshot()
        self.checker.merge_snapshot('peer', snapshot)
        self.assertEqual(len(subs.extract_links(self.checker.body(self.url)[0])), 2)
        self.assertEqual(self.checker.status(self.url)['local_working'], 1)
        self.assertEqual(self.checker.status(self.url)['working'], 2)
        self.assertEqual(len(self.checker.snapshot()['links']), 1, 'imported results must not echo')
        # Restart retains imported successes.
        self.assertEqual(len(checks.Checker(self.path, self.store).combined(self.url)), 2)
        # Duplicate successes still produce a single link.
        other.record(remote[0], 'ok', result)
        self.checker.merge_snapshot('peer', other.snapshot())
        self.assertEqual(len(self.checker.combined(self.url)), 2)
        # A failed recheck on peer removes only its own successes.
        for row in remote:
            other.record(row, 'failed', {})
        self.checker.merge_snapshot('peer', other.snapshot())
        self.assertEqual(len(self.checker.combined(self.url)), 1)
        self.checker.merge_snapshot('peer', snapshot)  # stale replay must not resurrect
        self.assertEqual(len(self.checker.combined(self.url)), 1)
        other.record(remote[1], 'ok', result)
        self.checker.merge_snapshot('peer', other.snapshot())
        with patch.object(checks.time, 'time', return_value=time.time() + checks.TTL + 1):
            self.assertEqual(self.checker.combined(self.url), [])

    def test_cluster_sync_outage_and_disabled_peer(self):
        from unittest.mock import Mock
        self.checker.ingest(self.url, VLESS.encode())
        row = self.checker.claim_batch([self.url], 1)[0]
        self.checker.record(row, 'ok', {'country':'NL','exit_ip':'1.1.1.1'})
        snapshot = self.checker.snapshot()
        self.checker.record(row, 'failed', {})
        cluster = Mock()
        cluster.id = 'self'
        cluster.get_nodes.return_value = [{'id':'self'}, {'id':'peer'}]
        cluster._peer_base.return_value = 'https://peer.example'
        cluster._http.return_value = snapshot
        self.checker.cluster = cluster
        self.checker.sync_once()
        cluster._http.assert_called_once_with('https://peer.example', '/cluster/source-checks', timeout=15)
        self.assertEqual(len(self.checker.combined(self.url)), 1)
        cluster._http.side_effect = TimeoutError
        self.checker.sync_once()
        self.assertEqual(len(self.checker.combined(self.url)), 1)
        cluster.get_nodes.return_value = [{'id':'self'}]
        self.assertEqual(self.checker.combined(self.url), [])
        self.checker.sync_once()
        with self.checker.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM checked_peer_links').fetchone()[0], 0)

    def test_auto_seed_once_and_empty_unsafe_source(self):
        self.checker.seed_public_source()
        self.assertEqual(len(self.store.get_config()['sources']), 1)
        self.store.update_config(lambda c: c.update(sources=[]))
        self.checker.seed_public_source()
        self.assertEqual(self.store.get_config()['sources'], [])
        with patch.object(subs, 'checked_source_reader', None):
            self.assertEqual(subs.fetch_source({'url': self.url, 'unsafe': True}), (b'', {}))


if __name__ == '__main__':
    unittest.main()
