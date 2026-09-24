"""No-network tests for queue persistence, filtering and unsafe provenance."""
import base64
import json
import os
from pathlib import Path
import tempfile
import time
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
