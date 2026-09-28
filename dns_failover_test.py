"""Offline regression tests: python3 -m unittest dns_failover_test -v."""
import os
import tempfile
import unittest
import io
from contextlib import redirect_stdout
from unittest.mock import patch, MagicMock

os.environ['DATABASE_URL'] = ''
import cluster
import dns_providers
from store import Store
import configure_dns_failover


class FakeRegRu(dns_providers.RegRuProvider):
    def __init__(self, addresses):
        super().__init__('test', 'test')
        self.addresses = set(addresses)
        self.calls = []
        self.fail = None

    def _call(self, method, data):
        self.calls.append((method, data))
        if method == self.fail:
            return {'result': 'error', 'error_code': 'TEST_FAILURE'}
        if method.endswith('get_resource_records'):
            return {'result': 'success', 'answer': {'domains': [{'dname': 'example.org', 'rrs':
                [{'rectype': 'A', 'subname': 'happ', 'content': x} for x in self.addresses] +
                [{'rectype': 'TXT', 'subname': '_acme-challenge.happ', 'content': 'keep'},
                 {'rectype': 'A', 'subname': 'admin', 'content': '192.0.2.5'}]}]}}
        if method.endswith('add_alias'):
            self.addresses.add(data['ipaddr'])
        if method.endswith('remove_record'):
            assert data['subdomain'] == 'happ' and data['record_type'] == 'A'
            self.addresses.discard(data['content'])
        return {'result': 'success', 'answer': {'domains': [{'result': 'success'}]}}


class DnsTests(unittest.TestCase):
    def test_add_before_remove(self):
        p = FakeRegRu(['192.0.2.1'])
        self.assertTrue(p.set_a_record('example.org', 'happ', '192.0.2.2'))
        methods = [m for m, _ in p.calls]
        self.assertLess(methods.index('zone/add_alias'), methods.index('zone/remove_record'))
        self.assertEqual(p.addresses, {'192.0.2.2'})

    def test_failed_add_preserves_old_ip(self):
        p = FakeRegRu(['192.0.2.1']); p.fail = 'zone/add_alias'
        self.assertFalse(p.set_a_record('example.org', 'happ', '192.0.2.2'))
        self.assertEqual(p.addresses, {'192.0.2.1'})

    def test_failed_read_never_mutates(self):
        p = FakeRegRu(['192.0.2.1']); p.fail = 'zone/get_resource_records'
        self.assertFalse(p.set_a_record('example.org', 'happ', '192.0.2.2'))
        self.assertEqual(len(p.calls), 1)

    def test_failed_remove_not_reported_as_success(self):
        p = FakeRegRu(['192.0.2.1']); p.fail = 'zone/remove_record'
        self.assertFalse(p.set_a_record('example.org', 'happ', '192.0.2.2'))
        self.assertEqual(p.addresses, {'192.0.2.1', '192.0.2.2'})

    def test_reconcile_round_robin_and_idempotence(self):
        p = FakeRegRu(['192.0.2.1', '192.0.2.2'])
        self.assertTrue(p.set_a_record('example.org', 'happ', '192.0.2.2'))
        p.calls.clear()
        self.assertTrue(p.set_a_record('example.org', 'happ', '192.0.2.2'))
        self.assertTrue(all(m.endswith('get_resource_records') for m, _ in p.calls))

    def test_malformed_success_never_removes_records(self):
        p = FakeRegRu(['192.0.2.1'])
        with patch.object(p, '_call', return_value={'result': 'success', 'answer': {}}) as call:
            self.assertFalse(p.set_a_record('example.org', 'happ', '192.0.2.2'))
            self.assertEqual(call.call_count, 1)


class ClusterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(db_file=self.tmp.name+'/test.db', origin='backup')
        self.cl = cluster.Cluster(self.store, {'id': 'backup', 'public_ip': '192.0.2.2', 'seeds': []})
        self.cl.ensure_self_registered()
        self.store.upsert_member('main', {'public_ip': '192.0.2.1', 'priority': 0, 'enabled': True}, 'backup')
        self.domain = {'id': 'd', 'zone': 'example.org', 'subdomain': 'happ', 'enabled': True}
        def setup(cfg):
            cfg['settings'].update(failover_enabled=True, require_quorum=False, preempt=False, cooldown=0)
            cfg['settings']['dns']['domains'] = [self.domain]
        self.store.update_config(setup)
        self.cl._record_failover('d', True, 'main', '192.0.2.1', 'test', True, 'ok')
        self.cl.pull_peer = lambda base: None
        self.cl.ping_peer = lambda node: None
        self.cl.liveness['main'] = {'alive': True, 'last_ok': 1, 'fails': 0}

    def tearDown(self):
        self.store._conn.close()
        self.tmp.cleanup()

    def poll(self, ready):
        with patch.object(self.cl, '_subscription_ready', side_effect=lambda d, n: ready[n['id']]), \
             patch('cluster.dns_providers.provider_from_domain', return_value=(dns_providers.MockProvider(), None)), \
             patch.object(self.cl, 'seize_domain', return_value=True) as seize:
            self.cl.poll_once()
            return seize.call_args_list

    def test_admin_alive_but_subscription_503_triggers_takeover(self):
        self.assertEqual(self.poll({'main': False, 'backup': True}), [])
        self.assertEqual(self.poll({'main': False, 'backup': True}), [])
        calls = self.poll({'main': False, 'backup': True})
        self.assertEqual(len(calls), 1)

    def test_never_select_unhealthy_self(self):
        self.assertEqual(self.poll({'main': False, 'backup': False}), [])
        self.assertIsNone(self.cl.best_alive_for_domain(self.domain, self.cl.get_nodes(), set()))

    def test_healthy_active_not_preempted(self):
        self.assertEqual(self.poll({'main': True, 'backup': True}), [])

    def test_active_repairs_stale_dns_then_rate_limits_audit(self):
        self.cl._record_failover('d', True, 'backup', '192.0.2.2', 'test', True, 'ok')
        self.assertEqual(len(self.poll({'main': True, 'backup': True})), 1)
        self.assertEqual(self.poll({'main': True, 'backup': True}), [])

    def test_quorum_still_blocks_two_node_minority_when_enabled(self):
        self.store.update_config(lambda c: c['settings'].update(require_quorum=True))
        for _ in range(4):
            self.assertEqual(self.poll({'main': False, 'backup': True}), [])

    def test_failure_threshold_after_success(self):
        nodes = self.cl.get_nodes()
        with patch.object(self.cl, '_subscription_ready', return_value=True):
            self.cl._subscription_alive(self.domain, nodes, {'main', 'backup'}, 3)
        with patch.object(self.cl, '_subscription_ready', side_effect=lambda d,n: n['id']=='backup'):
            self.assertIn('main', self.cl._subscription_alive(self.domain, nodes, {'main', 'backup'}, 3))
            self.assertIn('main', self.cl._subscription_alive(self.domain, nodes, {'main', 'backup'}, 3))
            self.assertNotIn('main', self.cl._subscription_alive(self.domain, nodes, {'main', 'backup'}, 3))

    def test_https_probe_keeps_host_and_pins_tcp_destination(self):
        connection = MagicMock()
        response = connection.getresponse.return_value
        response.status, response.read.return_value = 200, b'ok'
        with patch('cluster.http.client.HTTPSConnection', return_value=connection) as factory:
            self.assertTrue(self.cl._subscription_ready(self.domain, {'public_ip': '192.0.2.2'}))
            self.assertEqual(factory.call_args.args, ('happ.example.org', 443))
            connection.request.assert_called_once_with('GET', '/healthz', headers={
                'Host': 'happ.example.org', 'Connection': 'close'})
            with patch('cluster.socket.create_connection') as connect:
                connection._create_connection(('happ.example.org', 443), 6)
                connect.assert_called_once_with(('192.0.2.2', 443), 6, None)
            response.status = 503
            self.assertFalse(self.cl._subscription_ready(self.domain, {'public_ip': '192.0.2.2'}))
            response.status, response.read.return_value = 200, b'<html>login'
            self.assertFalse(self.cl._subscription_ready(self.domain, {'public_ip': '192.0.2.2'}))

    def test_activation_preview_and_explicit_two_node_apply(self):
        before = self.store.get_config()
        argv = ['configure_dns_failover.py', '--domain', 'happ.example.org', '--two-node']
        with patch('configure_dns_failover.Store', return_value=self.store), \
             patch('configure_dns_failover.cluster.Cluster', return_value=self.cl), \
             patch.object(self.cl, '_subscription_ready', return_value=True), \
             patch('configure_dns_failover.dns_providers.provider_from_domain', return_value=(dns_providers.MockProvider(), None)), \
             patch.dict(os.environ, {'REGRU_USERNAME': '', 'REGRU_PASSWORD': ''}), redirect_stdout(io.StringIO()):
            with patch('sys.argv', argv):
                configure_dns_failover.main()
            self.assertEqual(before, self.store.get_config())
            with patch('sys.argv', argv + ['--apply']):
                configure_dns_failover.main()
            settings = self.store.get_settings()
            self.assertTrue(settings['failover_enabled'])
            self.assertFalse(settings['require_quorum'])
            self.assertFalse(settings['preempt'])


if __name__ == '__main__':
    unittest.main()
