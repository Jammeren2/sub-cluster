"""Regression tests for cross-node upstream device identity."""
import os
import subprocess
import sys
import unittest

from subscriptions import upstream_hwid


class UpstreamIdentityTest(unittest.TestCase):
    def test_shared_identity_across_nodes_and_processes(self):
        identities = []
        for node in ('node_main', 'RU-Jamm'):
            env = {**os.environ, 'CLUSTER_SECRET': 'test-cluster-secret',
                   'NODE_ID': node, 'HAPP_HWID': '', 'HAPP_DEVICE_MODEL': '',
                   'HAPP_UA': '', 'HAPP_VERSION': ''}
            identities.append(subprocess.check_output(
                [sys.executable, '-c', 'import json,subscriptions; print(json.dumps(subscriptions.UPSTREAM_HEADERS,sort_keys=True))'],
                env=env, text=True))
        self.assertEqual(*identities)
        self.assertIn('DESKTOP-0000000_x86_64', identities[0])
        self.assertNotIn('test-cluster-secret', identities[0])

    def test_override_preserves_existing_provider_binding(self):
        self.assertEqual(upstream_hwid({'CLUSTER_SECRET': 'secret', 'HAPP_HWID': 'existing-device'}), 'existing-device')

    def test_clusters_are_distinct(self):
        self.assertNotEqual(upstream_hwid({'CLUSTER_SECRET': 'a'}), upstream_hwid({'CLUSTER_SECRET': 'b'}))


if __name__ == '__main__':
    unittest.main()
