#!/usr/bin/env python3
"""Run inside an app container with its normal environment; preview unless --apply."""
import argparse
import copy
import json
import os

import cluster
import dns_providers
import graph
import secretbox
from store import Store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain', required=True)
    parser.add_argument('--two-node', action='store_true', help='Explicitly allow DNS takeover without a majority in a two-node cluster')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--activate-here', action='store_true', help='Also reconcile the selected domain to this healthy node now')
    args = parser.parse_args()
    if args.activate_here and not args.apply:
        parser.error('--activate-here requires --apply')
    store = Store(origin=cluster.NODE_ID)
    cl = cluster.Cluster(store)
    nodes = cl.get_nodes()
    if args.two_node and len(nodes) != 2:
        parser.error('--two-node requires exactly two enabled registered nodes')
    if len(nodes) == 2 and not args.two_node:
        parser.error('Two nodes require explicit --two-node; one survivor cannot form a majority')
    settings = store.get_settings()
    domains = copy.deepcopy(graph.domain_list(settings))
    selected = [d for d in domains if graph.domain_fqdn(d) == args.domain.lower().rstrip('.')]
    if len(selected) != 1 or not selected[0].get('enabled', True):
        parser.error('Select an existing enabled subscription domain from Settings')
    domain = selected[0]
    username, password = os.environ.get('REGRU_USERNAME'), os.environ.get('REGRU_PASSWORD')
    if username or password:
        if not username or not password or not secretbox.crypto_ready():
            parser.error('Both REGRU variables and a working SECRET_KEY are required to save credentials securely')
        domain.update(regru_username=username, regru_password_enc=secretbox.encrypt(password))
    provider, error = dns_providers.provider_from_domain(domain, secretbox.decrypt)
    if error:
        parser.error(error + '; configure the domain credentials or provide REGRU_USERNAME/REGRU_PASSWORD privately')
    if not cl._self_enabled() or not cl.public_ip or not cl._subscription_ready(domain, {'public_ip': cl.public_ip}):
        parser.error('This node must be registered, enabled and serving the subscription HTTPS health check')
    plan = {'domain': graph.domain_fqdn(domain), 'node': cl.id, 'public_ip': cl.public_ip,
            'failover_enabled': True, 'require_quorum': not args.two_node, 'preempt': False,
            'poll_interval': 10, 'fail_threshold': 3, 'cooldown': 60,
            'enabled_subscription_domains': [graph.domain_fqdn(d) for d in graph.enabled_domains(settings)],
            'apply': args.apply, 'activate_here': args.activate_here}
    print(json.dumps(plan, ensure_ascii=False, indent=2))
    if not args.apply:
        return
    def configure(cfg):
        s = cfg.setdefault('settings', {})
        for key in ('failover_enabled', 'require_quorum', 'preempt', 'poll_interval', 'fail_threshold', 'cooldown'):
            s[key] = plan[key]
        # Update only the selected domain's credentials, preserving concurrent edits elsewhere.
        existing = s.setdefault('dns', {}).get('domains', [])
        target = next(d for d in existing if d['id'] == domain['id'])
        if username:
            target.update(regru_username=domain['regru_username'], regru_password_enc=domain['regru_password_enc'])
    store.update_config(configure)
    cl.clear_pin()
    if args.activate_here:
        default = graph.default_domain(store.get_settings()) or {}
        if not cl.seize_domain(domain, domain['id'] == default.get('id'), by='manual-restore'):
            raise SystemExit('Settings saved, but REG.RU did not confirm the DNS change; inspect failover history')
    print('DNS failover enabled. DNS cache expiry and database availability remain separate requirements.')


if __name__ == '__main__':
    main()
