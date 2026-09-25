"""Integration tests. TEST_DATABASE_URL must name a DISPOSABLE PostgreSQL database."""
import os
import unittest
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import tempfile
from pathlib import Path
import sqlite3
import time

# Never use a production DATABASE_URL implicitly.
url = os.environ.get('TEST_DATABASE_URL')
os.environ['DATABASE_URL'] = url or ''
import database
import store
import personal
import source_checks
import subscriptions
import cluster


@unittest.skipUnless(url, 'Set TEST_DATABASE_URL to a disposable PostgreSQL database')
class SharedDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.a = store.Store(origin='test-a')
        self.b = store.Store(origin='test-b')
        self.ra = personal.Registry('unused')
        self.rb = personal.Registry('unused')
        self.ca = source_checks.Checker('unused', self.a)
        self.cb = source_checks.Checker('unused', self.b)
        with database.connect('') as db:
            for table in ('personal_links','personal_limits','device_seen','admin_sessions','source_observations'):
                db.execute('DELETE FROM ' + table)
            for schema in (self.ca.schema, self.cb.schema):
                for table in ('checked_links','checked_sources'):
                    db.execute('DELETE FROM ' + schema + '.' + table)
        self.a.put('config', store.DEFAULT_CONFIG)
        self.a.put('members', store.DEFAULT_MEMBERS)

    def test_parallel_config_updates_are_not_lost_and_rollback(self):
        def increment(i):
            node = self.a if i % 2 else self.b
            node.update_config(lambda cfg: cfg.update(counter=cfg.get('counter', 0) + 1))
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(increment, range(40)))
        self.assertEqual(self.b.get_config()['counter'], 40)
        def fail(cfg):
            cfg['counter'] = 900
            raise ValueError('rollback')
        with self.assertRaises(ValueError):
            self.a.update_config(fail)
        self.assertEqual(self.b.get_config()['counter'], 40)
        self.assertFalse(self.a.merge_remote('config', {'data':{},'version':9999}))
        self.assertEqual(self.b.get_config()['counter'], 40)

    def test_concurrent_member_registration_and_blocks(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: (self.a if i%2 else self.b).upsert_member(str(i), {'enabled':True}, str(i)), range(20)))
        self.assertEqual(len(self.a.get_members()), 20)
        self.a.update_config(lambda c: c.update(blocked_devices=[{'route_id':'route','device':'hwid'}]))
        self.assertTrue(self.b.is_device_blocked('route', 'hwid'))

    def test_personal_claim_race_across_nodes_and_shared_limits(self):
        item = self.ra.create('route','Name','MyPhone',['id'],contact='@telegram')
        def claim(i):
            try:
                return (self.ra if i%2 else self.rb).access('route','myphone',hwid='device-'+str(i))
            except personal.PersonalError as exc:
                return exc.status
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(claim, range(8)))
        self.assertEqual(sum(isinstance(x, dict) for x in outcomes), 1)
        self.assertEqual(self.rb.access('route','MYPHONE',token=item['token'])['contact'], '@telegram')
        with self.assertRaises(personal.PersonalError):
            self.rb.create('route','Other','myphone',['id'])
        self.ra.limit('ip',1)
        with self.assertRaises(personal.PersonalError):
            self.rb.limit('ip',1)

    def test_stats_count_once_and_keep_nodes(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: (self.a if i%2 else self.b).record_device('r','h','','','ip',personal_name='Name',personal_contact='@contact'),range(40)))
        service = cluster.Cluster(self.b, identity={'id':'test-b'})
        with patch.object(service, '_http', side_effect=AssertionError('no peer sync')):
            stats = service.cluster_stats()
        self.assertEqual(stats['r']['requests'],40)
        self.assertEqual(stats['r']['devices'][0]['nodes'],['test-a','test-b'])
        self.assertEqual(stats['r']['devices'][0]['personal_contact'],'@contact')
        self.a.reset_stats('r')
        self.assertEqual(self.b.get_stats_rows(), [])

    def test_checks_visible_immediately_without_peer_sync(self):
        feed='https://feed.example'
        links=b'trojan://password@1.1.1.1:443\nvless://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@8.8.8.8:443'
        for checker in (self.ca,self.cb):
            checker.ingest(feed,links)
        a=self.ca.claim_batch([feed],2);b=self.cb.claim_batch([feed],2)
        self.assertEqual(len(a),2)
        self.assertEqual(len(b),2, 'each network must have its own queue')
        self.ca.record(a[0],'ok',{'country':'NL'})
        self.cb.record(b[1],'ok',{'country':'DE'})
        self.cb.record(b[0],'failed',{})
        self.assertEqual(len(self.cb.combined(feed)),2)
        self.assertEqual(len(self.ca.combined(feed)),2)
        self.ca.record(a[0],'failed',{})
        self.assertEqual(len(self.cb.combined(feed)),1)
        self.cb.ingest(feed,links.splitlines()[0])
        self.assertEqual(self.ca.combined(feed),[])

    def test_two_http_processes_share_sessions_and_personal_links(self):
        import subprocess
        import sys
        import json
        import urllib.request
        import urllib.error
        import graph
        link = 'trojan://password@1.1.1.1:443#Test'
        graph.add_route(self.a, '/shared-test', 'Shared', [link], 'merge', access='private')
        route = graph.get_routes(self.a)[0]
        items = personal.catalog(subscriptions.build_route_response(route, graph.resolve_links_spec(self.a, route))[0])
        self.ra.create(route['id'],'Alice','phone',[items[0]['id']])
        script = """
import json, threading
from http.server import ThreadingHTTPServer
import sub_server as app
admin=ThreadingHTTPServer(('127.0.0.1',0),app.AdminHandler)
sub=ThreadingHTTPServer(('127.0.0.1',0),app.SubHandler)
token,csrf=app.create_session()
print(json.dumps({'admin':admin.server_port,'sub':sub.server_port,'token':token}),flush=True)
threading.Thread(target=sub.serve_forever,daemon=True).start()
admin.serve_forever()
"""
        processes=[]
        try:
            peers=[]
            for node in ('http-a','http-b'):
                env={**os.environ,'DATABASE_URL':url,'NODE_ID':node,'CLUSTER_SECRET':'test-secret','ADMIN_PASSWORD':'test-password'}
                proc=subprocess.Popen([sys.executable,'-u','-c',script],env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
                processes.append(proc)
                peers.append(json.loads(proc.stdout.readline()))
            # Login issued by process A is accepted by process B.
            request=urllib.request.Request('http://127.0.0.1:'+str(peers[1]['admin'])+'/',headers={'Cookie':'session='+peers[0]['token']})
            with urllib.request.urlopen(request,timeout=10) as response:
                self.assertTrue('<title>Граф — Sub Cluster</title>' in response.read().decode())
            def fetch(peer, hwid):
                request=urllib.request.Request('http://127.0.0.1:'+str(peer['sub'])+'/shared-test/phone',headers={'X-Hwid':hwid,'User-Agent':'Happ/1.0'})
                with urllib.request.urlopen(request,timeout=10) as response:
                    return subscriptions.extract_links(response.read())
            self.assertTrue(any('password@1.1.1.1' in x for x in fetch(peers[0],'device-A')))
            self.assertTrue(any('password@1.1.1.1' in x for x in fetch(peers[1],'device-A')))
            self.assertFalse(any('password@1.1.1.1' in x for x in fetch(peers[1],'device-B')))
        finally:
            for proc in processes:
                proc.terminate()
                proc.wait(timeout=5)
                proc.stdout.close()

    def test_shared_admin_sessions(self):
        database.session_put('secret-token',time.time()+60,'csrf')
        self.assertEqual(database.session_get('secret-token')['csrf'],'csrf')
        database.session_delete('secret-token')
        self.assertIsNone(database.session_get('secret-token'))
        database.login_register('test-ip',True,2,60)
        database.login_register('test-ip',False,2,60)
        database.login_register('test-ip',False,2,60)
        self.assertGreater(database.login_blocked('test-ip'),0)
        database.login_register('test-ip',True,2,60)
        self.assertEqual(database.login_blocked('test-ip'),0)

    def test_pool_recovers_after_lost_connections(self):
        import psycopg
        self.a.update_config(lambda cfg: cfg.update(persisted='yes'))
        with psycopg.connect(url,autocommit=True) as admin:
            admin.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='sub-cluster' AND pid != pg_backend_pid()")
        deadline = time.monotonic() + 30
        while True:
            try:
                self.assertEqual(self.b.get_config()['persisted'],'yes')
                break
            except database.DatabaseUnavailable:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.2)

    def test_migration_conflict_rolls_back_authoritative_config(self):
        import migrate_shared_db
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'legacy.db')
            with patch.object(database,'DATABASE_URL',''):
                legacy=store.Store(path,origin='migration-conflict')
                legacy.update_config(lambda c:c.update(migration_marker='preserved'))
                personal.Registry(path).create('conflict','Alice','phone',['id'])
                legacy.close()
            self.ra.create('conflict','Bob','phone',['different'])
            with database.connect('') as db:
                db.execute("UPDATE kv SET version=0 WHERE key IN ('config','failover')")
                db.execute('DROP TABLE IF EXISTS sqlite_imports')
                db.execute('DROP SCHEMA IF EXISTS '+database.schema_for('migration-conflict')+' CASCADE')
            with self.assertRaises(ValueError):
                migrate_shared_db.import_snapshot(path,'migration-conflict',True)
            self.assertNotIn('migration_marker',self.b.get_config())
            with database.connect('') as db:
                db.execute("DELETE FROM personal_links WHERE route='conflict'")
            migrate_shared_db.import_snapshot(path,'migration-conflict',True)
            self.assertEqual(self.b.get_config()['migration_marker'],'preserved')

    def test_migration_preserves_private_links_checks_and_is_idempotent(self):
        import migrate_shared_db
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'legacy.db')
            with patch.object(database, 'DATABASE_URL', ''):
                legacy=store.Store(path,origin='migration-test')
                registry=personal.Registry(path)
                item=registry.create('migrated','Alice','phone',['id'],contact='@alice')
                registry.access('migrated','phone',hwid='bound-device')
                legacy.record_device('migrated','bound-device','','','',personal_name='Alice',personal_contact='@alice')
                check=source_checks.Checker(path,legacy)
                check.ingest('https://legacy.example',b'trojan://password@1.1.1.1:443')
                row=check.claim_batch(['https://legacy.example'],1)[0]
                check.record(row,'ok',{'country':'NL'})
                legacy.close()
            with database.connect('') as db:
                db.execute('DROP TABLE IF EXISTS sqlite_imports')
                db.execute('DROP SCHEMA IF EXISTS ' + database.schema_for('migration-test') + ' CASCADE')
            self.assertEqual(migrate_shared_db.import_snapshot(path,'migration-test'),'imported')
            self.assertEqual(migrate_shared_db.import_snapshot(path,'migration-test'),'already imported')
            self.assertEqual(self.rb.access('migrated','phone',token=item['token'])['contact'],'@alice')
            with self.assertRaises(personal.PersonalError):
                self.rb.access('migrated','phone',hwid='other-device')
            self.assertEqual(self.b.get_stats()['migrated']['requests'],1)
            self.assertEqual(len(self.ca.combined('https://legacy.example')),1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
