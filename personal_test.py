"""Isolated personal-subscription integration tests; no external network calls."""
import base64
import concurrent.futures
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch
from http.server import ThreadingHTTPServer

TEMP = tempfile.TemporaryDirectory(prefix='personal-tests-')
os.environ['DB_FILE'] = os.path.join(TEMP.name, 'cluster.db')
os.environ['NODE_ID'] = 'test-owner'
os.environ['CLUSTER_SECRET'] = 'test-peer-secret'
os.environ['PEERS'] = ''
import personal
import sub_server as server
import graph
import subscriptions as subs

LINK1 = 'vless://aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa@one.example:443?security=tls#One'
LINK2 = 'vless://bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb@two.example:443?security=tls#Two'


class PersonalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.http = ThreadingHTTPServer(('127.0.0.1', 0), server.SubHandler)
        cls.thread = threading.Thread(target=cls.http.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = 'http://127.0.0.1:' + str(cls.http.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown(); cls.http.server_close(); cls.thread.join()

    def setUp(self):
        server.STORE.put('config', {**server.storemod.DEFAULT_CONFIG, 'settings':json.loads(json.dumps(server.storemod.DEFAULT_CONFIG['settings'])), 'routes': [], 'sources': [], 'edges': []})
        self.path = '/s/' + os.urandom(5).hex()
        graph.add_route(server.STORE, self.path, 'Private', [LINK1, LINK2], 'merge', access='private')
        self.route = graph.get_routes(server.STORE)[0]
        self.catalog = personal.catalog(subs.build_route_response(self.route, graph.resolve_links_spec(server.STORE, self.route))[0])
        self.assertEqual(len(self.catalog), 2)

    def request(self, path=None, headers=None, data=None, method=None):
        req = urllib.request.Request(self.base + (path or self.path), headers=headers or {}, data=json.dumps(data).encode() if data is not None else None, method=method)
        try:
            with urllib.request.urlopen(req) as res:
                return res.status, res.read(), dict(res.headers)
        except urllib.error.HTTPError as res:
            with res:
                return res.code, res.read(), dict(res.headers)

    def create(self, slug=None):
        return server.PERSONAL.create(self.route['id'], 'Alice', slug or '', [self.catalog[0]['id']])

    def test_defaults_and_editor_roundtrip(self):
        graph.add_route(server.STORE, '/public', 'Public', [], 'merge')
        self.assertEqual(graph.get_routes(server.STORE)[1]['access'], 'public')
        data = graph.get_graph(server.STORE)
        data['routes'][0].pop('access')
        data['routes'][0]['personal_owner'] = 'forged-owner'
        self.assertTrue(graph.save_graph(server.STORE, data)[0])
        route = graph.get_routes(server.STORE)[0]
        self.assertEqual(route['access'], 'private')
        self.assertEqual(route['personal_owner'], server.CLUSTER.id)

    def test_private_base_notice_and_browser(self):
        status, body, headers = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(len(subs.extract_links(body)), 1)
        self.assertIn('Откройте в браузере', subs._frag_name(subs.extract_links(body)[0]))
        self.assertIn('браузере', base64.b64decode(headers['Announce'][7:]).decode())
        self.assertIn(self.base + self.path, base64.b64decode(headers['Announce'][7:]).decode())
        status, body, headers = self.request(headers={'Accept': 'text/html'})
        self.assertEqual(status, 200)
        self.assertIn(b'personal-form', body)
        self.assertNotIn(LINK1.encode(), body)
        self.assertEqual(headers['Cache-Control'], 'no-store')

    def test_browser_notice_uses_configured_subscription_url(self):
        server.STORE.update_config(lambda cfg: cfg.setdefault('settings', {}).update(dns={'domains':[
            {'id':'main','zone':'example.com','subdomain':'vpn','enabled':True,'default':True,'public_base':'https://vpn.example.com'}
        ]}))
        for suffix in ('?format=happ', '?format=clash'):
            _, _, headers = self.request(self.path + suffix, {'Host':'internal.invalid'})
            message = base64.b64decode(headers['Announce'][7:]).decode()
            self.assertIn('https://vpn.example.com' + self.path, message)
            self.assertNotIn('internal.invalid', message)
            self.assertNotIn('?format=', message)

    def test_public_hwid_gate_and_exemptions(self):
        server.STORE.update_config(lambda cfg: cfg.setdefault('settings', {}).update(require_device_hwid=True))
        graph.update_route(server.STORE, self.route['id'], access='public')
        _, body, headers = self.request(headers={'X-Forwarded-For': '203.0.113.5'})
        self.assertIn('Happ', base64.b64decode(headers['Announce'][7:]).decode())
        self.assertNotIn('one.example', base64.b64decode(body).decode())
        _, body, _ = self.request(headers={'X-Hwid': 'phone-uuid'})
        self.assertEqual(len(subs.extract_links(body)), 2)
        for ip in personal.EXEMPT_IPS:
            _, body, _ = self.request(headers={'X-Forwarded-For': ip})
            self.assertEqual(len(subs.extract_links(body)), 2)

    def test_hwid_protection_default_on_and_settings_toggle(self):
        server.STORE.update_config(lambda cfg: cfg.setdefault('settings', {}).update(require_client_version=False))
        server.STORE.update_config(lambda cfg: cfg['settings'].pop('require_device_hwid', None))
        self.assertTrue(server.STORE.get_settings()['require_device_hwid'])
        graph.update_route(server.STORE, self.route['id'], access='public')
        self.assertIn('blocked.invalid', base64.b64decode(self.request()[1]).decode())
        handler = object.__new__(server.AdminHandler)
        self.assertTrue(handler._save_settings({'domains_json':['[]']}))
        self.assertFalse(server.STORE.get_settings()['require_device_hwid'])
        self.assertEqual(len(subs.extract_links(self.request()[1])), 2)
        self.assertTrue(handler._save_settings({'domains_json':['[]'], 'require_device_hwid':['1']}))
        self.assertTrue(server.STORE.get_settings()['require_device_hwid'])
        self.assertIn('blocked.invalid', base64.b64decode(self.request()[1]).decode())
        self.assertEqual(len(subs.extract_links(self.request(headers={'X-Hwid':'phone'})[1])), 2)

    def test_hwid_validation(self):
        for value in ('', ' ', 'ip:203.0.113.7', 'IP-abc', '203.0.113.7', 'device-203.0.113.7-extra', '::1', '2001:db8::1', 'device-[2001:db8::1]', '::ffff:203.0.113.7'):
            self.assertFalse(personal.has_device_hwid(value), value)
        for value in ('phone', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'abcdef0123456789', '  Android-123  '):
            self.assertTrue(personal.has_device_hwid(value), value)

    def test_dynamic_cluster_ip_exemption(self):
        graph.update_route(server.STORE,self.route['id'],access='public')
        with patch.object(server.CLUSTER,'all_nodes',return_value=[{'public_ip':'203.0.113.99','enabled':False}]):
            self.assertEqual(len(subs.extract_links(self.request(headers={'X-Forwarded-For':'203.0.113.99'})[1])),2)
            self.assertIn('blocked.invalid',base64.b64decode(self.request(headers={'X-Forwarded-For':'203.0.113.98'})[1]).decode())
        self.assertTrue(personal.exempt_client_ip('::ffff:37.193.168.134',[]))
        self.assertTrue(personal.exempt_client_ip('2001:db8::1',[{'public_ip':'2001:0db8::1'}]))
        self.assertFalse(personal.exempt_client_ip('',[{'public_ip':''}]))

    def test_proxy_chain_and_spoofed_exemption(self):
        self.assertEqual(personal.client_ip('203.0.113.8', {'X-Forwarded-For': '37.193.168.134'}), '203.0.113.8')
        self.assertEqual(personal.client_ip('127.0.0.1', {'X-Forwarded-For': '37.193.168.134, 203.0.113.8'}), '203.0.113.8')
        self.assertFalse(personal.exempt_client_ip(personal.client_ip('203.0.113.8', {'X-Forwarded-For':'37.193.168.134'}), []))

    def test_one_device_selection_and_head(self):
        result = self.create()
        path = self.path + '/' + result['slug']
        hdr = {'X-Hwid': 'device-A', 'X-App-Version': '1.2.3'}
        self.request(path, hdr, method='HEAD')
        self.assertFalse(server.PERSONAL.access(self.route['id'], result['slug'], token=result['token'])['bound'])
        _, body, _ = self.request(path, hdr)
        self.assertEqual(len(subs.extract_links(body)), 1)
        self.assertEqual(subs.extract_links(body)[0], self.catalog[0]['value'])
        _, body2, _ = self.request(path, {**hdr, 'X-Forwarded-For': '203.0.113.10'})
        self.assertEqual(body, body2)
        _, denied, headers = self.request(path, {**hdr, 'X-Hwid': 'device-B'})
        self.assertNotEqual(body, denied)
        self.assertIn('другом устройстве', base64.b64decode(headers['Announce'][7:]).decode())

    def test_personal_title_and_route_only_announcement(self):
        link = self.create()
        path = self.path + '/' + link['slug']
        hdr = {'X-Hwid': 'phone', 'X-App-Version': '1.2.3'}
        for fmt in ('happ', 'clash'):
            graph.update_route(server.STORE, self.route['id'], title='Мой VPN', announce='Поддержка: @support')
            _, _, headers = self.request(path + '?format=' + fmt, hdr)
            self.assertEqual(base64.b64decode(headers['Profile-Title'][7:]).decode(), 'Мой VPN ● Личная')
            self.assertEqual(base64.b64decode(headers['Announce'][7:]).decode(), 'Поддержка: @support')
            graph.update_route(server.STORE, self.route['id'], announce='')
            _, _, headers = self.request(path + '?format=' + fmt, hdr)
            self.assertNotIn('Announce', headers)
        # Upstream metadata must not replace an empty route description.
        route = graph.get_routes(server.STORE)[0]
        body = subs._b64list([item['value'] for item in self.catalog])
        with patch('sub_server.subs.build_route_response', return_value=(body, {'announce': 'upstream text'})):
            response = server.personal_operation(route, {'op':'fetch','slug':link['slug'],'device':{'hwid':'phone'}})
        self.assertFalse(any(key.lower() == 'announce' for key in response['headers']))

    def test_missing_or_ip_hwid_never_claim(self):
        server.STORE.update_config(lambda cfg: cfg.setdefault('settings', {}).update(require_device_hwid=True))
        result = self.create(); path = self.path + '/' + result['slug']
        for hdr in ({'X-App-Version': '1.2.3'}, {'X-Hwid': 'ip:203.0.113.5'}, {'X-Hwid':'2001:db8::1'}, {'X-Forwarded-For': '37.193.168.134'}):
            _, body, _ = self.request(path, hdr)
            self.assertIn('blocked.invalid', base64.b64decode(body).decode())
            self.assertFalse(server.PERSONAL.access(self.route['id'], result['slug'], token=result['token'])['bound'])

    def test_parallel_claims_only_one_winner(self):
        result = self.create()
        def claim(i):
            try:
                server.PERSONAL.access(self.route['id'], result['slug'], hwid='device-'+str(i))
                return True
            except personal.PersonalError:
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(claim, range(8))), 1)

    def test_management_auth_and_update(self):
        result = self.create()
        with self.assertRaises(personal.PersonalError):
            server.PERSONAL.access(self.route['id'], result['slug'], token='wrong', selected=[])
        token = server.portal_csrf(self.route, '127.0.0.1:' + str(self.http.server_port))
        hdr = {'X-Portal-CSRF': token, 'Content-Type': 'application/json'}
        status, body, _ = self.request(headers=hdr, data={'op':'manage', 'slug':result['slug'], 'token':result['token']})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertNotIn('value', data['items'][0]); self.assertNotIn('token', data)
        status, _, _ = self.request(headers=hdr, data={'op':'update','slug':result['slug'],'token':result['token'],'selected':[self.catalog[1]['id']]})
        self.assertEqual(status, 200)
        info = server.PERSONAL.access(self.route['id'], result['slug'], token=result['token'])
        self.assertEqual(info['selected'], [self.catalog[1]['id']])
        status, _, _ = self.request(headers=hdr, data={'op':'update','slug':result['slug'],'token':result['token'],'selected':['forged']})
        self.assertEqual(status, 400)
        status, _, _ = self.request(data={'op':'manage','slug':result['slug'],'token':result['token']})
        self.assertEqual(status, 403)

    def test_turnstile_and_custom_slug(self):
        token = server.portal_csrf(self.route, '127.0.0.1:' + str(self.http.server_port))
        payload = {'op':'create','name':'Alice','slug':'my-phone','selected':[self.catalog[0]['id']], 'captcha':'token'}
        hdr = {'X-Portal-CSRF':token}
        with patch('personal.verify_turnstile', side_effect=personal.PersonalError('captcha required',403)):
            self.assertEqual(self.request(headers=hdr,data=payload)[0],403)
        with patch('personal.verify_turnstile'):
            status, body, _ = self.request(headers=hdr,data=payload)
            self.assertEqual(status,200)
            self.assertEqual(json.loads(body)['slug'],'my-phone')
            self.assertEqual(self.request(headers=hdr,data=payload)[0],409)
        with self.assertRaises(personal.PersonalError): self.create('../bad')

    def test_turnstile_fail_closed_hostname_action(self):
        from io import BytesIO
        with patch.dict(os.environ, {'TURNSTILE_SITE_KEY':'site','TURNSTILE_SECRET_KEY':'secret'}):
            for result in ({'success':False}, {'success':True,'hostname':'wrong','action':'personal_create'}, {'success':True,'hostname':'example.com','action':'wrong'}):
                with patch('urllib.request.urlopen', return_value=BytesIO(json.dumps(result).encode())):
                    with self.assertRaises(personal.PersonalError):personal.verify_turnstile('token','example.com')
            with patch('urllib.request.urlopen', return_value=BytesIO(b'{"success":true,"hostname":"example.com","action":"personal_create"}')):
                personal.verify_turnstile('token','example.com')
        with patch.dict(os.environ, {'TURNSTILE_SITE_KEY':'','TURNSTILE_SECRET_KEY':''}):
            with self.assertRaises(personal.PersonalError):personal.verify_turnstile('token','example.com')

    def test_json_groups_and_clash_preserved(self):
        config={'remarks':'Group','outbounds':[{'protocol':'freedom','tag':'direct'}]}
        items=personal.catalog(json.dumps([config]).encode())
        body,_=personal.selected_response(items,[items[0]['id']],{},'legacy','Group')
        self.assertEqual(json.loads(body),[config])
        body,_=personal.notice('Откройте в браузере',personal.OPEN_MESSAGE,'clash')
        self.assertIn(b'proxies:',body)
        self.assertNotIn(b'one.example',body)

    def test_owner_forward_and_unavailable(self):
        route={**self.route,'personal_owner':'other'}
        with patch.object(server.CLUSTER,'find_node',return_value={'cluster_url':'https://peer.example'}), patch.object(server.CLUSTER,'_http',return_value={'ok':True,'items':[]}) as call:
            self.assertTrue(server.personal_operation(route,{'op':'catalog'})['ok'])
            self.assertEqual(call.call_args.args[1],'/cluster/personal')
        with patch.object(server.CLUSTER,'find_node',return_value=None):
            with self.assertRaises(personal.PersonalError):server.personal_operation(route,{'op':'catalog'})
        with self.assertRaises(personal.PersonalError):server.personal_operation(route,{'op':'catalog'},remote=True)

    def test_disable_route_and_switch_public(self):
        result=self.create();path=self.path+'/'+result['slug']
        graph.update_route(server.STORE,self.route['id'],access='public')
        self.assertEqual(self.request(path)[0],404)
        graph.update_route(server.STORE,self.route['id'],access='private',enabled=False)
        self.assertEqual(self.request(path)[0],404)

    def test_peer_api_requires_hmac_and_serves_owner(self):
        peer = ThreadingHTTPServer(('127.0.0.1', 0), server.AdminHandler)
        thread = threading.Thread(target=peer.serve_forever, daemon=True)
        thread.start()
        base = 'http://127.0.0.1:' + str(peer.server_port)
        try:
            request = urllib.request.Request(base+'/cluster/personal', data=b'{}', method='POST')
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                urllib.request.urlopen(request)
            self.assertEqual(rejected.exception.code, 401)
            rejected.exception.close()
            result = server.CLUSTER._http(base, '/cluster/personal', 'POST', {'op':'catalog','route_id':self.route['id'],'ip':'peer-test'})
            self.assertTrue(result['ok'])
            self.assertEqual(len(result['items']),2)
            result = server.CLUSTER._http(base, '/cluster/personal', 'POST', {'op':'catalog','route_id':'missing','ip':'peer-test'})
            self.assertFalse(result['ok'])
        finally:
            peer.shutdown(); peer.server_close(); thread.join()

    def test_no_available_selection_does_not_bind(self):
        result=self.create()
        with patch('sub_server.subs.build_route_response',return_value=(b'',{})):
            response=server.personal_operation(self.route,{'op':'fetch','slug':result['slug'],'device':{'hwid':'A'},'format':'legacy'})
        self.assertIn('выберите',base64.b64decode(response['headers']['Announce'][7:]).decode())
        self.assertFalse(server.PERSONAL.access(self.route['id'],result['slug'],token=result['token'])['bound'])

    def test_nested_routes_cannot_shadow_personal_links(self):
        self.assertTrue(graph.validate_route_path(server.STORE, self.path + '/phone'))
        data = graph.get_graph(server.STORE)
        data['routes'].append({'id':'nested-test','path':self.path+'/phone','title':'nested'})
        self.assertFalse(graph.save_graph(server.STORE, data)[0])

    def test_rate_limit_and_expired_csrf(self):
        for _ in range(2):server.PERSONAL.limit('unique-test-bucket',2)
        with self.assertRaises(personal.PersonalError):server.PERSONAL.limit('unique-test-bucket',2)
        self.assertFalse(server.valid_portal_csrf(server.portal_csrf(self.route,'host',1),self.route,'host'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
