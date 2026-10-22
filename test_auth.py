import base64
import contextlib
import errno
import http.client
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error

import provider
import server

IDENTITY = 'unit-test@example.invalid'
TOKEN = 'synthetic-test-token-never-real'


class MockBackend:
    calls = 0

    def status(self):
        return {'device': 'mock-device', 'environments': []}

    def token(self, env):
        self.calls += 1
        return {'ok': True, 'env': env, 'token': TOKEN}

    def login(self, env, password):
        return {'ok': True, 'env': env, 'token': TOKEN, 'source': 'login'}

    def refresh(self, env):
        return {'ok': True, 'env': env, 'token': TOKEN, 'source': 'refresh'}


class AccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = MockBackend()
        cls.server = server.Server(('127.0.0.1', 0), server.DEFAULT_ORIGIN, [IDENTITY], cls.backend)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method='GET', path='/api/status', body=None, override=None):
        headers = {'Host': self.server.authority, 'Tailscale-User-Login': IDENTITY,
                   'Origin': server.DEFAULT_ORIGIN, 'Sec-Fetch-Site': 'same-origin'}
        if body is not None:
            headers.update({'Content-Type': 'application/json', 'X-Workbench-Request': '1'})
        for key, val in (override or {}).items():
            if val is None:
                headers.pop(key, None)
            else:
                headers[key] = val
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        conn.request(method, path, body, headers)
        response = conn.getresponse()
        data, status, response_headers = response.read(), response.status, dict(response.getheaders())
        conn.close()
        return status, response_headers, data

    def test_identity_host_and_origin(self):
        for override in ({'Tailscale-User-Login': None}, {'Tailscale-User-Login': 'intruder'}, {'Host': 'evil.invalid'}, {'Origin': 'https://evil.invalid'}, {'Sec-Fetch-Site': 'cross-site'}):
            with self.subTest(override=override):
                self.assertEqual(self.request(override=override)[0], 403)
        self.assertEqual(self.request(override={'Origin': None})[0], 200)

    def test_all_assets_and_failures_no_store(self):
        for path in ('/', '/app.js', '/style.css', '/api/status', '/does-not-exist'):
            status, headers, data = self.request(path=path)
            self.assertIn('no-store', headers['Cache-Control'])
            self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
            self.assertNotIn('Access-Control-Allow-Origin', headers)
            self.assertNotIn(TOKEN.encode(), data)
        self.assertEqual(self.request(path='/', override={'Tailscale-User-Login': None})[0], 403)

    def test_toolbox_navigation_only_page(self):
        navigation = {'Origin': None, 'Sec-Fetch-Site': 'same-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document'}
        self.assertEqual(self.request(path='/', override=navigation)[0], 200)
        self.assertEqual(self.request(path='/api/status', override=navigation)[0], 403)

    def test_post_csrf_and_schema(self):
        for override in ({'Origin': None}, {'X-Workbench-Request': None}, {'Content-Type': 'text/plain'}):
            self.assertEqual(self.request('POST', '/api/token', '{"env":"admin-t"}', override)[0], 403)
        for body in ('{}', '{"env":"production"}', '{"env":"admin-t","url":"http://evil"}', '{"env":"admin-t","env":"rms-t"}', 'x'*257, '{"env":[]}'):
            self.assertEqual(self.request('POST', '/api/token', body)[0], 400)
        self.assertEqual(self.request('POST', '/api/token?token=synthetic', '{"env":"admin-t"}')[0], 404)

    def test_token_only_in_explicit_response_not_logs(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status, headers, data = self.request('POST', '/api/token', '{"env":"admin-t"}')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)['token'], TOKEN)
        self.assertIn('no-store', headers['Cache-Control'])
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(stderr.getvalue(), '')

    def test_login_and_refresh_schema_csrf_no_password_echo(self):
        secret = 'synthetic-password-only'
        for path, body in [('/api/login', {'env':'admin-t','password':secret}), ('/api/refresh', {'env':'admin-t'})]:
            self.assertEqual(self.request('POST', path, json.dumps(body), {'Origin':None})[0],403)
            code, headers, data = self.request('POST', path, json.dumps(body))
            self.assertEqual(code,200)
            self.assertIn('no-store',headers['Cache-Control'])
            self.assertNotIn(secret.encode(),data)
        for body in ({'env':'rms-t'}, {'env':'rms-t','password':''}, {'env':'rms-t','password':secret,'username':'other'}, {'env':'admin-t','password':secret,'url':'https://invalid'}):
            self.assertEqual(self.request('POST','/api/login',json.dumps(body))[0],400)


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.environment = patch.dict(os.environ, {'XDG_CACHE_HOME': self.temp.name}, clear=True)
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temp.cleanup()

    def write_cache(self, env, data):
        path = provider.cache_path(env)
        path.parent.mkdir(mode=0o700, exist_ok=True)
        path.write_text(json.dumps(data))
        path.chmod(0o600)
        return path

    def test_expired_rms_no_password_never_loads_client(self):
        payload = base64.urlsafe_b64encode(json.dumps({'exp': time.time()-10}).encode()).decode().rstrip('=')
        self.write_cache('rms-t', {'token': 'x.'+payload+'.x'})
        with patch.object(provider, 'load_module') as load:
            with self.assertRaises(provider.Failure) as caught:
                provider.acquire('rms-t')
            self.assertEqual(caught.exception.code, 'login_required')
            load.assert_not_called()

    def test_valid_admin_cache_no_network_or_writes(self):
        path = self.write_cache('admin-t', {'env':'admin-t','username':'zhkyy','accessToken':TOKEN,'expires_at':time.time()+3600})
        before = path.read_bytes(), path.stat().st_mtime_ns
        with patch.object(provider, 'load_module') as load:
            status = provider.status('admin-t')
            self.assertEqual(status['state'], 'cached_unverified')
            self.assertFalse(status['upstreamVerified'])
            self.assertNotIn(TOKEN, json.dumps(status))
            self.assertEqual(provider.acquire('admin-t')['token'], TOKEN)
            load.assert_not_called()
        self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), before)

    def test_expiry_states_and_capabilities_are_read_only(self):
        for seconds_left,refresh,expected in [(3600,True,'cached_unverified'),(30,True,'expires_soon'),(-30,True,'refresh_available'),(-30,False,'expired')]:
            data={'env':'admin-t','username':'zhkyy','accessToken':TOKEN,'expires_at':time.time()+seconds_left}
            if refresh:data['refreshToken']='synthetic-refresh'
            path=self.write_cache('admin-t',data);before=path.read_bytes()
            with patch.object(provider,'load_module') as load:
                got=provider.status('admin-t');load.assert_not_called()
            self.assertEqual(got['state'],expected)
            self.assertEqual(got['capabilities']['refresh'],refresh)
            self.assertEqual(path.read_bytes(),before)

    def test_private_child_pipe_returns_only_controlled_result(self):
        self.write_cache('admin-t', {'env':'admin-t','username':'zhkyy','accessToken':TOKEN,'expires_at':time.time()+3600})
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            completed = subprocess.run([sys.executable,str(server.ROOT/'provider.py'),'admin-t'],input=b'{"operation":"get"}',capture_output=True,check=True)
            result = json.loads(completed.stdout)
            self.assertEqual(completed.stderr,b'')
        self.assertEqual(result['token'], TOKEN)
        self.assertEqual(result['source'], 'cache')
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(stderr.getvalue(), '')

    def test_cache_security_rejects_symlink_and_unsafe_permissions(self):
        path = self.write_cache('admin-t', {'env':'admin-t','username':'zhkyy'})
        path.chmod(0o644)
        self.assertEqual(provider.status('admin-t')['state'], 'cache_unavailable')
        path.unlink()
        path.symlink_to(Path(self.temp.name)/'missing')
        self.assertEqual(provider.status('admin-t')['state'], 'cache_unavailable')

    def test_admin_failed_refresh_does_not_login_or_erase_cache(self):
        from types import SimpleNamespace
        path = self.write_cache('admin-t', {'env':'admin-t','username':'zhkyy','accessToken':TOKEN,'refreshToken':'synthetic-refresh','expires_at':0})
        before = path.read_bytes()
        class Client:
            def __init__(self, *args):
                self.lock = path.with_suffix('.lock')
            def token_call(self, fields):
                return (401, {}, b'no')
            def accept_token(self, response):
                return False
            def login(self):
                raise AssertionError('must not attempt login')
            def save(self):
                raise AssertionError('failed refresh must not save')
        with patch.object(provider, 'load_module', return_value=SimpleNamespace(Client=Client)):
            with self.assertRaises(provider.Failure) as caught:
                provider.acquire('admin-t')
        self.assertEqual(caught.exception.code,'login_required')
        self.assertEqual(path.read_bytes(),before)

    def test_explicit_refresh_uses_real_helper_response_validation(self):
        old = {'env':'admin-t','username':'zhkyy','accessToken':TOKEN,'refreshToken':'synthetic-refresh','expires_at':time.time()+3600}
        path = self.write_cache('admin-t',old)
        module = provider.load_module('admin')
        new_token = 'synthetic-renewed-token'
        response = (200, {}, json.dumps({'code':200,'data':{'accessToken':new_token,'refreshToken':'rotated-synthetic','expiresIn':7200}}).encode())
        with patch.object(provider,'load_module',return_value=module), patch.object(module.Client,'basic_auth',return_value='Basic synthetic'), patch.object(module,'wire',return_value=response) as wire:
            got=provider.acquire('admin-t','refresh')
        self.assertEqual(got['source'],'refresh')
        self.assertTrue(got['authEndpointVerified'])
        self.assertTrue(got['tokenChanged'])
        self.assertTrue(got['expiryExtended'])
        self.assertEqual(json.loads(path.read_text())['accessToken'],new_token)
        self.assertIn(b'grant_type=refresh_token',wire.call_args.args[-1])
        # HTTP 200 plus JWT-looking content is insufficient without code=200.
        before=path.read_bytes()
        bad=(200,{},json.dumps({'code':401,'data':{'accessToken':TOKEN,'expiresIn':7200}}).encode())
        with patch.object(provider,'load_module',return_value=module), patch.object(module.Client,'basic_auth',return_value='Basic synthetic'), patch.object(module,'wire',return_value=bad):
            with self.assertRaises(provider.Failure):provider.acquire('admin-t','refresh')
        self.assertEqual(path.read_bytes(),before)

    def test_rms_gateway_refresh_and_no_header_are_distinct(self):
        def jwt(exp):
            return 'x.'+base64.urlsafe_b64encode(json.dumps({'exp':exp}).encode()).decode().rstrip('=')+'.x'
        old=jwt(int(time.time())-60);new=jwt(int(time.time())+180)
        path=self.write_cache('rms-t',{'ticket':'synthetic-ticket','token':old})
        module=provider.load_module('rms')
        with patch.object(provider,'load_module',return_value=module), patch.object(module.Client,'login',side_effect=AssertionError('no password fallback')), patch.object(module,'wire',return_value=(200,{'refreshToken':new},b'{"code":200,"data":[]}')) as wire:
            got=provider.acquire('rms-t','refresh')
        self.assertEqual(got['source'],'refresh');self.assertTrue(got['expiryExtended']);self.assertTrue(got['tokenChanged'])
        self.assertTrue(wire.call_args.args[1].endswith(provider.RMS_SESSION_CHECK))
        self.assertEqual(json.loads(path.read_text())['token'],new)
        before=path.read_bytes()
        with patch.object(provider,'load_module',return_value=module), patch.object(module,'wire',return_value=(200,{},b'{"code":200}')):
            got=provider.acquire('rms-t','refresh')
        self.assertEqual(got['source'],'cache');self.assertTrue(got['sessionCheckSucceeded']);self.assertEqual(path.read_bytes(),before)
        for response in [(401,{},b'{"code":401}'),(200,{'refreshToken':jwt(int(time.time())+7200)},b'{"code":500}')]:
            with patch.object(provider,'load_module',return_value=module), patch.object(module,'wire',return_value=response):
                with self.assertRaises(provider.Failure):provider.acquire('rms-t','refresh')
            self.assertEqual(path.read_bytes(),before)

    def test_web_login_persists_only_valid_result_and_keeps_failed_cache(self):
        from types import SimpleNamespace
        path=self.write_cache('admin-pre',{'env':'admin-pre','username':'zhkyy','accessToken':TOKEN,'expires_at':time.time()+3600})
        before=path.read_bytes()
        calls=[]
        class Client:
            def __init__(self,env,account,password):
                self.lock=path.with_suffix('.lock');self.password=password
            def save(self):
                calls.append('save');path.write_text(json.dumps(self.session))
            def login(self):
                self.session={}
                self.save()  # even an unexpected early helper save is deferred
                if self.password=='bad-synthetic':raise ValueError('sensitive raw error')
                self.session={'env':'admin-pre','username':'zhkyy','accessToken':'new-synthetic','expires_at':time.time()+7200}
                self.save();return self.session['accessToken']
        module=SimpleNamespace(Client=Client,Error=ValueError)
        with patch.object(provider,'load_module',return_value=module):
            with self.assertRaises(provider.Failure):provider.acquire('admin-pre','login','bad-synthetic')
            self.assertEqual(path.read_bytes(),before);self.assertEqual(calls,[])
            got=provider.acquire('admin-pre','login','good-synthetic')
        self.assertEqual(got['source'],'login');self.assertEqual(calls,['save'])

    def test_backend_private_password_pipe_mutex_backoff_and_cache_survival(self):
        self.write_cache('admin-t',{'env':'admin-t','username':'zhkyy','accessToken':TOKEN,'expires_at':time.time()+3600})
        backend=server.Backend();entered=threading.Event();release=threading.Event();errors=[]
        secret='synthetic-private-password'
        def run(args,**kwargs):
            self.assertNotIn(secret,' '.join(args))
            self.assertEqual(json.loads(kwargs['input'])['password'],secret)
            self.assertEqual(kwargs['stderr'],subprocess.DEVNULL)
            entered.set();release.wait(2)
            return subprocess.CompletedProcess(args,0,b'{"ok":false,"code":"authentication_failed"}')
        def login():
            try:backend.login('admin-t',secret)
            except provider.Failure as e:errors.append(e.code)
        with patch.object(server.subprocess,'run',side_effect=run) as mocked:
            t=threading.Thread(target=login);t.start();self.assertTrue(entered.wait(1))
            self.assertEqual(backend.status()['environments'][2]['state'],'authenticating')
            with self.assertRaises(provider.Failure) as e:backend.refresh('admin-t')
            self.assertEqual(e.exception.code,'busy')
            release.set();t.join(3);self.assertFalse(t.is_alive())
            with self.assertRaises(provider.Failure) as e:backend.login('admin-t',secret)
            self.assertEqual(e.exception.code,'cooldown')
            self.assertEqual(mocked.call_count,1)
            self.assertEqual(backend.token('admin-t')['token'],TOKEN)
        self.assertEqual(errors,['authentication_failed'])
        snapshot=json.dumps(backend.status());self.assertNotIn(secret,snapshot);self.assertNotIn(TOKEN,snapshot)

    def test_rejected_refresh_not_retried_until_cache_changes(self):
        path=self.write_cache('admin-t',{'env':'admin-t','username':'zhkyy','accessToken':TOKEN,'refreshToken':'synthetic-refresh','expires_at':0})
        state_file=Path(self.temp.name)/'state/rejected.json'
        backend=server.Backend(state_file)
        failed=subprocess.CompletedProcess([],0,b'{"ok":false,"code":"login_required","upstreamHttpStatus":500,"upstreamErrorCategory":"invalid_grant"}')
        with patch.object(server.subprocess,'run',return_value=failed) as run:
            with self.assertRaises(provider.Failure):backend.refresh('admin-t')
            backend.runtime['admin-t']['nextAllowed']=0
            self.assertFalse(backend.status()['environments'][2]['capabilities']['refresh'])
            self.assertEqual(backend.status()['environments'][2]['state'],'login_required')
            with self.assertRaises(provider.Failure):backend.refresh('admin-t')
            self.assertEqual(run.call_count,1)
            restored=server.Backend(state_file)
            self.assertFalse(restored.status()['environments'][2]['capabilities']['refresh'])
            with self.assertRaises(provider.Failure):restored.refresh('admin-t')
            self.assertEqual(run.call_count,1)
            path.write_text(json.dumps({'env':'admin-t','username':'zhkyy','accessToken':TOKEN,'refreshToken':'new-synthetic-refresh','expires_at':time.time()+3600}))
            self.assertTrue(backend.status()['environments'][2]['capabilities']['refresh'])
            path.write_text(json.dumps({'env':'admin-t','username':'zhkyy','accessToken':TOKEN,'expires_at':time.time()+30}))
            backend.runtime['admin-t']['rejectedCacheVersion']=backend.cache_version('admin-t')
            self.assertEqual(backend.token('admin-t')['token'],TOKEN)
            self.assertEqual(run.call_count,1)

    def test_error_classification(self):
        cases = [(socket.gaierror(-2,'synthetic'), 'dns_failure'),(OSError(errno.ENETUNREACH,'synthetic'),'route_unreachable'),(TimeoutError(),'timeout'),(urllib.error.HTTPError('https://invalid',401,'secret',{},None),'authentication_failed'),(urllib.error.HTTPError('https://invalid',503,'secret',{},None),'http_error'),(urllib.error.URLError(socket.gaierror(-2,'synthetic')),'dns_failure')]
        for error, expected in cases:
            self.assertEqual(provider.classify(error),expected)
            if isinstance(error, urllib.error.HTTPError):
                error.close()

    def test_refresh_failure_metadata_never_exposes_upstream_message(self):
        secret='synthetic-sensitive-response-value'
        failure=provider.refresh_failure((500,{},json.dumps({'code':500,'message':'server_error '+secret}).encode()))
        self.assertEqual(failure.http_status,500)
        self.assertEqual(failure.code,'http_error')
        self.assertEqual(failure.diagnostics,{'upstreamBusinessCode':'500','upstreamErrorCategory':'server_error'})
        self.assertNotIn(secret,json.dumps(failure.diagnostics))

    def test_frontend_has_no_persistence_or_external_dependencies(self):
        script = (server.ROOT/'app.js').read_text()
        for forbidden in ('localStorage', 'sessionStorage', 'console.', 'innerHTML', 'document.cookie'):
            self.assertNotIn(forbidden,script)
        self.assertIn('navigator.clipboard.writeText(token)',script)
        self.assertIn("cache:'no-store'",script)


if __name__ == '__main__':
    unittest.main()
