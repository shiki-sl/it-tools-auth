"""Loopback-only Token UI behind authenticated Tailscale Serve."""
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import tempfile
from urllib.parse import urlsplit

import provider

ROOT = Path(__file__).resolve().parent
DEFAULT_ORIGIN = 'https://shiki-9955hx.tailaed862.ts.net:8446'


class Backend:
    def __init__(self, state_file=None):
        self.locks = {env: threading.Lock() for env in provider.ENVS}
        self.state_file = state_file
        self.state_lock = threading.Lock()
        self.runtime = {env: {'running': None, 'failures': 0, 'nextAllowed': 0, 'lastOperation': None,
                              'rejectedCacheVersion': None} for env in provider.ENVS}
        if state_file is not None:
            try:
                saved = json.loads(state_file.read_text())
                for env, version in saved.items():
                    if env in self.runtime and isinstance(version,list) and len(version)==3 and all(isinstance(v,int) and v>=0 for v in version):
                        self.runtime[env]['rejectedCacheVersion'] = tuple(version)
            except (OSError, ValueError, AttributeError):
                pass

    def save_rejections(self):
        # Only inode/mtime/size markers; no credentials, tokens or response text.
        if self.state_file is None:
            return
        with self.state_lock:
            self.state_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, name = tempfile.mkstemp(dir=self.state_file.parent, prefix='.rejected-')
            try:
                with os.fdopen(fd, 'w') as stream:
                    json.dump({env:item['rejectedCacheVersion'] for env,item in self.runtime.items() if item['rejectedCacheVersion'] is not None}, stream)
                os.replace(name,self.state_file)
            finally:
                if os.path.exists(name):os.unlink(name)

    @staticmethod
    def cache_version(env):
        try:
            info = provider.cache_path(env).lstat()
            return (info.st_ino, info.st_mtime_ns, info.st_size)
        except FileNotFoundError:
            return None

    def status(self):
        environments = []
        for env in provider.ENVS:
            item = provider.status(env)
            runtime = self.runtime[env].copy()
            item['retryAfterSeconds'] = max(0, math.ceil(runtime['nextAllowed'] - time.monotonic()))
            item['lastOperation'] = runtime['lastOperation']
            if runtime['rejectedCacheVersion'] is not None and runtime['rejectedCacheVersion'] == self.cache_version(env):
                item['capabilities']['refresh'] = False
                item['refreshRequiresLogin'] = True
                if not item['expiresAt'] or item['expiresAt'] <= time.time():
                    item['state'] = 'login_required'
            if runtime['running']:
                item['state'] = 'authenticating' if runtime['running'] == 'login' else 'refreshing'
            environments.append(item)
        return {'device': 'shiki-9955hx', 'checkedAt': datetime.now(timezone.utc).isoformat(),
                'environments': environments,
                'notice': '状态读取不发起认证；认证来源与最近结果单独显示，业务接口授权未验证。'}

    def token(self, env):
        return self.perform(env, 'get')

    def refresh(self, env):
        return self.perform(env, 'refresh')

    def login(self, env, password):
        return self.perform(env, 'login', password)

    def perform(self, env, operation, password=None):
        if not self.locks[env].acquire(blocking=False):
            raise provider.Failure('busy')
        runtime = self.runtime[env]
        try:
            retry_after = max(0, math.ceil(runtime['nextAllowed'] - time.monotonic()))
            rejected = runtime['rejectedCacheVersion'] is not None and runtime['rejectedCacheVersion'] == self.cache_version(env)
            if operation == 'get':
                session, _ = provider.read_cache(env)
                token, expiry = provider.token_info(env, session)
                if token and expiry > time.time() + (0 if retry_after or rejected else 90):
                    return {'ok': True, **provider.result(env, token, expiry, 'cache')}
            if operation != 'login' and rejected:
                raise provider.Failure('login_required', retry_after)
            if retry_after:
                raise provider.Failure('cooldown', retry_after)
            runtime['running'] = operation
            try:
                try:
                    completed = subprocess.run([sys.executable, str(ROOT / 'provider.py'), env],
                                               input=json.dumps({'operation': operation, 'password': password}, ensure_ascii=False).encode(),
                                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                               timeout=45, check=False)
                except subprocess.TimeoutExpired:
                    raise provider.Failure('timeout') from None
                if completed.returncode != 0 or len(completed.stdout) > 131072:
                    raise provider.Failure('internal_error')
                try:
                    value = json.loads(completed.stdout)
                except (ValueError, UnicodeError):
                    raise provider.Failure('internal_error') from None
                if not isinstance(value, dict):
                    raise provider.Failure('internal_error')
                if value.get('ok') is not True:
                    code = value.get('code')
                    http_status = value.get('upstreamHttpStatus')
                    raise provider.Failure(code if code in provider.MESSAGES else 'internal_error',
                                           http_status=http_status if isinstance(http_status,int) and 100 <= http_status <= 599 else None,
                                           diagnostics={key:value[key] for key in ('upstreamBusinessCode','upstreamErrorCategory') if key in value})
                runtime.update(failures=0, rejectedCacheVersion=None, nextAllowed=time.monotonic() + (10 if value['source'] != 'cache' else 0),
                               lastOperation={'operation': operation, 'result': 'success', 'source': value['source'],
                                              'at': datetime.now(timezone.utc).isoformat()})
                try:
                    self.save_rejections()
                except OSError:
                    pass  # Persistence trouble must not relabel successful auth.
                return value
            except provider.Failure as exc:
                # Never replay an uncertain login/refresh. Repeated failures
                # require an explicit user action after bounded exponential backoff.
                runtime['failures'] = min(runtime['failures'] + 1, 6)
                delay = min(300, 15 * (2 ** (runtime['failures'] - 1)))
                runtime.update(nextAllowed=time.monotonic() + delay,
                               lastOperation={'operation': operation, 'result': 'failure', 'code': exc.code,
                                              'at': datetime.now(timezone.utc).isoformat()})
                if exc.http_status is not None:
                    runtime['lastOperation']['upstreamHttpStatus'] = exc.http_status
                runtime['lastOperation'].update(exc.diagnostics)
                if operation != 'login' and exc.code in ('login_required', 'refresh_unavailable'):
                    runtime['rejectedCacheVersion'] = self.cache_version(env)
                    try:
                        self.save_rejections()
                    except OSError:
                        pass  # Keep the in-memory guard and original auth error.
                exc.retry_after = delay
                raise
        finally:
            password = None
            runtime['running'] = None
            self.locks[env].release()


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, origin, identities, backend=None):
        if address[0] != '127.0.0.1':
            raise ValueError('Only 127.0.0.1 may be bound')
        parsed = urlsplit(origin)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username:
            raise ValueError('Origin must be an HTTPS origin')
        self.origin, self.authority = origin, parsed.netloc
        self.identities = frozenset(identities)
        if not self.identities:
            raise ValueError('At least one Tailscale identity is required')
        self.backend = backend or Backend()
        super().__init__(address, Handler)

    def handle_error(self, request, client_address):
        # The default implementation prints tracebacks and request context.
        pass


class Handler(BaseHTTPRequestHandler):
    server_version = 'PrivateWorkbench'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *args):
        pass

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        super().end_headers()

    def send_error(self, code, message=None, explain=None):
        # Never reflect request URLs, headers, bodies or exception text.
        self.reply(code, {'ok': False, 'code': 'request_rejected', 'message': '请求被拒绝。'})

    def reply(self, status, body, mime='application/json; charset=utf-8'):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(data)

    def allowed(self, write=False):
        # Serve replaces identity headers; only its loopback backend is exposed.
        sensitive = ('Host', 'Origin', 'Tailscale-User-Login', 'Sec-Fetch-Site', 'Content-Length', 'Content-Type', 'X-Workbench-Request')
        if any(len(self.headers.get_all(name, [])) > 1 for name in sensitive):
            return False
        if not ipaddress.ip_address(self.client_address[0]).is_loopback:
            return False
        if self.headers.get('Host') != self.server.authority:
            return False
        if self.headers.get('Tailscale-User-Login') not in self.server.identities:
            return False
        origin = self.headers.get('Origin')
        site = self.headers.get('Sec-Fetch-Site')
        if origin is not None and origin != self.server.origin:
            return False
        if site not in (None, 'none', 'same-origin'):
            # Top-level navigation from the separate toolbox origin is allowed;
            # only static assets are served by that cross-origin navigation.
            if write or self.path != '/' or self.headers.get('Sec-Fetch-Mode') != 'navigate' or self.headers.get('Sec-Fetch-Dest') != 'document':
                return False
        if write:
            return (origin == self.server.origin and self.headers.get('X-Workbench-Request') == '1'
                    and self.headers.get('Content-Type', '').split(';')[0].strip() == 'application/json')
        return True

    def do_GET(self):
        if not self.allowed():
            return self.reply(403, {'ok': False, 'code': 'access_denied', 'message': '仅允许已授权 Tailscale 身份从受信任入口访问。'})
        if self.path == '/api/status':
            try:
                return self.reply(200, {'ok': True, **self.server.backend.status()})
            except Exception:
                return self.reply(503, {'ok': False, 'code': 'internal_error', 'message': provider.MESSAGES['internal_error']})
        assets = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8')}
        if self.path in assets:
            name, mime = assets[self.path]
            return self.reply(200, (ROOT / name).read_bytes(), mime)
        return self.reply(404, {'ok': False, 'code': 'not_found', 'message': '入口不存在。'})

    def do_POST(self):
        if not self.allowed(write=True):
            return self.reply(403, {'ok': False, 'code': 'access_denied', 'message': '身份或请求来源校验失败。'})
        if self.path not in ('/api/token', '/api/refresh', '/api/login'):
            return self.reply(404, {'ok': False, 'code': 'not_found', 'message': '入口不存在。'})
        try:
            if self.headers.get('Transfer-Encoding'):
                raise ValueError()
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= (8192 if self.path == '/api/login' else 256):
                raise ValueError()
            def unique_pairs(pairs):
                result = {}
                for key, val in pairs:
                    if key in result:
                        raise ValueError()
                    result[key] = val
                return result
            value = json.loads(self.rfile.read(length), object_pairs_hook=unique_pairs)
            expected = {'env', 'password'} if self.path == '/api/login' else {'env'}
            if not isinstance(value, dict) or set(value) != expected or not isinstance(value['env'], str) or value['env'] not in provider.ENVS:
                raise ValueError()
            if self.path == '/api/login' and (not isinstance(value['password'], str) or not value['password'] or len(value['password'].encode()) > 4096 or '\0' in value['password']):
                raise ValueError()
        except (ValueError, UnicodeError, TimeoutError):
            return self.reply(400, {'ok': False, 'code': 'invalid_request', 'message': '请求须为限定环境的小型 JSON；登录还需本次密码，不接受其他参数。'})
        try:
            if self.path == '/api/login':
                result = self.server.backend.login(value['env'], value['password'])
            elif self.path == '/api/refresh':
                result = self.server.backend.refresh(value['env'])
            else:
                result = self.server.backend.token(value['env'])
            return self.reply(200, result)
        except provider.Failure as exc:
            status = 429 if exc.code in ('cooldown', 'busy') else 409 if exc.code in ('login_required', 'password_required', 'refresh_unavailable', 'authentication_failed', 'interactive_required') else 503
            return self.reply(status, {'ok': False, 'code': exc.code, 'message': provider.MESSAGES[exc.code],
                                      'retryAfterSeconds': exc.retry_after})
        except Exception:
            return self.reply(503, {'ok': False, 'code': 'internal_error', 'message': provider.MESSAGES['internal_error']})
        finally:
            value.pop('password', None)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8844)
    parser.add_argument('--config', type=Path, default=ROOT / 'config.json')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    state_file = Path.home()/'.local/state/it-tools-auth/refresh-rejections.json'
    Server(('127.0.0.1', args.port), config['origin'], config['identities'], Backend(state_file)).serve_forever()


if __name__ == '__main__':
    main()
