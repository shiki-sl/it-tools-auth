"""Restricted adapter for existing token clients. Never print raw exceptions."""
import base64
import errno
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import socket
import stat
import sys
import time
import urllib.error

ACCOUNT = 'zhkyy'
ENVS = ('rms-t', 'rms-pre', 'admin-t', 'admin-pre')
RMS_SESSION_CHECK = '/sino-workbench/permission/headMenu'
SCRIPTS = {
    'rms': Path.home() / '.local/share/ccxi-token/ccxi_token.py',
    'admin': Path.home() / '.codex/skills/ccxi-admin-auth/scripts/ccxi_admin_token.py',
}
MESSAGES = {
    'login_required': '需要通过本页的登录表单重新登录；不会使用默认密码。',
    'password_required': '请在私有登录表单输入本次使用的密码。',
    'refresh_unavailable': '当前协议或缓存不支持免密码刷新，请使用网页登录重新签发。',
    'cooldown': '认证暂处于退避等待，请按页面时间稍后操作。',
    'interactive_required': '登录流程要求额外交互，请在对应官方登录页面完成验证码或授权步骤后再试。',
    'protocol_changed': '认证服务未返回预期协议结果，已停止且保留原缓存。',
    'dns_failure': '执行设备无法解析认证服务域名。',
    'route_unreachable': '执行设备无法连接认证服务，请检查企业网络与路由。',
    'timeout': '认证服务响应超时，未自动重放请求。',
    'authentication_failed': '认证失败，需要在执行设备确认账号、登录或 MFA 状态。',
    'http_error': '认证服务返回 HTTP 错误，未展示可能含凭证的响应正文。',
    'cache_unavailable': '缓存无法安全读取，请在执行设备检查缓存文件权限或内容。',
    'tool_unavailable': '执行设备缺少既有认证助手。',
    'busy': '同一环境正在获取 Token，请稍后重试。',
    'internal_error': '认证助手未能完成操作，未展示原始异常。',
}


class Failure(Exception):
    def __init__(self, code, retry_after=0, http_status=None, diagnostics=None):
        self.code = code
        self.retry_after = retry_after
        self.http_status = http_status
        self.diagnostics = diagnostics or {}
        super().__init__(code)


def cache_path(env):
    kind = 'admin' if env.startswith('admin-') else 'rms'
    root = Path(os.environ.get('XDG_CACHE_HOME', str(Path.home() / '.cache')))
    key = env + '\0' + ACCOUNT + ('\0ccxi-admin' if kind == 'admin' else '')
    return root / ('ccxi-admin-token' if kind == 'admin' else 'ccxi-token') / (hashlib.sha256(key.encode()).hexdigest() + '.json')


def read_cache(env):
    path = cache_path(env)
    try:
        info = path.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Failure('cache_unavailable')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 131072:
                raise Failure('cache_unavailable')
            value = json.loads(stream.read(131073))
        if not isinstance(value, dict):
            raise Failure('cache_unavailable')
        if env.startswith('admin-') and (value.get('env') != env or value.get('username') != ACCOUNT):
            raise Failure('cache_unavailable')
        return value, info.st_mtime
    except FileNotFoundError:
        return {}, None
    except (OSError, ValueError, UnicodeError):
        raise Failure('cache_unavailable') from None


def token_info(env, session):
    token = session.get('accessToken' if env.startswith('admin-') else 'token', '')
    expiry = 0
    if not isinstance(token, str) or not token or len(token) > 65536 or any(ord(c) < 32 for c in token):
        return '', 0
    try:
        if env.startswith('admin-'):
            expiry = float(session.get('expires_at', 0))
        else:
            part = token.split('.')[1]
            expiry = float(json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))['exp'])
    except (ValueError, TypeError, KeyError, IndexError):
        pass
    return token, expiry if math.isfinite(expiry) else 0


def status(env):
    kind = 'admin' if env.startswith('admin-') else 'rms'
    result = {'env': env, 'account': ACCOUNT, 'toolPresent': SCRIPTS[kind].is_file(),
              'cachePresent': False, 'sourceTime': None, 'expiresAt': None,
              'state': 'login_required', 'upstreamVerified': False,
              'capabilities': {'login': True, 'refresh': False}}
    try:
        session, modified = read_cache(env)
        token, expiry = token_info(env, session)
        result.update(cachePresent=modified is not None, sourceTime=modified, expiresAt=expiry or None)
        result['capabilities']['refresh'] = can_refresh(env, session)
        if token and expiry > time.time() + 90:
            result['state'] = 'cached_unverified'
        elif token and expiry > time.time():
            result['state'] = 'expires_soon'
        elif result['capabilities']['refresh']:
            result['state'] = 'refresh_available'
        elif token:
            result['state'] = 'expired'
        if not result['toolPresent']:
            result['state'] = 'tool_unavailable'
    except Failure as exc:
        result['state'] = exc.code
    return result


def can_refresh(env, session):
    if env.startswith('admin-'):
        return isinstance(session.get('refreshToken'), str) and bool(session['refreshToken'])
    ticket = session.get('ticket')
    token, _ = token_info(env, session)
    return isinstance(ticket, str) and bool(ticket) and len(ticket) <= 16384 and not any(ord(c) < 32 for c in ticket) and bool(token)


def classify(exc):
    if isinstance(exc, Failure):
        return exc.code
    if isinstance(exc, urllib.error.HTTPError):
        return 'authentication_failed' if exc.code in (401, 403) else 'http_error'
    if isinstance(exc, urllib.error.URLError):
        return classify(exc.reason)
    if isinstance(exc, socket.gaierror):
        return 'dns_failure'
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return 'timeout'
    if isinstance(exc, OSError) and exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED, errno.ECONNRESET):
        return 'route_unreachable'
    return 'internal_error'


def load_module(kind):
    if not SCRIPTS[kind].is_file():
        raise Failure('tool_unavailable')
    spec = importlib.util.spec_from_file_location('existing_auth_client', SCRIPTS[kind])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def refresh_failure(response):
    """Return only bounded status codes and a fixed error category, never text."""
    status, _, body = response
    details = {}
    try:
        value = json.loads(body)
        if not isinstance(value, dict):
            value = {}
    except (ValueError, UnicodeError):
        value = {}
    code = str(value.get('code', ''))
    if code.isascii() and code.lstrip('-').isdigit() and len(code) <= 8:
        details['upstreamBusinessCode'] = code
    category = 'unknown'
    text = ' '.join(str(value.get(key, '')) for key in ('error', 'error_description', 'message', 'msg')).lower()
    for candidate in ('unsupported_grant_type', 'invalid_grant', 'invalid_token', 'server_error', 'temporarily_unavailable'):
        if candidate in text or candidate.replace('_', ' ') in text:
            category = candidate
            break
    details['upstreamErrorCategory'] = category
    failure = 'refresh_unavailable' if category == 'unsupported_grant_type' else 'login_required' if category in ('invalid_grant', 'invalid_token') or status in (200, 400, 401, 403) else 'http_error'
    return Failure(failure, http_status=status, diagnostics=details)


def acquire(env, operation='get', password=None):
    """Existing cache is the only persistence. No new password/Token store."""
    if env not in ENVS or operation not in ('get', 'refresh', 'login'):
        raise Failure('internal_error')
    kind = 'admin' if env.startswith('admin-') else 'rms'
    session, _ = read_cache(env)
    token, expiry = token_info(env, session)
    if operation == 'get' and token and expiry > time.time() + 90:
        return result(env, token, expiry, 'cache')
    refresh = can_refresh(env, session)
    if operation == 'login' and (not isinstance(password, str) or not password or len(password.encode()) > 4096):
        raise Failure('password_required')
    if operation == 'refresh' and not refresh:
        raise Failure('refresh_unavailable')
    if operation == 'get' and not refresh:
        # A near-expiry RMS token is still usable; no hidden password login.
        if token and expiry > time.time():
            return result(env, token, expiry, 'cache')
        raise Failure('login_required')
    module = load_module(kind)
    client = module.Client(env, ACCOUNT, password)
    # Never call helper token(): it can erase cache or fall back to login.
    # Hold all helper saves until the final protocol result is validated.
    persist = client.save
    client.save = lambda: None
    client.session = session
    fd = os.open(client.lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Failure('cache_unavailable')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Failure('busy') from None
        client.session, _ = read_cache(env)
        token, expiry = token_info(env, client.session)
        if operation == 'get' and token and expiry > time.time() + 90:
            return result(env, token, expiry, 'cache')
        previous_token, previous_expiry = token, expiry
        if operation != 'login' and kind == 'admin' and client.session.get('refreshToken'):
            response = client.token_call({'grant_type': 'refresh_token', 'refresh_token': client.session['refreshToken']})
            if client.accept_token(response):
                token, expiry = token_info(env, client.session)
                source = 'refresh'
            else:
                raise refresh_failure(response)
        elif operation != 'login' and kind == 'rms' and can_refresh(env, client.session):
            # This fixed endpoint only queries the current user's menu. The
            # existing gateway may renew its auth session for an expired JWT.
            # client.request() is deliberately avoided: it first password-logins.
            status_code, headers, body = module.wire(client.opener, client.api + RMS_SESSION_CHECK, headers=client.headers())
            envelope = module.decoded(body)
            if status_code != 200 or str(envelope.get('code')) != '200' or envelope.get('success') is False:
                raise Failure('login_required' if status_code in (401, 403) or str(envelope.get('code')) in ('401', '403', '307') else 'http_error', http_status=status_code)
            refreshed = headers.get('refreshToken')
            if not refreshed and previous_token and previous_expiry > time.time():
                # An unexpired RMS JWT does not enter the gateway renewal path.
                # A successful session check must not be labelled refresh.
                cached = result(env, previous_token, previous_expiry, 'cache')
                cached['sessionCheckSucceeded'] = True
                return cached
            token, expiry = token_info(env, {'token': refreshed})
            if not token or expiry <= time.time() or token == previous_token or expiry <= previous_expiry:
                raise Failure('refresh_unavailable', http_status=status_code)
            client.session = dict(client.session, token=token)
            source = 'refresh'
        elif operation == 'login':
            if kind == 'rms':
                # The legacy helper only checks HTTP and JWT expiry at the CAS
                # exchange; also require a successful business envelope if set.
                wire = module.wire
                def checked_wire(opener, url, *args, **kwargs):
                    response = wire(opener, url, *args, **kwargs)
                    if url == client.api + module.LOGIN_PATH:
                        envelope = module.decoded(response[2])
                        if response[0] != 200 or (envelope.get('code') is not None and str(envelope['code']) != '200') or envelope.get('success') is False:
                            raise Failure('authentication_failed')
                    return response
                module.wire = checked_wire
            try:
                token = client.login()
            except module.Error:
                # Do not expose raw upstream text or infer whether a rejected
                # credential actually failed due to password, MFA or CAPTCHA.
                raise Failure('authentication_failed') from None
            _, expiry = token_info(env, client.session)
            source = 'login'
        else:
            raise Failure('refresh_unavailable')
        if not token or expiry <= time.time():
            raise Failure('protocol_changed')
        response = result(env, token, expiry, source)
        response.update(authEndpointVerified=True, tokenChanged=token != previous_token,
                        expiryExtended=expiry > previous_expiry, previousExpiresAt=previous_expiry or None)
        # Only a successful helper exchange reaches the existing atomic writer.
        persist()
        return response
    finally:
        os.close(fd)


def result(env, token, expiry, source):
    if not isinstance(token, str) or not token or any(ord(c) < 32 for c in token):
        raise Failure('authentication_failed')
    return {'env': env, 'account': ACCOUNT, 'token': token, 'expiresAt': expiry or None,
            'headerName': 'CCXI-Auth' if env.startswith('admin-') else 'ccxiplatformtoken',
            'headerPrefix': 'Bearer ' if env.startswith('admin-') else '',
            'source': source, 'authEndpointVerified': False, 'businessAuthorizationVerified': False}


def main():
    # stdout is a private parent pipe, never the service journal; imports and
    # upstream operations have both output streams suppressed at fd level.
    output = os.dup(sys.stdout.fileno())
    try:
        with open(os.devnull, 'w') as sink:
            os.dup2(sink.fileno(), 1)
            os.dup2(sink.fileno(), 2)
            try:
                # Password travels through an anonymous stdin pipe only.
                raw = sys.stdin.buffer.read(32769)
                if len(raw) > 32768:
                    raise Failure('internal_error')
                request = json.loads(raw)
                if not isinstance(request, dict) or set(request) - {'operation', 'password'}:
                    raise Failure('internal_error')
                payload = {'ok': True, **acquire(sys.argv[1], request.get('operation', 'get'), request.get('password'))}
            except Exception as exc:
                code = classify(exc)
                payload = {'ok': False, 'code': code, 'message': MESSAGES[code]}
                http_status = exc.code if isinstance(exc, urllib.error.HTTPError) else getattr(exc, 'http_status', None)
                if isinstance(http_status, int) and 100 <= http_status <= 599:
                    payload['upstreamHttpStatus'] = http_status
                if isinstance(exc, Failure):
                    payload.update(exc.diagnostics)
        with os.fdopen(output, 'w') as stream:
            json.dump(payload, stream, ensure_ascii=False)
    except Exception:
        os._exit(1)


if __name__ == '__main__':
    main()
