"""REQ-002 spike against official Memos 26.11.0, NOT an authentication bridge.

Uses an isolated real Memos process, a test OAuth provider, and Chromium. fnOS,
the production bridge, code/state trust boundaries and full logout UX remain gates.
"""
import base64
import hashlib
import http.server
import json
import os
import pathlib
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

BINARY_SHA256 = 'bd62d659f01efca3fdab21df3fa301e9dcd8c426203ffcdfa7fe7c686edab405'
RELEASE_SHA256 = '38b81c2bd1859555f4f7f277756541fd1ca332c94bbbee443626ace42d7b4061'


class TestProvider(http.server.BaseHTTPRequestHandler):
    codes = {}
    tokens = {}
    client = secrets.token_urlsafe(24)
    secret = secrets.token_urlsafe(32)
    redirect = ''

    def log_message(self, *_):
        pass  # Never log OAuth requests, codes or tokens.

    def reply(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        form = urllib.parse.parse_qs(body.decode())
        expected = 'Basic '+base64.b64encode(f'{self.client}:{self.secret}'.encode()).decode()
        if self.path != '/token' or self.headers.get('Authorization') != expected:
            return self.reply(401, {'error': 'invalid_client'})
        code = form.get('code', [''])[0]
        record = self.codes.pop(code, None)
        verifier = form.get('code_verifier', [''])[0]
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        if (not record or challenge != record['challenge'] or form.get('redirect_uri') != [self.redirect]
                or form.get('grant_type') != ['authorization_code']):
            return self.reply(400, {'error': 'invalid_grant'})
        token = secrets.token_urlsafe(32)
        self.tokens[token] = record['subject']
        self.reply(200, {'access_token': token, 'token_type': 'Bearer', 'expires_in': 60})

    def do_GET(self):
        token = self.headers.get('Authorization', '').removeprefix('Bearer ')
        subject = self.tokens.get(token)
        if self.path != '/userinfo' or not subject:
            return self.reply(401, {'error': 'invalid_token'})
        self.reply(200, {'sub': subject, 'display_name': 'SSO feasibility user'})


def api(base, method, path, body=None, token=None, cookie=None, expected=200):
    headers = {'Content-Type': 'application/json'}
    if path.startswith('/memos.api.'):
        headers['Connect-Protocol-Version'] = '1'
    if token:
        headers['Authorization'] = 'Bearer '+token
    if cookie:
        headers['Cookie'] = cookie
    request = urllib.request.Request(base+path, json.dumps(body).encode() if body is not None else None, headers, method=method)
    try:
        response = urllib.request.urlopen(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        assert response.status == expected, f'{method} {path}: status {response.status}, expected {expected}'
        data = response.read()
        value = json.loads(data) if data and 'application/json' in response.headers.get('Content-Type', '') else data.decode()
        return value, response.headers


def main():
    from playwright.sync_api import sync_playwright

    binary = pathlib.Path(os.environ['MEMOS_BINARY']).resolve()
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == BINARY_SHA256, 'Use the verified official 26.11.0 Linux amd64 release'
    assert subprocess.check_output([str(binary), '--version'], text=True).strip() == '26.11.0'
    assert os.getuid() != 0, 'Run the feasibility process as an ordinary user'
    provider = http.server.ThreadingHTTPServer(('127.0.0.1', 0), TestProvider)
    provider_thread = threading.Thread(target=provider.serve_forever, daemon=True)
    provider_thread.start()
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    TestProvider.redirect = base+'/fnos-auth/callback'
    with tempfile.TemporaryDirectory(prefix='memos-auth-feasibility-') as temporary:
        # Server output stays in a private disposable directory, never in test evidence.
        with open(pathlib.Path(temporary)/'server.log', 'wb') as log:
            process = subprocess.Popen([str(binary), '--addr', '127.0.0.1', '--port', str(port), '--data', temporary],
                                       stdout=log, stderr=log, env={k: v for k, v in os.environ.items() if not k.startswith('MEMOS_')})
            try:
                ready = False
                for _ in range(100):
                    assert process.poll() is None, 'Isolated Memos process exited'
                    try:
                        api(base, 'GET', '/healthz')
                        ready = True
                        break
                    except (OSError, AssertionError):
                        time.sleep(.1)
                assert ready, 'Isolated Memos did not become ready'
                password = secrets.token_urlsafe(32)
                admin, _ = api(base, 'POST', '/api/users', {'username': 'spike-admin', 'password': password, 'role': 'ADMIN'})
                admin_session, _ = api(base, 'POST', '/api/auth/signin', {'passwordCredentials': {'username': admin['username'], 'password': password}})
                admin_token = admin_session['accessToken']
                provider_base = f'http://127.0.0.1:{provider.server_port}'
                identity, _ = api(base, 'POST', '/api/identity-providers', {
                    'type': 'OAUTH2', 'title': 'Isolated fnOS feasibility provider',
                    'config': {'oauth2Config': {'clientId': TestProvider.client, 'clientSecret': TestProvider.secret,
                        'authUrl': provider_base+'/authorize', 'tokenUrl': provider_base+'/token',
                        'userInfoUrl': provider_base+'/userinfo', 'scopes': ['identity'],
                        'fieldMapping': {'identifier': 'sub', 'displayName': 'display_name'}}},
                }, admin_token)

                def credentials(subject):
                    verifier = secrets.token_urlsafe(48)
                    code = secrets.token_urlsafe(32)
                    TestProvider.codes[code] = {'subject': subject, 'challenge': base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()}
                    return {'identityProvider': identity['name'], 'code': code, 'redirectUri': TestProvider.redirect, 'codeVerifier': verifier}

                def sso(subject):
                    return api(base, 'POST', '/api/auth/signin', {'ssoCredentials': credentials(subject)})

                a, rest_headers = sso('installation-subject-a')
                print('OBSERVED: REST SignIn cookie header names:', [k for k in rest_headers.keys() if 'cookie' in k.lower()])
                b, _ = sso('installation-subject-b')
                assert a['user']['name'] != b['user']['name']
                assert a['user']['role'] == b['user']['role'] == 'USER'
                repeated, _ = sso('installation-subject-a')
                assert repeated['user']['name'] == a['user']['name']
                marker = secrets.token_hex(8)
                memo_a, _ = api(base, 'POST', '/api/memos', {'content': 'spike-private-a-'+marker, 'visibility': 'PRIVATE'}, a['accessToken'])
                memo_b, _ = api(base, 'POST', '/api/memos', {'content': 'spike-private-b-'+marker, 'visibility': 'PRIVATE'}, b['accessToken'])
                api(base, 'GET', '/api/'+memo_a['name'], token=b['accessToken'], expected=403)
                api(base, 'GET', '/api/'+memo_b['name'], token=a['accessToken'], expected=403)
                print('PASS: real OAuth2 exchange with PKCE; distinct ordinary users; stable links; private-note isolation')

                existing, _ = api(base, 'POST', '/api/users', {'username': 'spike-existing', 'password': password, 'role': 'USER'}, admin_token)
                session, _ = api(base, 'POST', '/api/auth/signin', {'passwordCredentials': {'username': existing['username'], 'password': password}})
                existing_memo, _ = api(base, 'POST', '/api/memos', {'content': 'existing fixture', 'visibility': 'PRIVATE'}, session['accessToken'])
                api(base, 'POST', '/api/'+existing['name']+'/linkedIdentities', credentials('installation-existing'), session['accessToken'])
                linked, _ = sso('installation-existing')
                assert linked['user']['name'] == existing['name']
                assert api(base, 'GET', '/api/'+existing_memo['name'], token=linked['accessToken'])[0]['content'] == 'existing fixture'
                pat, _ = api(base, 'POST', '/api/'+existing['name']+'/personalAccessTokens', {'description': 'isolated-spike'}, session['accessToken'])
                assert api(base, 'GET', '/api/auth/me', token=pat['token'])[0]['user']['name'] == existing['name']
                print('PASS: protected existing-account linking preserves notes; password and PAT APIs remain usable')

                general, _ = api(base, 'GET', '/api/instance/settings/GENERAL', token=admin_token)
                general['generalSetting']['disallowUserRegistration'] = True
                api(base, 'PATCH', '/api/instance/settings/GENERAL', general, admin_token)
                api(base, 'POST', '/api/auth/signin', {'ssoCredentials': credentials('closed-new-user')}, expected=403)
                assert sso('installation-subject-a')[0]['user']['name'] == a['user']['name']
                print('PASS: closed registration stays closed while existing linked users can sign in')

                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(headless=True)
                    context = browser.new_context(service_workers='block')
                    page = context.new_page()
                    responses = []
                    page.on('response', lambda response: responses.append([urllib.parse.urlsplit(response.url).path, response.status]))

                    def browser_sso(subject):
                        response = context.request.post(base+'/memos.api.AuthService/SignIn',
                            headers={'Connect-Protocol-Version': '1'}, data={'ssoCredentials': credentials(subject)})
                        assert response.status == 200, 'Browser SSO fixture exchange failed'
                        # Discard the response JWT. Native UI must bootstrap from the HttpOnly cookie.

                    def current():
                        try:
                            page.wait_for_function("!!localStorage.getItem('memos_access_token')", timeout=10000)
                        except Exception:
                            # Isolated fixture diagnostics: no cookie values, tokens or URL queries.
                            print(json.dumps({'ui_title': page.title(), 'ui_text': page.locator('body').inner_text()[:1000],
                                'response_paths': responses, 'cookie_flags': [
                                    {k: c[k] for k in ('name', 'httpOnly', 'secure', 'sameSite')}
                                    for c in context.cookies()]}), flush=True)
                            raise
                        return page.evaluate("""async () => {
                            const token = localStorage.getItem('memos_access_token');
                            const result = await fetch('/api/auth/me', {headers: {Authorization: 'Bearer '+token}});
                            return (await result.json()).user.name;
                        }""")

                    browser_sso('installation-subject-a')
                    page.goto(base, wait_until='domcontentloaded')
                    assert current() == a['user']['name']
                    page.get_by_text(memo_a['content'], exact=True).wait_for()
                    cookie = next(c for c in context.cookies() if c['name'] == 'memos_refresh')
                    assert cookie['httpOnly'] and cookie['sameSite'] == 'Lax'
                    print('PASS: Chromium native Memos UI bootstraps from refresh cookie without injected access token')

                    browser_sso('installation-subject-b')
                    page.reload(wait_until='domcontentloaded')
                    assert current() == a['user']['name'], 'Negative control changed: recheck upstream cache contract'
                    print('CONFIRMED RISK: changing refresh cookie alone leaves a valid cached user A token active')
                    page.evaluate("localStorage.removeItem('memos_access_token'); localStorage.removeItem('memos_token_expires_at')")
                    page.reload(wait_until='domcontentloaded')
                    assert current() == b['user']['name']
                    page.get_by_text(memo_b['content'], exact=True).wait_for()
                    assert page.get_by_text(memo_a['content'], exact=True).count() == 0
                    print('PASS: clearing stale pinned-version cache before native bootstrap enters B with B private notes')

                    token = page.evaluate("localStorage.getItem('memos_access_token')")
                    refresh = next(c for c in context.cookies() if c['name'] == 'memos_refresh')['value']
                    response = context.request.post(base+'/memos.api.AuthService/SignOut', data={},
                        headers={'Authorization': 'Bearer '+token, 'Connect-Protocol-Version': '1'})
                    assert response.status == 200
                    api(base, 'POST', '/memos.api.AuthService/RefreshToken', {}, cookie='memos_refresh='+refresh, expected=401)
                    print('PASS: native SignOut API revokes the current refresh session')
                    browser_version = browser.version
                    browser.close()
                print(json.dumps({'memos_version': '26.11.0', 'release_archive_sha256': RELEASE_SHA256,
                                  'release_binary_sha256': BINARY_SHA256, 'chromium': browser_version,
                                  'fnos_hardware_validation': 'pending', 'production_bridge_implemented': False}))
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                provider.shutdown()
                provider.server_close()
                provider_thread.join(timeout=2)


if __name__ == '__main__':
    main()
