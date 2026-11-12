"""Real, isolated Memos API/persistence/backup test; run only on a disposable Docker host."""
import base64
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
NAME = 'memos-fnos-memos'
BASE = 'http://127.0.0.1:5230'


def run(args, env=None, check=True):
    return subprocess.run(args, env=env, check=check, capture_output=True, text=True, timeout=240)


def api(method, path, body=None, token=None, expected=200, raw=False):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request(BASE + path, json.dumps(body).encode() if body is not None else None, headers, method=method)
    try:
        response = urllib.request.urlopen(request, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        data = response.read()
        assert response.status == expected, f'{method} {path}: status {response.status}, expected {expected}'
    return data if raw else json.loads(data or '{}')


def main():
    run(['docker', 'info'])
    assert run(['docker', 'inspect', NAME], check=False).returncode != 0, 'Existing container: refusing to touch this host'
    test_id = secrets.token_hex(8)
    with tempfile.TemporaryDirectory(prefix='memos-container-') as temporary:
        base = pathlib.Path(temporary)
        share = base / 'memos-fnos'
        share.mkdir()
        env = dict(os.environ, TRIM_DATA_SHARE_PATHS=str(share), TRIM_UID=str(os.getuid()), TRIM_GID=str(os.getgid()),
                   TRIM_SERVICE_PORT='5230', TRIM_APPVER='0.1.0', TRIM_TEMP_LOGFILE=str(base / 'lifecycle-error'))
        assert os.getuid() != 0, 'Run this test as a non-root user with Docker access'
        hook = lambda name, *args, **kw: run(['bash', str(ROOT / 'packaging/cmd' / name), *args], env=env, **kw)
        hook('install_init')
        hook('install_callback')
        override = {'services': {'memos': {'labels': {'io.mamre.memos-fnos.test-id': test_id}}}}
        if os.environ.get('MEMOS_TEST_PLATFORM'):
            override['services']['memos']['platform'] = os.environ['MEMOS_TEST_PLATFORM']
        override_file = base / 'override.json'
        override_file.write_text(json.dumps(override))
        compose = ['docker', 'compose', '-p', 'memos-fnos', '-f', str(ROOT / 'packaging/app/docker/docker-compose.yaml'), '-f', str(override_file)]

        def start():
            result = run(compose + ['up', '-d', '--wait', '--wait-timeout', '180'], env=env, check=False)
            if result.returncode:
                print(result.stdout, result.stderr)
                print(run(compose + ['logs', '--tail', '50'], env=env, check=False).stdout)
                raise RuntimeError('Memos container did not become healthy')
            hook('main', 'status')

        def stop():
            run(compose + ['stop'], env=env)
            assert hook('main', 'status', check=False).returncode == 3

        def remove_owned():
            inspect = run(['docker', 'inspect', '--format', '{{index .Config.Labels "io.mamre.memos-fnos.test-id"}}', NAME], check=False)
            if inspect.returncode == 0:
                assert inspect.stdout.strip() == test_id, 'Cleanup ownership mismatch'
                run(compose + ['down'], env=env)

        try:
            start()
            uid = run(['docker', 'exec', NAME, 'id', '-u']).stdout.strip()
            assert uid == env['TRIM_UID'] and uid != '0'
            assert hook('upgrade_init', check=False).returncode == 1, 'Live backup was accepted'
            password = secrets.token_urlsafe(24)
            api('POST', '/api/users', {'username': 'integration-admin', 'password': password, 'role': 'ADMIN'})

            def login():
                result = api('POST', '/api/auth/signin', {'passwordCredentials': {'username': 'integration-admin', 'password': password}})
                return result['accessToken']

            token = login()
            # Check malformed/injection credentials cannot authenticate.
            rejected = api('POST', '/api/auth/signin', {'passwordCredentials': {'username': "' OR 1=1 --", 'password': password}}, expected=400)
            assert rejected['code'] == 3 and 'accessToken' not in rejected  # Upstream INVALID_ARGUMENT contract.
            content = '持久化检查 #integration\n<script>window.WRAPPER_XSS=1</script>'
            memo = api('POST', '/api/memos', {'content': content, 'visibility': 'PRIVATE'}, token)
            payload = (ROOT / 'packaging/ICON.PNG').read_bytes()
            attachment = api('POST', '/api/attachments', {'filename': 'check.png', 'type': 'image/png',
                             'content': base64.b64encode(payload).decode(), 'memo': memo['name']}, token)
            expected_hash = hashlib.sha256(payload).hexdigest()
            # Also put a disk asset in the mounted data tree, independently of the server's storage default.
            (share / 'data/local-asset.bin').write_bytes(payload)

            def verify():
                current = login()
                assert api('GET', '/api/' + memo['name'], token=current)['content'] == content
                asset = api('GET', '/api/' + attachment['name'], token=current)
                assert asset['filename'] == 'check.png'
                assert (share / 'data/local-asset.bin').read_bytes() == payload
                # Private resources must not become readable anonymously after restore.
                try:
                    response = urllib.request.urlopen(BASE + '/api/' + memo['name'], timeout=10)
                except urllib.error.HTTPError as error:
                    assert error.code in (401, 403, 404)
                else:
                    response.close()
                    raise AssertionError('Private memo became anonymous')
                # Managed storage is served through an authenticated file route.
                url = BASE + '/file/' + attachment['name'] + '/check.png'
                req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + current})
                with urllib.request.urlopen(req, timeout=20) as response:
                    assert hashlib.sha256(response.read()).hexdigest() == expected_hash

            stop()
            start()
            verify()
            stop()
            remove_owned()
            start()  # Container recreation must keep the same database and assets.
            verify()
            stop()
            hook('upgrade_init')
            backup, = (share / 'backups').glob('upgrade-*')
            subprocess.run(['sha256sum', '-c', 'SHA256SUMS'], cwd=backup, check=True, capture_output=True)
            remove_owned()
            isolated = base / 'restored'
            isolated.mkdir()
            with tarfile.open(backup / 'data.tar.gz') as archive:
                archive.extractall(isolated, filter='data')
            original_data = share / 'data'
            original_data.rename(base / 'original-preserved')
            shutil.move(str(isolated / 'data'), original_data)
            start()
            verify()
            stop()
            hook('uninstall_init')
            hook('uninstall_callback')
            hook('install_callback')
            start()
            verify()
            print('PASS: real Memos auth, private notes, attachments, non-root UID, stop/start, recreation, backup/restore, uninstall retention')
            print('Platform:', os.environ.get('MEMOS_TEST_PLATFORM', 'native'))
        finally:
            remove_owned()


if __name__ == '__main__':
    main()
