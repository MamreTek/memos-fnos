"""Run the actual FPK amd64 payload locally; this is not a fnOS device test."""
import argparse
import json
import os
import pathlib
import platform
import subprocess
import tarfile
import tempfile
import time
import io

from build import MODULE, VERSION, payload
from lifecycle_test import UnixHTTPConnection


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--package', type=pathlib.Path, default=MODULE / f'dist/gateway-probe/memos-sso-probe-{VERSION}-all.fpk')
    args = parser.parse_args()
    assert platform.machine() in ('x86_64', 'aarch64'), 'Run on a supported native host'
    with tarfile.open(args.package) as package:
        outer = payload(package)
    with tarfile.open(fileobj=io.BytesIO(outer['app.tgz'])) as package:
        inner = payload(package)
    with tempfile.TemporaryDirectory(prefix='fnos-probe-package-smoke-') as temporary:
        root = pathlib.Path(temporary)
        dest, var = root / 'target', root / 'var'
        var.mkdir()
        for name, content in inner.items():
            path = dest / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            if name.startswith('bin/'):
                path.chmod(0o755)
        for name, content in outer.items():
            if name.startswith('cmd/'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                path.chmod(0o755)
        env = dict(os.environ, TRIM_APPDEST=str(dest), TRIM_PKGVAR=str(var))

        def command(action, expected=0):
            result = subprocess.run(['bash', str(root / 'cmd/main'), action], env=env, capture_output=True, timeout=15)
            assert result.returncode == expected, f'Package lifecycle failed: {action}'

        command('status', 3)
        result = None
        try:
            command('start')
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                conn = UnixHTTPConnection(dest / 'app.sock')
                try:
                    conn.request('GET', '/app/memos-sso-probe', headers={
                        'X-Trim-Userid': '123456789', 'X-Trim-Username': 'package-smoke-fixture', 'X-Trim-Isadmin': 'false',
                    })
                    response = conn.getresponse()
                    assert response.status == 200, 'Package gateway route failed'
                    result = json.load(response)
                finally:
                    conn.close()
                assert result['probe_version'] == VERSION and result['memos_sso_implemented'] is False
                checks = result['auth_checks']
                if checks['status'] != 'running':
                    assert checks['status'] == 'passed', f'Package self-check failed: {checks}'
                    assert checks['cases'] == {name: 'passed' for name in ('endpoint', 'memosclient', 'browserflow', 'oauthbridge')}
                    break
                time.sleep(0.1)
            else:
                raise AssertionError('Package self-check timed out')
            command('status')
            assert not list((var / 'probe').glob('auth-check-*')), 'Disposable data was not cleaned'
            assert (var / 'probe/auth-check.log').stat().st_mode & 0o777 == 0o600
        finally:
            command('stop')
        command('status', 3)
        assert not (dest / 'app.sock').exists(), 'Package socket was not removed'
        print(json.dumps({'package_version': VERSION, 'architecture': result['architecture'], 'auth_checks': result['auth_checks'], 'fnos_hardware_validation': False}))


if __name__ == '__main__':
    main()
