"""Exercise real Unix sockets and process control without Docker or fnOS."""
import http.client
import json
import os
import pathlib
import platform
import socket
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=3)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class LifecycleTest(unittest.TestCase):
    def test_start_status_identity_restart_stop_and_retain_state(self):
        with tempfile.TemporaryDirectory(prefix='fnos-probe-test-') as temporary:
            base = pathlib.Path(temporary)
            dest, var = base / 'target', base / 'var'
            dest.mkdir()
            var.mkdir()
            arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
            binary = dest / 'bin' / f'probe-{arch}'
            binary.parent.mkdir()
            subprocess.run(['go', 'build', '-buildvcs=false', '-o', str(binary), '.'], cwd=ROOT, check=True)
            env = dict(os.environ, TRIM_APPDEST=str(dest), TRIM_PKGVAR=str(var))

            def command(action, expected=0):
                result = subprocess.run(['bash', str(ROOT / 'packaging/cmd/main'), action], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stderr)

            def identity(uid, name):
                conn = UnixHTTPConnection(dest / 'app.sock')
                try:
                    conn.request('GET', '/app/memos-sso-probe', headers={
                        'X-Trim-Userid': uid, 'X-Trim-Username': name, 'X-Trim-Isadmin': 'false',
                    })
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    return json.load(response)
                finally:
                    conn.close()

            command('status', 3)
            try:
                command('start')
                command('start')  # Idempotent; no second daemon or regenerated key.
                command('status')
                self.assertEqual((dest / 'app.sock').stat().st_mode & 0o777, 0o660)
                self.assertEqual((var / 'probe/control.sock').stat().st_mode & 0o777, 0o600)
                self.assertEqual((var / 'probe/fingerprint.key').stat().st_mode & 0o777, 0o600)
                before = identity('1000', 'test-alice')
                other = identity('1001', 'test-bob')
                self.assertNotEqual(before['uid_fingerprint'], other['uid_fingerprint'])
                conn = UnixHTTPConnection(dest / 'app.sock')
                conn.request('POST', '/stop')  # Private control route cannot cross onto gateway listener.
                self.assertEqual(conn.getresponse().status, 404)
                conn.close()
                command('status')
                command('stop')
                command('status', 3)
                command('stop')
                command('start')
                self.assertEqual(before, identity('1000', 'test-alice'))
                # Exercise the actual uninstall hook without removing any state.
                subprocess.run(['bash', str(ROOT / 'packaging/cmd/uninstall_init')], env=env, check=True, timeout=10)
                command('status', 3)
                command('start')
            finally:
                command('stop')
            command('status', 3)
            self.assertTrue((var / 'probe/fingerprint.key').is_file())
            self.assertFalse((dest / 'app.sock').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
