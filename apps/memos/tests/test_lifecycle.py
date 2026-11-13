import fcntl
import itertools
import os
import pathlib
import socket
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CMD = ROOT / 'packaging/cmd'
IMAGE = 'neosmemo/memos:26.11.0@sha256:087e7dc6b76b31fcd1107a5767398b2a310ced209adb791efd8760c745dc8034'
FAKE_DOCKER = '''#!/usr/bin/env python3
import os,sys
action=sys.argv[1]
if os.environ.get('DAEMON_DOWN'): sys.exit('Cannot connect to the Docker daemon. Is the docker daemon running?')
if action=='info' and os.environ.get('INFO_ERROR'):
    print(os.environ['INFO_ERROR'], file=sys.stderr)
    sys.exit(int(os.environ.get('INFO_EXIT', '1')))
if action=='info': print('28.4.0')
elif action=='inspect':
    record=os.environ.get('RECORD','')
    if not record: sys.exit(1)
    print(record)
elif action=='ps': print('')
else: sys.exit('Unexpected Docker mutation: '+action)
'''


class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='memos-lifecycle-')
        self.addCleanup(self.temporary.cleanup)
        self.base = pathlib.Path(self.temporary.name)
        self.share = self.base / 'memos-fnos'
        self.share.mkdir()
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        fake = self.bin / 'docker'
        fake.write_text(FAKE_DOCKER)
        fake.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'],
                        TRIM_DATA_SHARE_PATHS=str(self.share), TRIM_UID=str(os.getuid()),
                        TRIM_GID=str(os.getgid()), TRIM_APPVER='0.1.3',
                        TRIM_TEMP_LOGFILE=str(self.base / 'error.log'))
        self.env.pop('DAEMON_DOWN', None)
        self.env.pop('RECORD', None)
        self.env.pop('INFO_ERROR', None)
        self.env.pop('INFO_EXIT', None)

    def run_hook(self, hook, *args, code=0, **changes):
        result = subprocess.run(['bash', str(CMD / hook), *args], env=dict(self.env, **changes),
                                text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def record(self, state='exited', health='none', project='memos-fnos'):
        return f'{state}|{health}|{project}|memos|{IMAGE}'

    def test_setup_is_idempotent_and_preserves_data_and_modes(self):
        self.run_hook('install_callback')
        note = self.share / 'data/note.txt'
        note.write_text('private existing note')
        (self.share / 'data').chmod(0o750)
        self.run_hook('install_callback')
        self.run_hook('upgrade_callback')
        self.assertEqual(note.read_text(), 'private existing note')
        self.assertEqual((self.share / 'data').stat().st_mode & 0o777, 0o750)

    def test_invalid_share_and_shell_input_are_rejected_without_side_effects(self):
        marker = self.base / 'injected'
        for value in ['', '/', str(self.base), str(self.share) + ':other', str(self.share) + '\n']:
            self.run_hook('install_callback', code=1, TRIM_DATA_SHARE_PATHS=value)
        self.run_hook('install_callback', code=1, TRIM_UID=f'$(touch {marker})')
        self.run_hook('install_callback', code=1, TRIM_UID='0')
        self.assertFalse(marker.exists())
        self.assertFalse((self.share / 'data').exists())

    def test_declared_subshares_resolve_one_root_and_preserve_existing_data(self):
        data, backups = self.share / 'data', self.share / 'backups'
        data.mkdir(mode=0o750)
        backups.mkdir(mode=0o700)
        note = data / 'existing.txt'
        note.write_text('keep existing data')
        for paths in itertools.permutations([self.share, data, backups]):
            with self.subTest(paths=paths):
                self.run_hook('install_callback', TRIM_DATA_SHARE_PATHS=':'.join(map(str, paths)))
                self.assertEqual(note.read_text(), 'keep existing data')
                self.assertEqual(data.stat().st_mode & 0o777, 0o750)

    def test_share_list_rejects_duplicates_unknown_and_cross_root_paths(self):
        data, backups = self.share / 'data', self.share / 'backups'
        data.mkdir()
        backups.mkdir()
        outside = self.base / 'outside'
        outside.mkdir()
        other = outside / 'memos-fnos'
        other.mkdir()
        for paths in [(self.share, self.share), (self.share, str(self.share) + '/.'),
                      (self.share, outside), (self.share, other), (data, backups)]:
            with self.subTest(paths=paths):
                self.run_hook('install_callback', code=1, TRIM_DATA_SHARE_PATHS=':'.join(map(str, paths)))
        for value in [f':{self.share}', f'{self.share}:', f'{self.share}::{data}']:
            self.run_hook('install_callback', code=1, TRIM_DATA_SHARE_PATHS=value)
        self.assertEqual(list(data.iterdir()), [])
        self.assertEqual(list(backups.iterdir()), [])
        self.assertEqual(list(other.iterdir()), [])

    def test_symlink_does_not_redirect_data_or_backup(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (self.share / 'data').symlink_to(outside, target_is_directory=True)
        self.run_hook('install_callback', code=1)
        self.assertEqual(list(outside.iterdir()), [])

    def test_unwritable_data_fails_without_changing_permissions(self):
        self.run_hook('install_callback')
        data = self.share / 'data'
        data.chmod(0o500)
        try:
            self.run_hook('install_callback', code=1)
            self.assertEqual(data.stat().st_mode & 0o777, 0o500)
        finally:
            data.chmod(0o700)

    def test_status_checks_health_and_ownership(self):
        self.run_hook('main', 'status', RECORD=self.record('running', 'healthy'))
        for record in ['', self.record(), self.record('running', 'starting'), self.record('running', 'unhealthy')]:
            self.run_hook('main', 'status', code=3, RECORD=record)
        self.run_hook('main', 'status', code=1, RECORD=self.record('running', 'healthy', 'other'))
        self.run_hook('main', 'status', code=1, DAEMON_DOWN='1')
        self.run_hook('main', 'unknown', code=1)
        self.run_hook('main', 'start')
        self.run_hook('main', 'stop')

    def test_preflight_rejects_daemon_and_port_conflicts(self):
        self.run_hook('install_init', code=1, DAEMON_DOWN='1')
        self.run_hook('install_init', code=1, RECORD=self.record('running', 'healthy', 'foreign'))
        listener = socket.socket()
        try:
            try:
                listener.bind(('127.0.0.1', 5230))
                listener.listen()
            except OSError:
                pass  # An existing listener also exercises the real conflict path.
            result = self.run_hook('install_init', code=1)
            self.assertIn('5230', result.stderr)
        finally:
            listener.close()

    def test_docker_failures_are_distinct_and_do_not_expose_raw_details(self):
        private_detail = 'private-context-do-not-log'
        cases = [
            ('permission denied while connecting to the Docker daemon', '1', 'E_DOCKER_PERMISSION'),
            ('operation not permitted', '1', 'E_DOCKER_PERMISSION'),
            ('Cannot connect to the Docker daemon. Is the docker daemon running?', '1', 'E_DOCKER_UNAVAILABLE'),
            ('connection refused', '1', 'E_DOCKER_UNAVAILABLE'),
            ('waiting', '124', 'E_DOCKER_TIMEOUT'),
            ('context deadline exceeded', '1', 'E_DOCKER_TIMEOUT'),
            ('unsupported Docker API', '1', 'E_DOCKER_CHECK'),
        ]
        for detail, exit_code, error_code in cases:
            with self.subTest(error_code=error_code, detail=detail):
                result = self.run_hook('main', 'status', code=1,
                                       INFO_ERROR=f'{detail}: {private_detail}', INFO_EXIT=exit_code)
                logged = (self.base / 'error.log').read_text()
                self.assertIn(error_code, result.stderr)
                self.assertIn(error_code, logged)
                self.assertNotIn(private_detail, result.stdout + result.stderr + logged)
                self.assertEqual(result.stderr.strip(), logged.strip())
                self.assertFalse((self.share / 'data').exists())

    def test_live_or_locked_backup_aborts(self):
        self.run_hook('install_callback')
        self.run_hook('upgrade_init', code=1, RECORD=self.record('running', 'healthy'))
        with (self.share / '.lifecycle.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.run_hook('upgrade_init', code=1, RECORD=self.record())
        self.assertEqual(list((self.share / 'backups').iterdir()), [])

    def test_backup_round_trip_preserves_sqlite_and_binary_attachment(self):
        self.run_hook('install_callback')
        data = self.share / 'data'
        with sqlite3.connect(data / 'memos_prod.db') as db:
            db.execute('create table notes (content text)')
            db.execute('insert into notes values (?)', ('笔记 <script>text only</script>',))
        (data / 'attachment.bin').write_bytes(bytes(range(256)))
        for _ in range(2):
            self.run_hook('upgrade_init', RECORD=self.record())
        backups = list((self.share / 'backups').iterdir())
        self.assertEqual(len(backups), 2)
        backup = backups[0]
        subprocess.run(['sha256sum', '-c', 'SHA256SUMS'], cwd=backup, check=True, capture_output=True)
        self.assertIn(IMAGE, (backup / 'metadata.txt').read_text())
        restored = self.base / 'restored'
        restored.mkdir()
        with tarfile.open(backup / 'data.tar.gz') as archive:
            archive.extractall(restored, filter='data')
        with sqlite3.connect(restored / 'data/memos_prod.db') as db:
            self.assertEqual(db.execute('select content from notes').fetchone()[0], '笔记 <script>text only</script>')
        self.assertEqual((restored / 'data/attachment.bin').read_bytes(), bytes(range(256)))

    def test_failed_tar_aborts_upgrade_and_cleans_only_its_staging_directory(self):
        self.run_hook('install_callback')
        note = self.share / 'data/keep.txt'
        note.write_text('keep')
        fake = self.bin / 'tar'
        fake.write_text('#!/bin/sh\nexit 1\n')
        fake.chmod(0o755)
        self.run_hook('upgrade_init', code=1, RECORD=self.record())
        self.assertEqual(note.read_text(), 'keep')
        self.assertEqual(list((self.share / 'backups').iterdir()), [])

    def test_uninstall_never_removes_data(self):
        self.run_hook('install_callback')
        note = self.share / 'data/keep.txt'
        note.write_text('retain')
        self.run_hook('uninstall_init')
        self.run_hook('uninstall_callback')
        self.assertEqual(note.read_text(), 'retain')


if __name__ == '__main__':
    unittest.main()
