"""Offline checks for the actual fnOS package contract; no third-party dependencies."""
import hashlib
import json
import pathlib
import struct
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = ROOT / 'packaging'


def load(path):
    return json.loads(path.read_text())


def check():
    manifest = {}
    for line in (PKG / 'manifest').read_text().splitlines():
        key, value = line.split('=', 1)
        assert key not in manifest, f'Duplicate manifest key: {key}'
        manifest[key] = value
    assert manifest['appname'] == 'memos-fnos'
    assert manifest['platform'] == 'all'
    assert manifest['ctl_stop'] == manifest['checkport'] == 'true'
    assert manifest['service_port'] == '5230'
    assert manifest['install_dep_apps'] == 'docker'
    privilege = load(PKG / 'config/privilege')
    assert privilege['defaults']['run-as'] == 'package'
    resources = load(PKG / 'config/resource')
    assert resources['data-share']['shares'] == [{'name': 'memos-fnos'}]
    assert resources['docker-project']['projects'] == [{'name': 'memos-fnos', 'path': 'docker'}]
    ui = load(PKG / 'app/ui/config')['.url'][manifest['desktop_applaunchname']]
    assert (ui['type'], ui['port'], ui['url']) == ('url', '5230', '/')
    image = load(PKG / 'app/image.json')
    assert image['package_version'] == manifest['version']
    index_bytes = (ROOT / 'docs/evidence/image-index.json').read_bytes()
    assert image['index_digest'] == 'sha256:' + hashlib.sha256(index_bytes).hexdigest()
    platforms = {f"{m['platform']['os']}/{m['platform']['architecture']}" for m in json.loads(index_bytes)['manifests']}
    assert {'linux/amd64', 'linux/arm64'} <= platforms
    service = load(PKG / 'app/docker/docker-compose.yaml')['services']['memos']
    assert service['image'] == image['image']
    assert service['image'].endswith('@' + image['index_digest'])
    assert 'platform' not in service and 'privileged' not in service
    assert service['user'] == '${TRIM_UID:?Missing app UID}:${TRIM_GID:?Missing app GID}'
    assert service['read_only'] and service['cap_drop'] == ['ALL']
    assert len(service['volumes']) == 1
    assert service['volumes'][0]['target'] == '/var/opt/memos'
    assert service['volumes'][0]['bind']['create_host_path'] is False
    for wizard in (PKG / 'wizard').iterdir():
        assert isinstance(load(wizard), list)
    required = {'main', 'install_init', 'install_callback', 'upgrade_init', 'upgrade_callback',
                'config_init', 'config_callback', 'uninstall_init', 'uninstall_callback', 'common'}
    assert {p.name for p in (PKG / 'cmd').iterdir()} == required
    for script in (PKG / 'cmd').iterdir():
        subprocess.run(['bash', '-n', str(script)], check=True)
        assert script.stat().st_mode & 0o111, f'Not executable: {script}'
    for filename, size in [('ICON.PNG', 64), ('ICON_256.PNG', 256),
                           ('app/ui/images/icon_64.png', 64), ('app/ui/images/icon_256.png', 256)]:
        data = (PKG / filename).read_bytes()
        assert data[:8] == b'\x89PNG\r\n\x1a\n'
        assert struct.unpack('>II', data[16:24]) == (size, size)
    for path in PKG.rglob('*'):
        assert not path.is_symlink(), f'Package source symlink: {path}'
        if path.is_file() and path.suffix.lower() != '.png':
            text = path.read_text()
            assert '/home/' not in text and '/Users/' not in text, f'Local path: {path}'
    print('PASS: package metadata, resources, image provenance, JSON, scripts, icons and paths')


if __name__ == '__main__':
    check()
