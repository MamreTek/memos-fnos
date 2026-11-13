"""Build a separate disposable probe; never edit the Memos package or data."""
import argparse
import hashlib
import io
import json
import os
import pathlib
import shutil
import struct
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent
MODULE = ROOT.parents[1]
FNPACK_SHA256 = '54b97fa7b70968c4d05c79840f5daeff508957d0bb2062fdb0376d00d9615c93'
VERSION = '0.0.2'
RELEASE_HASHES = {
    'amd64': '38b81c2bd1859555f4f7f277756541fd1ca332c94bbbee443626ace42d7b4061',
    'arm64': '1575ed41ce1f668a2e70b50f73c95d2f1b04605db83d4529b8914358b394145e',
}
MEMOS_HASHES = {
    'amd64': 'bd62d659f01efca3fdab21df3fa301e9dcd8c426203ffcdfa7fe7c686edab405',
    'arm64': '06e8b9cda66209abb5dcdd5c9c512e172fc6dce088e19af8c0ddb94d1ffca9b6',
}
SUITES = ('endpoint', 'memosclient', 'browserflow', 'oauthbridge')


def release_binary(arch, cache):
    name = f'memos_26.11.0_linux_{arch}.tar.gz'
    archive = cache / name
    if not archive.exists():
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=cache, prefix='download-', delete=False) as output:
            download = pathlib.Path(output.name)
            try:
                with urllib.request.urlopen(f'https://github.com/usememos/memos/releases/download/26.11.0/{name}', timeout=60) as response:
                    size = 0
                    while chunk := response.read(1024 * 1024):
                        size += len(chunk)
                        assert size <= 128 * 1024 * 1024, 'Release archive too large'
                        output.write(chunk)
                output.flush()
                assert hashlib.sha256(download.read_bytes()).hexdigest() == RELEASE_HASHES[arch], 'Official release archive mismatch'
                os.replace(download, archive)
            finally:
                download.unlink(missing_ok=True)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == RELEASE_HASHES[arch], 'Cached official release archive mismatch'
    with tarfile.open(archive) as package:
        members = package.getmembers()
        assert len(members) == 1 and members[0].name == 'memos' and members[0].isfile(), 'Unexpected official archive contents'
        binary = package.extractfile(members[0]).read()
    assert hashlib.sha256(binary).hexdigest() == MEMOS_HASHES[arch], 'Official Memos binary mismatch'
    return binary


def verify_elf(binary, machine):
    data = binary.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01' and struct.unpack('<H', data[18:20])[0] == machine
    offset = struct.unpack('<Q', data[32:40])[0]
    size, count = struct.unpack('<HH', data[54:58])
    assert all(struct.unpack('<I', data[offset+i*size:offset+i*size+4])[0] != 3 for i in range(count)), 'Dynamic ELF interpreter found'
    return hashlib.sha256(data).hexdigest()


def payload(archive):
    result = {}
    for member in archive.getmembers():
        name = pathlib.PurePosixPath(member.name)
        assert not name.is_absolute() and '..' not in name.parts
        assert not member.issym() and not member.islnk()
        if member.isfile():
            assert str(name) not in result
            if str(name).startswith(('cmd/', 'bin/')):
                assert member.mode & 0o111, f'Not executable: {name}'
            result[str(name)] = archive.extractfile(member).read()
    return result


def verify(artifact, stage):
    with tarfile.open(artifact, 'r:gz') as archive:
        outer = payload(archive)
    app = outer.pop('app.tgz')
    with tarfile.open(fileobj=io.BytesIO(app), mode='r:gz') as archive:
        inner = payload(archive)
    expected = {str(p.relative_to(stage / 'app')): p.read_bytes() for p in (stage / 'app').rglob('*') if p.is_file()}
    expected.update({f'config/{p.name}': p.read_bytes() for p in (stage / 'config').iterdir()})
    assert inner == expected, 'Unexpected, changed, or missing inner files'
    manifest = outer.pop('manifest')
    parse = lambda raw: dict(tuple(s.strip() for s in line.split('=', 1)) for line in raw.decode().splitlines() if line.strip())
    fields = parse(manifest)
    assert fields.pop('checksum') == hashlib.md5(app, usedforsecurity=False).hexdigest()
    assert fields == parse((stage / 'manifest').read_bytes())
    expected = {str(p.relative_to(stage)): p.read_bytes() for p in stage.rglob('*')
                if p.is_file() and not p.is_relative_to(stage / 'app') and p.name not in ('manifest', artifact.name)}
    assert outer == expected, 'Unexpected, changed, or missing outer files'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fnpack', default=str(MODULE / '.cache/fnpack'))
    parser.add_argument('--memos-release-cache', default=str(MODULE / '.cache/memos-release'))
    args = parser.parse_args()
    fnpack = pathlib.Path(args.fnpack).resolve()
    assert hashlib.sha256(fnpack.read_bytes()).hexdigest() == FNPACK_SHA256, 'Use official fnpack 1.2.3'
    go_version = subprocess.check_output(['go', 'version'], text=True).strip()
    assert go_version == 'go version go1.26.8 linux/amd64', 'Probe toolchain is pinned to Go 1.26.8 linux/amd64'
    with tempfile.TemporaryDirectory(prefix='fnos-gateway-probe-build-') as temporary:
        stage = pathlib.Path(temporary) / 'package'
        shutil.copytree(ROOT / 'packaging', stage)
        for script in (stage / 'cmd').iterdir():
            script.chmod(0o755)
            subprocess.run(['bash', '-n', str(script)], check=True)
        for path in (stage / 'config').iterdir():
            json.loads(path.read_text())
        json.loads((stage / 'app/ui/config').read_text())
        for name in ('ICON.PNG', 'ICON_256.PNG'):
            shutil.copyfile(MODULE / 'packaging' / name, stage / name)
        images = stage / 'app/ui/images'
        images.mkdir()
        for size in (64, 256):
            shutil.copyfile(MODULE / f'packaging/app/ui/images/icon_{size}.png', images / f'icon_{size}.png')
        for name in ('PACKAGING-LICENSE', 'MOE-MEMOS-LICENSE', 'MOE-MEMOS-NOTICE'):
            shutil.copyfile(MODULE / 'packaging/app' / name, stage / 'app' / name)
        for name in ('GO-LICENSE', 'MEMOS-LICENSE', 'MEMOS-NOTICE'):
            shutil.copyfile(ROOT / name, stage / 'app' / name)
        binaries = stage / 'app/bin'
        binaries.mkdir()
        binary_hashes = {}
        auth_hashes = {}
        for arch, machine in (('amd64', 62), ('arm64', 183)):
            env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH=arch, GOTOOLCHAIN='local')
            binary = binaries / f'probe-{arch}'
            subprocess.run(['go', 'build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w -buildid=', '-o', str(binary), '.'],
                           cwd=ROOT, env=env, check=True)
            binary_hashes[arch] = verify_elf(binary, machine)
            auth_hashes[arch] = {}
            memos = binaries / f'memos-{arch}'
            memos.write_bytes(release_binary(arch, pathlib.Path(args.memos_release_cache).resolve()))
            memos.chmod(0o755)
            auth_hashes[arch]['memos'] = verify_elf(memos, machine)
            for suite in SUITES:
                binary = binaries / f'auth-suite-{suite}-{arch}'
                subprocess.run(['go', 'test', '-c', '-trimpath', '-buildvcs=false', '-ldflags=-s -w -buildid=', '-o', str(binary), f'./internal/{suite}'],
                               cwd=MODULE / 'auth-bridge', env=env, check=True)
                auth_hashes[arch][suite] = verify_elf(binary, machine)
        (stage / 'app/auth-payload.json').write_text(json.dumps({
            'version': VERSION, 'memos_version': '26.11.0', 'sha256': auth_hashes,
        }, indent=2) + '\n')
        subprocess.run([str(fnpack), 'build'], cwd=stage, check=True)
        artifact = stage / 'memos-sso-probe.fpk'
        verify(artifact, stage)
        dist = MODULE / 'dist/gateway-probe'
        dist.mkdir(parents=True, exist_ok=True)
        target = dist / f'memos-sso-probe-{VERSION}-all.fpk'
        shutil.copyfile(artifact, target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        target.with_suffix('.fpk.sha256').write_text(f'{digest}  {target.name}\n')
        (dist / 'build-info.json').write_text(json.dumps({
            'package': target.name, 'sha256': digest, 'toolchain': go_version,
            'binary_sha256': binary_hashes, 'fnpack_version': '1.2.3',
            'auth_payload_sha256': auth_hashes, 'memos_release_sha256': RELEASE_HASHES,
            'fnos_hardware_validation': 'pending', 'memos_sso_implemented': False,
        }, indent=2) + '\n')
        print('PASS: amd64/arm64 ELF and official fnpack payload verified:', target)


if __name__ == '__main__':
    main()
