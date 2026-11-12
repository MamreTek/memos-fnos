"""Build with official fnpack, then inspect the real nested archive before delivery."""
import argparse
import hashlib
import io
import json
import pathlib
import shutil
import subprocess
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def safe_members(archive):
    for member in archive.getmembers():
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or member.issym() or member.islnk():
            raise RuntimeError('Unsafe archive member: ' + member.name)
        yield member, str(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fnpack', required=True)
    args = parser.parse_args()
    fnpack = pathlib.Path(args.fnpack).resolve()
    with tempfile.TemporaryDirectory(prefix='memos-fnos-build-') as temporary:
        stage = pathlib.Path(temporary) / 'package'
        shutil.copytree(ROOT / 'packaging', stage)
        subprocess.run([str(fnpack), 'build'], cwd=stage, check=True)
        artifact = stage / 'memos-fnos.fpk'
        expected = {str(path.relative_to(stage)): path for path in stage.rglob('*') if path.is_file() and path != artifact and not path.is_relative_to(stage / 'app')}
        with tarfile.open(artifact, 'r:gz') as outer:
            seen = set()
            app_seen = False
            for member, name in safe_members(outer):
                if not member.isfile():
                    continue
                if name == 'app.tgz':
                    app_seen = True
                    # fnpack 1.2.3 also duplicates resource/privilege into app/config.
                    app_expected = {str(p.relative_to(stage / 'app')): p for p in (stage / 'app').rglob('*') if p.is_file()}
                    app_expected.update({f'config/{p.name}': p for p in (stage / 'config').iterdir() if p.is_file()})
                    with tarfile.open(fileobj=io.BytesIO(outer.extractfile(member).read()), mode='r:gz') as inner:
                        inner_seen = set()
                        for entry, relative in safe_members(inner):
                            if entry.isfile():
                                assert relative in app_expected, relative
                                source = app_expected[relative]
                                assert inner.extractfile(entry).read() == source.read_bytes(), relative
                                inner_seen.add(relative)
                        assert inner_seen == set(app_expected)
                    continue
                assert name in expected, f'Unexpected file: {name}'
                actual = outer.extractfile(member).read()
                if name == 'manifest':
                    parse = lambda raw: dict(tuple(part.strip() for part in line.split('=', 1)) for line in raw.decode().splitlines() if line.strip())
                    actual_fields = parse(actual)
                    checksum = actual_fields.pop('checksum')
                    assert checksum == hashlib.md5(outer.extractfile('app.tgz').read(), usedforsecurity=False).hexdigest()
                    assert actual_fields == parse(expected[name].read_bytes())
                else:
                    assert actual == expected[name].read_bytes(), name
                seen.add(name)
            assert seen == set(expected), (seen, set(expected))
            assert app_seen, 'Missing app.tgz'
        lock = json.loads((stage / 'app/image.json').read_text())
        dist = ROOT / 'dist'
        dist.mkdir(exist_ok=True)
        target = dist / f"memos-fnos-{lock['package_version']}-all.fpk"
        shutil.copyfile(artifact, target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        target.with_suffix('.fpk.sha256').write_text(f'{digest}  {target.name}\n')
        (dist / 'build-info.json').write_text(json.dumps({'package': target.name, 'sha256': digest, 'memos': lock, 'hardware_validation': 'pending'}, indent=2) + '\n')
        print(f'PASS: verified outer/inner payload; candidate at {target}')


if __name__ == '__main__':
    main()
