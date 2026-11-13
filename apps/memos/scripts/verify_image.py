"""Verify the pinned OCI index directly against the public Docker registry."""
import hashlib
import json
import pathlib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    lock = json.loads((ROOT / 'packaging/app/image.json').read_text())
    with urllib.request.urlopen('https://auth.docker.io/token?service=registry.docker.io&scope=repository:neosmemo/memos:pull', timeout=30) as response:
        token = json.load(response)['token']
    request = urllib.request.Request('https://registry-1.docker.io/v2/neosmemo/memos/manifests/' + lock['index_digest'], headers={
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json',
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
    assert lock['index_digest'] == 'sha256:' + hashlib.sha256(raw).hexdigest()
    platforms = {f"{m['platform']['os']}/{m['platform']['architecture']}" for m in json.loads(raw)['manifests']}
    assert set(lock['platforms']) <= platforms
    print('PASS: registry digest and linux/amd64 + linux/arm64')


if __name__ == '__main__':
    main()
