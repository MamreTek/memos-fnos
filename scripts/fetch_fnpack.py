"""Fetch only the pinned official Linux amd64 build tool, never a NAS payload."""
import hashlib
import pathlib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
URL = 'https://static2.fnnas.com/fnpack/fnpack-1.2.3-linux-amd64'
SHA256 = '54b97fa7b70968c4d05c79840f5daeff508957d0bb2062fdb0376d00d9615c93'


def main():
    target = ROOT / '.cache/fnpack'
    if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == SHA256:
        print('Pinned fnpack already available')
        return
    with urllib.request.urlopen(URL, timeout=60) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise RuntimeError('Official fnpack download did not match the reviewed SHA-256')
    target.parent.mkdir(exist_ok=True)
    temporary = target.with_suffix('.download')
    temporary.write_bytes(data)
    temporary.chmod(0o755)
    temporary.replace(target)
    print('Verified official fnpack 1.2.3 (Linux amd64)')


if __name__ == '__main__':
    main()
