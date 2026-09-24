"""Pinned build-time installation, no runtime downloads of executable code."""
import gzip
import hashlib
import os
from pathlib import Path
import platform
import urllib.request

VERSION = 'v1.19.31'
ASSETS = {
    'x86_64': ('amd64-compatible', '04cf9f09671704f839ddbee2e93069dc831a4123a75281e725d1d96ab9ac1afc'),
    'aarch64': ('arm64', '9e0f11afbf38426b8bd88fdc594678f8161c57eccb4e1b77acb12b493904f1d4'),
}


def install(destination='/opt/mihomo/mihomo'):
    arch, checksum = ASSETS[platform.machine()]
    url = f'https://github.com/MetaCubeX/mihomo/releases/download/{VERSION}/mihomo-linux-{arch}-{VERSION}.gz'
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read(64 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != checksum:
        raise RuntimeError('mihomo checksum mismatch')
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.decompress(data))
    path.chmod(0o755)


if __name__ == '__main__':
    install(os.environ.get('MIHOMO_INSTALL_PATH', '/opt/mihomo/mihomo'))
