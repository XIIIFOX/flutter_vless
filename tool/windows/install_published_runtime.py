#!/usr/bin/env python3
"""Install and probe one fixed public Windows runtime; never build or repackage it."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
import zipfile

from package_managed_runtime import capabilities

TAG = 'xray-windows-v26.10.31-r1'
ARCHIVE = 'Xray-windows-managed-64.zip'
ZIP_SHA256 = '19268b7f9f5ddedbcf9c3cb294175f28f1c6a4d495327e790f8e519e8073aa48'
CORE_SHA256 = '00842f12870358c85a67fc3816a3dd75439566aef96a7d41d5a54e14e9a80eb0'
MANIFEST_SHA256 = '70aaad33abab2a7ff81e2e13771d5d74996eefbc323c0caa977f0c20674a1842'
PRODUCER_HEAD = '13c47ed2caabd70b082449ed4917ce65574df91e'
CORE_COMMIT = 'a4a3dff5b20c2faae567b742c172c7b95e75c083'
FILES = {'xray.exe', 'geoip.dat', 'geosite.dat', 'LICENSE.xray-core'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(archive, manifest):
    if sha(archive) != ZIP_SHA256 or sha(manifest) != MANIFEST_SHA256:
        raise ValueError('Published archive or manifest checksum differs')
    document = json.loads(manifest)
    expected = dict(success=True, head=PRODUCER_HEAD, platform='windows-amd64', core='26.10.31',
                    core_commit=CORE_COMMIT, runtime_revision='26.10.31-r1',
                    archive=ARCHIVE, archive_sha256=ZIP_SHA256)
    capability = document.get('capabilities', {})
    if any(document.get(k) != v for k, v in expected.items()) or document.get('success') is not True \
            or capability != {'stage': 'capabilities', 'code': 0, 'managed_service_lifetimes': 7} \
            or type(capability.get('code')) is not int or type(capability.get('managed_service_lifetimes')) is not int:
        raise ValueError('Published manifest identity or capabilities differ')
    with zipfile.ZipFile(io.BytesIO(archive)) as packed:
        if len(packed.infolist()) != len(FILES) or set(packed.namelist()) != FILES \
                or sum(row.file_size for row in packed.infolist()) > 256 * 1024 * 1024:
            raise ValueError('Published archive file set differs')
        files = {name: packed.read(name) for name in FILES}
    if document.get('files_sha256') != {name: sha(data) for name, data in files.items()} \
            or sha(files['xray.exe']) != CORE_SHA256:
        raise ValueError('Published extracted file checksums differ')
    data = files['xray.exe']; offset = int.from_bytes(data[60:64], 'little')
    if data[:2] != b'MZ' or data[offset:offset+6] != b'PE\0\0\x64\x86':
        raise ValueError('Published Core is not an AMD64 PE image')
    return document, files


def install(directory, archive, manifest):
    if sys.platform != 'win32':
        raise ValueError('Published runtime execution is restricted to Windows CI')
    directory = Path(directory)
    if directory.is_symlink() or (directory/'published-runtime-results.json').exists():
        raise ValueError('Published acceptance requires an owned fresh output')
    document, files = verify(archive, manifest)
    directory.mkdir(parents=True, exist_ok=True)
    for name, data in files.items(): (directory/name).write_bytes(data)
    (directory/'published-runtime-manifest-results.json').write_bytes(manifest)
    executable = directory/'xray.exe'
    child = subprocess.run([str(executable), 'version'], capture_output=True, timeout=10, check=True)
    if len(child.stdout) > 4096 or child.stderr or not re.match(rb'^Xray 26\.10\.31 \(', child.stdout):
        raise ValueError('Published runtime version differs')
    actual = capabilities(executable)
    if any(sha((directory/name).read_bytes()) != sha(data) for name, data in files.items()):
        raise ValueError('Published files changed during probes')
    result = dict(success=True, runtime_source='published', tag=TAG, archive_sha256=ZIP_SHA256,
                  core_sha256=CORE_SHA256, manifest_sha256=MANIFEST_SHA256,
                  actual_version=child.stdout.decode().splitlines()[0], capabilities=actual)
    (directory/'published-runtime-results.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'win32': parser.error('This probe runs only on Windows CI')
    def download(name, limit):
        with urllib.request.urlopen(f'https://github.com/XIIIFOX/flutter_vless/releases/download/{TAG}/{name}', timeout=45) as response:
            data = response.read(limit + 1)
        if len(data) > limit: raise ValueError('Published download exceeds its bound')
        return data
    print(json.dumps(install(args.directory, download(ARCHIVE, 256*1024*1024),
                             download('manifest.json', 2*1024*1024)), indent=2))
