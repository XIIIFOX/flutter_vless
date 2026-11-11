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

TAG = 'xray-windows-v26.11.9-r1'
ARCHIVE = 'Xray-windows-managed-64.zip'
ZIP_SHA256 = '81df36b77068fa7cf49f07311879a02d23e5d6bde9606c7d6cd024a5a01b6264'
CORE_SHA256 = '8385a665b77fbe2c0ce31972668e520f36cd453d895f98689ba3435ecca1699e'
MANIFEST_SHA256 = '3dd40bdef1383d9accb60c2082f53d5e82a48f337e9b63598e6d95830b356c30'
PRODUCER_HEAD = 'a56429a73d0229ffd5ac5223bfabdcd6a7c19724'
CORE_COMMIT = '676eaf66f8f05d4d558ee7a74b4736623d3feeb9'
LIFETIME_PATCH_SCOPE = ['classic_dns', 'xhttp_h3_dial', 'xdrive_services', 'geodata_updater', 'xhttp_h2_listener_cleanup']
XHTTP_PATCH = 'third_party/xray-native-dns/xhttp_listener_lifetime_patch.py'
XHTTP_PATCH_SHA256 = '7ec0ea9b256b7373b0d068211350b7cd0b6dc6126b99e5ce9d4269f3a004a674'
XHTTP_SOURCE_SHA256 = '02e72bb06a541d150716276e105dbf8bfd505fd0206db4d4ac26d1fdfe431dce'
FILES = {'xray.exe', 'geoip.dat', 'geosite.dat', 'LICENSE.xray-core'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(archive, manifest):
    if sha(archive) != ZIP_SHA256 or sha(manifest) != MANIFEST_SHA256:
        raise ValueError('Published archive or manifest checksum differs')
    document = json.loads(manifest)
    expected = dict(success=True, head=PRODUCER_HEAD, platform='windows-amd64', core='26.11.9',
                    core_commit=CORE_COMMIT, runtime_revision='26.11.9-r1',
                    archive=ARCHIVE, archive_sha256=ZIP_SHA256)
    capability = document.get('capabilities', {})
    if any(document.get(k) != v for k, v in expected.items()) or document.get('success') is not True \
            or capability != {'stage': 'capabilities', 'code': 0, 'managed_service_lifetimes': 7} \
            or type(capability.get('code')) is not int or type(capability.get('managed_service_lifetimes')) is not int:
        raise ValueError('Published manifest identity or capabilities differ')
    if document.get('lifetime_patch_scope') != LIFETIME_PATCH_SCOPE \
            or document.get('xhttp_listener_cleanup_applied') is not True \
            or document.get('xhttp_listener_cleanup_patch_sha256') != XHTTP_PATCH_SHA256 \
            or document.get('xhttp_listener_cleanup_source_sha256') != XHTTP_SOURCE_SHA256 \
            or not isinstance(document.get('source_sha256'), dict) \
            or document['source_sha256'].get(XHTTP_PATCH) != XHTTP_PATCH_SHA256:
        raise ValueError('Published XHTTP listener cleanup provenance differs')
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
    if len(child.stdout) > 4096 or child.stderr or not re.match(rb'^Xray 26\.11\.9 \(', child.stdout):
        raise ValueError('Published runtime version differs')
    actual = capabilities(executable)
    if any(sha((directory/name).read_bytes()) != sha(data) for name, data in files.items()):
        raise ValueError('Published files changed during probes')
    result = dict(success=True, runtime_source='published', tag=TAG, archive_sha256=ZIP_SHA256,
                  core_sha256=CORE_SHA256, manifest_sha256=MANIFEST_SHA256,
                  producer_head=PRODUCER_HEAD, lifetime_patch_scope=document['lifetime_patch_scope'],
                  xhttp_listener_cleanup_applied=True,
                  xhttp_listener_cleanup_patch_sha256=document['xhttp_listener_cleanup_patch_sha256'],
                  xhttp_listener_cleanup_source_sha256=document['xhttp_listener_cleanup_source_sha256'],
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
