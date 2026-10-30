#!/usr/bin/env python3
"""Package a CI-qualified managed Windows Core; never publish it."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from package_apple_core_preview import digest, git_bindings

ROOT = Path(__file__).resolve().parents[2]
REVISION = '26.10.29-r3'


def capabilities(executable):
    if sys.platform != 'win32':
        raise ValueError('Runtime execution is restricted to Windows CI')
    child = subprocess.run([str(executable), 'native-services', 'capabilities'],
                           capture_output=True, timeout=10, check=True)
    if len(child.stdout) > 4096 or child.stderr:
        raise ValueError('Unexpected capability output')
    value = json.loads(child.stdout)
    if value != {'stage': 'capabilities', 'code': 0, 'managed_service_lifetimes': 7} \
            or type(value.get('code')) is not int or type(value.get('managed_service_lifetimes')) is not int:
        raise ValueError('Managed lifetime capabilities must equal 7')
    return value


def package(directory, producer_path, destination, head, repository=ROOT):
    directory, producer_path, destination, repository = map(Path, (directory, producer_path, destination, repository))
    if destination.exists() or destination.is_symlink() or producer_path.is_symlink():
        raise ValueError('A new package output and regular producer receipt are required')
    producer = json.loads(producer_path.read_text())
    producer_digest = digest(producer_path)
    required = ('success', 'source_snapshot_unchanged', 'module_cache_source_unchanged',
                'core_copy_unchanged', 'mobile_copy_unchanged', 'xdrive_lifetime_applied', 'geodata_lifetime_applied')
    if any(producer.get(k) is not True for k in required) \
            or producer.get('tags') != 'flutter_vless_vpn_routing_cli,flutter_vless_vpn_routing,flutter_vless_managed_service_lifetimes' \
            or producer.get('goos') != 'windows' or producer.get('goarch') != 'amd64':
        raise ValueError('Incomplete managed Windows producer')
    sources = dict(producer['input_sha256'])
    for name in ('tool/windows/package_managed_runtime.py', 'tool/windows/test_package_managed_runtime.py',
                 '.github/workflows/windows-runtime.yml', 'tool/fixtures/xdrive-v26.10.29/LICENSE'):
        sources[name] = digest(repository/name)
    git_bindings(repository, head, sources)
    executable = directory/'xray.exe'
    if executable.is_symlink() or digest(executable) != producer.get('artifact_sha256'):
        raise ValueError('Selected Windows executable differs from its producer')
    data = executable.read_bytes()
    offset = int.from_bytes(data[60:64], 'little')
    if data[:2] != b'MZ' or data[offset:offset+6] != b'PE\x00\x00\x64\x86':
        raise ValueError('Expected an AMD64 Windows PE image')
    rows = json.loads((directory/'proxy-results.json').read_text())
    if not rows or any(row.get('passed') is not True for row in rows):
        raise ValueError('Windows routing and cleanup acceptance is incomplete')
    routed = {(row.get('host'), row.get('actual')) for row in rows
              if isinstance(row.get('host'), str) and isinstance(row.get('actual'), str)}
    required_routes = {(host, result) for host in ('2ip.ru', '2ip.io', 'myip.com')
                       for result in ('DIRECT-FIXTURE', 'PROXY-FIXTURE')}
    if not required_routes.issubset(routed) or sum(row.get('check') == 'owned traffic counter sample' for row in rows) != 2:
        raise ValueError('Windows reverse domain routing and traffic controls are incomplete')
    actual_capabilities = capabilities(executable)
    files = {'xray.exe': executable, 'LICENSE.xray-core': repository/'tool/fixtures/xdrive-v26.10.29/LICENSE'}
    for name in ('geoip.dat', 'geosite.dat'):
        path = directory/name
        expected = repository/'android_runtime/xray_android/src/main/assets'/name
        if path.is_symlink() or digest(path) != digest(expected):
            raise ValueError('Full project GeoDAT differs: '+name)
        files[name] = path
    hashes = {name: digest(path) for name, path in files.items()}
    destination.mkdir(parents=True)
    archive = destination/'Xray-windows-managed-64.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as target:
        for name, path in files.items():
            target.write(path, name)
    with zipfile.ZipFile(archive) as target:
        if set(target.namelist()) != set(files) or any(hashlib.sha256(target.read(name)).hexdigest() != value for name, value in hashes.items()):
            raise ValueError('Windows archive bytes differ')
    if any(digest(files[name]) != value for name, value in hashes.items()):
        raise ValueError('Windows runtime changed during packaging')
    if digest(producer_path) != producer_digest:
        raise ValueError('Windows producer changed during packaging')
    git_bindings(repository, head, sources)
    manifest = dict(success=True, head=head, platform='windows-amd64', runtime_revision=REVISION,
                    core='26.10.29', producer_sha256=digest(producer_path),
                    acceptance_sha256=digest(directory/'proxy-results.json'),
                    capabilities=actual_capabilities, source_sha256=sources,
                    archive=archive.name, archive_sha256=digest(archive), files_sha256=hashes,
                    published=False)
    (destination/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    (destination/'SHA256SUMS').write_text(digest(archive)+'  '+archive.name+'\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('directory', 'producer', 'output', 'head'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    package(args.directory, args.producer, args.output, args.head)
