#!/usr/bin/env python3
"""Install fixed public Apple SDK bytes in CI and verify them after runtime tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import urllib.request
import zipfile

from package_apple_core_preview import digest, git_bindings, safe_name, tree

ROOT = Path(__file__).resolve().parents[1]
HEAD = '13c47ed2caabd70b082449ed4917ce65574df91e'
CORE_COMMIT = 'a4a3dff5b20c2faae567b742c172c7b95e75c083'
PINS = {
    'ios': {'zip': '22813f46cd978341a2f6aa61f8d346fb57393c53a9f271d5f42b6b1a3371b9cc',
            'manifest': '486a80ae724e685bdf40f1e97016fdcdfa54f3a2ca27474b3ba0804c06c7a28a'},
    'macos': {'zip': '15de3fed0dc69604ba0a76172ff0d1550f2d64ebc1c173109e2308ef657cb07c',
              'manifest': 'd462d49969c8e098378f896a908ea21a12469d70e490cba31f9fcfc480ba2d21'},
}
PATHS = {
    'ios': {'package': 'ios/flutter_vless/Package.swift', 'framework': 'ios/XRay.xcframework'},
    'macos': {'package': 'packages/flutter_vless_macos/macos/flutter_vless_macos/Package.swift',
              'framework': 'packages/flutter_vless_macos/macos/XRay.xcframework'},
}


def verify_archive(platform, archive, manifest):
    if digest(archive) != PINS[platform]['zip'] or digest(manifest) != PINS[platform]['manifest']:
        raise ValueError('Published Apple archive or manifest checksum differs')
    document = json.loads(manifest.read_text())
    expected = dict(success=True, platform=platform, head=HEAD, release_version='26.10.31', runtime_revision='r1',
                    core_commit=CORE_COMMIT, archive='XRay.xcframework.zip', archive_sha256=PINS[platform]['zip'])
    if any(document.get(k) != v for k, v in expected.items()) or document.get('success') is not True \
            or any(type(document.get(k)) is not int or document[k] != 1 for k in
                   ['routing_capability_expected', 'darwin_interface_binding_capability_expected']):
        raise ValueError('Published Apple source identity or capability metadata differs')
    files = document['framework_sha256']
    if not files: raise ValueError('Published Apple file map is empty')
    for name in files: safe_name(name)
    with zipfile.ZipFile(archive) as packed:
        if len(packed.infolist()) != len(files) or set(packed.namelist()) != {'XRay.xcframework/'+name for name in files}:
            raise ValueError('Published Apple archive file set differs')
        for name, expected_hash in files.items():
            value = hashlib.sha256()
            with packed.open('XRay.xcframework/'+name) as source:
                for block in iter(lambda: source.read(1024*1024), b''): value.update(block)
            if value.hexdigest() != expected_hash: raise ValueError('Published Apple archive file checksum differs')
    return document


def verify_preferred(root, platform, document):
    primary = root/PATHS[platform]['framework']
    preferred = (root/PATHS[platform]['package']).parent/'XRay.xcframework'
    if preferred.is_symlink():
        if preferred.resolve() != primary.resolve():
            raise ValueError('Preferred Apple SDK alias targets a foreign cache')
    elif preferred.exists() and tree(preferred) != document['framework_sha256']:
        raise ValueError('Preferred package-local cached Apple SDK differs')


def verify_installed(root, platform, document):
    if tree(root/PATHS[platform]['framework']) != document['framework_sha256']:
        raise ValueError('Installed Apple SDK differs from published bytes')
    verify_preferred(root, platform, document)


def install(root, platform, archive, manifest):
    document = verify_archive(platform, archive, manifest)
    package = (root/PATHS[platform]['package']).read_text()
    if re.findall(r'let xrayReleaseTag = "([^"]+)"', package) != [f'xray-{platform}-v26.10.31-r1'] \
            or re.findall(r'let xrayChecksum = "([0-9a-f]{64})"', package) != [PINS[platform]['zip']]:
        raise ValueError('SwiftPM public SDK pins differ')
    git_bindings(root, HEAD, document['source_sha256'])
    verify_preferred(root, platform, document)
    destination = root/PATHS[platform]['framework']
    if destination.is_symlink(): raise ValueError('Apple SDK destination must be a real directory')
    with tempfile.TemporaryDirectory(prefix='published-apple-', dir=archive.parent) as folder:
        with zipfile.ZipFile(archive) as packed: packed.extractall(folder)
        extracted = Path(folder)/'XRay.xcframework'
        if tree(extracted) != document['framework_sha256']: raise ValueError('Extracted Apple SDK differs')
        if destination.exists(): shutil.rmtree(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(extracted, destination)
    verify_installed(root, platform, document)
    result = dict(success=True, platform=platform, runtime_source='published', tag=f'xray-{platform}-v26.10.31-r1',
                  producer_head=HEAD, core_commit=CORE_COMMIT, archive_sha256=PINS[platform]['zip'],
                  manifest_sha256=PINS[platform]['manifest'], framework_sha256=document['framework_sha256'],
                  runtime_checks_pending=True)
    output = root/'build/published_apple_runtime'/platform; output.mkdir(parents=True, exist_ok=True)
    (output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


def finish(root, platform):
    output = root/'build/published_apple_runtime'/platform
    document = verify_archive(platform, output/'XRay.xcframework.zip', output/'manifest.json')
    git_bindings(root, HEAD, document['source_sha256'])
    verify_installed(root, platform, document)
    log_path = root/f'build/{platform}_privacy_runtime_probe/runtime.log'; log = log_path.read_text()
    markers = ['RUNTIME=26.10.31', 'APPLE_GEODATA_LIFETIME_CAPABILITY_PASS=1', 'APPLE_XDRIVE_LIFETIME_CAPABILITY_PASS=2',
               'APPLE_DARWIN_INTERFACE_BIND_CAPABILITY_PASS=1', 'APPLE_FAKEDNS_SDK_PASS=2', 'APPLE_DNS_DATA_MAPS_SDK_PASS=2',
               'NATIVE_ROUTING_RUNTIME_PASS=0', 'NATIVE_ROUTING_RUNTIME_PASS=1', 'NATIVE_ROUTING_RUNTIME_DRAIN_PASS']
    if any(log.splitlines().count(marker) != 1 for marker in markers):
        raise ValueError('Published Apple runtime capability or routing proof is incomplete')
    result = json.loads((output/'result.json').read_text())
    result.update(runtime_checks_pending=False, post_test_framework_unchanged=True,
                  actual_version='26.10.31', actual_capabilities={'geodata': 1, 'xdrive': 2, 'darwin_binding': 1},
                  runtime_log_sha256=digest(log_path), runtime_markers=markers,
                  optional_skip_lines=[line for line in log.splitlines() if 'SKIP' in line])
    (output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-installed', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'darwin' or os.environ.get('GITHUB_ACTIONS') != 'true':
        parser.error('Public SDK installation and runtime qualification run only on macOS CI')
    for platform in ['ios', 'macos']:
        output = ROOT/'build/published_apple_runtime'/platform
        if args.verify_installed:
            result = finish(ROOT, platform)
        else:
            output.mkdir(parents=True, exist_ok=False)
            for name, limit in [('XRay.xcframework.zip', 512*1024*1024), ('manifest.json', 2*1024*1024)]:
                url = f'https://github.com/XIIIFOX/flutter_vless/releases/download/xray-{platform}-v26.10.31-r1/{name}'
                with urllib.request.urlopen(url, timeout=45) as response, (output/name).open('xb') as target:
                    count = 0
                    while block := response.read(1024*1024):
                        count += len(block)
                        if count > limit: raise ValueError('Public Apple download exceeds bound')
                        target.write(block)
            result = install(ROOT, platform, output/'XRay.xcframework.zip', output/'manifest.json')
        print(json.dumps(result, indent=2))
