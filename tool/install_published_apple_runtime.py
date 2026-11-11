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
HEAD = 'a56429a73d0229ffd5ac5223bfabdcd6a7c19724'
CORE_COMMIT = '676eaf66f8f05d4d558ee7a74b4736623d3feeb9'
CORE_VERSION = '26.11.9'
REVISION = 'r1'
XHTTP_LISTENER_PATCH = 'third_party/xray-native-dns/xhttp_listener_lifetime_patch.py'
XHTTP_LISTENER_SOURCE_SHA256 = 'cca83bacf332240835197de5532cc022e3870063e62880e1302a7defa263cf1e'
LIFETIME_SOURCE_SCOPES = {
    'classic_dns': 'third_party/xray-native-dns/classic_lifetime_patch.py',
    'xhttp_h3_dial': 'third_party/xray-native-dns/h3_lifetime_patch.py',
    'xdrive_services': 'third_party/xray-native-dns/xdrive_lifetime_patch.py',
    'geodata_updater': 'third_party/xray-native-dns/geodata_lifetime_patch.py',
    'xhttp_h2_listener_cleanup': XHTTP_LISTENER_PATCH,
}
DARWIN_BINDING_PATCH = 'third_party/xray-native-dns/darwin_interface_bind_patch.py'
PINS = {
    'ios': {'zip': 'd4c700415f3f61de9b7c6fa83cf5df10b48253eb36a5e6e16f09510a9829a837',
            'manifest': '668c4df5fef1436e768d7ba15c06c6ce76d1c70443144ee8a057cb28c95bfe7e'},
    'macos': {'zip': '3a9c5b3c18a9706539d44c74cc176ba6232f663cf662d1cf2ce13ac40f3096c7',
              'manifest': '43c7b9170115fcbc1124b9dd4d750b5fafa03f6e8ba7c71910c73b82e4395153'},
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
    expected = dict(success=True, platform=platform, head=HEAD, release_version=CORE_VERSION, runtime_revision=REVISION,
                    core_commit=CORE_COMMIT, archive='XRay.xcframework.zip', archive_sha256=PINS[platform]['zip'])
    if any(document.get(k) != v for k, v in expected.items()) or document.get('success') is not True \
            or any(type(document.get(k)) is not int or document[k] != 1 for k in
                   ['routing_capability_expected', 'darwin_interface_binding_capability_expected']):
        raise ValueError('Published Apple source identity or capability metadata differs')
    sources = document.get('source_sha256')
    required_sources = [*LIFETIME_SOURCE_SCOPES.values(), DARWIN_BINDING_PATCH]
    if not isinstance(sources, dict) or any(not isinstance(sources.get(name), str)
            or not re.fullmatch('[0-9a-f]{64}', sources[name]) for name in required_sources) \
            or document.get('xhttp_listener_cleanup_applied') is not True \
            or document.get('xhttp_listener_cleanup_patch_sha256') != sources[XHTTP_LISTENER_PATCH] \
            or document.get('xhttp_listener_cleanup_source_sha256') != XHTTP_LISTENER_SOURCE_SHA256 \
            or document.get('go_version') != 'go1.27.3' \
            or document.get('root_ca_filter_toolchain_minimum') != 'go1.27.3' \
            or type(document.get('h2buf_cap_kib')) is not int or document['h2buf_cap_kib'] != 128:
        raise ValueError('Published Apple listener cleanup or qualified lifetime source binding differs')
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
    if re.findall(r'let xrayReleaseTag = "([^"]+)"', package) != [f'xray-{platform}-v{CORE_VERSION}-{REVISION}'] \
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
    result = dict(success=True, platform=platform, runtime_source='published', tag=f'xray-{platform}-v{CORE_VERSION}-{REVISION}',
                  producer_head=HEAD, core_commit=CORE_COMMIT, archive_sha256=PINS[platform]['zip'],
                  manifest_sha256=PINS[platform]['manifest'], framework_sha256=document['framework_sha256'],
                  xhttp_listener_cleanup_applied=True,
                  xhttp_listener_cleanup_patch_sha256=document['xhttp_listener_cleanup_patch_sha256'],
                  xhttp_listener_cleanup_source_sha256=document['xhttp_listener_cleanup_source_sha256'],
                  verified_derived_lifetime_scope=list(LIFETIME_SOURCE_SCOPES),
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
    markers = ['RUNTIME='+CORE_VERSION, 'APPLE_GEODATA_LIFETIME_CAPABILITY_PASS=1', 'APPLE_XDRIVE_LIFETIME_CAPABILITY_PASS=2',
               'APPLE_DARWIN_INTERFACE_BIND_CAPABILITY_PASS=1', 'APPLE_FAKEDNS_SDK_PASS=2', 'APPLE_DNS_DATA_MAPS_SDK_PASS=2',
               'NATIVE_ROUTING_RUNTIME_PASS=0', 'NATIVE_ROUTING_RUNTIME_PASS=1', 'NATIVE_ROUTING_RUNTIME_DRAIN_PASS']
    if any(log.splitlines().count(marker) != 1 for marker in markers):
        raise ValueError('Published Apple runtime capability or routing proof is incomplete')
    result = json.loads((output/'result.json').read_text())
    result.update(runtime_checks_pending=False, post_test_framework_unchanged=True,
                  actual_version=CORE_VERSION, actual_capabilities={'geodata': 1, 'xdrive': 2, 'darwin_binding': 1},
                  runtime_log_sha256=digest(log_path), runtime_markers=markers,
                  optional_skip_lines=[line for line in log.splitlines() if 'SKIP' in line])
    (output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-installed', action='store_true')
    parser.add_argument('--platform', choices=['all', 'ios', 'macos'], default='all',
                        help='Select one SDK for a platform-only CI job; default checks both.')
    return parser


def selected_platforms(platform):
    if platform == 'all':
        return ['ios', 'macos']
    if platform in PATHS:
        return [platform]
    raise ValueError('Unknown Apple SDK platform')


def main():
    parser = argument_parser()
    args = parser.parse_args()
    if sys.platform != 'darwin' or os.environ.get('GITHUB_ACTIONS') != 'true':
        parser.error('Public SDK installation and runtime qualification run only on macOS CI')
    for platform in selected_platforms(args.platform):
        output = ROOT/'build/published_apple_runtime'/platform
        if args.verify_installed:
            result = finish(ROOT, platform)
        else:
            output.mkdir(parents=True, exist_ok=False)
            for name, limit in [('XRay.xcframework.zip', 512*1024*1024), ('manifest.json', 2*1024*1024)]:
                url = f'https://github.com/XIIIFOX/flutter_vless/releases/download/xray-{platform}-v{CORE_VERSION}-{REVISION}/{name}'
                with urllib.request.urlopen(url, timeout=45) as response, (output/name).open('xb') as target:
                    count = 0
                    while block := response.read(1024*1024):
                        count += len(block)
                        if count > limit: raise ValueError('Public Apple download exceeds bound')
                        target.write(block)
            result = install(ROOT, platform, output/'XRay.xcframework.zip', output/'manifest.json')
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
