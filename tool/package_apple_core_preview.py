#!/usr/bin/env python3
"""Verify and archive a source-bound unpublished iOS SDK; never execute Core."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import plistlib
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
EXPORTS = ('XRayStartPrivate', 'XRayCheckPrivate', 'XRayRoutingCapability',
           'XRayCheckRoutingPrivate', 'XRayStartRoutingPrivate', 'XRayDarwinInterfaceBindingCapability')
PACKAGING_INPUTS = ('.github/workflows/apple-sdk-preview.yml',
                    'tool/package_apple_core_preview.py', 'tool/test_package_apple_core_preview.py')
H3_PATCH = 'third_party/xray-native-dns/h3_lifetime_patch.py'
BINDING_PATCH = 'third_party/xray-native-dns/darwin_interface_bind_patch.py'
PRODUCER_INPUTS = ('tool/build_apple_core_preview.sh', 'third_party/xray-mobile/go.mod',
                   'third_party/xray-mobile/go.sum', 'third_party/xray-vpn-routing/apply.py',
                   'third_party/xray-vpn-routing/pin-manifest.json',
                   'third_party/xray-native-dns/classic_lifetime_patch.py', H3_PATCH, BINDING_PATCH,
                   'third_party/xray-native-dns/pin-manifest.json',
                   'third_party/xray-native-dns/overlay/app/dns/native_classic_lifetime.go',
                   'third_party/xray-native-dns/overlay/app/dns/native_classic_lifetime_test.go')


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    if not name or '\\' in name or path.is_absolute() or any(part in ('', '.', '..') for part in name.split('/')):
        raise ValueError('Unsafe archive/source path')
    return path


def tree(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Expected a real source directory')
    result = {}
    for path in sorted(directory.rglob('*')):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError('Source links and special files are unsupported')
        if path.is_file():
            name = path.relative_to(directory).as_posix()
            safe_name(name)
            result[name] = digest(path)
    return result


def output(command, *, cwd):
    return subprocess.check_output(command, cwd=cwd, timeout=60)


def git_bindings(repository, head, bindings):
    if not isinstance(bindings, dict) or not bindings:
        raise ValueError('Missing source bindings')
    for name, expected in bindings.items():
        relative = safe_name(name)
        path = repository.joinpath(*relative.parts)
        if not re.fullmatch('[0-9a-f]{64}', str(expected)) or path.is_symlink() \
                or not path.resolve().is_relative_to(repository.resolve()) or digest(path) != expected:
            raise ValueError('Checkout source binding differs: ' + name)
        if hashlib.sha256(output(['git', 'show', head + ':' + name], cwd=repository)).hexdigest() != expected:
            raise ValueError('Git source binding differs: ' + name)


def verify_archive(archive, expected):
    seen = set()
    with tarfile.open(archive, 'r:gz') as packed:
        for member in packed:
            safe_name(member.name)
            if not member.isfile() or member.name in seen or member.name not in expected:
                raise ValueError('Unexpected archive member or link')
            seen.add(member.name)
            value = hashlib.sha256()
            with packed.extractfile(member) as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    value.update(chunk)
            if value.hexdigest() != expected[member.name]:
                raise ValueError('Archive member checksum differs')
    if seen != set(expected):
        raise ValueError('Archive member set differs')


def package(preview, destination, head, repository=ROOT):
    preview, destination, repository = Path(preview), Path(destination), Path(repository)
    if not re.fullmatch('[0-9a-f]{40}', head) \
            or output(['git', 'rev-parse', 'HEAD'], cwd=repository).decode().strip() != head:
        raise ValueError('Exact checkout commit is required')
    if destination.exists() or destination.is_symlink():
        raise ValueError('Package output must be new')
    framework = preview/'XRay.xcframework'
    receipts = {}
    for name in ('routing-preview.json', 'preview.json'):
        path = preview/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Expected regular producer receipt')
        receipts[name] = json.loads(path.read_text())
    producer, summary = receipts['routing-preview.json'], receipts['preview.json']
    pin = json.loads((repository/'third_party/xray-vpn-routing/pin-manifest.json').read_text())
    for key in ('success', 'source_unchanged', 'module_cache_source_unchanged', 'copies_unchanged',
                'classic_dns_lifetime_applied', 'h3_lifetime_applied', 'darwin_interface_binding_source_applied'):
        if producer.get(key) is not True:
            raise ValueError('Incomplete producer evidence: ' + key)
    if any(producer.get(key) is not False for key in ('published', 'runtime_executed')) \
            or producer.get('routing_capability_expected') != 1 or isinstance(producer['routing_capability_expected'], bool) \
            or producer.get('routing_tag') != 'flutter_vless_vpn_routing' \
            or type(producer.get('darwin_interface_binding_capability_expected')) is not int \
            or producer.get('darwin_interface_binding_capability_expected') != 1 \
            or producer.get('darwin_interface_binding_tag') != 'flutter_vless_darwin_interface_binding' \
            or producer.get('lifetime_patch_scope') != ['classic_dns', 'xhttp_h3_dial']:
        raise ValueError('Producer scope differs')
    for field, key in (('core', 'module_version'), ('core_module', 'module'),
                       ('core_sum', 'module_sum'), ('core_commit', 'core_commit')):
        if producer.get(field) != pin[key]:
            raise ValueError('Producer Core pin differs')
    if summary != {'platform': 'ios', 'core': pin['module_version'], 'preflightABI': 1, 'published': False} \
            or type(summary.get('preflightABI')) is not int or summary.get('published') is not False:
        raise ValueError('Producer platform/ABI differs')
    sources = producer.get('source_sha256')
    expected_sources = set(PRODUCER_INPUTS)
    expected_sources.update(path.relative_to(repository).as_posix() for path in (repository/'third_party/xray-mobile').glob('*.go'))
    expected_sources.update(path.relative_to(repository).as_posix() for path in (repository/'third_party/xray-vpn-routing/overlay').rglob('*.go'))
    if not isinstance(sources, dict) or set(sources) != expected_sources:
        raise ValueError('Producer source input set differs')
    git_bindings(repository, head, sources)
    if producer.get('h3_lifetime_patch_sha256') != sources.get(H3_PATCH) or H3_PATCH not in sources:
        raise ValueError('H3 patch input is not bound')
    if producer.get('darwin_interface_binding_patch_sha256') != sources.get(BINDING_PATCH) or BINDING_PATCH not in sources:
        raise ValueError('Darwin binding patch input is not bound')
    packaging = {name: digest(repository/name) for name in PACKAGING_INPUTS}
    git_bindings(repository, head, packaging)
    copies = [(Path(producer['core_source']), 'module_cache_before_sha256'),
              (Path(producer['core_replacement']), 'core_copy_sha256'),
              (preview/'routing/mobile', 'mobile_copy_sha256')]
    for path, field in copies:
        if tree(path) != producer.get(field):
            raise ValueError('Producer source/copy changed: ' + field)
    for protected in [preview, *[path for path, _ in copies]]:
        if destination.resolve() == protected.resolve() or protected.resolve() in destination.resolve().parents:
            raise ValueError('Package output overlaps build inputs')
    framework_hashes = tree(framework)
    info = plistlib.loads((framework/'Info.plist').read_bytes())
    libraries = info.get('AvailableLibraries')
    if not isinstance(libraries, list) or len(libraries) != 2:
        raise ValueError('Expected device and simulator SDK libraries')
    architectures, symbols, variants = {}, {}, set()
    for library in libraries:
        variant = library.get('SupportedPlatformVariant', 'device')
        expected = {'arm64'} if variant == 'device' else {'arm64', 'x86_64'}
        identifier = library.get('LibraryIdentifier', '')
        if len(safe_name(identifier).parts) != 1 or variant not in ('device', 'simulator') or variant in variants \
                or library.get('SupportedPlatform') != 'ios' or library.get('LibraryPath') != 'XRay.framework' \
                or set(library.get('SupportedArchitectures', [])) != expected \
                or len(library.get('SupportedArchitectures', [])) != len(expected):
            raise ValueError('SDK architecture metadata differs')
        variants.add(variant)
        archive = framework/identifier/'XRay.framework/XRay'
        actual = output(['xcrun', 'lipo', '-archs', str(archive)], cwd=repository).decode().split()
        if set(actual) != expected or len(actual) != len(expected):
            raise ValueError('SDK binary architectures differ')
        architectures[identifier] = sorted(actual)
        header = (archive.parent/'Headers/XRay.objc.h').read_text()
        if not all(re.search(r'\b' + name + r'\s*\(', header) for name in EXPORTS):
            raise ValueError('SDK ABI header is incomplete')
        for architecture in sorted(expected):
            lines = output(['xcrun', 'nm', '-arch', architecture, '-m', '-gU', str(archive)], cwd=repository).decode().splitlines()
            for name in EXPORTS:
                matches = [line for line in lines if re.search(r'(?:^|\s)_' + re.escape(name) + r'$', line)]
                if len(matches) != 1 or not re.search(r'\bexternal\b', matches[0]) \
                        or not any(kind in matches[0] for kind in ('(__TEXT,__text)', '(LTO,CODE)')) \
                        or re.search(r'weak|undefined', matches[0], re.I):
                    evidence = json.dumps([line[-240:] for line in matches[:2]])
                    raise ValueError(f'SDK strong ABI export missing: {name}; library={identifier} '
                                     f'arch={architecture} matches={len(matches)} evidence={evidence}')
            symbols[identifier + '/' + architecture] = list(EXPORTS)
    receipt_hashes = {name: digest(preview/name) for name in receipts}
    members = {'XRay.xcframework/' + name: value for name, value in framework_hashes.items()}
    members.update(receipt_hashes)
    destination.mkdir(parents=True)
    archive = destination/'ios-sdk-preview.tar.gz'
    with archive.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as compressed, \
            tarfile.open(fileobj=compressed, mode='w') as packed:
        for name in sorted(members):
            source = preview.joinpath(*safe_name(name).parts)
            entry = tarfile.TarInfo(name)
            entry.size = source.stat().st_size
            entry.mode = 0o644
            with source.open('rb') as content:
                packed.addfile(entry, content)
    verify_archive(archive, members)
    if tree(framework) != framework_hashes or any(digest(preview/name) != value for name, value in receipt_hashes.items()) \
            or any(tree(path) != producer[field] for path, field in copies):
        raise ValueError('SDK or producer inputs changed during packaging')
    git_bindings(repository, head, {**sources, **packaging})
    manifest = {'schema': 1, 'success': True, 'head': head, 'platform': 'ios',
                'archive': archive.name, 'archive_sha256': digest(archive), 'members_sha256': members,
                'framework_sha256': framework_hashes, 'producer_receipt_sha256': receipt_hashes,
                'producer_source_sha256': sources, 'packaging_source_sha256': packaging,
                'architectures': architectures, 'strong_exports': symbols,
                'core_commit': pin['core_commit'], 'core_module': pin['module'],
                'core_version': pin['module_version'], 'core_sum': pin['module_sum'],
                'h3_lifetime_patch_sha256': sources[H3_PATCH], 'routing_capability_expected': 1, 'darwin_interface_binding_capability_expected': 1,
                'darwin_interface_binding_patch_sha256': sources[BINDING_PATCH],
                'runtime_executed': False, 'installed': False, 'published': False}
    (destination/'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preview', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--head', required=True)
    args = parser.parse_args(argv)
    try:
        result = package(args.preview, args.output, args.head)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, 'Unpublished iOS SDK packaging failed: ' + str(error) + '\n')
    print('APPLE_SDK_PREVIEW_PACKAGED=' + result['archive_sha256'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
