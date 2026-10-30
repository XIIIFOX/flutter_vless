#!/usr/bin/env python3
"""Package canonical Apple runtime outputs; no release upload or Core execution."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess
import zipfile

from package_apple_core_preview import (EXPORTS, XDRIVE_PATCH, GEODATA_PATCH, digest, git_bindings,
                                       require_managed_lifetimes, safe_name, tree)

ROOT = Path(__file__).resolve().parents[1]


def output(command, root):
    return subprocess.check_output(command, cwd=root, timeout=90).decode()


def package(platform, framework, preparation, destination, head, repository=ROOT):
    framework, preparation, destination, repository = map(Path, (framework, preparation, destination, repository))
    if platform not in ('ios', 'macos') or not re.fullmatch('[0-9a-f]{40}', head) \
            or output(['git', 'rev-parse', 'HEAD'], repository).strip() != head:
        raise ValueError('Exact Apple platform and checkout head required')
    if destination.exists() or destination.is_symlink() or preparation.is_symlink():
        raise ValueError('New output and regular preparation receipt required')
    report = json.loads(preparation.read_text())
    preparation_sha = digest(preparation)
    pin = json.loads((repository/'third_party/xray-vpn-routing/pin-manifest.json').read_text())
    for field, key in [('module', 'module'), ('version', 'module_version'), ('sum', 'module_sum'), ('core_commit', 'core_commit')]:
        if report.get(field) != pin[key]:
            raise ValueError('Canonical Core pin differs')
    for field in ('success', 'h3_lifetime_applied', 'xdrive_lifetime_applied', 'geodata_lifetime_applied', 'darwin_interface_binding_source_applied',
                  'module_cache_source_unchanged', 'core_copy_unchanged'):
        if report.get(field) is not True:
            raise ValueError('Incomplete canonical producer: '+field)
    if report.get('stage') != 'post-build-verified' or report.get('lifetime_patch_scope') != ['classic_dns', 'xhttp_h3_dial', 'xdrive_services', 'geodata_updater'] \
            or type(report.get('routing_capability_expected')) is not int or report['routing_capability_expected'] != 1 \
            or type(report.get('darwin_interface_binding_capability_expected')) is not int \
            or report['darwin_interface_binding_capability_expected'] != 1 \
            or report.get('runtime_executed') is not False or report.get('published') is not False \
            or type(report.get('h2buf_cap_kib')) is not int or report['h2buf_cap_kib'] != 128:
        raise ValueError('Canonical release scope differs')
    version = re.fullmatch(r'go(\d+)\.(\d+)\.(\d+)', report.get('go_version', ''))
    if not version or tuple(map(int, version.groups())) < (1, 27, 3) \
            or report.get('root_ca_filter_toolchain_minimum') != 'go1.27.3':
        raise ValueError('Root CA filtering requires Go 1.27.3 or newer')
    for path, field in [(Path(report['core_source']), 'module_cache_before_sha256'),
                        (Path(report['replacement']), 'core_copy_sha256')]:
        if tree(path) != report[field]:
            raise ValueError('Canonical source changed: '+field)
    sources = dict(report['source_sha256'])
    expected_inputs = {'tool/prepare_apple_classic_core.py', 'third_party/xray-vpn-routing/apply.py',
                       'third_party/xray-vpn-routing/pin-manifest.json',
                       'third_party/xray-native-dns/classic_lifetime_patch.py',
                       'third_party/xray-native-dns/h3_lifetime_patch.py',
                       'third_party/xray-native-dns/darwin_interface_bind_patch.py',
                       'third_party/xray-native-dns/pin-manifest.json',
                       'third_party/xray-native-dns/overlay/app/dns/native_classic_lifetime.go',
                       'third_party/xray-native-dns/overlay/app/dns/native_classic_lifetime_test.go'}
    expected_inputs.update({XDRIVE_PATCH, GEODATA_PATCH,
                           'third_party/xray-native-dns/overlay/main/native_services_cli.go',
                           'third_party/xray-native-dns/overlay/transport/internet/xdrive/native_lifetime.go'})
    expected_inputs.update(p.relative_to(repository).as_posix()
                           for p in (repository/'third_party/xray-vpn-routing/overlay').rglob('*.go'))
    native_overlay = repository/'third_party/xray-native-dns/overlay'
    for folder, pattern in [('transport/internet/xdrive', '*_test.go'), ('app/geodata', 'native_*.go'),
                            ('core', 'native_managed_lifetime_test.go')]:
        expected_inputs.update(p.relative_to(repository).as_posix() for p in (native_overlay/folder).glob(pattern))
    if set(sources) != expected_inputs:
        raise ValueError('Canonical producer source set differs')
    require_managed_lifetimes(report, sources)
    producer = 'ios/build_xray_ios.sh' if platform == 'ios' else 'packages/flutter_vless_macos/macos/build_xray_macos.sh'
    names = [producer, '.github/workflows/apple-runtime-build.yml', 'tool/package_apple_runtime_release.py',
             'tool/package_apple_core_preview.py', 'third_party/xray-mobile/go.mod', 'third_party/xray-mobile/go.sum']
    names += [p.relative_to(repository).as_posix() for p in (repository/'third_party/xray-mobile').glob('*.go')]
    sources.update({name: digest(repository/name) for name in names})
    git_bindings(repository, head, sources)
    files = tree(framework)
    libraries = plistlib.loads((framework/'Info.plist').read_bytes()).get('AvailableLibraries')
    if not isinstance(libraries, list) or len(libraries) != (2 if platform == 'ios' else 1):
        raise ValueError('Unexpected Apple library set')
    architectures, symbols, variants = {}, {}, set()
    for library in libraries:
        identifier = library.get('LibraryIdentifier', '')
        variant = library.get('SupportedPlatformVariant', 'device')
        expected = {'arm64'} if platform == 'ios' and variant == 'device' else {'arm64', 'x86_64'}
        if len(safe_name(identifier).parts) != 1 or library.get('SupportedPlatform') != platform \
                or variant not in ({'device', 'simulator'} if platform == 'ios' else {'device'}) or variant in variants \
                or set(library.get('SupportedArchitectures', [])) != expected \
                or len(library.get('SupportedArchitectures', [])) != len(expected):
            raise ValueError('Apple architecture metadata differs')
        variants.add(variant)
        relative = library.get('LibraryPath', '')
        if relative != ('XRay.framework' if platform == 'ios' else 'libXRay.a'):
            raise ValueError('Canonical Apple library layout differs')
        binary = framework/identifier/relative
        if platform == 'ios':
            binary = binary/'XRay'
            header = binary.parent/'Headers/XRay.objc.h'
        else:
            if library.get('HeadersPath') != 'Headers':
                raise ValueError('Canonical macOS headers differ')
            header = framework/identifier/'Headers/XRay.objc.h'
        if not all(re.search(r'\b'+name+r'\s*\(', header.read_text()) for name in EXPORTS):
            raise ValueError('Canonical ABI header incomplete')
        actual = output(['xcrun', 'lipo', '-archs', str(binary)], repository).split()
        if set(actual) != expected or len(actual) != len(expected):
            raise ValueError('Actual binary architectures differ')
        architectures[identifier] = sorted(actual)
        for arch in sorted(expected):
            lines = output(['xcrun', 'nm', '-arch', arch, '-m', '-gU', str(binary)], repository).splitlines()
            strong = {}
            for name in EXPORTS:
                matches = [line for line in lines if re.search(r'(?:^|\s)_'+re.escape(name)+r'$', line)]
                if len(matches) != 1 or not re.search(r'\bexternal\b', matches[0]) \
                        or not any(kind in matches[0] for kind in ('(__TEXT,__text)', '(LTO,CODE)')) \
                        or re.search(r'weak|undefined', matches[0], re.I):
                    raise ValueError('Canonical strong ABI missing: '+identifier+'/'+arch+'/'+name)
                strong[name] = matches[0]
            symbols[identifier+'/'+arch] = strong
    if variants != ({'device', 'simulator'} if platform == 'ios' else {'device'}):
        raise ValueError('Apple variant set differs')
    destination.mkdir(parents=True)
    archive = destination/'XRay.xcframework.zip'
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as packed:
        for name in sorted(files):
            safe_name(name)
            member = zipfile.ZipInfo('XRay.xcframework/'+name, (2000, 1, 1, 0, 0, 0))
            member.external_attr = 0o100644 << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            packed.writestr(member, (framework/name).read_bytes())
    with zipfile.ZipFile(archive) as packed:
        if set(packed.namelist()) != {'XRay.xcframework/'+name for name in files}:
            raise ValueError('ZIP member set differs')
        for name, checksum in files.items():
            if hashlib.sha256(packed.read('XRay.xcframework/'+name)).hexdigest() != checksum:
                raise ValueError('ZIP bytes differ')
    if tree(framework) != files or digest(preparation) != preparation_sha \
            or any(tree(Path(report[path])) != report[field] for path, field in
                   [('core_source', 'module_cache_before_sha256'), ('replacement', 'core_copy_sha256')]):
        raise ValueError('Framework changed during packaging')
    git_bindings(repository, head, sources)
    manifest = {'success': True, 'platform': platform, 'head': head, 'release_version': '26.10.29', 'runtime_revision': 'r2',
                'core_commit': pin['core_commit'], 'core_version': pin['module_version'], 'core_sum': pin['module_sum'],
                'archive': archive.name, 'archive_sha256': digest(archive), 'framework_sha256': files,
                'architectures': architectures, 'strong_exports': symbols, 'source_sha256': sources,
                'preparation_receipt_sha256': digest(preparation), 'go_version': report['go_version'],
                'root_ca_filter_toolchain_minimum': 'go1.27.3', 'h2buf_cap_kib': 128,
                'routing_capability_expected': 1, 'darwin_interface_binding_capability_expected': 1,
                'runtime_executed_by_packager': False, 'published': False}
    (destination/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    (destination/'SHA256SUMS').write_text(manifest['archive_sha256']+'  '+archive.name+'\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=('ios', 'macos'), required=True)
    for name in ('framework', 'preparation', 'output', 'head'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    value = package(args.platform, args.framework, args.preparation, args.output, args.head)
    print('APPLE_CANONICAL_RUNTIME_PACKAGED='+value['archive_sha256'])
