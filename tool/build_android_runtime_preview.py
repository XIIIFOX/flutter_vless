#!/usr/bin/env python3
"""CI-only ordinary Android runtime preview; never publish, install or run it."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess

import test_native_dns_context_runtime as processes

ROOT = Path(__file__).resolve().parents[1]
ABIS = ('arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64')
RUNTIME = 'android_runtime/xray_android'
H3 = 'third_party/xray-native-dns/h3_lifetime_patch.py'
DIALER = 'transport/internet/splithttp/dialer.go'
PROJECT_FILES = ('build.gradle.kts', 'settings.gradle.kts', 'src/main/AndroidManifest.xml')
WRAPPER_INPUTS = ('tool/build_android_runtime_preview.py', 'tool/test_native_dns_context_runtime.py',
                  RUNTIME + '/runtime-inputs.sha256.json', 'example/android/gradlew',
                  'example/android/gradle/wrapper/gradle-wrapper.jar',
                  'example/android/gradle/wrapper/gradle-wrapper.properties',
                  *(RUNTIME + '/' + name for name in PROJECT_FILES))
ORDINARY_FILES = ('packages/flutter_vless_android/android/build_xray.sh',
                  'third_party/xray-mobile/go.mod', 'third_party/xray-mobile/go.sum',
                  'third_party/xray-vpn-routing/apply.py', 'third_party/xray-vpn-routing/pin-manifest.json',
                  *(('third_party/xray-native-dns/' + name) for name in
                    ('classic_lifetime_patch.py', 'h3_lifetime_patch.py', 'darwin_interface_bind_patch.py', 'pin-manifest.json',
                     'overlay/app/dns/native_classic_lifetime.go', 'overlay/app/dns/native_classic_lifetime_test.go')))


def ordinary_inputs(repository):
    """The ordinary build_xray.sh input vector, including its dynamic Go inputs."""
    mobile = repository / 'third_party/xray-mobile'
    capability = repository / 'third_party/xray-vpn-routing'
    protect = repository / 'packages/flutter_vless_android/android/xray-protect'
    paths = [repository / name for name in ORDINARY_FILES]
    paths += sorted(mobile.glob('*.go')) + sorted((mobile / 'nativecli').rglob('*.go'))
    paths += sorted((capability / 'overlay').rglob('*.go'))
    paths += sorted(protect.glob('*.py')) + sorted(protect.glob('*.go'))
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError('Ordinary producer inputs must be real files')
    return sorted({path.relative_to(repository).as_posix() for path in paths})


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def safe_relative(name):
    if not isinstance(name, str) or not name or '\\' in name:
        raise ValueError('Unsafe relative path')
    path = Path(name)
    if path.is_absolute() or any(part in ('', '.', '..') for part in name.split('/')):
        raise ValueError('Unsafe relative path')
    return path


def tree(path):
    if path.is_symlink() or not path.is_dir():
        raise ValueError('Expected a real source directory')
    paths = sorted(path.rglob('*'))
    if any(p.is_symlink() for p in paths):
        raise ValueError('Source symlinks are unsupported')
    return {p.relative_to(path).as_posix(): digest(p) for p in paths if p.is_file()}


def git_head(repository):
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repository, timeout=20).decode().strip()


def preview_version(head):
    if not re.fullmatch('[0-9a-f]{40}', head):
        raise ValueError('Exact Git head required')
    return '26.10.17-h3-preview.' + head[:12]


def core_copy(receipt_name, repository):
    match = re.fullmatch(r'classic-preview-(security-android-classic\.[A-Za-z0-9]+)\.json', receipt_name)
    if not match:
        raise ValueError('Ordinary Core receipt name differs')
    path = repository / 'build' / match.group(1) / 'Core'
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Owned Core copy path differs')
    return path


def checked(name, command, output, environment, results, *, cwd=ROOT, seconds=600):
    processes.EVIDENCE = output / 'logs'
    processes.checked(name, command, cwd=cwd, environment=environment, seconds=seconds, results=results)


def build(output, head, repository=ROOT):
    # Refuse before child commands, mkdir, dependency resolution or copying.
    if os.environ.get('CI') != 'true' or os.environ.get('GITHUB_ACTIONS') != 'true' \
            or os.uname().sysname != 'Linux':
        raise ValueError('Android preview builds require Linux GitHub Actions')
    version = preview_version(head)
    if git_head(repository) != head:
        raise ValueError('Checkout head differs')
    output = output.absolute()
    build_root = (repository / 'build').resolve()
    if output.exists() or output.is_symlink() or build_root not in output.resolve().parents \
            or any(p.is_symlink() for p in [output.parent, *output.parents] if p.exists()):
        raise ValueError('Preview output must be new and inside the owned build directory')
    ordinary_names = ordinary_inputs(repository)
    inputs = {name: digest(repository / name) for name in sorted(set(WRAPPER_INPUTS) | set(ordinary_names))}
    pins = json.loads((repository / RUNTIME / 'runtime-inputs.sha256.json').read_text())
    pinned = {name: value for name, value in pins.items() if not name.endswith('/libxray.so')}
    expected_pinned = {f'jniLibs/{abi}/libtun2socks.so' for abi in ABIS} | {'assets/geoip.dat', 'assets/geosite.dat'}
    if set(pinned) != expected_pinned:
        raise ValueError('Pinned HEV/geodata set differs')
    for name, value in pins.items():
        path = repository / RUNTIME / 'src/main' / safe_relative(name)
        if path.is_symlink() or digest(path) != value:
            raise ValueError('Committed runtime pin differs')
    output.mkdir(parents=True)
    (output / 'logs').mkdir()
    project = output / 'project'
    for name in PROJECT_FILES:
        destination = project / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repository / RUNTIME / name, destination)
    for name in pinned:
        destination = project / 'src/main' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repository / RUNTIME / 'src/main' / name, destination)
    environment = {k: v for k, v in os.environ.items()
                   if not k.startswith(('SIGNING_', 'CENTRAL_', 'XRAY_', 'V2RAY_'))}
    environment.update(GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='', XRAY_NATIVE_ROUTING='0',
                       XRAY_VERSION='v26.10.17', TARGET_DIR=str(output / 'fresh-jni'))
    environment.update({name: '1' for name in ('XRAY_BUILD_ARM64', 'XRAY_BUILD_ARMV7', 'XRAY_BUILD_X86', 'XRAY_BUILD_X86_64')})
    result = {'schema': 1, 'success': False, 'head': head, 'version': version,
              'source_sha256': inputs, 'pinned_HEV_geodata_sha256': pinned,
              'runtime_executed': False, 'installed': False, 'published': False, 'results': []}
    copied, cache, receipt, staged_before, fresh_before = None, None, None, None, None
    try:
        checked('ordinary-core-build', ['bash', str(repository / 'packages/flutter_vless_android/android/build_xray.sh')],
                output, environment, result['results'], cwd=repository, seconds=1200)
        receipts = list((output / 'fresh-jni').glob('classic-preview-*.json'))
        if len(receipts) != 1:
            raise ValueError('One fresh ordinary Core receipt required')
        receipt = json.loads(receipts[0].read_text())
        if any(receipt.get(k) is not True for k in ('success', 'source_unchanged', 'module_cache_source_unchanged',
                                                   'copies_unchanged', 'classic_dns_lifetime_applied', 'h3_lifetime_applied', 'darwin_interface_binding_source_applied')) \
                or type(receipt.get('routing_capability_expected')) is not int or receipt['routing_capability_expected'] != 0 \
                or receipt.get('lifetime_patch_scope') != ['classic_dns', 'xhttp_h3_dial'] \
                or any(receipt.get(k) is not False for k in ('runtime_executed', 'published')) \
                or receipt.get('selected_abis') != list(ABIS):
            raise ValueError('Ordinary lifetime build receipt differs')
        expected = {abi + '/libxray.so' for abi in ABIS}
        if set(receipt['artifacts_sha256']) != expected:
            raise ValueError('All four fresh Xray ABIs required')
        for name, value in receipt['artifacts_sha256'].items():
            source = output / 'fresh-jni' / safe_relative(name)
            if source.is_symlink() or digest(source) != value or value == pins['jniLibs/' + name]:
                raise ValueError('Fresh Xray byte provenance differs or old runtime was relabelled')
            destination = project / 'src/main/jniLibs' / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        copied = core_copy(receipts[0].name, repository)
        cache = Path(receipt['core_source'])
        if not cache.is_absolute() or tree(copied) != receipt['core_copy_sha256'] \
                or tree(cache) != receipt['module_cache_before_sha256']:
            raise ValueError('Ordinary copied source/cache changed')
        if set(receipt['source_sha256']) != set(ordinary_names) \
                or any(inputs[name] != value for name, value in receipt['source_sha256'].items()):
            raise ValueError('Ordinary producer source provenance differs')
        result.update(core_build_receipt='fresh-jni/' + receipts[0].name,
                      core_build_receipt_sha256=digest(receipts[0]),
                      copied_h3_sha256=receipt['core_copy_sha256'][DIALER])
        staged_before, fresh_before = tree(project / 'src/main'), tree(output / 'fresh-jni')
        result['staged_runtime_sha256'] = staged_before
        checked('isolated-aar-build', [str(repository / 'example/android/gradlew'), '-p', str(project), '--no-daemon',
                '--max-workers=2', '-PxrayRuntimeVersion=' + version, 'clean', 'verifyRuntimeInputs',
                'publishReleasePublicationToLocalBuildRepository'], output, environment, result['results'],
                cwd=repository, seconds=600)
        repo = project / 'build/repo'
        result['maven_files_sha256'] = tree(repo)
        aar = repo / f'dev/tfox/fluttervless/xray-android/{version}/xray-android-{version}.aar'
        result.update(aar=aar.relative_to(output).as_posix(), aar_sha256=digest(aar))
        result['success'] = True
    finally:
        invariants = {
            'source_unchanged': lambda: ordinary_inputs(repository) == ordinary_names and all(
                digest(repository / safe_relative(name)) == value for name, value in inputs.items()),
            'copied_source_unchanged': lambda: copied is not None and tree(copied) == receipt['core_copy_sha256'],
            'module_cache_source_unchanged': lambda: cache is not None and tree(cache) == receipt['module_cache_before_sha256'],
            'staged_runtime_unchanged': lambda: staged_before is not None and tree(project / 'src/main') == staged_before,
            'fresh_outputs_unchanged': lambda: fresh_before is not None and tree(output / 'fresh-jni') == fresh_before,
        }
        for name, check in invariants.items():
            try:
                result[name] = check()
            except (OSError, ValueError, KeyError, TypeError):
                result[name] = False
        if not all(result[name] for name in invariants):
            result['success'] = False
        (output / 'preview.json').write_text(json.dumps(result, indent=2) + '\n')
    if not result['success']:
        raise ValueError('Preview build input changed')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--head', required=True)
    args = parser.parse_args()
    try:
        build(args.output, args.head)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Unpublished Android runtime build failed: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
