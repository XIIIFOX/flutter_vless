#!/usr/bin/env python3
"""Build a separate pinned FD-handoff forwarder, without running it."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil

import build_android_dns_preview as common

ROOT = common.ROOT
CAPABILITY = ROOT / 'third_party/tun2socks-native'


def input_hashes():
    paths = [CAPABILITY / name for name in ('apply.py', 'pin-manifest.json')]
    paths += sorted((CAPABILITY / 'overlay').rglob('*.go'))
    # Copy/cache guards are part of the exact builder inputs too.
    paths += [common.CAPABILITY / 'apply.py', ROOT / 'tool/build_android_tun_preview.py',
              ROOT / 'tool/build_android_dns_preview.py']
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def guarded_source_hashes(source, manifest):
    """Hash exact guarded files in the disposable post-apply tree, never links."""
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise ValueError('Forwarder guarded source root is missing or symlinked')
    result = {}
    for relative in manifest['upstream_sha256']:
        path = Path(relative)
        if path.is_absolute() or not path.parts or '..' in path.parts:
            raise ValueError('Forwarder guarded source path is invalid')
        candidate = source
        for part in path.parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise ValueError('Forwarder guarded source contains a symlink')
        if not candidate.is_file():
            raise ValueError('Forwarder guarded source file is missing')
        result[relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--arch', choices=common.TARGETS, default='x86_64')
    parser.add_argument('--go', default='go')
    parser.add_argument('--ndk', type=Path, default=os.environ.get('ANDROID_NDK_HOME'))
    args = parser.parse_args()
    if platform.system() not in ('Darwin', 'Linux') or args.ndk is None:
        parser.error('An existing macOS/Linux Android NDK is required')
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error('output must be a new disposable directory')
    go = str(Path(shutil.which(args.go) or args.go).resolve())
    compiler = args.ndk.resolve() / 'toolchains/llvm/prebuilt' / ('darwin-x86_64' if platform.system() == 'Darwin' else 'linux-x86_64') / 'bin'
    architecture, arm, target = common.TARGETS[args.arch]
    cc, cxx = compiler / (target + '-clang'), compiler / (target + '-clang++')
    if not cc.is_file() or not cxx.is_file():
        parser.error('Android target compiler is unavailable')
    initial = input_hashes()
    manifest = json.loads((CAPABILITY / 'pin-manifest.json').read_text())
    env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off')
    metadata = json.loads(common.owned([go, 'mod', 'download', '-json', manifest['module'] + '@' + manifest['module_version']],
                                     cwd=ROOT / 'third_party/xray-mobile', environment=env, seconds=180, capture=True))
    if metadata.get('Version') != manifest['module_version'] or metadata.get('Sum') != manifest['module_sum']:
        raise RuntimeError('Pinned forwarder module/checksum mismatch')
    spec = importlib.util.spec_from_file_location('private_forwarder_copy', CAPABILITY / 'apply.py')
    copier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(copier)
    source, work = Path(metadata['Dir']).resolve(), output / 'Source'
    # Validate before creating the parent; a module-cache output is forbidden.
    guard_spec = importlib.util.spec_from_file_location('forwarder_build_guard', common.CAPABILITY / 'apply.py')
    guard = importlib.util.module_from_spec(guard_spec)
    guard_spec.loader.exec_module(guard)
    guard.validate_destination(source, output, guard.module_cache_paths(go))
    output.mkdir(parents=True)
    report = {'success': False, 'published': False, 'production_enabled': False, 'host_qualified': False,
              'capability': manifest['capability'], 'forwarder_commit': manifest['commit'], 'arch': args.arch,
              'module_sum': manifest['module_sum'], 'input_sha256': initial, 'runtime_executed': False,
              'copied_guarded_sources_unchanged': False}
    try:
        copier.copy_and_apply(source, work, go)
        # Includes existing files modified by the guarded patch, not only the
        # additive overlay. Capture before the compiler can read any of them.
        report['patched_source_sha256'] = guarded_source_hashes(work, manifest)
        artifact = output / 'jniLibs' / args.arch / 'libtun2socks_preview.so'
        artifact.parent.mkdir(parents=True)
        build_env = dict(env, GOOS='android', GOARCH=architecture, GOARM=arm, CGO_ENABLED='1', CC=str(cc), CXX=str(cxx))
        common.owned([go, 'build', '-trimpath', '-buildvcs=false', '-buildmode=pie',
                      '-ldflags=-s -w -buildid= -checklinkname=0 -linkmode=external -extldflags=-Wl,-z,max-page-size=16384',
                      '-o', str(artifact), './main/nativepreview'], cwd=work, environment=build_env, seconds=600)
        report.update(artifact=str(artifact), artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest())
        report['source_snapshot_unchanged'] = initial == input_hashes() and all(
            hashlib.sha256((work / p.relative_to(CAPABILITY / 'overlay')).read_bytes()).hexdigest() == initial[str(p.relative_to(ROOT))]
            for p in (CAPABILITY / 'overlay').rglob('*.go'))
        if not report['source_snapshot_unchanged']:
            raise RuntimeError('Forwarder input snapshot changed')
        report['copied_guarded_sources_unchanged'] = report['patched_source_sha256'] == guarded_source_hashes(work, manifest)
        if not report['copied_guarded_sources_unchanged']:
            raise RuntimeError('Forwarder copied guarded sources changed')
        report['success'] = True
    except BaseException as error:
        report['error_type'] = type(error).__name__
        raise
    finally:
        try:
            report['copied_guarded_sources_unchanged'] = isinstance(report.get('patched_source_sha256'), dict) and report['patched_source_sha256'] == guarded_source_hashes(work, manifest)
        except (OSError, ValueError):
            report['copied_guarded_sources_unchanged'] = False
        try:
            report['module_cache_targeted_sources_unchanged'] = guarded_source_hashes(source, manifest) == manifest['upstream_sha256']
        except (OSError, ValueError):
            report['module_cache_targeted_sources_unchanged'] = False
        report['success'] = report['success'] and report['module_cache_targeted_sources_unchanged'] and report['copied_guarded_sources_unchanged']
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    if not report['success']:
        raise RuntimeError('Forwarder source verification failed')


if __name__ == '__main__':
    main()
