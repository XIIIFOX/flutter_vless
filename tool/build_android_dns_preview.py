#!/usr/bin/env python3
"""Build a separate, unpublished Android scoped entry; never install or run it."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CAPABILITY = ROOT / 'third_party/xray-native-dns'
PROTECTION = ROOT / 'packages/flutter_vless_android/android/xray-protect'
TARGETS = {
    'arm64-v8a': ('arm64', '', 'aarch64-linux-android23'),
    'armeabi-v7a': ('arm', '7', 'armv7a-linux-androideabi23'),
    'x86': ('386', '', 'i686-linux-android23'),
    'x86_64': ('amd64', '', 'x86_64-linux-android23'),
}


def owned(command, *, cwd, environment, seconds, capture=False):
    """Own a new compiler group; timeout cleanup includes its children."""
    process = subprocess.Popen(command, cwd=cwd, env=environment,
                               stdout=subprocess.PIPE if capture else None,
                               stderr=subprocess.PIPE if capture else None,
                               text=True, encoding='utf-8', start_new_session=True)
    try:
        output, error = process.communicate(timeout=seconds)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate(timeout=15)
        raise
    if process.returncode:
        raise RuntimeError(f'Build phase failed with status {process.returncode}')
    return output or ''


def input_hashes():
    paths = [CAPABILITY / name for name in ('apply.py', 'pin-manifest.json')]
    paths += sorted(CAPABILITY.glob('*_patch.py'))
    paths += sorted((CAPABILITY / 'overlay').rglob('*.go'))
    paths += [path for path in sorted(PROTECTION.glob('*')) if path.is_file()]
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='new disposable directory')
    parser.add_argument('--arch', choices=TARGETS, default='x86_64')
    parser.add_argument('--go', default='go', help='existing Go 1.27+; no toolchain installation')
    parser.add_argument('--ndk', type=Path, default=os.environ.get('ANDROID_NDK_HOME'))
    args = parser.parse_args()
    system = platform.system()
    if system not in ('Darwin', 'Linux'):
        parser.error('Android NDK build requires macOS or Linux')
    if args.ndk is None:
        parser.error('--ndk or ANDROID_NDK_HOME is required')
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error('output must be a new disposable directory')
    go = str(Path(shutil.which(args.go) or args.go).resolve())
    ndk = args.ndk.resolve()
    compiler = ndk / 'toolchains/llvm/prebuilt' / ('darwin-x86_64' if system == 'Darwin' else 'linux-x86_64') / 'bin'
    architecture, arm, target = TARGETS[args.arch]
    cc, cxx = compiler / f'{target}-clang', compiler / f'{target}-clang++'
    if not cc.is_file() or not cxx.is_file():
        parser.error('requested Android NDK compilers are unavailable')
    initial_hashes = input_hashes()
    manifest = json.loads((CAPABILITY / 'pin-manifest.json').read_text())
    environment = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off')
    metadata = json.loads(owned([go, 'mod', 'download', '-json', f"{manifest['module']}@{manifest['module_version']}"],
                                cwd=ROOT / 'third_party/xray-mobile', environment=environment, seconds=180, capture=True))
    if metadata.get('Version') != manifest['module_version'] or metadata.get('Sum') != manifest['module_sum']:
        raise RuntimeError('Pinned Core version/checksum mismatch')
    spec = importlib.util.spec_from_file_location('scoped_android_copy', CAPABILITY / 'apply.py')
    copier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(copier)
    source, work = Path(metadata['Dir']).resolve(), output / 'Core'
    copier.validate_destination(source, output, copier.module_cache_paths(go))
    output.mkdir(parents=True)
    report = {'published': False, 'production_enabled': False, 'host_qualified': False,
              'capability': 'native-instance-preview-1', 'core_commit': manifest['core_commit'],
              'arch': args.arch, 'module_sum': metadata['Sum'], 'go_binary': go, 'success': False,
              'input_sha256': initial_hashes}
    try:
        copier.copy_and_apply(source, work, go=go)
        owned([os.sys.executable, str(PROTECTION / 'apply.py'), str(work)], cwd=ROOT,
              environment=environment, seconds=30)
        artifact = output / 'jniLibs' / args.arch / 'libxray_dns_preview.so'
        artifact.parent.mkdir(parents=True)
        build_environment = dict(environment, CGO_ENABLED='1', GOOS='android', GOARCH=architecture,
                                 GOARM=arm, CC=str(cc), CXX=str(cxx))
        owned([go, 'build', '-trimpath', '-buildvcs=false', '-buildmode=pie',
               '-ldflags=-s -w -buildid= -checklinkname=0 -linkmode=external -extldflags=-Wl,-z,max-page-size=16384',
               '-o', str(artifact), './main/nativepreview'], cwd=work, environment=build_environment, seconds=600)
        report['artifact'] = str(artifact)
        report['artifact_sha256'] = hashlib.sha256(artifact.read_bytes()).hexdigest()
        report['source_snapshot_unchanged'] = input_hashes() == report['input_sha256']
        overlay_prefix = 'third_party/xray-native-dns/overlay/'
        for relative, digest in report['input_sha256'].items():
            if relative.startswith(overlay_prefix):
                compiled_input = work / relative[len(overlay_prefix):]
                if hashlib.sha256(compiled_input.read_bytes()).hexdigest() != digest:
                    report['source_snapshot_unchanged'] = False
        # The Android copier has fixed destination names, unlike the additive
        # DNS overlay. Check the files used by this separate executable too.
        for name, copied in {'protect.go': 'common/androidprotect/protect.go',
                             'main_android.go': 'main/flutter_vless_protect_android.go'}.items():
            relative = str((PROTECTION / name).relative_to(ROOT))
            if hashlib.sha256((work / copied).read_bytes()).hexdigest() != report['input_sha256'][relative]:
                report['source_snapshot_unchanged'] = False
        if not report['source_snapshot_unchanged']:
            raise RuntimeError('Build input snapshot changed')
        report['module_cache_targeted_sources_unchanged'] = all(
            hashlib.sha256((source / relative).read_bytes()).hexdigest() == digest
            for relative, digest in manifest['upstream_sha256'].items())
        if not report['module_cache_targeted_sources_unchanged']:
            raise RuntimeError('Original pinned sources changed')
        report['success'] = True
    except BaseException as error:
        report['success'] = False
        report['error_type'] = type(error).__name__
        raise
    finally:
        report['module_cache_targeted_sources_unchanged'] = all(
            hashlib.sha256((source / relative).read_bytes()).hexdigest() == digest
            for relative, digest in manifest['upstream_sha256'].items())
        if not report['module_cache_targeted_sources_unchanged']:
            report['success'] = False
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    if not report['module_cache_targeted_sources_unchanged']:
        raise RuntimeError('Original pinned sources changed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
