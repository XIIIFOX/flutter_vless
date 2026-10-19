#!/usr/bin/env python3
"""Package the existing opt-in Android CLI build for instrumentation only."""
import argparse
import hashlib
import json
import os
from pathlib import Path

import build_android_dns_preview as common

ROOT = Path(__file__).resolve().parents[1]
CAPABILITY = ROOT / 'third_party/xray-vpn-routing'
MOBILE = ROOT / 'third_party/xray-mobile'
PROTECT = ROOT / 'packages/flutter_vless_android/android/xray-protect'
BUILD = ROOT / 'packages/flutter_vless_android/android/build_xray.sh'
NAME = 'libxray_routing_preview.so'
CAPABILITY_ID = 'native-vpn-routing-cli-preview-1'
TAGS = ['flutter_vless_vpn_routing_cli', 'flutter_vless_vpn_routing']
FLAGS = {'arm64-v8a': 'XRAY_BUILD_ARM64', 'armeabi-v7a': 'XRAY_BUILD_ARMV7', 'x86': 'XRAY_BUILD_X86', 'x86_64': 'XRAY_BUILD_X86_64'}


def digest(path):
    with Path(path).open('rb') as source:
        value = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b''): value.update(chunk)
        return value.hexdigest()


def source_hashes():
    paths = [BUILD, MOBILE/'go.mod', MOBILE/'go.sum', CAPABILITY/'apply.py', CAPABILITY/'pin-manifest.json']
    paths += sorted(MOBILE.glob('*.go')) + sorted((MOBILE/'nativecli').rglob('*.go')) + sorted((CAPABILITY/'overlay').rglob('*.go'))
    paths += sorted(PROTECT.glob('*.py')) + sorted(PROTECT.glob('*.go'))
    if MOBILE.is_symlink() or (MOBILE/'nativecli').is_symlink() or any(path.is_symlink() for path in paths) or any(
            path.is_symlink() for base in (MOBILE/'nativecli', CAPABILITY/'overlay') for path in base.rglob('*')):
        raise ValueError('Routing source symlinks are unsupported')
    return {path.relative_to(ROOT).as_posix(): digest(path) for path in paths}


def validate_receipt(receipt, arch, raw):
    manifest = json.loads((CAPABILITY/'pin-manifest.json').read_text())
    expected = {'core_module': manifest['module'], 'core': manifest['module_version'], 'core_sum': manifest['module_sum'],
                'core_commit': manifest['core_commit'], 'overlay_capability': manifest['capability'], 'routing_tags': TAGS,
                'selected_abis': [arch], 'protection_overlay': 'ordinary H/P/D', 'routing_capability_expected': 1,
                }
    if any(receipt.get(k) != v for k, v in expected.items()) or receipt.get('routing_capability_expected') is True:
        raise ValueError('Routing build pin, protection or fixed tag evidence differs')
    if any(receipt.get(k) is not False for k in ('runtime_executed','published')):
        raise ValueError('Routing build must remain unpublished and unexecuted')
    if any(receipt.get(k) is not True for k in ('success','source_unchanged','module_cache_source_unchanged','copies_unchanged')):
        raise ValueError('Routing build evidence is incomplete')
    if receipt.get('source_sha256') != source_hashes() or Path(receipt.get('output_directory','')).absolute() != raw.absolute():
        raise ValueError('Routing build source snapshot or output differs')
    artifacts = receipt.get('artifacts_sha256')
    if not isinstance(artifacts, dict) or set(artifacts) != {arch+'/libxray.so'}:
        raise ValueError('Routing build ABI artifact set differs')
    return artifacts[arch+'/libxray.so']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--arch', choices=tuple(FLAGS), default='x86_64')
    args = parser.parse_args(argv)
    output = args.output.absolute()
    if output.exists() or output.is_symlink(): parser.error('Output must be a new directory')
    if not args.ndk.is_dir(): parser.error('Existing Android NDK is required')
    for protected in (CAPABILITY, MOBILE, PROTECT, BUILD.parent):
        if output.resolve() == protected.resolve() or protected.resolve() in output.resolve().parents:
            parser.error('Output must be outside source directories')
    cache = Path(common.owned(['go','env','GOMODCACHE'],cwd=MOBILE,environment=dict(os.environ,GOTOOLCHAIN='local',GOWORK='off'),seconds=20,capture=True).strip())
    if not cache.is_absolute() or output.resolve() == cache.resolve() or cache.resolve() in output.resolve().parents:
        parser.error('Output must be outside the Go module cache')
    before = source_hashes()
    output.mkdir(parents=True)
    raw = output/'raw'
    environment = dict(os.environ, ANDROID_NDK_HOME=str(args.ndk.resolve()), TARGET_DIR=str(raw), XRAY_NATIVE_ROUTING='1',
                       GOTOOLCHAIN='local', GOWORK='off', XRAY_VERSION='v26.10.17')
    environment.update({key: '1' if arch == args.arch else '0' for arch, key in FLAGS.items()})
    report = {'success': False, 'published': False, 'production_enabled': False, 'host_qualified': False,
              'runtime_executed': False, 'capability': CAPABILITY_ID, 'routing_capability_expected': 1, 'arch': args.arch}
    try:
        common.owned(['bash',str(BUILD)], cwd=ROOT, environment=environment, seconds=1200)
        receipts = list(raw.glob('routing-preview-*.json'))
        if len(receipts) != 1 or receipts[0].is_symlink(): raise ValueError('Expected one owned routing receipt')
        receipt = json.loads(receipts[0].read_text())
        expected = validate_receipt(receipt, args.arch, raw)
        source = raw/args.arch/'libxray.so'
        if source.is_symlink() or not source.is_file() or digest(source) != expected: raise ValueError('Routing output checksum differs')
        from verify_android_dns_preview import elf_alignment
        alignments = elf_alignment(source,args.arch)
        artifact = output/'jniLibs'/args.arch/NAME
        artifact.parent.mkdir(parents=True)
        source.rename(artifact)
        if source_hashes() != before: raise ValueError('Routing sources changed during packaging')
        report.update(success=True, build_receipt=receipt, artifact=str(artifact), artifact_sha256=digest(artifact), load_alignments=alignments)
    finally:
        (output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    from verify_android_routing_preview import verify
    (output/'verification.json').write_text(json.dumps(verify(output),indent=2)+'\n')
    return 0


if __name__ == '__main__': raise SystemExit(main())
