#!/usr/bin/env python3
"""Actual GeoDAT host policies with synthetic files; never link/execute Core.

Apple compiles only Foundation/Darwin policy sources, not the SDK or provider.
Windows' MSVC counterpart is registered in windows/build_native_tests.cmd.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=['apple', 'cpp', 'all'], default='all')
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'build/geodata-assets-current')
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    children, source_hashes, results = [], {}, []

    def copy(source, destination):
        data = source.read_bytes()
        source_hashes[str(source.relative_to(ROOT))] = hashlib.sha256(data).hexdigest()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)

    def call(argv, name, timeout):
        with (output / (name + '.log')).open('xb') as log:
            child = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                child.wait(timeout=timeout)
            finally:
                if child.poll() is None:
                    if os.getpgid(child.pid) != child.pid:
                        raise RuntimeError('Owned process identity changed')
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=2)
                children.append({'role': name, 'PID': child.pid, 'exit': child.returncode, 'reaped': True})
        if child.returncode:
            raise RuntimeError(name + ' failed; see owned log')

    try:
        if args.platform in ('cpp', 'all'):
            windows = ROOT / 'packages/flutter_vless_windows/windows'
            copied = output / 'cpp-source'
            for source in windows.rglob('*'):
                if source.is_file() and (source.suffix in ('.h', '.hpp') or source.name == 'geodata_assets_test.cpp'):
                    copy(source, copied / source.relative_to(windows))
            binary = output / 'cpp-policy'
            call(['clang++', '-std=c++17', '-O2', '-DNDEBUG', str(copied / 'geodata_assets_test.cpp'), '-o', str(binary)], 'cpp-compile', 90)
            call([str(binary)], 'cpp-run', 15)
            results.append({'platform': 'cpp-real-host-filesystem', 'success': True})

        if args.platform in ('apple', 'all'):
            for platform, base in [
                ('ios', 'ios/flutter_vless/Sources/flutter_vless_privacy'),
                ('macos', 'packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_privacy'),
            ]:
                directory = output / (platform + '-source')
                directory.mkdir()
                inputs = []
                for name in ('GeoDatAssetPolicy.swift', 'XdriveServicePolicy.swift'):
                    target = directory / name
                    copy(ROOT / base / name, target)
                    inputs.append(target)
                field_source = ROOT / base / 'LocalProxyAccessPolicy.swift'
                text = field_source.read_text()
                source_hashes[str(field_source.relative_to(ROOT))] = hashlib.sha256(field_source.read_bytes()).hexdigest()
                text = text[text.index('public enum XrayJSONField {'):]
                field = directory / 'ActualSchemaField.swift'
                field.write_text(text)
                inputs.append(field)
                fixture = directory / 'Checks.swift'
                copy(ROOT / 'tool/fixtures/geodata_asset_policy.swift', fixture)
                inputs.append(fixture)
                binary = output / (platform + '-policy')
                call(['xcrun', 'swiftc', '-O', '-parse-as-library', *map(str, inputs), '-o', str(binary)], platform + '-compile', 100)
                call([str(binary)], platform + '-run', 15)
                results.append({'platform': platform + '-actual-policy-real-filesystem', 'success': True})
    finally:
        (output / 'result.json').write_text(json.dumps({
            'results': results, 'owned_children': children,
            'all_owned_children_reaped': all(c['reaped'] for c in children),
            'source_sha256': source_hashes,
            'Core_SDK_or_VPN_executed': False,
            'owner_configurations_or_downloads_used': False,
        }, indent=2) + '\n')
    print(json.dumps({'success': True, 'results': results, 'Core_execution': False}))


if __name__ == '__main__':
    os.umask(0o077)
    main()
