#!/usr/bin/env python3
"""Actual native JSON preparers with fake I/O boundaries; never executes Core."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'tool/fixtures/compatibility/dns-ipv6-servers.json'
WINDOWS = ROOT / 'packages/flutter_vless_windows/windows'
APPLE = {
    'ios': (ROOT / 'ios/flutter_vless', 'flutter_vless'),
    'macos': (ROOT / 'packages/flutter_vless_macos/macos/flutter_vless_macos', 'flutter_vless_macos'),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_paths():
    paths = [Path(__file__).resolve(), CORPUS,
             ROOT / 'tool/fixtures/dns_ipv6_preparer.cpp', ROOT / 'tool/fixtures/dns_ipv6_preparer.swift',
             WINDOWS / 'xray_config.h', WINDOWS / 'preparation_report.h', WINDOWS / 'asset_location.h',
             WINDOWS / 'third_party/nlohmann/json.hpp']
    for base, module in APPLE.values():
        paths.extend(sorted((base / 'Sources' / (module + '_privacy')).glob('*.swift')))
        paths.extend(path for path in sorted((base / 'Sources' / (module + '_tunnel_support')).glob('*.swift'))
                     if path.name != 'FlutterVlessPacketTunnelProvider.swift')
    return paths


def apple_commands(label, output):
    base, module = APPLE[label]
    privacy = sorted((base / 'Sources' / (module + '_privacy')).glob('*.swift'))
    support = [path for path in sorted((base / 'Sources' / (module + '_tunnel_support')).glob('*.swift'))
               if path.name != 'FlutterVlessPacketTunnelProvider.swift']
    flags = ['xcrun', 'swiftc', '-O', '-target', platform.machine() + '-apple-macos13.0']
    directory = output / label
    directory.mkdir()
    definitions = ['-D', 'DNS_PREPARER_IOS_SOURCE'] if label == 'ios' else []
    common = ['-parse-as-library', '-emit-module', '-emit-object', '-whole-module-optimization']
    binary = directory / 'preparer'
    return binary, [
        flags + common + ['-module-name', module + '_privacy', '-emit-module-path',
            str(directory / (module + '_privacy.swiftmodule'))] + list(map(str, privacy)) + ['-o', str(directory / 'privacy.o')],
        flags + common + ['-I', str(directory), '-module-name', module + '_tunnel_support', '-emit-module-path',
            str(directory / (module + '_tunnel_support.swiftmodule'))] + list(map(str, support)) + ['-o', str(directory / 'support.o')],
        flags + definitions + ['-I', str(directory), str(ROOT / 'tool/fixtures/dns_ipv6_preparer.swift'),
            str(directory / 'privacy.o'), str(directory / 'support.o'), '-o', str(binary)],
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    arguments = parser.parse_args()
    os.umask(0o077)
    output = arguments.output.resolve()
    if output.exists():
        parser.error('Preserve previous evidence before a fresh run')
    output.mkdir(parents=True)
    before = {str(path.relative_to(ROOT)): digest(path) for path in source_paths()}
    corpus = json.loads(CORPUS.read_text())
    assert len(corpus) == 4 and {case['family'] for case in corpus} == {4, 6}
    # The same numeric admission helper owns these existing remote DNS modes.
    # This is preparation coverage only; wire tests cover UDP/TCP via a proxy.
    for name, address, hosts, direct in [
        ('numeric_https', 'https://[2001:db8::53]/dns-query', {}, False),
        ('numeric_h2c', 'h2c://[2001:db8::53]:8053/dns-query', {}, False),
        ('named_tcp', 'tcp://resolver.invalid:18053', {'full:resolver.invalid': '2001:db8::53'}, False),
        ('named_https', 'https://resolver.invalid/dns-query', {'full:resolver.invalid': ['2001:db8::53']}, False),
        ('named_h2c', 'h2c://resolver.invalid:8053/dns-query', {'full:resolver.invalid': ['2001:db8::53']}, False),
        ('mixed_static', 'https://resolver.invalid/dns-query', {'full:resolver.invalid': ['192.0.2.53', '2001:db8::53']}, False),
        ('direct_scalar', '2001:db8::53', {}, True),
    ]:
        case = json.loads(json.dumps(corpus[0]))
        case['name'] = 'ipv6_preparation_' + name
        case['config']['dns']['servers'][0]['address'] = address
        case['config']['dns']['hosts'].update(hosts)
        if direct:
            case['config']['outbounds'] = [{'tag': 'direct', 'protocol': 'freedom'}]
            case['config']['routing']['rules'] = []
        corpus.append(case)
    cpp = output / 'cpp-preparer'
    commands = [('cpp', cpp, [['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
        '-I', str(WINDOWS), str(ROOT / 'tool/fixtures/dns_ipv6_preparer.cpp'), '-o', str(cpp)]])]
    if platform.system() == 'Darwin':
        for label in APPLE:
            binary, compile_commands = apple_commands(label, output)
            commands.append((label, binary, compile_commands))
    results = []
    report = {'scope': 'native file-only preparation; no Core/socket/resolver/SDK/device',
              'source_sha256': before, 'cases': results, 'compilations': []}
    try:
        for label, binary, compile_commands in commands:
            for index, command in enumerate(compile_commands):
                compiled = subprocess.run(command, capture_output=True, timeout=120)
                log = output / f'{label}-compile-{index}.log'
                log.write_bytes(compiled.stdout + compiled.stderr)
                report['compilations'].append({'label': label, 'command': command,
                    'exit': compiled.returncode, 'log_sha256': digest(log)})
                if compiled.returncode:
                    raise RuntimeError('Preparation fixture failed to compile: ' + label)
            for case in corpus:
                prefix = label + '-' + case['name']
                original = json.dumps(case['config'], ensure_ascii=False, sort_keys=True).encode()
                source, effective = output / (prefix + '-source.json'), output / (prefix + '-effective.json')
                source.write_bytes(original)
                result = subprocess.run([str(binary), str(source), str(effective)], capture_output=True, timeout=10)
                (output / (prefix + '.log')).write_bytes(result.stdout + result.stderr)
                assert result.returncode in (0, 3), 'Unexpected preparation/fixture error'
                summary = json.loads(result.stdout)
                assert source.read_bytes() == original and summary['resolver_calls'] == 0
                assert summary['accepted'] == (result.returncode == 0)
                if summary['accepted']:
                    actual = json.loads(effective.read_bytes())
                    assert summary['dns_equal'] and actual['dns'] == case['config']['dns']
                    assert summary['availability_calls'] > 0, 'Positive control bypassed injected allocation'
                else:
                    assert not effective.exists(), 'Refusal emitted a partial profile'
                results.append({'preparer': label, 'name': case['name'], 'family': case['family'],
                    'expected_accepted': True, 'passed': summary['accepted'], 'exit': result.returncode,
                    'summary': summary, 'binary_sha256': digest(binary)})
        report['passed'] = sum(case['passed'] for case in results)
        report['failed'] = len(results) - report['passed']
        report['success'] = report['failed'] == 0
    finally:
        report['sources_unchanged'] = before == {str(path.relative_to(ROOT)): digest(path) for path in source_paths()}
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    assert report['sources_unchanged']
    print(json.dumps({'passed': report['passed'], 'failed': report['failed'], 'result': str(output / 'result.json')}))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
