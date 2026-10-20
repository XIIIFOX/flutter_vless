#!/usr/bin/env python3
"""Compile/run actual Apple SOCKS methods with finite in-memory socket boundaries."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parent.parent
PRIVACY = {
    'ios': ROOT / 'ios/flutter_vless/Sources/flutter_vless_privacy',
    'macos': ROOT / 'packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_privacy',
}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def public_method(source, name):
    marker = '    public static func ' + name + '('
    assert source.count(marker) == 1, 'public method boundary changed'
    start = source.index(marker)
    return source[start:source.index('\n    }\n', start)]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=('ios', 'macos', 'all'), default='all')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/apple_socks5_budget')
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=True)
    fixture = ROOT / 'tool/fixtures/apple_socks5_budget_test.swift'
    results = {}
    for label in PRIVACY if args.platform == 'all' else (args.platform,):
        folder = PRIVACY[label]
        sources = [folder / name for name in ['LocalProxyAccessPolicy.swift', 'XrayServiceTags.swift', 'LocalProxyIOBudget.swift', 'LocalSOCKS5Client.swift']]
        sources += [fixture, ROOT / 'tool/test_apple_socks5_budget.py']
        before = {str(p.relative_to(ROOT)): sha(p) for p in sources}
        client = (folder / 'LocalSOCKS5Client.swift').read_text()
        for name in ['authenticate', 'sendAll', 'receiveExactly', 'receiveSome']:
            method = public_method(client, name)
            assert f'if let budget {{ return {name}(' in method and 'budget: budget, io: LocalSOCKS5SystemIO())' in method
        connection = public_method(client, 'openConnection')
        assert 'if let budget {' in connection and 'return try openConnection(' in connection
        assert 'timeout: timeout, budget: budget, io: LocalSOCKS5SystemIO())' in connection
        local = public_method(client, 'openProxyConnection')
        assert 'try openProxyConnection(' in local and 'io: LocalSOCKS5SystemIO())' in local
        assert 'MSG_DONTWAIT | MSG_NOSIGNAL' in client and 'Darwin.recv(fd, pointer, count, MSG_DONTWAIT)' in client
        output = args.output / label
        output.mkdir(exist_ok=True)
        command = ['xcrun', 'swiftc', '-O', '-warnings-as-errors', '-parse-as-library', *map(str, sources[:-1]), '-o', str(output / 'probe')]
        built = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (output / 'compile.log').write_text(built.stdout + built.stderr)
        assert built.returncode == 0, 'actual inert Swift compilation failed'
        result = subprocess.run([str(output / 'probe')], capture_output=True, text=True, timeout=10)
        (output / 'probe.log').write_text(result.stdout + result.stderr)
        assert result.returncode == 0, 'actual inert SOCKS budget assertion failed'
        assert result.stdout.count('PASS ') == 26 and 'APPLE_SOCKS5_BUDGET_PASS=26\n' in result.stdout
        assert before == {str(p.relative_to(ROOT)): sha(p) for p in sources}, 'source changed during verification'
        results[label] = {'source_sha256': before, 'controls': 26, 'passed': True,
                          'compile_command': command, 'boundary': 'fake I/O and monotonic clock only',
                          'binary_sha256': sha(output / 'probe'), 'log_sha256': sha(output / 'probe.log')}
        print(f'PASS {label}: actual SOCKS budget controls=26; no sockets/Core/SDK/device')
    (args.output / 'result.json').write_text(json.dumps(results, indent=2) + '\n')

if __name__ == '__main__':
    main()
