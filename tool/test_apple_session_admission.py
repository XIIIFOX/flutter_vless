#!/usr/bin/env python3
"""Run actual provider admission methods against in-memory native boundaries."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parent.parent
PROVIDERS = {
    'ios': ROOT / 'example/ios/XrayTunnel/PacketTunnelProvider.swift',
    'macos': ROOT / 'packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_tunnel_support/FlutterVlessPacketTunnelProvider.swift',
}
GATES = {
    'ios': ROOT / 'ios/flutter_vless/Sources/flutter_vless_tunnel_support/TunnelSessionAdmission.swift',
    'macos': ROOT / 'packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_tunnel_support/TunnelSessionAdmission.swift',
}
METHODS = ['setForwardingReady', 'isForwardingReady', 'stopTunnel', 'setStartupPreparation',
           'startNativeRuntime', 'stopNativeRuntime', 'scheduleNativeRecovery', 'sleep', 'wake',
           'startTunnelWatchdog', 'stopTunnelWatchdog', 'scheduleTunnelHealthCheck',
           'scheduleRecoveryCheck', 'performTunnelHealthCheck', 'reportTerminalFailure',
           'handleRuntimeFailure']


def block(source, marker):
    start = source.index(marker)
    # Provider methods/structs are indented four spaces. Inner scopes retain
    # their own indentation; do not extract an adjacent synthetic implementation.
    end = source.index('\n    }\n', start) + len('\n    }\n')
    return source[start:end]


def check_wiring(source):
    entry = block(source, '    ' + ('open override' if '    open override func startTunnel' in source else 'override') + ' func startTunnel')
    assert 'let epoch = sessionAdmission.begin()' in entry
    assert 'isCancelled: { !self.sessionAdmission.isCurrent(epoch) }' in entry
    assert 'guard sessionAdmission.isCurrent(epoch) else { throw CancellationError() }\n        try await setTunnelNetworkSettings(settings)' in entry
    assert 'guard sessionAdmission.isCurrent(epoch), !preparation.isCancelled else' in entry
    assert 'guard startTunnelWatchdog(spec) else { throw CancellationError() }' in entry
    hev = block(source, '    private func startSocks5Tunnel')
    assert hev.count('sessionAdmission.permitsRuntime(epoch)') >= 3
    assert 'code: Int(exitCode), epoch: epoch' in hev
    if 'TunnelPacketBridge' in hev:
        assert 'packetBridgeEpoch == epoch' in hev
        assert 'self.sessionAdmission.permitsRuntime(epoch), !self.watchdogSuspended' in hev
    stop = block(source, '    ' + ('open override' if '    open override func stopTunnel' in source else 'override') + ' func stopTunnel')
    assert stop.index('sessionAdmission.revoke()') < stop.index('stopTunnelWatchdog') < stop.index('runtimeQueue.async')
    assert 'ownedBy: stoppedEpoch' in stop
    sleep = block(source, '    ' + ('open override' if '    open override func sleep' in source else 'override') + ' func sleep')
    assert sleep.index('sessionAdmission.suspend(epoch)') < sleep.index('watchdogQueue.async')
    assert '!self.sessionAdmission.permitsRuntime(epoch)' in sleep
    wake = block(source, '    ' + ('open override' if '    open override func wake' in source else 'override') + ' func wake')
    assert wake.index('sessionAdmission.resume(epoch)') < wake.index('watchdogQueue.async')
    assert 'guard self.sessionAdmission.permitsRuntime(epoch)' in wake
    recovery = block(source, '    private func scheduleRecoveryCheck')
    assert recovery.index('self.sessionAdmission.isCurrent(epoch)') < recovery.index('self.recoveryCheck = nil')
    assert recovery.index('self.recoveryCheck = nil') < recovery.index('guard self.sessionAdmission.permitsRuntime(epoch)')
    assert 'watchdogGeneration' not in source and 'startupStopped' not in source


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=tuple(PROVIDERS), required=True)
    args = parser.parse_args()
    output = ROOT / 'build/apple_session_admission' / args.platform
    output.mkdir(parents=True, exist_ok=True)
    (output / 'result.json').unlink(missing_ok=True)
    assert GATES['ios'].read_bytes() == GATES['macos'].read_bytes(), 'Apple admission gates diverged'
    source = PROVIDERS[args.platform].read_text()
    gate = GATES[args.platform].read_bytes()
    check_wiring(source)
    parts = [block(source, '    private struct RuntimeSpec')]
    for method in METHODS:
        candidates = [line for line in source.splitlines() if f'func {method}(' in line]
        assert len(candidates) == 1, (method, candidates)
        method_source = block(source, candidates[0])
        if method == 'performTunnelHealthCheck':
            method_source = '    @discardableResult\n' + method_source
        parts.append(method_source)
    actual = '\n'.join(parts).replace('private struct', 'struct').replace('private func', 'func').replace('open override func', 'func').replace('override func', 'func')
    fixture_path = ROOT / 'tool/fixtures/apple_session_admission_test.swift'
    fixture_source = fixture_path.read_text()
    fixture = fixture_source
    assert fixture.count('    // SOURCE_PROVIDER_METHODS') == 1
    fixture = fixture.replace('    // SOURCE_PROVIDER_METHODS', actual)
    generated = output / 'Probe.swift'
    generated.write_text(fixture)
    support = ROOT / 'ios/flutter_vless/Sources/flutter_vless_tunnel_support/TunnelRuntimeSupport.swift'
    command = ['xcrun', 'swiftc', '-O', '-parse-as-library', str(GATES[args.platform]), str(support), str(generated), '-o', str(output / 'probe')]
    subprocess.run(command, check=True, timeout=120)
    result = subprocess.run([str(output / 'probe')], capture_output=True, text=True, timeout=20)
    (output / 'probe.log').write_text(result.stdout + result.stderr)
    print(result.stdout, end='')
    assert result.returncode == 0, (result.returncode, result.stderr)
    assert len([line for line in result.stdout.splitlines() if line.startswith('PASS ')]) == 8
    assert PROVIDERS[args.platform].read_text() == source and GATES[args.platform].read_bytes() == gate
    assert fixture_path.read_text() == fixture_source, 'Source changed during verification'
    (output / 'result.json').write_text(json.dumps({
        'platform': args.platform, 'provider_sha256': hashlib.sha256(source.encode()).hexdigest(),
        'gate_sha256': hashlib.sha256(gate).hexdigest(),
        'fixture_sha256': hashlib.sha256(fixture_source.encode()).hexdigest(),
        'native_boundaries': 'in-memory-only', 'passed': True}, indent=2) + '\n')
    print(f'PASS {args.platform} provider source wiring and controlled callback admission')


if __name__ == '__main__':
    main()
