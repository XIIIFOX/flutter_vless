#!/usr/bin/env python3
"""Run transitive actual provider admission/start code against inert boundaries."""
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


def block(source, marker):
    start = source.index(marker)
    end = source.index('\n    }\n', start) + len('\n    }\n')
    return source[start:end]


def check_wiring(source):
    entry = block(source, '    ' + ('open override' if '    open override func startTunnel' in source else 'override') + ' func startTunnel')
    initial = block(source, '    private func prepareInitialRuntimeSpec(')
    preflight = block(source, '    private func checkEndpointPreflight(')
    install = block(source, '    private func installProtectedSettings(')
    spec = block(source, '    private struct RuntimeSpec')
    native = block(source, '    private func startNativeRuntime(')
    start = block(source, '    private func startXRay(')
    # Follow the actual call graph, rather than demanding a moved operation be
    # textually present in the entry method. Direct entry writes bypass this gate.
    assert entry.index('NativeRoutingSpec.requireRuntime') < entry.index('sessionAdmission.begin()') < entry.index('prepareInitialRuntimeSpec(source)')
    assert entry.index('prepareInitialRuntimeSpec(source)') < entry.index('TunnelOnDemandPolicy.enableForStart') < entry.index('endpointAdmission.commit(token)') < entry.index('startTunnelWatchdog(spec)')
    assert 'routingIntent: routingIntent' in entry and 'setTunnelNetworkSettings(' not in entry
    assert initial.index('prepareEndpointConfig(') < initial.index('RuntimeSpec(source: source, prepared: prepared,') < initial.index('checkEndpointPreflight(') < initial.index('endpointCommitQueue.submit') < initial.index('installProtectedSettings(spec)') < initial.index('return spec')
    assert 'prepared.endpointPath == path' in initial
    assert initial.count('endpointAdmission.isCurrent(token)') >= 4
    assert preflight.index('(source.routingIntent == nil) == (prepared.routingEnvelope == nil)') < preflight.index('NativeRoutingSpec.check(')
    assert 'if prepared.routingEnvelope != nil || FLVlessHasCorePreflight()' in preflight
    assert 'try NativeRoutingSpec.check(envelope, capability: FLVlessCoreRoutingCapability, check: FLVlessCheckCoreRoutingPrivate)' in preflight
    assert '} else { try CorePreflightPolicy.validate(prepared.data, check: FLVlessCheckCorePrivate) }' in preflight
    assert install.index('setTunnelNetworkSettings(protectedNetworkSettings(spec))') < install.index('installedSettingsKey = key')
    assert 'installedSettingsKey = nil' in install
    assert 'config = prepared.routingEnvelope?.configurationData ?? prepared.data' in spec
    assert 'routingMetadata = prepared.routingEnvelope?.metadataData' in spec
    pair = 'try startXRay(xrayConfig: spec.config, geoAssetsDirectory: spec.geoAssetsDirectory, routingMetadata: spec.routingMetadata)'
    assert pair in native and native.index(pair) < native.index('startSocks5Tunnel(')
    assert start.index('NativeRoutingSpec.requireRuntime') < start.index('XRaySetMemoryLimit()')
    assert 'FLVlessStartCoreRoutingPrivate(xrayConfig, routingMetadata, logger, &error)' in start
    return entry, initial, preflight, install, spec, native, start


def mutation_controls(source):
    entry, initial, preflight, install, spec, native, start = check_wiring(source)
    checked = '                try await onRuntimeQueue { try self.checkEndpointPreflight(spec, prepared: prepared, source: source) }\n'
    installed = '                    try await self.installProtectedSettings(spec)\n'
    assert initial.count(checked) == initial.count(installed) == 1
    reordered = initial.replace(checked, '', 1).replace(installed, installed + checked, 1)
    controls = {
        'missing-early-capability': source.replace('if routingIntent != nil { try NativeRoutingSpec.requireRuntime(FLVlessCoreRoutingCapability()) }', 'if routingIntent != nil {}', 1),
        'preflight-after-routes': source.replace(initial, reordered, 1),
        'direct-entry-route-bypass': source.replace(entry, entry.replace('        let epoch = sessionAdmission.begin()', '        try await setTunnelNetworkSettings(nil)\n        let epoch = sessionAdmission.begin()', 1), 1),
        'routing-check-made-optional': source.replace(preflight, preflight.replace('prepared.routingEnvelope != nil || FLVlessHasCorePreflight()', 'FLVlessHasCorePreflight()', 1), 1),
        'routing-config-unpaired': source.replace(spec, spec.replace('prepared.routingEnvelope?.configurationData ?? prepared.data', 'prepared.data', 1), 1),
        'routing-metadata-dropped': source.replace(spec, spec.replace('routingMetadata = prepared.routingEnvelope?.metadataData', 'routingMetadata = nil', 1), 1),
        'runtime-metadata-dropped': source.replace(native, native.replace('routingMetadata: spec.routingMetadata)', 'routingMetadata: nil)', 1), 1),
        'routing-start-falls-back': source.replace(start, start.replace('FLVlessStartCoreRoutingPrivate(xrayConfig, routingMetadata, logger, &error)', 'XRayStartPrivate(xrayConfig, logger, &error)', 1), 1),
    }
    for name, mutated in controls.items():
        assert mutated != source, ('mutation did not reach source', name)
        try:
            check_wiring(mutated)
        except (AssertionError, ValueError):
            continue
        raise AssertionError(('source guard admitted mutation', name))
    return list(controls)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'build/apple_native_routing_admission')
    output = parser.parse_args().output_dir
    output.mkdir(parents=True, exist_ok=True)
    (output / 'result.json').unlink(missing_ok=True)
    fixture_path = ROOT / 'tool/fixtures/apple_native_routing_admission.swift'
    fixture = fixture_path.read_text()
    privacy = ROOT / 'ios/flutter_vless/Sources/flutter_vless_privacy'
    support = ROOT / 'ios/flutter_vless/Sources/flutter_vless_tunnel_support'
    inputs = [privacy / name for name in ['LocalProxyAccessPolicy.swift', 'XrayServiceTags.swift', 'NativeRoutingSpec.swift', 'CorePreflightPolicy.swift']]
    inputs += [support / 'TunnelSessionAdmission.swift', support / 'TunnelEndpointPlanAdmission.swift']
    hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs + [fixture_path, Path(__file__)]}
    mutations = {}
    for platform, path in PROVIDERS.items():
        source = path.read_text()
        hashes[str(path.relative_to(ROOT))] = hashlib.sha256(source.encode()).hexdigest()
        entry, _, _, _, _, native, start_method = check_wiring(source)
        mutations[platform] = mutation_controls(source)
        parts = [block(source, '    private struct ' + name) for name in ['RuntimeSource', 'RuntimeSpec', 'ProtectedSettingsKey']]
        parts += [block(source, '    private func ' + name) for name in ['prepareInitialRuntimeSpec(', 'checkEndpointPreflight(', 'installProtectedSettings(', 'onRuntimeQueue<']]
        actual = '\n'.join(parts).replace('private struct', 'struct').replace('private func', 'func')
        capability = [line for line in entry.splitlines() if 'if routingIntent != nil { try NativeRoutingSpec.requireRuntime' in line]
        start_pair = [line for line in native.splitlines() if 'try startXRay(xrayConfig:' in line]
        assert len(capability) == len(start_pair) == 1
        generated = fixture.replace('    // SOURCE_ADMISSION_HELPERS', actual)
        generated = generated.replace('        // SOURCE_CAPABILITY_ENTRY', capability[0])
        generated = generated.replace('        // SOURCE_RUNTIME_START_PAIR', start_pair[0])
        generated = generated.replace('    // SOURCE_START', start_method.replace('private func', 'func'))
        destination = output / (platform + '.swift')
        destination.write_text(generated)
        executable = output / (platform + '-probe')
        subprocess.run(['xcrun', 'swiftc', '-O', '-parse-as-library', *map(str, inputs), str(destination), '-o', str(executable)], check=True, timeout=100)
        result = subprocess.run([str(executable)], text=True, capture_output=True, timeout=15)
        (output / (platform + '.log')).write_text(result.stdout + result.stderr)
        assert result.returncode == 0, (platform, result.returncode, result.stderr, result.stdout)
        assert 'PASS provider exact routing pair, capability admission and no fallback' in result.stdout
        print(platform + ': ' + result.stdout, end='')
        assert path.read_text() == source
    for name, digest in hashes.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
    (output / 'result.json').write_text(json.dumps({'success': True, 'native_runtime_executed': False,
        'source_sha256': hashes, 'source_mutation_controls': mutations,
        'transitive_actual_methods': ['prepareInitialRuntimeSpec', 'RuntimeSource', 'RuntimeSpec', 'checkEndpointPreflight', 'installProtectedSettings', 'onRuntimeQueue', 'startXRay', 'actual native start pair']}, indent=2) + '\n')


if __name__ == '__main__':
    main()
