#!/usr/bin/env python3
"""Compile actual provider admission/start methods against inert native boundaries."""
from pathlib import Path
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


def main():
    output = ROOT / 'build/apple_native_routing_admission'
    output.mkdir(parents=True, exist_ok=True)
    fixture_path = ROOT / 'tool/fixtures/apple_native_routing_admission.swift'
    fixture = fixture_path.read_text()
    privacy = ROOT / 'ios/flutter_vless/Sources/flutter_vless_privacy'
    inputs = [privacy / name for name in ['LocalProxyAccessPolicy.swift', 'XrayServiceTags.swift',
              'NativeRoutingSpec.swift', 'CorePreflightPolicy.swift']]
    hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs + [fixture_path, Path(__file__)]}
    for platform, path in PROVIDERS.items():
        source = path.read_text()
        hashes[str(path.relative_to(ROOT))] = hashlib.sha256(source.encode()).hexdigest()
        entry = block(source, '    ' + ('open override' if '    open override func startTunnel' in source else 'override') + ' func startTunnel')
        assert entry.index('NativeRoutingSpec.requireRuntime') < entry.index('sessionAdmission.begin()') < entry.index('setTunnelNetworkSettings(settings)')
        assert 'routingIntent: routingIntent' in entry
        begin = entry.index('        guard (routingIntent == nil)')
        end = entry.index('        let settings = NEPacketTunnelNetworkSettings', begin)
        admission = entry[begin:end]
        start = entry.index('        let spec = RuntimeSpec(')
        end = entry.index('        guard startTunnelWatchdog(spec)', start)
        spec_creation = entry[start:end]
        assert entry.index('NativeRoutingSpec.check') < entry.index('setTunnelNetworkSettings(settings)') < start
        start_method = block(source, '    private func startXRay(').replace('private func', 'func')
        assert start_method.index('NativeRoutingSpec.requireRuntime') < start_method.index('XRaySetMemoryLimit()')
        assert 'FLVlessStartCoreRoutingPrivate(xrayConfig, routingMetadata, logger, &error)' in start_method
        generated = fixture.replace('    // SOURCE_ADMISSION', admission + '\n        Boundary.events.append("routes")\n' + spec_creation + '\n        return spec')
        generated = generated.replace('    // SOURCE_START', start_method)
        generated = generated.replace('    // SOURCE_RUNTIME_SPEC', block(source, '    private struct RuntimeSpec').replace('private struct', 'struct'))
        destination = output / (platform + '.swift')
        destination.write_text(generated)
        executable = output / (platform + '-probe')
        subprocess.run(['xcrun', 'swiftc', '-O', '-parse-as-library', *map(str, inputs), str(destination), '-o', str(executable)], check=True, timeout=100)
        result = subprocess.run([str(executable)], text=True, capture_output=True, timeout=10)
        (output / (platform + '.log')).write_text(result.stdout + result.stderr)
        assert result.returncode == 0, (platform, result.returncode, result.stderr)
        assert 'PASS provider exact routing pair, capability admission and no fallback' in result.stdout
        print(platform + ': ' + result.stdout, end='')
        assert path.read_text() == source
    for name, digest in hashes.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
    (output / 'result.json').write_text(json.dumps({'success': True, 'native_runtime_executed': False, 'source_sha256': hashes}, indent=2) + '\n')


if __name__ == '__main__':
    main()
