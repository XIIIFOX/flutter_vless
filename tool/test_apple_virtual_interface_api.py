#!/usr/bin/env python3
"""Typecheck the actual provider interface getter against Apple SDK overlays.

Only Network and NetworkExtension are imported. The observer is an inert type;
no provider is instantiated, callback installed, SDK loaded, or binary run.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = {
    'ios': ('example/ios/XrayTunnel/PacketTunnelProvider.swift', 'iphoneos',
            'arm64-apple-ios15.0'),
    'macos': ('packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/'
              'flutter_vless_macos_tunnel_support/FlutterVlessPacketTunnelProvider.swift',
              'macosx', 'arm64-apple-macos12.0'),
}


def probe_source(source):
    marker = '    private func makePhysicalPathObserver() -> TunnelPhysicalPathObserver {'
    if source.count(marker) != 1:
        raise ValueError('Unique actual interface factory required')
    begin = source.index(marker)
    end = source.index('\n    }\n', begin) + len('\n    }\n')
    method = source[begin:end]
    return '''import Network
import NetworkExtension

private final class TunnelPhysicalPathObserver {
    init(excludedInterfaceIndex: @escaping @Sendable () -> UInt32?) {}
}

private final class ProviderInterfaceProbe: NEPacketTunnelProvider {
''' + method + '\n}\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path,
                        default=ROOT/'build/apple-virtual-interface-api')
    args = parser.parse_args()
    output = args.output_dir
    if output.exists() or output.is_symlink():
        raise ValueError('New typecheck output directory required')
    output.mkdir(parents=True)
    results = {}
    for platform, (name, sdk_name, target) in PROVIDERS.items():
        original = (ROOT/name).read_bytes()
        generated = probe_source(original.decode())
        swift = output/(platform+'.swift')
        swift.write_text(generated)
        sdk = subprocess.check_output(['xcrun', '--sdk', sdk_name, '--show-sdk-path'],
                                      text=True, timeout=15).strip()
        command = ['xcrun', 'swiftc', '-typecheck', '-target', target, '-sdk', sdk,
                   '-module-cache-path', str(output/(platform+'-modules')), str(swift)]
        with (output/(platform+'.log')).open('wb') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=90)
        if (ROOT/name).read_bytes() != original:
            raise ValueError('Provider changed during typecheck')
        results[platform] = {
            'exit': result.returncode, 'sdk': sdk, 'target': target,
            'provider_path': name, 'provider_sha256': hashlib.sha256(original).hexdigest(),
            'probe_sha256': hashlib.sha256(generated.encode()).hexdigest(),
            'log_sha256': hashlib.sha256((output/(platform+'.log')).read_bytes()).hexdigest(),
        }
        print(platform, 'typecheck', result.returncode, flush=True)
    (output/'result.json').write_text(json.dumps({
        'results': results, 'typecheck_only': True, 'binary_executed': False,
        'Core_SDK_loaded_or_built': False, 'network_or_provider_instantiated': False,
    }, indent=2)+'\n')
    return 0 if all(row['exit'] == 0 for row in results.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
