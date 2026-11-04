#!/usr/bin/env python3
"""Require actual macOS build and released-SDK evidence, not an empty green job."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess

from install_published_apple_runtime import PINS, REVISION

ROOT = Path(__file__).resolve().parents[1]
MAC_SOURCES = 'packages/flutter_vless_macos/macos/flutter_vless_macos/Sources'
PROVIDER = MAC_SOURCES + '/flutter_vless_macos_tunnel_support/FlutterVlessPacketTunnelProvider.swift'
HEV_MARKERS = ('PASS bulk integrity: 8 MiB download',
    'PASS shipped HEV: IPv6 TCP exact target and nonce through IPv4 SOCKS and AF_INET6 packetFlow',
    'PASS shipped HEV: IPv6 UDP exact target and nonce through IPv4 SOCKS and AF_INET6 packetFlow',
    'PASS shipped HEV: packetFlow -> owned datagram bridge -> HEV TCP -> loopback SOCKS -> packetFlow; clean shutdown')
RUNTIME_MARKERS = ('RUNTIME=26.10.31', 'NATIVE_ROUTING_RUNTIME_PASS=0', 'NATIVE_ROUTING_RUNTIME_PASS=1',
                   'NATIVE_ROUTING_RUNTIME_DRAIN_PASS', 'DOMAIN_ROUTING_PASS=0', 'DOMAIN_ROUTING_PASS=1',
                   'MACOS_COUNTERS_MISSING_POLICY_DEFAULTS_PASS=2')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def qualify(root, sha):
    root = Path(root)
    if re.fullmatch('[0-9a-f]{40}', sha) is None: raise ValueError('Exact source SHA required')
    output = root/'build/macos-validation'
    sdk_path = root/'build/published_apple_runtime/macos/result.json'
    sdk = json.loads(sdk_path.read_text())
    expected = {'success': True, 'platform': 'macos', 'runtime_source': 'published',
                'tag': 'xray-macos-v26.10.31-' + REVISION, 'archive_sha256': PINS['macos']['zip'],
                'runtime_checks_pending': False, 'post_test_framework_unchanged': True,
                'actual_version': '26.10.31'}
    if any(sdk.get(k) != v for k, v in expected.items()): raise ValueError('Published macOS SDK proof missing or stale')
    runtime = root/'build/macos_privacy_runtime_probe/runtime.log'
    if sdk.get('runtime_log_sha256') != digest(runtime): raise ValueError('Runtime proof hash differs')
    text = runtime.read_text()
    if any(text.splitlines().count(m) != 1 for m in RUNTIME_MARKERS): raise ValueError('Actual runtime exchange proof missing')
    hev = root/'build/macos_packet_bridge_probe/runtime.log'
    if any(m not in hev.read_text() for m in HEV_MARKERS) or 'FAIL' in hev.read_text():
        raise ValueError('Actual HEV packet or clean-stop proof missing')
    support = output/'support.log'
    if "Test Suite 'TunnelEndpointDiscoveryTests' passed" not in support.read_text() \
            or 'PASS macos provider source wiring and controlled callback admission' not in support.read_text():
        raise ValueError('Current DNS discovery or session suite did not execute')
    if 'PASS macOS manager:' not in (output/'manager.log').read_text(): raise ValueError('Manager checks missing')
    if re.search(r'MACOS_READINESS_CHECKS=[1-9][0-9]*;FAILURES=0', (output/'readiness.log').read_text()) is None:
        raise ValueError('Readiness checks missing')
    cold = json.loads((root/'build/apple-cold-start-current/result.json').read_text())['results']['macos']
    if cold.get('exit') != 0 or cold.get('provider_sha256') != digest(root/PROVIDER):
        raise ValueError('Cold-start result differs from the current provider')
    version = re.search(r'^version:\s*([^+\s]+)\+([0-9]+)', (root/'example/pubspec.yaml').read_text(), re.M)
    if version is None: raise ValueError('Example version missing')
    app = output/'example/flutter_vless_example.app'
    executables = {}
    for name, bundle in [('app', app), ('provider', app/'Contents/PlugIns/XrayTunnel.appex')]:
        info = plistlib.loads((bundle/'Contents/Info.plist').read_bytes())
        if info.get('CFBundleShortVersionString') != version[1] or str(info.get('CFBundleVersion')) != version[2]:
            raise ValueError('Example/provider version differs')
        executable = info.get('CFBundleExecutable')
        if not isinstance(executable, str) or Path(executable).name != executable: raise ValueError('Invalid executable name')
        binary = bundle/'Contents/MacOS'/executable
        with binary.open('rb') as stream: magic = stream.read(4)
        if magic not in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'):
            raise ValueError('Actual compiled Mach-O missing')
        executables[name] = {'path': str(binary.relative_to(root)), 'sha256': digest(binary)}
    proof_paths = [sdk_path, runtime, hev, support, output/'manager.log', output/'readiness.log',
                   root/'build/apple-cold-start-current/result.json', output/'example-build.log']
    result = {'success': True, 'source_sha': sha, 'platform': 'macos', 'runtime_source': 'published',
              'runtime_version': '26.10.31', 'SDK_archive_sha256': sdk['archive_sha256'],
              'source_provider_sha256': digest(root/PROVIDER), 'compiled_executables': executables,
              'live_NetworkExtension_VPN_or_owner_network_acceptance': False,
              'scope': 'Published Core routing/DNS/counters/stop and HEV packet exchanges with controlled OS boundaries; actual example/provider build',
              'proof_sha256': {str(p.relative_to(root)): digest(p) for p in proof_paths}}
    return result


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'macOS' \
            or os.environ.get('GITHUB_REF') != 'refs/heads/main':
        raise ValueError('Qualification runs only in the main macOS CI worker')
    sha = os.environ.get('EXPECTED_SHA', '')
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip() != sha:
        raise ValueError('Checkout source mismatch')
    result = qualify(ROOT, sha)
    (ROOT/'build/macos-validation/result.json').write_text(json.dumps(result, indent=2) + '\n')
    print('MACOS_PUBLISHED_RUNTIME_QUALIFIED=1')


if __name__ == '__main__': main()
