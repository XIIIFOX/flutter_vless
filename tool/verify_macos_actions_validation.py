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
import measure_macos_endpoint_startup as endpoint_timing

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
# These literals are compiled into the provider that implements the early DNS
# admission path. A fresh host app or a matching marketing version alone does
# not prove that an older provider was not linked into the bundle.
PROVIDER_STARTUP_MARKERS = (b'Startup timing phase=keychain-setup',
                            b'Initial DNS correction begin')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_provider_compilation(root, binary, build_log):
    expected_source = str(Path(root)/PROVIDER)
    compiled_current_source = any(line.startswith('SwiftCompile ')
        and expected_source in line for line in build_log.splitlines())
    if not compiled_current_source:
        raise ValueError('Current provider compiler input was not recorded')
    payload = Path(binary).read_bytes()
    if any(marker not in payload for marker in PROVIDER_STARTUP_MARKERS):
        raise ValueError('Compiled provider lacks the current DNS startup implementation')



def verify_endpoint_startup_timing(root, sha):
    """Bind measured DNS and controlled provider gates to current source/logs."""
    directory = root/'build/macos-endpoint-startup-timing'
    result_path = directory/'result.json'
    try:
        result = json.loads(result_path.read_text())
        if type(result.get('schema')) is not int or result['schema'] != 1 \
                or result.get('success') is not True or result.get('dns_only') is not True \
                or result.get('live_ne_vpn') is not False or result.get('prepared_only', False) is not False \
                or result.get('candidate_ref') != sha or result.get('baseline_ref') != endpoint_timing.BASELINE:
            raise ValueError('Incorrect scope, source refs or incomplete run')
        test_hash = digest(root/endpoint_timing.TEST)
        if result.get('test_sha256') != test_hash:
            raise ValueError('Current XCTest hash differs')
        expected = {str(p.relative_to(root)): digest(p)
            for module in ('flutter_vless_macos_privacy', 'flutter_vless_macos_tunnel_support')
            for p in sorted((root/MAC_SOURCES/module).glob('*.swift'))
            if p.name != 'FlutterVlessPacketTunnelProvider.swift'}
        discovery = MAC_SOURCES+'/flutter_vless_macos_tunnel_support/TunnelEndpointDiscovery.swift'
        production = result.get('production_sha256', {})
        if discovery not in expected or set(production) != {'baseline', 'candidate'} \
                or production['candidate'] != expected or set(production['baseline']) != set(expected):
            raise ValueError('Incomplete or stale production Swift source map')
        for mode in ('baseline', 'candidate'):
            for name, checksum in production[mode].items():
                prepared = directory/mode/'Sources'/name.split('/Sources/', 1)[1]
                if digest(prepared) != checksum:
                    raise ValueError('Prepared production source differs')
            copied_test = directory/mode/'Tests/flutter_vless_macos_tunnel_supportTests'/Path(endpoint_timing.TEST).name
            if digest(copied_test) != test_hash:
                raise ValueError('Revisions did not execute the same current XCTest')
        logs = {mode+'-run.log': directory/(mode+'-run.log') for mode in ('baseline', 'candidate')}
        if result.get('log_sha256') != {name: digest(path) for name, path in logs.items()}:
            raise ValueError('Timing log digests differ')
        metrics = {}
        for mode in ('baseline', 'candidate'):
            text = logs[mode+'-run.log'].read_text()
            if "Test Suite 'TunnelEndpointStartupTimingTests' passed" not in text:
                raise ValueError('Timing XCTest did not pass')
            metrics[mode] = endpoint_timing.parse_metrics(text, mode)
        if result.get('metrics') != metrics or result.get('comparison') != endpoint_timing.compare(metrics['baseline'], metrics['candidate']):
            raise ValueError('Timing rows or improvement comparison differ')
        policies = ['example/ios/XrayTunnel/PacketTunnelProvider.swift', PROVIDER]
        if result.get('provider_policy_source_sha256') != {name: digest(root/name) for name in policies}:
            raise ValueError('Current provider policy source differs')
        provider_metrics, provider_logs = {}, []
        for platform in ('ios', 'macos'):
            for mode, folder in [('candidate', 'apple-cold-start-current'), ('baseline', 'apple-cold-start-negative')]:
                path = root/'build'/folder/(platform+'.log')
                provider_logs.append(path)
                provider_metrics[platform+'-'+mode] = endpoint_timing.provider_metrics(path.read_text(), ready=mode == 'candidate')
        if result.get('provider_policy_metrics') != provider_metrics:
            raise ValueError('Provider readiness timing rows differ')
        return result, [result_path, *logs.values(), *provider_logs]
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        raise ValueError('Endpoint startup timing proof invalid: '+str(error)) from error


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
    timing_path = root/'build/macos-startup-timing-current/result.json'
    timing = json.loads(timing_path.read_text())
    timing_log = root/'build/macos-startup-timing-current/runtime.log'
    if timing.get('exit') != 0 or timing.get('fixture_only') is not True \
            or timing.get('Core_Keychain_NetworkExtension_network_or_devices') is not False \
            or timing.get('log_sha256') != digest(timing_log) \
            or re.search(r'^MACOS_STARTUP_TIMING checks=[1-9][0-9]* failures=\[\]$', timing_log.read_text(), re.M) is None:
        raise ValueError('Actual host timing admission checks missing')
    timing_sources = [MAC_SOURCES+'/flutter_vless_macos/FlutterVlessPlugin.swift',
        MAC_SOURCES+'/flutter_vless_macos_privacy/NativeDiagnostics.swift',
        MAC_SOURCES+'/flutter_vless_macos/NativeOperationQueue.swift',
        'tool/fixtures/macos_startup_timing.swift']
    if timing.get('source_sha256') != {name: digest(root/name) for name in timing_sources}:
        raise ValueError('Timing admission result differs from the current host')
    endpoint_result, endpoint_proofs = verify_endpoint_startup_timing(root, sha)
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
        if name == 'provider':
            verify_provider_compilation(root, binary, (output/'example-build.log').read_text())
    proof_paths = [sdk_path, runtime, hev, support, output/'manager.log', output/'readiness.log',
                   root/'build/apple-cold-start-current/result.json', output/'example-build.log',
                   timing_path, timing_log, *endpoint_proofs]
    result = {'success': True, 'source_sha': sha, 'platform': 'macos', 'runtime_source': 'published',
              'runtime_version': '26.10.31', 'SDK_archive_sha256': sdk['archive_sha256'],
              'source_provider_sha256': digest(root/PROVIDER), 'compiled_executables': executables,
              'compiled_provider_source_and_startup_markers_verified': True,
              'endpoint_startup_timing': {'dns_only': True, 'live_ne_vpn': False,
                  'comparison': endpoint_result['comparison']},
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
