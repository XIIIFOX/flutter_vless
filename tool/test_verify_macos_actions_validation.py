"""Inert result qualification fixtures; no compiler, Core, device or network."""
import hashlib
import json
from pathlib import Path
import plistlib
import tempfile
import unittest

import verify_macos_actions_validation as subject


class WorkerProof(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.sha = 'a'*40
        self.output = self.root/'build/macos-validation'
        def write(name, data):
            p = self.root/name; p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data if isinstance(data, bytes) else data.encode()); return p
        self.write = write
        self.write('example/pubspec.yaml', 'version: 1.1.7+117\n')
        self.write(subject.PROVIDER, 'actual provider source fixture\n')
        runtime = self.write('build/macos_privacy_runtime_probe/runtime.log', '\n'.join(subject.RUNTIME_MARKERS)+'\n')
        self.write('build/macos_packet_bridge_probe/runtime.log', '\n'.join(subject.HEV_MARKERS)+'\n')
        self.write('build/macos-validation/support.log', "Test Suite 'TunnelEndpointDiscoveryTests' passed\nPASS macos provider source wiring and controlled callback admission\n")
        self.write('build/macos-validation/manager.log', 'PASS macOS manager: fake boundaries executed\n')
        self.write('build/macos-validation/readiness.log', 'MACOS_READINESS_CHECKS=45;FAILURES=0\n')
        self.build_log = self.write('build/macos-validation/example-build.log',
            f'SwiftCompile normal arm64 Compiling provider {self.root/subject.PROVIDER} (in target support)\n** BUILD SUCCEEDED **\n')
        self.write('build/apple-cold-start-current/result.json', json.dumps({'results': {'macos': {'exit': 0, 'provider_sha256': subject.digest(self.root/subject.PROVIDER)}}}))
        timing_sources = [subject.MAC_SOURCES+'/flutter_vless_macos/FlutterVlessPlugin.swift',
            subject.MAC_SOURCES+'/flutter_vless_macos_privacy/NativeDiagnostics.swift',
            subject.MAC_SOURCES+'/flutter_vless_macos/NativeOperationQueue.swift',
            'tool/fixtures/macos_startup_timing.swift']
        for name in timing_sources: self.write(name, 'actual host timing source fixture\n')
        timing_log = self.write('build/macos-startup-timing-current/runtime.log', 'MACOS_STARTUP_TIMING checks=16 failures=[]\n')
        self.timing = {'exit': 0, 'fixture_only': True,
            'Core_Keychain_NetworkExtension_network_or_devices': False,
            'log_sha256': subject.digest(timing_log),
            'source_sha256': {name: subject.digest(self.root/name) for name in timing_sources}}
        self.timing_path = self.write('build/macos-startup-timing-current/result.json', json.dumps(self.timing))
        self.sdk = {'success': True, 'platform': 'macos', 'runtime_source': 'published',
                    'tag': 'xray-macos-v'+subject.CORE_VERSION+'-'+subject.REVISION,
                    'archive_sha256': subject.PINS['macos']['zip'], 'runtime_checks_pending': False,
                    'post_test_framework_unchanged': True, 'actual_version': subject.CORE_VERSION,
                    'runtime_log_sha256': subject.digest(runtime)}
        self.sdk_path = self.write('build/published_apple_runtime/macos/result.json', json.dumps(self.sdk))
        self.app = self.output/'example/flutter_vless_example.app'
        for bundle, executable in [(self.app, 'flutter_vless_example'), (self.app/'Contents/PlugIns/XrayTunnel.appex', 'XrayTunnel')]:
            self.write(str((bundle/'Contents/Info.plist').relative_to(self.root)), plistlib.dumps({'CFBundleShortVersionString': '1.1.7', 'CFBundleVersion': '117', 'CFBundleExecutable': executable}))
            self.write(str((bundle/'Contents/MacOS'/executable).relative_to(self.root)),
                b'\xcf\xfa\xed\xfeinert test bytes, never executed\0'+b'\0'.join(subject.PROVIDER_STARTUP_MARKERS))
        self.prepare_endpoint_proof()
    def prepare_endpoint_proof(self):
        self.endpoint = self.root/'build/macos-endpoint-startup-timing'
        self.write(subject.endpoint_timing.TEST, 'inert same-current-XCTest fixture\n')
        self.write(subject.MAC_SOURCES+'/flutter_vless_macos_tunnel_support/TunnelEndpointDiscovery.swift', 'candidate production discovery fixture\n')
        self.write(subject.MAC_SOURCES+'/flutter_vless_macos_tunnel_support/TunnelEndpointResolver.swift', 'candidate production resolver fixture\n')
        candidate = {str(p.relative_to(self.root)): subject.digest(p)
            for module in ('flutter_vless_macos_privacy', 'flutter_vless_macos_tunnel_support')
            for p in (self.root/subject.MAC_SOURCES/module).glob('*.swift')
            if p.name != 'FlutterVlessPacketTunnelProvider.swift'}
        self.benchmark = {'schema': 1, 'success': True, 'dns_only': True, 'live_ne_vpn': False,
            'candidate_ref': self.sha, 'baseline_ref': subject.endpoint_timing.BASELINE,
            'test_sha256': subject.digest(self.root/subject.endpoint_timing.TEST),
            'production_sha256': {'candidate': candidate, 'baseline': {}}, 'metrics': {},
            'log_sha256': {}, 'provider_policy_source_sha256': {}, 'provider_policy_metrics': {}}
        self.endpoint_logs = {}
        for mode in ('baseline', 'candidate'):
            for name in candidate:
                target = 'build/macos-endpoint-startup-timing/'+mode+'/Sources/'+name.split('/Sources/', 1)[1]
                data = (self.root/name).read_bytes()
                copied = self.write(target, (b'baseline '+data) if mode == 'baseline' else data)
                if mode == 'baseline': self.benchmark['production_sha256']['baseline'][name] = subject.digest(copied)
            self.write('build/macos-endpoint-startup-timing/'+mode+'/Tests/flutter_vless_macos_tunnel_supportTests/'+Path(subject.endpoint_timing.TEST).name,
                (self.root/subject.endpoint_timing.TEST).read_bytes())
            rows = []
            for case, count in subject.endpoint_timing.CASES.items():
                for sample in range(count):
                    elapsed = {'terminal_unavailable_fallback': (2100+sample if mode == 'baseline' else 120+sample),
                        'no_record_late_aaaa': 1900, 'silence_fallback': 2100,
                        'private_name_no_fallback': 2000, 'ipv6_only_no_ipv4_fallback': 2000,
                        'stop_cancel': 20, 'path_cancel': 60}[case]
                    rows.append({'schema': 1, 'mode': mode, 'case': case, 'sample': sample,
                        'elapsed_ms': elapsed, 'dns_only': True, 'live_ne_vpn': False,
                        'registered_refs': 2, 'closed_refs': 2,
                        'fallback_calls': int(case in ('terminal_unavailable_fallback', 'silence_fallback')),
                        'candidate_families': {'terminal_unavailable_fallback': ['ipv4'],
                            'silence_fallback': ['ipv4'], 'no_record_late_aaaa': ['ipv6']}.get(case, [])})
            log = self.write('build/macos-endpoint-startup-timing/'+mode+'-run.log',
                '\n'.join(subject.endpoint_timing.PREFIX+json.dumps(row) for row in rows)+
                "\nTest Suite 'TunnelEndpointStartupTimingTests' passed\n")
            self.endpoint_logs[mode] = log
            self.benchmark['log_sha256'][mode+'-run.log'] = subject.digest(log)
            self.benchmark['metrics'][mode] = subject.endpoint_timing.parse_metrics(log.read_text(), mode)
        self.benchmark['comparison'] = subject.endpoint_timing.compare(self.benchmark['metrics']['baseline'], self.benchmark['metrics']['candidate'])
        ios = 'example/ios/XrayTunnel/PacketTunnelProvider.swift'
        self.write(ios, 'actual iOS provider policy fixture\n')
        self.benchmark['provider_policy_source_sha256'] = {name: subject.digest(self.root/name) for name in [ios, subject.PROVIDER]}
        for platform in ('ios', 'macos'):
            for mode, folder in [('candidate', 'apple-cold-start-current'), ('baseline', 'apple-cold-start-negative')]:
                ready = mode == 'candidate'
                rows = [{'scenario': 'first-ready-'+kind, 'realNetworkExtension': False,
                    'controlledBoundaries': 'NE-Core-HEV-DNS', 'outcome': 'ready' if ready else 'noReady',
                    'passed': ready, 'startToReadyMs': 450 if ready else None,
                    'finalForceToReadyMs': 100 if ready else None} for kind in ('encrypted', 'literal', 'sealed-system')]
                log = self.write('build/'+folder+'/'+platform+'.log',
                    '\n'.join('APPLE_PROVIDER_STARTUP_METRIC '+json.dumps(row) for row in rows)+'\n')
                self.benchmark['provider_policy_metrics'][platform+'-'+mode] = subject.endpoint_timing.provider_metrics(log.read_text(), ready=ready)
        self.endpoint_path = self.write('build/macos-endpoint-startup-timing/result.json', json.dumps(self.benchmark))

    def test_complete_bound_evidence_qualifies(self):
        result = subject.qualify(self.root, self.sha)
        self.assertTrue(result['success']); self.assertFalse(result['live_NetworkExtension_VPN_or_owner_network_acceptance'])
        self.assertEqual(result['source_sha'], self.sha); self.assertEqual(set(result['compiled_executables']), {'app','provider'})
        self.assertTrue(result['compiled_provider_source_and_startup_markers_verified'])
        self.assertTrue(result['endpoint_startup_timing']['dns_only'])
        for name in ['result.json', 'baseline-run.log', 'candidate-run.log']:
            self.assertIn('build/macos-endpoint-startup-timing/'+name, result['proof_sha256'])
        for folder in ['apple-cold-start-current', 'apple-cold-start-negative']:
            for platform in ['ios', 'macos']:
                self.assertIn('build/'+folder+'/'+platform+'.log', result['proof_sha256'])
    def test_same_version_provider_from_old_implementation_cannot_qualify(self):
        binary = self.app/'Contents/PlugIns/XrayTunnel.appex/Contents/MacOS/XrayTunnel'
        binary.write_bytes(b'\xcf\xfa\xed\xfeold provider, same bundle version')
        with self.assertRaisesRegex(ValueError, 'current DNS startup'):
            subject.qualify(self.root, self.sha)
    def test_current_source_mentioned_outside_compilation_does_not_qualify(self):
        for log in [f'Source receipt: {self.root/subject.PROVIDER}\n** BUILD SUCCEEDED **\n',
                    f'SwiftCompile normal arm64 /old-checkout/{subject.PROVIDER}\n** BUILD SUCCEEDED **\n']:
            self.build_log.write_text(log)
            with self.assertRaisesRegex(ValueError, 'compiler input'):
                subject.qualify(self.root, self.sha)
    def test_missing_stale_or_mislabelled_timing_proof_is_refused(self):
        for key, value in [('exit', 1), ('fixture_only', False),
                           ('Core_Keychain_NetworkExtension_network_or_devices', True),
                           ('source_sha256', {}), ('log_sha256', 'f'*64)]:
            self.timing_path.write_text(json.dumps(dict(self.timing, **{key: value})))
            with self.assertRaisesRegex(ValueError, 'timing|Timing'):
                subject.qualify(self.root, self.sha)
    def test_missing_runtime_or_ipv6_packet_proof_cannot_be_green(self):
        for name in ['build/macos_privacy_runtime_probe/runtime.log', 'build/macos_packet_bridge_probe/runtime.log']:
            p = self.root/name; original = p.read_text(); p.write_text('')
            with self.assertRaises(ValueError): subject.qualify(self.root, self.sha)
            p.write_text(original)
    def test_wrong_sdk_platform_revision_or_pending_proof_fails(self):
        for k,v in [('platform','ios'),('runtime_source','build'),('runtime_checks_pending',True),('post_test_framework_unchanged',False),('archive_sha256','b'*64),('tag','xray-macos-v26.10.31-r1')]:
            self.sdk_path.write_text(json.dumps(dict(self.sdk, **{k:v})))
            with self.assertRaises(ValueError): subject.qualify(self.root, self.sha)
        self.sdk_path.write_text(json.dumps(self.sdk))
    def test_source_change_after_cold_checks_is_refused(self):
        (self.root/subject.PROVIDER).write_text('changed source\n')
        with self.assertRaises(ValueError): subject.qualify(self.root, self.sha)
    def test_no_compiled_provider_or_wrong_version_is_refused(self):
        binary = self.app/'Contents/PlugIns/XrayTunnel.appex/Contents/MacOS/XrayTunnel'
        binary.write_bytes(b'placeholder')
        with self.assertRaises(ValueError): subject.qualify(self.root, self.sha)
    def test_empty_host_or_readiness_suites_are_refused(self):
        for name in ['support.log','manager.log','readiness.log']:
            p=self.output/name; value=p.read_text();p.write_text('')
            with self.assertRaises(ValueError): subject.qualify(self.root,self.sha)
            p.write_text(value)


    def test_endpoint_timing_missing_or_empty_evidence_is_refused(self):
        self.endpoint_path.unlink()
        with self.assertRaisesRegex(ValueError, 'Endpoint startup timing'):
            subject.qualify(self.root, self.sha)
        self.endpoint_path.write_text(json.dumps(self.benchmark))
        for mode, log in self.endpoint_logs.items():
            original = log.read_text(); log.write_text('')
            with self.assertRaisesRegex(ValueError, 'Endpoint startup timing'):
                subject.qualify(self.root, self.sha)
            log.write_text(original)

    def test_endpoint_scope_refs_hashes_and_comparison_are_bound(self):
        for key, value in [('schema', True), ('success', False), ('dns_only', False),
                ('live_ne_vpn', True), ('prepared_only', True), ('candidate_ref', 'b'*40),
                ('baseline_ref', 'c'*40), ('test_sha256', 'd'*64), ('production_sha256', {}),
                ('log_sha256', {}), ('metrics', {}), ('comparison', {}),
                ('provider_policy_source_sha256', {}), ('provider_policy_metrics', {})]:
            with self.subTest(key=key):
                self.endpoint_path.write_text(json.dumps(dict(self.benchmark, **{key: value})))
                with self.assertRaisesRegex(ValueError, 'Endpoint startup timing'):
                    subject.qualify(self.root, self.sha)

    def test_endpoint_current_copied_source_and_same_test_cannot_drift(self):
        discovery = subject.MAC_SOURCES+'/flutter_vless_macos_tunnel_support/TunnelEndpointDiscovery.swift'
        paths = [self.root/discovery,
            self.endpoint/'baseline/Sources/flutter_vless_macos_tunnel_support/TunnelEndpointDiscovery.swift',
            self.endpoint/'candidate/Sources/flutter_vless_macos_tunnel_support/TunnelEndpointResolver.swift',
            self.endpoint/'baseline/Tests/flutter_vless_macos_tunnel_supportTests'/Path(subject.endpoint_timing.TEST).name,
            self.root/subject.endpoint_timing.TEST,
            self.root/'example/ios/XrayTunnel/PacketTunnelProvider.swift']
        for path in paths:
            with self.subTest(path=str(path)):
                original = path.read_bytes(); path.write_bytes(b'changed measured input')
                with self.assertRaisesRegex(ValueError, 'Endpoint startup timing'):
                    subject.qualify(self.root, self.sha)
                path.write_bytes(original)

    def test_self_reported_success_does_not_bypass_actual_log_delta(self):
        value = json.loads(json.dumps(self.benchmark))
        for row in value['metrics']['candidate']:
            if row['case'] == 'terminal_unavailable_fallback': row['elapsed_ms'] = 1100
        log = self.endpoint_logs['candidate']
        log.write_text('\n'.join(subject.endpoint_timing.PREFIX+json.dumps(row) for row in value['metrics']['candidate'])+
            "\nTest Suite 'TunnelEndpointStartupTimingTests' passed\n")
        value['log_sha256']['candidate-run.log'] = subject.digest(log)
        self.endpoint_path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, '900ms'):
            subject.qualify(self.root, self.sha)

    def test_rehashed_empty_wrong_scope_or_incomplete_timing_log_is_refused(self):
        for change in ('empty', 'wrong-scope', 'missing-sample'):
            value = json.loads(json.dumps(self.benchmark)); rows = value['metrics']['candidate']
            if change == 'empty': rows.clear()
            elif change == 'wrong-scope': rows[0]['live_ne_vpn'] = True
            else: rows.pop()
            log = self.endpoint_logs['candidate']
            log.write_text('\n'.join(subject.endpoint_timing.PREFIX+json.dumps(row) for row in rows)+
                "\nTest Suite 'TunnelEndpointStartupTimingTests' passed\n")
            value['log_sha256']['candidate-run.log'] = subject.digest(log)
            self.endpoint_path.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'Endpoint startup timing'):
                subject.qualify(self.root, self.sha)

    def test_actual_provider_ready_or_negative_rows_cannot_be_fabricated(self):
        path = self.root/'build/apple-cold-start-negative/macos.log'
        text = path.read_text().replace('"startToReadyMs": null', '"startToReadyMs": 0')
        path.write_text(text)
        with self.assertRaisesRegex(ValueError, 'noReady'):
            subject.qualify(self.root, self.sha)


if __name__ == '__main__': unittest.main()
