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
                    'tag': 'xray-macos-v26.10.31-'+subject.REVISION,
                    'archive_sha256': subject.PINS['macos']['zip'], 'runtime_checks_pending': False,
                    'post_test_framework_unchanged': True, 'actual_version': '26.10.31',
                    'runtime_log_sha256': subject.digest(runtime)}
        self.sdk_path = self.write('build/published_apple_runtime/macos/result.json', json.dumps(self.sdk))
        self.app = self.output/'example/flutter_vless_example.app'
        for bundle, executable in [(self.app, 'flutter_vless_example'), (self.app/'Contents/PlugIns/XrayTunnel.appex', 'XrayTunnel')]:
            self.write(str((bundle/'Contents/Info.plist').relative_to(self.root)), plistlib.dumps({'CFBundleShortVersionString': '1.1.7', 'CFBundleVersion': '117', 'CFBundleExecutable': executable}))
            self.write(str((bundle/'Contents/MacOS'/executable).relative_to(self.root)),
                b'\xcf\xfa\xed\xfeinert test bytes, never executed\0'+b'\0'.join(subject.PROVIDER_STARTUP_MARKERS))
    def test_complete_bound_evidence_qualifies(self):
        result = subject.qualify(self.root, self.sha)
        self.assertTrue(result['success']); self.assertFalse(result['live_NetworkExtension_VPN_or_owner_network_acceptance'])
        self.assertEqual(result['source_sha'], self.sha); self.assertEqual(set(result['compiled_executables']), {'app','provider'})
        self.assertTrue(result['compiled_provider_source_and_startup_markers_verified'])
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


if __name__ == '__main__': unittest.main()
