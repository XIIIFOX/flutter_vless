#!/usr/bin/env python3
"""Pure runner guard/command tests; never invokes Core or network."""
import importlib.util
import io
import json
import os
from pathlib import Path, PureWindowsPath
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('native_dns_preservation_runner', Path(__file__).with_name('test_native_dns_preservation.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class PreservationRunnerGuards(unittest.TestCase):
    def h3_log(self, preparers=1):
        modes = ['raw_numeric', 'native_cnc_windows'] + (['native_cnc_apple'] if preparers == 2 else [])
        lines = ''.join(f'    xhttp_h3_lifetime_test.go:400: H3_LIFETIME_PASS mode={mode}\n'
                        f'    --- PASS: TestNativeXHTTPH3Lifetime/{mode} (0.01s)\n' for mode in modes)
        return lines + '--- PASS: TestNativeXHTTPH3Lifetime (0.03s)\nPASS\n'

    def complete_phase(self):
        return {'exit_code': 0, 'process_exit_code': 0, 'timed_out': False,
                'output_closed': True, 'output_eof': True, 'output_errors': []}

    def test_h3_lifetime_requires_all_exact_source_modes_and_selected_passes(self):
        for preparers in (1, 2):
            good = self.h3_log(preparers)
            expected = ['raw_numeric', 'native_cnc_windows'] + (['native_cnc_apple'] if preparers == 2 else [])
            self.assertEqual(runner.require_xhttp_h3_lifetime_runtime(good, preparers, self.complete_phase()), expected)
            runner.require_xhttp_h3_lifetime_runtime(good.replace('\n', '\r\n'), preparers, self.complete_phase())
            for body in ('', good.replace('mode=raw_numeric', 'mode=unknown'),
                         good.replace('xhttp_h3_lifetime_test.go:', 'unrelated.go:'),
                         good.replace('H3_LIFETIME_PASS mode=raw_numeric', 'prefix H3_LIFETIME_PASS mode=raw_numeric'),
                         good.replace('    xhttp_h3_lifetime_test.go:400: H3_LIFETIME_PASS mode=raw_numeric\n', ''),
                         good + '    xhttp_h3_lifetime_test.go:400: H3_LIFETIME_PASS mode=raw_numeric\n',
                         good.replace('--- PASS: TestNativeXHTTPH3Lifetime/raw_numeric', '--- SKIP: TestNativeXHTTPH3Lifetime/raw_numeric'),
                         good.replace('--- PASS: TestNativeXHTTPH3Lifetime/raw_numeric', '--- PASS: AnotherTest/raw_numeric'),
                         good + '--- FAIL: owned_drain (0.01s)\n', good.removesuffix('PASS\n')):
                with self.subTest(preparers=preparers, body=body), self.assertRaises(RuntimeError):
                    runner.require_xhttp_h3_lifetime_runtime(body, preparers, self.complete_phase())
        for body, preparers in [(self.h3_log(), 2), (self.h3_log(2), 1), (self.h3_log(), 0), (self.h3_log(), 3)]:
            with self.subTest(preparers=preparers), self.assertRaises(RuntimeError):
                runner.require_xhttp_h3_lifetime_runtime(body, preparers, self.complete_phase())

    def test_h3_lifetime_rejects_truncated_failed_or_unreaped_phase(self):
        for key, value in [('exit_code', 1), ('process_exit_code', 1), ('timed_out', True),
                           ('output_closed', False), ('output_eof', False), ('output_errors', ['capture failed'])]:
            phase = self.complete_phase(); phase[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                runner.require_xhttp_h3_lifetime_runtime(self.h3_log(), 1, phase)
        phase = self.complete_phase(); del phase['output_eof']
        with self.assertRaises(RuntimeError):
            runner.require_xhttp_h3_lifetime_runtime(self.h3_log(), 1, phase)

    def test_snapshot_binds_transitive_preparation_report_header(self):
        with mock.patch.object(runner, 'digest', return_value='synthetic-digest'), \
                mock.patch.object(runner.platform, 'system', return_value='Linux'):
            snapshot = runner.source_snapshot()
        self.assertEqual(snapshot.get('packages/flutter_vless_windows/windows/preparation_report.h'), 'synthetic-digest')

    def test_snapshot_binds_h3_patch_and_its_exact_source_guards(self):
        with mock.patch.object(runner, 'digest', return_value='synthetic-digest'), \
                mock.patch.object(runner.platform, 'system', return_value='Linux'):
            snapshot = runner.source_snapshot()
        for path in ['third_party/xray-native-dns/h3_lifetime_patch.py',
                     'tool/test_h3_lifetime_patch.py']:
            self.assertEqual(snapshot.get(path), 'synthetic-digest', path)

    def test_snapshot_binds_opaque_field_corpus(self):
        with mock.patch.object(runner, 'digest', return_value='synthetic-digest'), \
                mock.patch.object(runner.platform, 'system', return_value='Linux'):
            snapshot = runner.source_snapshot()
        self.assertEqual(snapshot.get('tool/fixtures/compatibility/opaque-fields.json'), 'synthetic-digest')
        self.assertEqual(snapshot.get('third_party/xray-mobile/native_dns_preservation/opaque_fields_test.go'), 'synthetic-digest')

    def test_snapshot_binds_schema_field_corpus(self):
        with mock.patch.object(runner, 'digest', return_value='synthetic-digest'), \
                mock.patch.object(runner.platform, 'system', return_value='Linux'):
            snapshot = runner.source_snapshot()
        self.assertEqual(snapshot.get('tool/fixtures/compatibility/schema-fields.json'), 'synthetic-digest')
        self.assertEqual(snapshot.get('third_party/xray-mobile/native_dns_preservation/schema_fields_test.go'), 'synthetic-digest')

    def test_snapshot_binds_port_environment_oracle_and_generator(self):
        with mock.patch.object(runner, 'digest', return_value='synthetic-digest'), \
                mock.patch.object(runner.platform, 'system', return_value='Linux'):
            snapshot = runner.source_snapshot()
        for path in ['tool/fixtures/compatibility/port-env.json',
                     'tool/generate_core_env_case.go', 'tool/generate_core_env_case_test.go']:
            self.assertEqual(snapshot.get(path), 'synthetic-digest', path)

    def test_snapshot_binds_shared_fakedns_corpus(self):
        with mock.patch.object(runner, 'digest', return_value='synthetic-digest'), \
                mock.patch.object(runner.platform, 'system', return_value='Linux'):
            snapshot = runner.source_snapshot()
        self.assertIn('tool/fixtures/compatibility/fakedns.json', snapshot)
        self.assertEqual(snapshot['tool/fixtures/compatibility/fakedns.json'], 'synthetic-digest')
        self.assertEqual(snapshot['tool/fixtures/compatibility/dns-data-maps.json'], 'synthetic-digest')
        self.assertEqual(snapshot['tool/fixtures/compatibility/transport-data-maps.json'], 'synthetic-digest')
        self.assertEqual(snapshot['tool/fixtures/compatibility/routing-attrs.json'], 'synthetic-digest')

    def test_snapshot_binds_shared_counter_wire_corpus(self):
        seen = []
        def record(path):
            seen.append(path)
            return 'synthetic-digest'
        with mock.patch.object(runner, 'digest', side_effect=record), \
                mock.patch.object(runner.platform, 'system', return_value='Linux'):
            snapshot = runner.source_snapshot()
        name = 'tool/fixtures/compatibility/traffic-counters.json'
        self.assertIn(runner.ROOT / name, seen)
        self.assertEqual(snapshot[name], 'synthetic-digest')

    def test_child_environment_disables_core_init_listener_without_parent_mutation(self):
        source = {'PATH': 'keep-toolchain', 'CI': 'true', 'xray.browser.dialer': 'must-not-listen',
                  'XRAY_BROWSER_DIALER': 'must-not-listen', 'Xray_Location_Cert': 'caller-location'}
        before = dict(source)
        result = runner.child_environment(source)
        self.assertEqual(source, before)
        self.assertEqual(result['PATH'], source['PATH'])
        self.assertEqual(result['CI'], 'true')
        self.assertEqual(result['xray.browser.dialer'], '')
        self.assertEqual(result['XRAY_BROWSER_DIALER'], '')
        self.assertNotIn('Xray_Location_Cert', result)
        self.assertEqual(result['GOTOOLCHAIN'], 'local')
        self.assertEqual(result['GOWORK'], 'off')

    def test_runtime_refused_before_any_child_or_evidence(self):
        for system, environment in [('Linux', {}), ('Windows', {}), ('Darwin', {'CI': 'true'})]:
            with self.subTest(system=system), tempfile.TemporaryDirectory() as directory:
                evidence = Path(directory) / 'not-created'
                with mock.patch.object(runner, 'EVIDENCE', evidence), mock.patch.dict(os.environ, environment, clear=True), \
                        mock.patch.object(runner.common.platform, 'system', return_value=system), \
                        mock.patch.object(runner.sys, 'argv', ['runner', '--run-runtime']), \
                        mock.patch.object(runner.common, 'checked') as checked, \
                        mock.patch.object(runner.sys, 'stderr', io.StringIO()), self.assertRaises(SystemExit) as exit_status:
                    runner.main()
                self.assertEqual(exit_status.exception.code, 2)
                checked.assert_not_called()
                self.assertFalse(evidence.exists())

    def test_existing_evidence_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(runner, 'EVIDENCE', Path(directory)), mock.patch.object(runner.sys, 'argv', ['runner']), \
                    mock.patch.object(runner.sys, 'stderr', io.StringIO()), mock.patch.object(runner.common, 'checked') as checked, \
                    self.assertRaises(SystemExit):
                runner.main()
            checked.assert_not_called()

    def test_windows_batch_has_bounded_trusted_toolchain_commands(self):
        script = runner.msvc_script(Path(r'C:\safe path\dns-preparer.exe'), Path(r'C:\safe path\config-pure.exe'), {})
        self.assertIn('setlocal DisableDelayedExpansion', script)
        self.assertIn('-requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64', script)
        self.assertIn('vcvars64.bat', script)
        self.assertEqual(script.count('cl /nologo /std:c++17'), 2)
        self.assertEqual(script.count('/W4 /WX /DNOMINMAX'), 2)
        self.assertIn('/Fe:"C:\\safe path\\dns-preparer.exe"', script)
        self.assertGreaterEqual(script.count('if errorlevel 1 exit /b 1'), 4)
        self.assertNotIn('acceptance.test', script)

    def test_batch_paths_do_not_expand_environment_or_inject_lines(self):
        self.assertEqual(runner.cmd_path(Path('owned%PATH%file')), '"owned%%PATH%%file"')
        for value in ['bad"path', 'bad\npath', 'bad\rpath']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner.cmd_path(Path(value))

    def test_apple_build_only_links_production_json_preparer_without_core(self):
        binary, phases = runner.apple_commands(Path('/owned/test package'))
        self.assertEqual(binary, Path('/owned/test package/apple-dns-preparer'))
        self.assertEqual(len(phases), 3)
        commands = [command for _, command in phases]
        self.assertTrue(all(command[:2] == ['xcrun', 'swiftc'] for command in commands))
        flattened = '\n'.join(argument for command in commands for argument in command)
        self.assertIn('native_dns_preparer.swift', flattened)
        self.assertIn('TunnelDNSPolicy.swift', flattened)
        self.assertNotIn('FlutterVlessPacketTunnelProvider.swift', flattened)
        self.assertNotIn('libXRay', flattened)
        self.assertNotIn('CXRay', flattened)

    def test_actual_success_requires_exact_selected_pass(self):
        for output in ['PASS\n', 'testing: warning: no tests to run\nPASS\n', '--- PASS: OtherTest (0.00s)\nPASS\n']:
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                runner.common.require_selected_test_pass(output, runner.SELECTED_TEST)
        runner.common.require_selected_test_pass('--- PASS: TestNativeDNSPreservation (0.01s)\nPASS\n', runner.SELECTED_TEST)

    def test_runtime_transport_maps_requires_both_modes_per_preparer(self):
        def line(mode):
            return f'    xhttp_runtime_test.go:400: XHTTP_TRANSPORT_DATA_MAPS_PASS chained={mode}\n'
        independent = '    xhttp_runtime_test.go:401: XHTTP_INDEPENDENT_DOWNLOAD_PASS\n'
        pair = line('false') + line('true')
        valid = pair + independent
        runner.require_transport_data_runtime(valid, 1)
        runner.require_transport_data_runtime(valid * 2, 2)
        for output, preparers in [('', 1), (line('false'), 1), (valid * 2, 1),
                                    (valid, 2), (valid + line('true'), 1),
                                    (pair, 1), (valid + independent, 1),
                                    ('noise XHTTP_TRANSPORT_DATA_MAPS_PASS chained=false\n' + line('true'), 1)]:
            with self.subTest(output=output, preparers=preparers), self.assertRaises(RuntimeError):
                runner.require_transport_data_runtime(output, preparers)

    def test_inactive_tls_snapshot_and_exact_runtime_modes(self):
        with mock.patch.object(runner, 'digest', return_value='synthetic-digest'), \
                mock.patch.object(runner.platform, 'system', return_value='Linux'):
            snapshot = runner.source_snapshot()
        for path in ['tool/fixtures/compatibility/inactive-tls.json',
                     'third_party/xray-mobile/native_dns_preservation/inactive_tls_test.go']:
            self.assertEqual(snapshot.get(path), 'synthetic-digest', path)
        lines = [f'    xhttp_runtime_test.go:400: XHTTP_DORMANT_ECH_PASS mode={mode}\n'
                 for mode in ('direct', 'chained', 'independent')]
        valid = ''.join(lines)
        runner.require_inactive_tls_runtime(valid, 1)
        runner.require_inactive_tls_runtime(valid * 2, 2)
        for output, preparers in [('', 1), (''.join(lines[:2]), 1), (valid * 2, 1),
                                 (valid, 2), (valid + lines[0], 1), (valid, 0), (valid, 3),
                                 (valid + lines[0].replace('mode=direct', 'mode=unknown'), 1),
                                 ('noise ' + lines[0].lstrip() + ''.join(lines[1:]), 1)]:
            with self.subTest(output=output, preparers=preparers), self.assertRaises(RuntimeError):
                runner.require_inactive_tls_runtime(output, preparers)

    def test_loopback_chain_snapshot_and_exact_runtime_count(self):
        with mock.patch.object(runner, 'digest', return_value='synthetic-digest'), \
                mock.patch.object(runner.platform, 'system', return_value='Linux'):
            snapshot = runner.source_snapshot()
        for path in ['tool/fixtures/compatibility/loopback-chains.json',
                     'third_party/xray-mobile/native_dns_preservation/loopback_chains_test.go']:
            self.assertEqual(snapshot.get(path), 'synthetic-digest', path)
        marker = '    xhttp_runtime_test.go:400: XHTTP_LOOPBACK_CHAIN_PASS\n'
        runner.require_loopback_chain_runtime(marker, 1)
        runner.require_loopback_chain_runtime(marker * 2, 2)
        for output, preparers in [('', 1), (marker * 2, 1), (marker, 2), (marker, 0), (marker, 3),
                                 ('noise ' + marker.lstrip(), 1), (marker.replace('PASS', 'PASS_EXTRA'), 1)]:
            with self.subTest(output=output, preparers=preparers), self.assertRaises(RuntimeError):
                runner.require_loopback_chain_runtime(output, preparers)

    def test_xhttp_tls_runtime_requires_all_three_exact_modes(self):
        with mock.patch.object(runner, 'digest', return_value='synthetic-digest'), \
                mock.patch.object(runner.platform, 'system', return_value='Linux'):
            snapshot = runner.source_snapshot()
        self.assertEqual(snapshot.get('third_party/xray-mobile/native_dns_preservation/xhttp_tls_runtime_test.go'),
                         'synthetic-digest')
        modes = ('independent', 'wrong_ca', 'wrong_sni')
        lines = [f'    xhttp_tls_runtime_test.go:400: XHTTP_TLS_H2_PASS mode={mode}\n'
                 for mode in modes]
        valid = ''.join(lines)
        runner.require_xhttp_tls_runtime(valid, 1)
        runner.require_xhttp_tls_runtime(valid * 2, 2)
        for output, preparers in [('', 1), (''.join(lines[:2]), 1), (valid * 2, 1),
                                 (valid, 2), (valid + lines[0], 1), (valid, 0), (valid, 3),
                                 (valid.replace('mode=wrong_ca', 'mode=unknown'), 1),
                                 (valid.replace('xhttp_tls_runtime_test.go:', 'unrelated.go:'), 1),
                                 ('noise ' + lines[0].lstrip() + ''.join(lines[1:]), 1)]:
            with self.subTest(output=output, preparers=preparers), self.assertRaises(RuntimeError):
                runner.require_xhttp_tls_runtime(output, preparers)

    def test_ipv6_dns_snapshot_and_exact_runtime_modes(self):
        with mock.patch.object(runner, 'digest', return_value='synthetic-digest'), \
                mock.patch.object(runner.platform, 'system', return_value='Linux'):
            snapshot = runner.source_snapshot()
        for path in ['tool/fixtures/compatibility/dns-ipv6-servers.json',
                     'tool/test_native_dns_ipv6_preparation.py',
                     'tool/fixtures/dns_ipv6_preparer.cpp', 'tool/fixtures/dns_ipv6_preparer.swift',
                     'third_party/xray-mobile/native_dns_preservation/dns_ipv6_servers_test.go']:
            self.assertEqual(snapshot.get(path), 'synthetic-digest', path)
        lines = [f'    dns_ipv6_servers_test.go:300: DNS_IPV6_UPSTREAM_RUNTIME_PASS transport={transport} strategy={strategy}\n'
                 for transport in ('udp', 'tcp') for strategy in ('UseIP', 'UseIPv4')]
        valid = ''.join(lines)
        runner.require_ipv6_dns_runtime(valid, 1)
        runner.require_ipv6_dns_runtime(valid * 2, 2)
        for output, count in [('', 1), (''.join(lines[:-1]), 1), (valid + lines[0], 1),
                              (valid, 2), (valid * 2, 1), (valid, 0),
                              (valid.replace('dns_ipv6_servers_test.go:', 'unrelated.go:'), 1)]:
            with self.subTest(count=count, output=output), self.assertRaises(RuntimeError):
                runner.require_ipv6_dns_runtime(output, count)

    def test_ipv4_classic_lifetime_modes_are_both_required(self):
        lines = [f'    dns_ipv6_servers_test.go:10: DNS_IPV4_UPSTREAM_RUNTIME_PASS transport=udp strategy={strategy}\n'
                 for strategy in ('UseIP', 'UseIPv4')]
        valid = ''.join(lines)
        runner.require_ipv4_dns_runtime(valid, 1)
        runner.require_ipv4_dns_runtime(valid * 2, 2)
        for output, count in [('', 1), (lines[0], 1), (valid + lines[0], 1), (valid, 2),
                              (valid * 2, 1), (valid, 0),
                              (valid.replace('transport=udp', 'transport=tcp'), 1),
                              (valid.replace('dns_ipv6_servers_test.go:', 'unrelated.go:'), 1)]:
            with self.subTest(output=output, count=count), self.assertRaises(RuntimeError):
                runner.require_ipv4_dns_runtime(output, count)

    def test_classic_lifetime_copy_uses_checked_disposable_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source, overlay = base / 'upstream', base / 'overlay'
            overlay.mkdir()
            required = ('app/dns/dns.go', 'app/dns/nameserver_udp.go',
                        'transport/internet/udp/dispatcher.go')
            for name in required:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('original ' + name)
                path.chmod(0o444)
            for name in ('native_classic_lifetime.go', 'native_classic_lifetime_test.go'):
                (overlay / name).write_text('package dns\n')
            manifest = {'upstream_sha256': {name: runner.digest(source / name) for name in required}}
            original = dict(manifest['upstream_sha256'])
            calls = []

            def patch(root, replace):
                calls.append(root)
                replace(required[0], 'original', 'patched')

            destination = base / 'copy'
            report = runner.prepare_classic_core(source, destination, manifest,
                                                 patch_apply=patch, overlay=overlay)
            self.assertEqual(calls, [destination])
            self.assertEqual((destination / required[0]).read_text(), 'patched ' + required[0])
            self.assertEqual({name: runner.digest(source / name) for name in required}, original)
            self.assertEqual(set(report['changed_upstream']), {required[0]})
            self.assertEqual(len(report['added_files']), 2)
            self.assertTrue(report['source_unchanged'])
            with self.assertRaises(ValueError):
                runner.prepare_classic_core(source, destination, manifest,
                                            patch_apply=patch, overlay=overlay)
            with self.assertRaises(ValueError):
                runner.prepare_classic_core(source, source / 'nested', manifest,
                                            patch_apply=patch, overlay=overlay)
            self.assertEqual(calls, [destination])
            (source / required[0]).chmod(0o644)
            (source / required[0]).write_text('tampered')
            with self.assertRaises(ValueError):
                runner.prepare_classic_core(source, base / 'bad-copy', manifest,
                                            patch_apply=patch, overlay=overlay)
            self.assertFalse((base / 'bad-copy').exists())

    def test_classic_lifetime_copy_refuses_symlinks_and_unowned_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source, overlay = base / 'upstream', base / 'overlay'
            overlay.mkdir()
            required = ('app/dns/dns.go', 'app/dns/nameserver_udp.go',
                        'transport/internet/udp/dispatcher.go')
            for name in required:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('original')
            for name in ('native_classic_lifetime.go', 'native_classic_lifetime_test.go'):
                (overlay / name).write_text('package dns\n')
            manifest = {'upstream_sha256': {name: runner.digest(source / name) for name in required}}
            alias = source / 'alias'
            alias.write_text('filesystem boundary control')
            actual_is_symlink = Path.is_symlink
            # Exercise refusal without requiring Windows symlink privileges.
            with mock.patch.object(Path, 'is_symlink',
                    lambda path: path == alias or actual_is_symlink(path)), self.assertRaises(ValueError):
                runner.prepare_classic_core(source, base / 'symlink-copy', manifest,
                                            patch_apply=lambda *_: None, overlay=overlay)
            self.assertFalse((base / 'symlink-copy').exists())
            (source / 'alias').unlink()
            def unowned(root, replace):
                replace('go.mod', 'module', 'changed')
            with self.assertRaises(ValueError):
                runner.prepare_classic_core(source, base / 'unowned-copy', manifest,
                                            patch_apply=unowned, overlay=overlay)
            self.assertFalse((source / 'go.mod').exists())

    def lifetime_fixture(self, base):
        source, overlay = base / 'upstream', base / 'overlay'
        overlay.mkdir()
        spec = importlib.util.spec_from_file_location('fixture_h3_patch', runner.H3_PATCH)
        patch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(patch)
        files = {'app/dns/dns.go': 'original dns',
                 'app/dns/nameserver_udp.go': 'original nameserver',
                 'transport/internet/udp/dispatcher.go': 'original dispatcher',
                 runner.H3_DIALER: 'package splithttp\n' + patch.BEFORE + '\n',
                 'unrelated.go': 'original unrelated'}
        for name, text in files.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            path.chmod(0o444)
        for name in ('native_classic_lifetime.go', 'native_classic_lifetime_test.go'):
            (overlay / name).write_text('package dns\n')
        manifest = {'upstream_sha256': {name: runner.digest(source / name) for name in files}}

        def classic(root, replace):
            replace('app/dns/dns.go', 'original dns', 'patched dns')

        return source, overlay, manifest, classic, patch

    def test_combined_lifetime_copy_retains_separate_scopes_and_original_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source, overlay, manifest, classic, patch = self.lifetime_fixture(base)
            original = dict(manifest['upstream_sha256'])
            classic_copy = base / 'classic-only'
            classic_report = runner.prepare_classic_core(source, classic_copy, manifest,
                                                        patch_apply=classic, overlay=overlay)
            self.assertEqual((classic_copy / runner.H3_DIALER).read_bytes(),
                             (source / runner.H3_DIALER).read_bytes())
            destination = base / 'combined'
            report = runner.prepare_lifetime_core(source, destination, manifest,
                                                  classic_apply=classic, overlay=overlay)
            self.assertEqual(report['classic_lifetime_patch'], classic_report)
            self.assertEqual(set(classic_report['changed_upstream']), {'app/dns/dns.go'})
            self.assertEqual(len(classic_report['added_files']), 2)
            self.assertEqual(report['lifetime_patch_scope'], ['classic_dns', 'xhttp_h3_dial'])
            h3 = report['h3_lifetime_patch']
            self.assertEqual(h3['kind'], 'xhttp-h3-dial-lifetime-only')
            self.assertTrue(h3['source_unchanged'])
            self.assertEqual(h3['patch_sha256'], runner.digest(runner.H3_PATCH))
            self.assertEqual(h3['changed_upstream'], {runner.H3_DIALER: runner.digest(destination / runner.H3_DIALER)})
            self.assertEqual((destination / runner.H3_DIALER).read_text(),
                             'package splithttp\n' + patch.AFTER + '\n')
            self.assertEqual({name: runner.digest(source / name) for name in original}, original)
            self.assertEqual((destination / 'unrelated.go').read_text(), 'original unrelated')
            with self.assertRaises(ValueError):
                runner.prepare_lifetime_core(source, destination, manifest,
                                             classic_apply=classic, overlay=overlay)
            self.assertEqual({name: runner.digest(source / name) for name in original}, original)

    def test_combined_lifetime_copy_refuses_missing_or_stale_h3_pin_before_copy(self):
        for mode in ('missing-pin', 'stale-source'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                source, overlay, manifest, classic, _ = self.lifetime_fixture(base)
                if mode == 'missing-pin':
                    del manifest['upstream_sha256'][runner.H3_DIALER]
                else:
                    (source / runner.H3_DIALER).chmod(0o644)
                    (source / runner.H3_DIALER).write_text('tampered')
                with mock.patch.object(runner, 'prepare_classic_core') as prepare, self.assertRaises(ValueError):
                    runner.prepare_lifetime_core(source, base / 'copy', manifest,
                                                 classic_apply=classic, overlay=overlay)
                prepare.assert_not_called()
                self.assertFalse((base / 'copy').exists())

    def test_combined_lifetime_snapshot_keys_are_portable_windows_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source, overlay, manifest, classic, _ = self.lifetime_fixture(base)
            relative_to = Path.relative_to
            # Keep the real host filesystem; only model Windows relative path
            # rendering, the boundary used to key the owned-copy snapshot.
            with mock.patch.object(Path, 'relative_to', lambda path, *parts:
                                   PureWindowsPath(relative_to(path, *parts))):
                report = runner.prepare_lifetime_core(source, base / 'copy', manifest,
                                                      classic_apply=classic, overlay=overlay)
            self.assertEqual(set(report['h3_lifetime_patch']['changed_upstream']), {runner.H3_DIALER})

    def test_combined_lifetime_copy_refuses_already_patched_boundary_even_with_matching_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source, overlay, manifest, classic, patch = self.lifetime_fixture(base)
            path = source / runner.H3_DIALER
            path.chmod(0o644)
            path.write_text(path.read_text().replace(patch.BEFORE, patch.AFTER))
            manifest['upstream_sha256'][runner.H3_DIALER] = runner.digest(path)
            with self.assertRaisesRegex(ValueError, 'replacement boundary changed'):
                runner.prepare_lifetime_core(source, base / 'copy', manifest,
                                             classic_apply=classic, overlay=overlay)
            self.assertEqual(runner.digest(path), manifest['upstream_sha256'][runner.H3_DIALER])

    def test_combined_lifetime_copy_rejects_unowned_noop_added_or_cache_changes(self):
        for mode in ('unowned-callback', 'unrelated-file', 'noop', 'added-file', 'source-cache'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                source, overlay, manifest, classic, patch = self.lifetime_fixture(base)

                def h3(root, replace):
                    if mode == 'unowned-callback':
                        replace('unrelated.go', 'original', 'wrong')
                        return
                    if mode == 'noop':
                        return
                    patch.apply(root, replace)
                    if mode == 'unrelated-file':
                        (root / 'unrelated.go').write_text('wrong')
                    if mode == 'added-file':
                        (root / 'extra.go').write_text('wrong')
                    if mode == 'source-cache':
                        path = source / 'unrelated.go'
                        path.chmod(0o644)
                        path.write_text('wrong')

                with self.assertRaises(ValueError):
                    runner.prepare_lifetime_core(source, base / 'copy', manifest,
                                                 classic_apply=classic, h3_apply=h3, overlay=overlay)
                if mode != 'source-cache':
                    self.assertTrue(all(runner.digest(source / name) == value
                                        for name, value in manifest['upstream_sha256'].items()))

    def test_runtime_uses_lifetime_copy_and_alternate_modfile(self):
        self.exercise_runtime_main()

    def test_runtime_main_refuses_invalid_h3_after_old_phases_pass(self):
        self.exercise_runtime_main(self.h3_log().replace('mode=raw_numeric', 'mode=unknown'), expected_exit=1)

    def test_runtime_main_refuses_changed_owned_h3_on_success_or_failure(self):
        for invalid_output in (False, True):
            with self.subTest(invalid_output=invalid_output):
                output = self.h3_log().replace('mode=raw_numeric', 'mode=unknown') if invalid_output else self.h3_log()
                self.exercise_runtime_main(output, expected_exit=1, mutate_owned=True)

    def test_runtime_main_checks_inputs_in_finally_after_runtime_failure(self):
        self.exercise_runtime_main(self.h3_log().replace('mode=raw_numeric', 'mode=unknown'),
                                   expected_exit=1, mutate_inputs=True)

    def test_runtime_main_refuses_mutated_owned_binding_even_after_selected_tests_pass(self):
        self.exercise_runtime_main(expected_exit=1,mutate_binding=True)

    def exercise_runtime_main(self, h3_output=None, expected_exit=0, mutate_owned=False, mutate_inputs=False, mutate_binding=False):
        h3_output = self.h3_log() if h3_output is None else h3_output
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            evidence, source = base / 'evidence', base / 'original-core'
            source.mkdir()
            (source / 'guarded.go').write_text('original')
            manifest = {'module': 'synthetic.invalid/core', 'module_version': 'v1.0.0',
                        'module_sum': 'synthetic',
                        'upstream_sha256': {'guarded.go': runner.digest(source / 'guarded.go')}}
            commands = []
            budgets = {}
            inputs_changed = False

            def prepare_copy(source, destination, manifest):
                path = destination / runner.H3_DIALER
                path.parent.mkdir(parents=True)
                path.write_text('prepared H3 dialer')
                binding = destination / runner.BINDING_SOURCE
                binding.parent.mkdir(parents=True,exist_ok=True)
                binding.write_text('prepared Darwin mandatory binding')
                return {'darwin_interface_binding': {'source_applied': True, 'changed_upstream': {runner.BINDING_SOURCE: runner.digest(binding)}},
                        'classic_lifetime_patch': {'kind': 'classic-udp-lifetime-only'},
                        'h3_lifetime_patch': {'kind': 'xhttp-h3-dial-lifetime-only',
                                              'changed_upstream': {runner.H3_DIALER: runner.digest(path)}},
                        'lifetime_patch_scope': ['classic_dns', 'xhttp_h3_dial']}

            def checked(name, command, **kwargs):
                nonlocal inputs_changed
                commands.append((name, command))
                budgets[name] = kwargs['seconds']
                kwargs['results'].append({'name': name, 'exit_code': 0, 'process_exit_code': 0,
                    'timed_out': False, 'output_closed': True, 'output_eof': True, 'output_errors': []})
                if '-o' in command:
                    Path(command[command.index('-o') + 1]).write_text('compiled')
                if name == 'core-pin':
                    (evidence / 'core-pin.log').write_text(json.dumps(
                        {'Version': 'v1.0.0', 'Sum': 'synthetic', 'Dir': str(source)}))
                if name == 'protocol-preparation-pure':
                    selection = command[command.index('-test.run') + 1][2:-2]
                    (evidence / 'protocol-preparation-pure.log').write_text(''.join(
                        f'--- PASS: {test} (0.01s)\n' for test in selection.split('|')))
                if name == 'actual-core-dns':
                    (evidence / 'actual-core-dns.log').write_text(
                        '--- PASS: TestNativeDNSPreservation (0.01s)\n' +
                        ''.join(f'    xhttp_runtime_test.go:10: XHTTP_TRANSPORT_DATA_MAPS_PASS chained={mode}\n'
                                for mode in ('true', 'false')) +
                        '    xhttp_runtime_test.go:10: XHTTP_INDEPENDENT_DOWNLOAD_PASS\n' +
                        ''.join(f'    xhttp_runtime_test.go:10: XHTTP_DORMANT_ECH_PASS mode={mode}\n'
                                for mode in ('direct', 'chained', 'independent')) +
                        '    xhttp_runtime_test.go:10: XHTTP_LOOPBACK_CHAIN_PASS\n' +
                        ''.join(f'    dns_ipv6_servers_test.go:10: DNS_IPV6_UPSTREAM_RUNTIME_PASS transport={transport} strategy={strategy}\n'
                                for transport in ('udp', 'tcp') for strategy in ('UseIP', 'UseIPv4')) +
                        ''.join(f'    dns_ipv6_servers_test.go:10: DNS_IPV4_UPSTREAM_RUNTIME_PASS transport=udp strategy={strategy}\n'
                                for strategy in ('UseIP', 'UseIPv4')))
                if name == 'actual-xhttp-tls':
                    (evidence / 'actual-xhttp-tls.log').write_text(
                        '--- PASS: TestNativeXHTTPTLS (0.01s)\n' + ''.join(
                            f'    xhttp_tls_runtime_test.go:10: XHTTP_TLS_H2_PASS mode={mode}\n'
                            for mode in ('independent', 'wrong_ca', 'wrong_sni')))
                if name == 'actual-xhttp-h3-lifetime':
                    (evidence / 'actual-xhttp-h3-lifetime.log').write_text(h3_output)
                    if mutate_owned:
                        (evidence / 'LifetimeCore' / runner.H3_DIALER).write_text('mutated H3 dialer')
                    if mutate_binding:
                        (evidence / 'LifetimeCore' / runner.BINDING_SOURCE).write_text('mutated mandatory binding')
                    inputs_changed = mutate_inputs
            with mock.patch.object(runner, 'EVIDENCE', evidence), \
                    mock.patch.object(runner.sys, 'argv', ['runner', '--run-runtime']), \
                    mock.patch.object(runner.sys, 'stderr', io.StringIO()), \
                    mock.patch.object(runner.platform, 'system', return_value='Linux'), \
                    mock.patch.object(runner, 'os', SimpleNamespace(name='posix', environ=os.environ, sep=os.sep)), \
                    mock.patch.object(runner.common, 'runtime_authorized', return_value=True), \
                    mock.patch.object(runner.common, 'MANIFEST', manifest), \
                    mock.patch.object(runner, 'source_snapshot', side_effect=lambda:
                                      {'synthetic': 'changed' if inputs_changed else 'hash'}), \
                    mock.patch.object(runner, 'require_xhttp_h3_lifetime_runtime',
                                      wraps=runner.require_xhttp_h3_lifetime_runtime) as h3_verify, \
                    mock.patch.object(runner.common, 'checked', side_effect=checked), \
                    mock.patch.object(runner, 'prepare_protected_core', side_effect=prepare_copy) as prepare:
                self.assertEqual(runner.main(), expected_exit)
            h3_verify.assert_called_once()
            self.assertEqual(h3_verify.call_args.args[0], h3_output)
            self.assertEqual(h3_verify.call_args.args[1], 1)
            prepare.assert_called_once_with(source.resolve(), evidence / 'LifetimeCore', manifest)
            compile_command = next(command for name, command in commands if name == 'acceptance-compile')
            self.assertIn('-modfile=' + str(evidence / 'native-lifetime.mod'), compile_command)
            edit = next(command for name, command in commands if name == 'lifetime-modfile')
            self.assertIn('-replace=synthetic.invalid/core=' + str(evidence / 'LifetimeCore'), edit)
            self.assertEqual((source / 'guarded.go').read_text(), 'original')
            old_runtime = next(command for name, command in commands if name == 'actual-core-dns')
            self.assertIn('-test.timeout=120s', old_runtime)
            tls_runtime = next(command for name, command in commands if name == 'actual-xhttp-tls')
            self.assertIn('^TestNativeXHTTPTLS$', tls_runtime)
            self.assertIn('-test.timeout=90s', tls_runtime)
            self.assertIn('actual-xhttp-h3-lifetime', dict(commands))
            h3_runtime = dict(commands)['actual-xhttp-h3-lifetime']
            self.assertIn('^TestNativeXHTTPH3Lifetime$', h3_runtime)
            self.assertIn('-test.timeout=150s', h3_runtime)
            self.assertEqual(budgets['actual-core-dns'], 140)
            self.assertEqual(budgets['actual-xhttp-tls'], 110)
            self.assertEqual(budgets['actual-xhttp-h3-lifetime'], 170)
            self.assertEqual([name for name, _ in commands].count('acceptance-compile'), 1)
            report = json.loads((evidence / 'result.json').read_text())
            self.assertTrue(report['core_overlay_applied'])
            self.assertFalse(report['native_dns_context_overlay_applied'])
            self.assertEqual(report['classic_lifetime_patch']['kind'], 'classic-udp-lifetime-only')
            self.assertIn('h3_lifetime_patch', report)
            self.assertEqual(report['h3_lifetime_patch']['kind'], 'xhttp-h3-dial-lifetime-only')
            self.assertEqual(report['lifetime_patch_scope'], ['classic_dns', 'xhttp_h3_dial'])
            self.assertIs(report['success'], expected_exit == 0)
            if expected_exit == 0:
                self.assertEqual(report['h3_lifetime_copy_sha256'],
                                 report['h3_lifetime_patch']['changed_upstream'][runner.H3_DIALER])
                self.assertTrue(report['h3_lifetime_copy_unchanged'])
                self.assertEqual(report['results'][-1]['selected_tests'], ['TestNativeXHTTPH3Lifetime'])
                self.assertEqual(report['results'][-1]['h3_lifetime_modes'], ['raw_numeric', 'native_cnc_windows'])
            else:
                expected_error = ('Darwin binding copy changed during verification' if mutate_binding else
                                  'H3 lifetime prepared copy changed during verification' if mutate_owned else
                                  'Production preparer/acceptance source changed during verification' if mutate_inputs else
                                  'Exact H3 lifetime modes missing or duplicated')
                self.assertEqual(report['error'], expected_error)
                if mutate_binding:
                    self.assertFalse(report['darwin_binding_copy_unchanged'])
                if mutate_owned:
                    self.assertFalse(report['h3_lifetime_copy_unchanged'])
                if mutate_inputs:
                    self.assertFalse(report['source_snapshot_unchanged'])
                if 'mode=unknown' in h3_output:
                    self.assertNotIn('selected_test_pass', report['results'][-1])

    def test_default_selects_pure_preparation_without_core_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / 'evidence'
            core = Path(directory) / 'ordinary-core'
            core.mkdir()
            (core / 'guarded.go').write_text('synthetic source')
            manifest = {'module': 'synthetic.invalid/core', 'module_version': 'v1.0.0', 'module_sum': 'synthetic',
                        'upstream_sha256': {'guarded.go': runner.digest(core / 'guarded.go')}}
            commands = []

            def fake_checked(name, command, **kwargs):
                commands.append(command)
                kwargs['results'].append({'name': name, 'exit_code': 0})
                if '-o' in command:
                    Path(command[command.index('-o') + 1]).write_text('synthetic compiled output')
                if name == 'core-pin':
                    (evidence / 'core-pin.log').write_text(json.dumps({'Version': 'v1.0.0', 'Sum': 'synthetic', 'Dir': str(core)}))
                if name == 'protocol-preparation-pure':
                    (evidence / 'protocol-preparation-pure.log').write_text(
                        '--- PASS: TestNativeProtocolPreparation (0.01s)\n--- PASS: TestProtocolCorpusBuilds (0.01s)\n--- PASS: TestNativeDoHMaterialOnly (0.01s)\n--- PASS: TestNativeSelectorPrefixAllocation (0.01s)\n'
                        '--- PASS: TestNativeCertificatePaths (0.01s)\n--- PASS: TestNativeRoutingContextTailCatchall (0.01s)\n--- PASS: TestNativeRoutingContextLoopbackDNS (0.01s)\n--- PASS: TestNativeRoutingContextCandidate (0.01s)\n')
                    with (evidence / 'protocol-preparation-pure.log').open('a') as output:
                        output.write('--- PASS: TestRoutingAttrsBuilds (0.01s)\n--- PASS: TestNativeRoutingAttrsPreservation (0.01s)\n')
                        output.write('--- PASS: TestPortEnvironmentAliases (0.01s)\n')
                        output.write('--- PASS: TestSchemaFieldsPreparation (0.01s)\n')
                        output.write('--- PASS: TestOpaqueFieldsPreparation (0.01s)\n')

            with mock.patch.object(runner, 'EVIDENCE', evidence), mock.patch.object(runner.sys, 'argv', ['runner']), \
                    mock.patch.object(runner.platform, 'system', return_value='Linux'), \
                    mock.patch.object(runner, 'os', SimpleNamespace(name='posix', environ=os.environ, sep=os.sep)), \
                    mock.patch.object(runner.common, 'MANIFEST', manifest), \
                    mock.patch.object(runner, 'source_snapshot', return_value={'synthetic': 'hash'}), \
                    mock.patch.object(runner.common, 'checked', side_effect=fake_checked):
                self.assertEqual(runner.main(), 0)
            self.assertTrue(any('test' in command and '-c' in command for command in commands))
            selections = [command[command.index('-test.run') + 1] for command in commands if '-test.run' in command]
            self.assertEqual(selections, ['^(TestNativeProtocolPreparation|TestProtocolCorpusBuilds|TestNativeDoHMaterialOnly|TestNativeSelectorPrefixAllocation|TestNativeCertificatePaths|TestNativeRoutingContextTailCatchall|TestNativeRoutingContextLoopbackDNS|TestNativeRoutingContextCandidate|TestRoutingAttrsBuilds|TestNativeRoutingAttrsPreservation|TestPortEnvironmentAliases|TestSchemaFieldsPreparation|TestOpaqueFieldsPreparation)$'])
            self.assertIn(['go', 'test', str(runner.ROOT / 'tool/generate_core_env_case.go'),
                           str(runner.ROOT / 'tool/generate_core_env_case_test.go')], commands)
            self.assertIn(['go', 'run', str(runner.ROOT / 'tool/generate_core_env_case.go'), '-check'], commands)
            self.assertFalse(any(runner.SELECTED_TEST in selection for selection in selections))
            report = json.loads((evidence / 'result.json').read_text())
            self.assertFalse(report['runtime_requested'])
            self.assertFalse(report['core_overlay_applied'])
            self.assertTrue(report['success'])


if __name__ == '__main__':
    unittest.main()
