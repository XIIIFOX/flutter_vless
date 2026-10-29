import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import run_apple_runtime_probe as probe


class AppleCounterRuntimeWiringTest(unittest.TestCase):
    root = Path(__file__).resolve().parents[1]

    def generated(self, platform, *, fakedns_only=False):
        script = (self.root / ('tool/test_' + platform + '_privacy_runtime.sh')).read_text()
        begin = 'python3 - "$ROOT" "$OUT" <<\'PY\'\n'
        self.assertEqual(1, script.count(begin))
        body = script.split(begin, 1)[1].split('\nPY\n', 1)[0]
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            (output / 'Probe.app').mkdir()
            # Execute only the actual file-generation block. Swift is text;
            # none of its SDK/Core calls, nor any shell step, are executed.
            with mock.patch.dict(os.environ, {'APPLE_RUNTIME_PROBE_MODE': 'fakedns-only' if fakedns_only else 'full'}), \
                    mock.patch.object(sys, 'argv', ['-', str(self.root), str(output)]):
                exec(compile(body, 'counter-harness-generation', 'exec'), {})
            return (output / 'main.swift').read_text()

    def assert_one_gate(self, platform):
        generated = self.generated(platform)
        names = [name for name in ('runMacCounterChecks', 'runAppleProxyCounterChecks')
                 if 'func ' + name + '() async throws' in generated]
        self.assertEqual(1, len(names), 'Actual harness must include exactly one counter fixture')
        name = names[0]
        self.assertEqual(1, generated.count('func ' + name + '() async throws'))
        self.assertEqual(1, generated.count('try await ' + name + '()'))
        modes = generated[generated.index('func runModes()'):]
        self.assertLess(modes.index('try await ' + name + '()'), modes.index('    let markers = ['))

    def test_ios_generated_runtime_has_one_counter_gate_before_modes(self):
        self.assert_one_gate('ios')

    def test_macos_generated_runtime_keeps_one_counter_gate_before_modes(self):
        self.assert_one_gate('macos')

    def test_ios_qualifier_requires_all_three_fixed_counter_markers(self):
        script = (self.root / 'tool/test_ios_privacy_runtime.sh').read_text()
        qualifier = script.rsplit('python3 - "$OUT/runtime.log" <<\'PY\'\n', 1)[1]
        for suffix in ('AND_API_PASSTHROUGH_PASS', 'UNTAGGED_UNAVAILABLE_PASS', 'DISABLED_UNAVAILABLE_PASS'):
            self.assertIn('IOS_COUNTERS_' + suffix, qualifier)
        self.assertIn('assert text.splitlines().count(marker) == 1', qualifier)


class AppleFakeDNSRuntimeWiringTest(unittest.TestCase):
    root = AppleCounterRuntimeWiringTest.root
    generated = AppleCounterRuntimeWiringTest.generated

    def assert_fake_dns_gate(self, platform):
        generated = self.generated(platform)
        self.assertEqual(1, generated.count('func runAppleFakeDNSRuntimeChecks() throws'))
        self.assertEqual(1, generated.count('try runAppleFakeDNSRuntimeChecks()'))
        modes = generated[generated.index('func runModes()'):]
        self.assertLess(modes.index('try runAppleFakeDNSRuntimeChecks()'), modes.index('    let markers = ['))
        script = (self.root / ('tool/test_' + platform + '_privacy_runtime.sh')).read_text()
        qualifier = script.rsplit('python3 - "$OUT/runtime.log" <<\'PY\'\n', 1)[1]
        self.assertIn("assert text.splitlines().count('APPLE_FAKEDNS_SDK_PASS=2') == 1", qualifier)

    def test_ios_generated_runtime_requires_one_actual_sdk_fakedns_gate(self):
        self.assert_fake_dns_gate('ios')

    def test_macos_generated_runtime_requires_one_actual_sdk_fakedns_gate(self):
        self.assert_fake_dns_gate('macos')

    def test_actual_dns_udp_query_uses_current_policy_virtual_address(self):
        generated = self.generated('ios')
        self.assertNotIn('[0, 0, 0, 1, 198, 18, 0, 2, 0, 53]', generated)
        self.assertIn('host: TunnelDNSPolicy.virtualServer, port: 53, payload: query)', generated)
        self.assertIn('dnsProbeUDPHeader(host: host, port: port)', generated)

    def test_sdk_fixture_preserves_and_queries_opaque_hosts_before_and_after(self):
        for platform in ('ios', 'macos'):
            with self.subTest(platform=platform):
                generated = self.generated(platform, fakedns_only=True)
                body = generated[generated.index('func runAppleFakeDNSRuntimeChecks() throws'):]
                self.assertIn('"useSystemHosts": true', body)
                for entry in ('"allowInsecure": "192.0.2.8"', '"network": "MiXeD.Target.Invalid"',
                              '"full:mixed.target.invalid": "192.0.2.9"', '"xHTTPSettings": "192.0.2.10"'):
                    self.assertIn(entry, body)
                self.assertIn('"address": "tcp://127.0.0.1:9"', body)
                self.assertIn('"skipFallback": true', body)
                self.assertIn('effective["dns"] as! NSDictionary == dns as NSDictionary', body)
                self.assertIn('for udp in [false, true]', body)
                self.assertIn('answer.suffix(4).elementsEqual(expected)', body)
                self.assertEqual(1, body.count('try verifyStaticHosts(generation, afterFakeDNS: false)'))
                self.assertEqual(1, body.count('try verifyStaticHosts(generation, afterFakeDNS: true)'))
                self.assertLess(body.index('try verifyStaticHosts(generation, afterFakeDNS: false)'), body.index('var fake:'))
                self.assertGreater(body.index('try verifyStaticHosts(generation, afterFakeDNS: true)'), body.index('payload: datagram) == datagram'))
                self.assertLess(body.index('upstream.requireComplete()'), body.index('print("APPLE_DNS_DATA_MAPS_SDK_PASS=2")'))


class AppleFakeDNSOnlyModeTest(unittest.TestCase):
    root = AppleCounterRuntimeWiringTest.root
    generated = AppleCounterRuntimeWiringTest.generated

    def test_generated_entry_runs_only_existing_fakedns_fixture(self):
        for platform in ('ios', 'macos'):
            with self.subTest(platform=platform):
                generated = self.generated(platform, fakedns_only=True)
                entry = generated[generated.index('func runModes() async {'):]
                end = '\nclass ModeDelegate:' if platform == 'ios' else '\nTask { await runModes() }'
                entry = entry.split(end, 1)[0]
                self.assertIn('print("RUNTIME=\\(XRayGetVersion())")', entry)
                self.assertEqual(1, entry.count('try runAppleFakeDNSRuntimeChecks()'))
                self.assertIn('exit(0)', entry)
                for unrelated in ('runRawRuntimeProbe()', 'runNativeRoutingRuntimeChecks()',
                                  'runAppleProxyCounterChecks()', 'MODE_PASS=', 'let markers ='):
                    self.assertNotIn(unrelated, entry)
                self.assertIn('func runNativeRoutingRuntimeChecks()', generated)

    def test_scoped_qualifier_requires_version_single_marker_and_privacy(self):
        for platform in ('ios', 'macos'):
            script = (self.root / ('tool/test_' + platform + '_privacy_runtime.sh')).read_text()
            body = script.rsplit('python3 - "$OUT/runtime.log" <<\'PY\'\n', 1)[1].split('\nPY', 1)[0]
            valid = 'RUNTIME=26.10.29\nAPPLE_FAKEDNS_SDK_PASS=2\nAPPLE_DNS_DATA_MAPS_SDK_PASS=2\n'
            cases = [(valid, True), ('APPLE_FAKEDNS_SDK_PASS=2\n', False),
                     (valid.replace('26.10.29', '26.10.18'), False),
                     (valid.replace('26.10.29', '26.10.290'), False),
                     (valid + 'RUNTIME=26.10.29\n', False),
                     ('RUNTIME=26.10.29\n', False), (valid + 'APPLE_FAKEDNS_SDK_PASS=2\n', False),
                     (valid + 'synthetic-password-canary\n', False)]
            with tempfile.TemporaryDirectory() as folder:
                log = Path(folder) / 'runtime.log'
                for content, accepted in cases:
                    with self.subTest(platform=platform, accepted=accepted, content=content):
                        log.write_text(content)
                        with mock.patch.dict(os.environ, {'APPLE_RUNTIME_PROBE_MODE': 'fakedns-only',
                                                          'REQUIRE_CORE_PREFLIGHT': '1', 'REQUIRE_VPN_ROUTING': '1'}), \
                                mock.patch.object(sys, 'argv', ['-', str(log)]), contextlib.redirect_stdout(io.StringIO()):
                            if accepted:
                                with self.assertRaises(SystemExit) as result:
                                    exec(compile(body, 'fakedns-only-qualifier', 'exec'), {})
                                self.assertEqual(0, result.exception.code)
                            else:
                                with self.assertRaises(AssertionError):
                                    exec(compile(body, 'fakedns-only-qualifier', 'exec'), {})
                # A scoped log must never qualify the default full gate.
                log.write_text(valid)
                with mock.patch.dict(os.environ, {'APPLE_RUNTIME_PROBE_MODE': 'full'}), \
                        mock.patch.object(sys, 'argv', ['-', str(log)]):
                    with self.assertRaises(AssertionError):
                        exec(compile(body, 'default-full-qualifier', 'exec'), {})

    def test_both_qualifier_modes_require_one_data_maps_marker_before_other_gates(self):
        for platform in ('ios', 'macos'):
            script = (self.root / ('tool/test_' + platform + '_privacy_runtime.sh')).read_text()
            body = script.rsplit('python3 - "$OUT/runtime.log" <<\'PY\'\n', 1)[1].split('\nPY', 1)[0]
            with tempfile.TemporaryDirectory() as folder:
                log = Path(folder) / 'runtime.log'
                for mode in ('full', 'fakedns-only'):
                    for count in (0, 2):
                        with self.subTest(platform=platform, mode=mode, count=count):
                            log.write_text('RUNTIME=26.10.29\nAPPLE_FAKEDNS_SDK_PASS=2\n' + 'APPLE_DNS_DATA_MAPS_SDK_PASS=2\n' * count)
                            failure = None
                            with mock.patch.dict(os.environ, {'APPLE_RUNTIME_PROBE_MODE': mode}), \
                                    mock.patch.object(sys, 'argv', ['-', str(log)]), contextlib.redirect_stdout(io.StringIO()):
                                try:
                                    exec(compile(body, 'data-maps-qualifier', 'exec'), {})
                                except AssertionError as error:
                                    failure = str(error)
                                except SystemExit as error:
                                    self.assertEqual(0, error.code)
                            self.assertEqual('Missing or duplicate Apple DNS data maps SDK gate', failure)

    def test_shell_arguments_are_closed_before_any_compile_or_runtime(self):
        for platform in ('ios', 'macos'):
            script = (self.root / ('tool/test_' + platform + '_privacy_runtime.sh')).read_text()
            prefix = script[:script.index('ROOT=')]
            for args in (['--unknown'], ['--fakedns-only', '--extra'], ['', ''], ['--fakedns-only', '--fakedns-only']):
                with self.subTest(platform=platform, args=args):
                    result = subprocess.run(['bash', '-c', prefix, 'probe', *args],
                                            env={**os.environ, 'SIMULATOR_UDID': 'inert-no-simulator'},
                                            capture_output=True, timeout=3)
                    self.assertEqual(2, result.returncode)
            for args in ([], ['--fakedns-only']):
                result = subprocess.run(['bash', '-c', prefix + '\nprintf "%s" "$APPLE_RUNTIME_PROBE_MODE"\n', 'probe', *args],
                                        env={**os.environ, 'SIMULATOR_UDID': 'inert-no-simulator'},
                                        capture_output=True, timeout=3)
                self.assertEqual(0, result.returncode)
                self.assertEqual(b'fakedns-only' if args else b'full', result.stdout)


class ApplePhaseMetadataTest(unittest.TestCase):
    simulator = '01234567-89AB-CDEF-0123-456789ABCDEF'

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.container = self.root / 'data'
        self.file = self.container / 'Library/Caches/flutter-vless-probe-phase.json'
        self.file.parent.mkdir(parents=True)
        self.log = self.root / 'runtime.log'; self.log.write_text('PROBE_APP_PID=27841\n')
        self.launched = time.time() - 5
        self.calls = []

    def fake_run(self, command, **kwargs):
        self.calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, (str(self.container) + '\n').encode())

    def receipt(self, **changes):
        value = dict(schema=1, pid=27841, phase=1, completed_modes=11)
        value.update(changes); self.file.write_text(json.dumps(value))
        return value

    def collect(self):
        return probe.collect_ios_phase(self.log, self.simulator, self.launched, run=self.fake_run)

    def test_valid_numeric_phases_are_identity_matched_bounded_and_redacted(self):
        for phase in range(1, 9):
            self.receipt(phase=phase, completed_modes=12 if phase >= 7 else 11, private='PRIVATE_PHASE_CANARY')
            value = self.collect()
            self.assertEqual(dict(state='matched', schema=1, pid=27841, phase=phase,
                                  completed_modes=12 if phase >= 7 else 11), value)
            self.assertNotIn('CANARY', json.dumps(value))
        for command, options in self.calls:
            self.assertEqual(['xcrun', 'simctl', 'get_app_container', self.simulator, probe.IOS_BUNDLE, 'data'], command)
            self.assertEqual(10, options['timeout']); self.assertIs(options['stderr'], subprocess.DEVNULL)

    def test_stdout_pid_is_exact_unique_and_corroborates_console_if_present(self):
        self.receipt()
        for text in ('PROBE_PROCESS_STARTED=owned-child;pid=27841\n', 'quoted PROBE_APP_PID=27841\n',
                     'PROBE_APP_PID=27841\nPROBE_APP_PID=27841\n', 'PROBE_APP_PID=27841\nPROBE_APP_PID=12345\n',
                     'PROBE_APP_PID=2147483648\n', 'PROBE_APP_PID=27841\n' + probe.IOS_BUNDLE + ': 7\n'):
            with self.subTest(text=text):
                self.log.write_text(text); self.calls.clear()
                self.assertEqual('unavailable', self.collect()['state']); self.assertFalse(self.calls)
        self.log.write_text('PROBE_APP_PID=27841\n' + probe.IOS_BUNDLE + ': 27841\n')
        self.assertEqual('matched', self.collect()['state'])

    def test_receipt_types_ranges_pid_malformed_duplicate_and_size_refuse(self):
        for changes in ({'schema': True}, {'schema': 2}, {'pid': 7}, {'pid': True},
                        {'phase': True}, {'phase': 0}, {'phase': 9}, {'phase': '1'},
                        {'completed_modes': -1}, {'completed_modes': 13}, {'completed_modes': True}):
            with self.subTest(changes=changes):
                self.receipt(**changes); self.assertEqual('unavailable', self.collect()['state'])
        for raw in ('{bad', '[' * 1000 + '0' + ']' * 1000, ' ' * 2049,
                    '{"schema":1,"pid":27841,"pid":7,"phase":1,"completed_modes":11}'):
            self.file.write_text(raw); self.assertEqual('unavailable', self.collect()['state'])

    def test_receipt_freshness_regular_file_single_link_and_no_follow(self):
        self.receipt(); os.utime(self.file, (self.launched - 1, self.launched - 1))
        self.assertEqual('unavailable', self.collect()['state'])
        self.receipt(); os.utime(self.file, (time.time() + 600, time.time() + 600))
        self.assertEqual('unavailable', self.collect()['state'])
        self.file.unlink(); outside = self.root / 'outside.json'
        outside.write_text(json.dumps(dict(schema=1, pid=27841, phase=1, completed_modes=11)))
        self.file.symlink_to(outside); self.assertEqual('unavailable', self.collect()['state'])
        self.file.unlink(); os.link(outside, self.file); self.assertEqual('unavailable', self.collect()['state'])
        self.file.unlink(); self.file.mkdir(); self.assertEqual('unavailable', self.collect()['state'])
        self.file.rmdir(); os.mkfifo(self.file); self.assertEqual('unavailable', self.collect()['state'])
        self.file.unlink(); caches = self.file.parent; caches.rmdir()
        caches.symlink_to(self.root); self.assertEqual('unavailable', self.collect()['state'])

    def test_invalid_launch_or_container_output_is_bounded_unavailable(self):
        self.receipt()
        for launched in (0, -1, float('nan'), float('inf')):
            with self.subTest(launched=launched):
                with mock.patch.object(probe.subprocess, 'run') as command:
                    self.assertEqual('unavailable', probe.collect_ios_phase(self.log, self.simulator, launched)['state'])
                    command.assert_not_called()
        for output in (b'relative/path\n', b'/PRIVATE_PATH_CANARY\x00\n', b'/' + b'x' * 4096):
            def fake(command, **kwargs): return subprocess.CompletedProcess(command, 0, output)
            value = probe.collect_ios_phase(self.log, self.simulator, self.launched, run=fake)
            self.assertEqual('unavailable', value['state']); self.assertNotIn('CANARY', json.dumps(value))
        def timeout(command, **kwargs): raise subprocess.TimeoutExpired(command, 10, output=b'PRIVATE_OUTPUT')
        value = probe.collect_ios_phase(self.log, self.simulator, self.launched, run=timeout)
        self.assertEqual('unavailable', value['state']); self.assertNotIn('PRIVATE', json.dumps(value))

    def test_appended_phase_is_diagnostic_only_and_preserves_log(self):
        self.receipt(); previous = self.log.read_text()
        with mock.patch.object(probe, 'collect_ios_phase', return_value=self.collect()), contextlib.redirect_stdout(io.StringIO()) as console:
            self.assertTrue(probe.append_ios_phase(self.log, self.simulator, self.launched))
        self.assertTrue(self.log.read_text().startswith(previous))
        self.assertLessEqual(len(console.getvalue().encode()), 2048)
        self.assertIn('PROBE_IOS_PHASE=', console.getvalue()); self.assertNotIn('MODE_PASS', console.getvalue())
        self.assertNotIn(str(self.container), console.getvalue())

    def test_nonregular_log_append_cannot_wait_for_a_pipe_reader(self):
        self.log.unlink(); os.mkfifo(self.log)
        original_open = probe.os.open
        def guarded_open(path, flags, *args, **kwargs):
            if str(path) == str(self.log) and flags & os.O_WRONLY:
                self.assertTrue(flags & os.O_NONBLOCK, 'Append could block on an unrelated FIFO')
            return original_open(path, flags, *args, **kwargs)
        with mock.patch.object(probe.os, 'open', side_effect=guarded_open), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(probe.append_ios_phase(self.log, self.simulator, self.launched))

    def test_actual_writer_and_shell_keep_phase_diagnostic_outside_qualification(self):
        root = Path(probe.__file__).resolve().parent.parent
        swift = AppleCounterRuntimeWiringTest().generated('ios')
        self.assertEqual(1, swift.count('print("PROBE_APP_PID='))
        self.assertIn('enum Phase: Int', swift)
        self.assertIn('case sleepEnter = 1, sleepReturn, closeEnter, closeReturn', swift)
        self.assertIn('case stopEnter, stopReturn, modePass, complete', swift)
        self.assertIn('.cachesDirectory', swift)
        self.assertIn('flutter-vless-probe-phase.json', swift)
        self.assertIn('data.count <= 512', swift); self.assertIn('options: .atomic', swift)
        self.assertIn('.posixPermissions: 0o600', swift)
        shell = (root / 'tool/test_ios_privacy_runtime.sh').read_text()
        function = shell[shell.index('collect_probe_phase() {'):shell.index('cleanup_probe() {')]
        self.assertIn('PHASE_COLLECTED=1', function)
        self.assertLess(function.index('PHASE_COLLECTED=1'), function.index('--collect-ios-phase'))
        self.assertIn('|| true', function)
        cleanup = shell[shell.index('cleanup_probe() {'):shell.index('trap cleanup_probe EXIT')]
        self.assertLess(cleanup.index('collect_probe_phase'), cleanup.index('simctl uninstall'))
        self.assertIn('exit "$status"', cleanup)
        normal = shell[shell.index('xcrun simctl launch --console'):]
        qualifier_start = normal.index('python3 - "$OUT/runtime.log"')
        self.assertLess(normal.index('collect_probe_phase'), qualifier_start)
        self.assertNotIn('PROBE_IOS_PHASE', normal[qualifier_start:])
        self.assertIn('Missing mode', normal[qualifier_start:])

    def test_cli_collects_phase_without_launch_and_rejects_mixed_modes(self):
        argv = ['probe', '--collect-ios-phase', str(self.log), '--ios-simulator', self.simulator, '--launched-at', str(self.launched)]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(probe, 'append_ios_phase', return_value=True) as append, mock.patch.object(probe, 'run_probe') as launch:
            self.assertEqual(0, probe.main()); launch.assert_not_called(); append.assert_called_once()
        for bad in (['probe', '--collect-ios-phase', str(self.log)],
                    argv + ['--collect-ios-termination', str(self.log)], argv + ['--', 'PRIVATE_COMMAND']):
            with mock.patch.object(sys, 'argv', bad), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit): probe.main()


class AppleTerminationMetadataTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.reports = self.root / 'reports'
        self.reports.mkdir()
        self.log = self.root / 'runtime.log'
        self.log.write_text('PROBE_PROCESS_STARTED=owned-child;pid=7\n' + probe.IOS_BUNDLE + ': 27841\n')
        self.launched = time.time() - 5

    def write_report(self, name='Probe-current.ips', *, pid=27841, bundle=probe.IOS_BUNDLE, process='Probe', two_documents=True):
        header = {'bundleID': bundle, 'unknown': 'privacy-canary.invalid'}
        body = {'pid': pid, 'procName': process, 'bundleInfo': {'CFBundleIdentifier': bundle},
                'termination': {'namespace': 'FRONTBOARD', 'code': 0x8badf00d, 'reasons': ['synthetic-password-canary']},
                'exception': {'type': 'EXC_CRASH', 'signal': 'SIGKILL'},
                'procPath': '/private/canary', 'threads': ['local-password-canary']}
        path = self.reports / name
        path.write_text((json.dumps(header) + '\n' if two_documents else '') + json.dumps(body))
        return path

    def collect(self):
        return probe.collect_ios_termination(self.log, self.launched, self.reports)

    def test_two_json_documents_match_owned_app_not_simctl_and_redact(self):
        self.write_report()
        metadata = self.collect()
        self.assertEqual({'state': 'matched', 'pid': 27841, 'reason': 'watchdog', 'namespace': 'FRONTBOARD',
                          'code': 0x8badf00d, 'signal': 'SIGKILL', 'exception': 'EXC_CRASH'}, metadata)
        self.assertNotIn('canary', json.dumps(metadata))

    def test_single_document_supported_and_unknown_freeform_values_discarded(self):
        path = self.write_report(two_documents=False)
        body = json.loads(path.read_text())
        body['termination'] = {'namespace': 'synthetic-password-canary', 'code': 'private-code', 'indicator': 'private-reason'}
        body['exception'] = {'type': 'private-type', 'signal': 'private-signal'}
        path.write_text(json.dumps(body))
        self.assertEqual({'state': 'matched', 'pid': 27841, 'reason': 'termination', 'namespace': 'unknown'}, self.collect())

    def test_wrong_pid_bundle_and_process_never_match(self):
        for values in ({'pid': 7}, {'bundle': 'another.bundle'}, {'process': 'AnotherProcess'}):
            with self.subTest(values=values):
                self.write_report(**values)
                self.assertEqual('unavailable', self.collect()['state'])

    def test_conflicting_bundle_identity_never_matches(self):
        path = self.write_report()
        header, body = path.read_text().split('\n', 1)
        path.write_text(json.dumps({'bundleID': 'another.bundle'}) + '\n' + body)
        self.assertEqual('unavailable', self.collect()['state'])

    def test_stale_oversized_malformed_and_symlink_reports_never_match(self):
        stale = self.write_report('Probe-stale.ips')
        os.utime(stale, (self.launched - 1, self.launched - 1))
        (self.reports / 'Probe-large.ips').write_bytes(b' ' * (probe.MAX_IPS_BYTES + 1))
        (self.reports / 'Probe-bad.ips').write_text('{malformed')
        (self.reports / 'Probe-deep.ips').write_text('[' * 2000 + '0' + ']' * 2000)
        unrelated = self.root / 'outside.ips'
        unrelated.write_text(self.write_report('Probe-template.ips').read_text())
        (self.reports / 'Probe-template.ips').unlink()
        (self.reports / 'Probe-link.ips').symlink_to(unrelated)
        self.assertEqual('unavailable', self.collect()['state'])

    def test_opened_report_mtime_is_rechecked_after_directory_scan(self):
        path = self.write_report()
        os.utime(path, (self.launched - 1, self.launched - 1))
        entry = mock.Mock(name=path.name, path=str(path))
        entry.name = path.name
        entry.is_file.return_value = True
        entry.stat.return_value = mock.Mock(st_mtime=time.time(), st_size=path.stat().st_size)
        with mock.patch.object(probe.os, 'scandir', return_value=contextlib.nullcontext([entry])):
            self.assertEqual('unavailable', self.collect()['state'])

    def test_missing_or_ambiguous_app_pid_never_uses_owned_console_pid(self):
        self.write_report()
        for text in ('PROBE_PROCESS_STARTED=owned-child;pid=27841\n',
                     probe.IOS_BUNDLE + ': 27841\n' + probe.IOS_BUNDLE + ': 12345\n'):
            with self.subTest(text=text):
                self.log.write_text(text)
                self.assertEqual('app-pid-unavailable', self.collect()['reason'])

    def test_report_read_count_is_bounded(self):
        for index in range(probe.MAX_IPS_REPORTS + 3):
            self.write_report(f'Probe-{index}.ips', pid=7)
        with mock.patch.object(probe, '_ips_documents', wraps=probe._ips_documents) as read:
            self.assertEqual('unavailable', self.collect()['state'])
        self.assertEqual(probe.MAX_IPS_REPORTS, read.call_count)

    def test_appended_metadata_is_small_and_preserves_existing_runtime_log(self):
        self.write_report()
        previous = self.log.read_text()
        with mock.patch.object(probe, 'collect_ios_termination', return_value=self.collect()), contextlib.redirect_stdout(io.StringIO()) as output:
            probe.append_ios_termination(self.log, self.launched)
        self.assertTrue(self.log.read_text().startswith(previous))
        self.assertLessEqual(len(output.getvalue().encode('utf-8')), 2048)
        self.assertNotIn('canary', output.getvalue())

    def test_failure_only_shell_trap_preserves_primary_exit_and_uninstall(self):
        root = Path(probe.__file__).resolve().parent.parent
        source = (root / 'tool/test_ios_privacy_runtime.sh').read_text()
        trap = source[source.index('PHASE_COLLECTED=0'):source.index('trap cleanup_probe EXIT')]
        fake_bin = self.root / 'bin'
        fake_bin.mkdir()
        fake_xcrun = fake_bin / 'xcrun'
        fake_xcrun.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$UNINSTALL_RECORD"\nexit 17\n')
        fake_xcrun.chmod(0o700)
        home = self.root / 'home'
        reports = home / 'Library/Logs/DiagnosticReports'
        reports.mkdir(parents=True)
        (reports / 'Probe-current.ips').write_text(self.write_report().read_text())
        environment = dict(os.environ, HOME=str(home), PATH=str(fake_bin) + os.pathsep + os.environ['PATH'], UNINSTALL_RECORD=str(self.root / 'uninstall.log'))
        for status in (19, 0):
            with self.subTest(status=status):
                self.log.write_text(probe.IOS_BUNDLE + ': 27841\n')
                command = 'set -euo pipefail\nROOT="$1"\nOUT="$2"\nSIMULATOR_UDID=owned-disposable\nBUNDLE=dev.tfox.security-runtime-probe\nPROBE_LAUNCHED_AT="$3"\n' + trap + '\ntrap cleanup_probe EXIT\nexit ' + str(status)
                result = subprocess.run(['bash', '-c', command, 'fixture', str(root), str(self.root), str(self.launched)],
                                        env=environment, text=True, capture_output=True, timeout=5)
                self.assertEqual(status, result.returncode)
                self.assertEqual(status != 0, 'PROBE_IOS_TERMINATION=' in self.log.read_text())
        self.assertEqual(['simctl uninstall owned-disposable ' + probe.IOS_BUNDLE] * 2,
                         (self.root / 'uninstall.log').read_text().splitlines())


class AppleRuntimeProbeTimeoutTest(unittest.TestCase):
    def run_child(self, source, timeout=3):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = probe.run_probe([sys.executable, '-c', source], timeout)
        return result, output.getvalue()

    def test_success_and_nonzero_are_preserved(self):
        self.assertEqual(0, self.run_child('pass')[0])
        self.assertEqual(23, self.run_child('raise SystemExit(23)')[0])

    def test_child_signal_failure_is_preserved(self):
        source = 'import os, signal; os.kill(os.getpid(), signal.SIGTERM)'
        self.assertEqual(128 + signal.SIGTERM, self.run_child(source)[0])

    def test_timeout_reaps_only_owned_child(self):
        with tempfile.TemporaryDirectory() as folder:
            pid_file = Path(folder) / 'child.pid'
            source = f'import os, pathlib, time; pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(30)'
            unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
            try:
                result, output = self.run_child(source, timeout=0.3)
                self.assertEqual(124, result)
                self.assertIn('PROBE_TIMEOUT=runtime', output)
                pid = int(pid_file.read_text())
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)
                self.assertIsNone(unrelated.poll(), 'Timeout killed an unrelated process')
            finally:
                unrelated.terminate()
                unrelated.wait(timeout=3)

    def test_timeout_escalates_when_owned_child_ignores_termination(self):
        source = 'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'
        with mock.patch.object(probe, 'STOP_SECONDS', 0.1):
            self.assertEqual(124, self.run_child(source, timeout=0.3)[0])

    def test_helper_interruption_reaps_its_owned_child(self):
        helper = Path(probe.__file__).resolve()
        process = subprocess.Popen([sys.executable, str(helper), '--timeout', '30', '--',
            sys.executable, '-c', 'import time; time.sleep(30)'], stdout=subprocess.PIPE, text=True)
        try:
            line = process.stdout.readline()
            self.assertIn('PROBE_PROCESS_STARTED=owned-child;pid=', line)
            child = int(line.rstrip().split('pid=')[1])
            process.terminate()
            output, _ = process.communicate(timeout=5)
            self.assertEqual(128 + signal.SIGTERM, process.returncode)
            self.assertIn('PROBE_INTERRUPTED=signal-', output)
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            process.stdout.close()

    def test_invalid_timeout_never_launches(self):
        for timeout in (0, -1, float('nan'), float('inf')):
            with self.subTest(timeout=timeout), mock.patch.object(probe.subprocess, 'Popen') as launch:
                with self.assertRaises(ValueError):
                    probe.run_probe(['unused'], timeout)
                launch.assert_not_called()

    def test_simulator_cleanup_requires_exact_owned_launch(self):
        with mock.patch.object(probe.subprocess, 'Popen') as launch:
            with self.assertRaises(ValueError):
                probe.run_probe(['xcrun', 'simctl', 'launch', 'another-app'], 1, 'disposable-simulator')
            launch.assert_not_called()

    def test_simulator_timeout_and_console_failure_clean_only_fixed_bundle(self):
        actual_popen = subprocess.Popen
        command = ['xcrun', 'simctl', 'launch', '--console', 'disposable-simulator', probe.IOS_BUNDLE]
        for source, expected in [('import time; time.sleep(30)', 124), ('raise SystemExit(17)', 17)]:
            cleaned = []
            def launch(_command):
                self.assertEqual(command, _command)
                return actual_popen([sys.executable, '-c', source])
            with self.subTest(expected=expected), mock.patch.object(probe.subprocess, 'Popen', side_effect=launch), \
                    contextlib.redirect_stdout(io.StringIO()):
                result = probe.run_probe(command, 0.3, 'disposable-simulator', cleaned.append)
            self.assertEqual(expected, result)
            self.assertEqual(['disposable-simulator'], cleaned)

    def test_simulator_cleanup_command_is_fixed_and_bounded(self):
        calls = []
        def run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0)
        with contextlib.redirect_stdout(io.StringIO()):
            probe.terminate_ios_probe('disposable-simulator', run=run)
        self.assertEqual(['xcrun', 'simctl', 'terminate', 'disposable-simulator', probe.IOS_BUNDLE], calls[0][0])
        self.assertEqual(10, calls[0][1]['timeout'])

    def test_cli_output_stream_and_failure_survive_tee(self):
        helper = Path(probe.__file__).resolve()
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / 'runtime.log'
            completed = subprocess.run(['bash', '-o', 'pipefail', '-c',
                '"$1" "$2" --timeout 3 -- "$1" -c \'print("SYNTHETIC_MARKER", flush=True); raise SystemExit(19)\' 2>&1 | tee "$3"',
                'fixture', sys.executable, str(helper), str(log)], capture_output=True, text=True, timeout=5)
            self.assertEqual(19, completed.returncode)
            self.assertIn('SYNTHETIC_MARKER', completed.stdout)
            self.assertIn('SYNTHETIC_MARKER', log.read_text())


if __name__ == '__main__':
    unittest.main()
