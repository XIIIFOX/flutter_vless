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

    def generated(self, platform):
        script = (self.root / ('tool/test_' + platform + '_privacy_runtime.sh')).read_text()
        begin = 'python3 - "$ROOT" "$OUT" <<\'PY\'\n'
        self.assertEqual(1, script.count(begin))
        body = script.split(begin, 1)[1].split('\nPY\n', 1)[0]
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            (output / 'Probe.app').mkdir()
            # Execute only the actual file-generation block. Swift is text;
            # none of its SDK/Core calls, nor any shell step, are executed.
            with mock.patch.object(sys, 'argv', ['-', str(self.root), str(output)]):
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
        trap = source[source.index('cleanup_probe() {'):source.index('trap cleanup_probe EXIT')]
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
