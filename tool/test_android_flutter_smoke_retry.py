import contextlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import test_android_flutter_smoke as smoke

PASS = smoke.TEST_ENTRY + '\nANDROID_XRAY_CORE_VERSION=Xray26.10.21\n🎉 3 tests passed.\n'


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A killed orphan waiting for init is not an executing owned child.
    proc = Path(f'/proc/{pid}/stat')
    if proc.exists():
        try:
            return proc.read_text().rsplit(')', 1)[1].split()[0] != 'Z'
        except (OSError, IndexError):
            pass
    return True


def wait_for(predicate, timeout=3):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError('Synthetic process did not reach its controlled boundary')


class SmokeProcessTest(unittest.TestCase):
    def attempt(self, code, *, hook=lambda _: None, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'live.log'
            result = smoke.stream_attempt([sys.executable, '-u', '-c', code], path,
                cwd=directory, cancellation=smoke.Cancellation(), on_failure=hook,
                timeout=kwargs.pop('timeout', 2), **kwargs)
            return result, path.read_bytes()

    def test_real_github_and_compact_success_summaries_qualify(self):
        for output in (PASS, PASS.replace('🎉 3 tests passed.', '00:03 +3: All tests passed!')):
            result, raw = self.attempt(f'print({output!r}, flush=True)')
            self.assertEqual(0, result['exit_code'])
            self.assertEqual('exit', result['reason'])
            self.assertTrue(result['cleanup']['leader_reaped'])
            self.assertIn(smoke.TEST_ENTRY.encode(), raw)

    def test_zero_exit_without_real_test_evidence_is_not_success(self):
        for output in ('', '3 tests passed.', smoke.TEST_ENTRY, PASS.replace('3 tests passed.', '2 tests passed.'), PASS.replace('3 tests passed.', '13 tests passed.')):
            result, _ = self.attempt(f'print({output!r}, flush=True)')
            self.assertEqual(125, result['exit_code'])
            self.assertEqual('unqualified', result['reason'])

    def test_markers_are_byte_chunk_safe(self):
        tracker = smoke.Markers()
        for value in (smoke.DDS_FAILURE + PASS).encode():
            tracker.feed(bytes([value]))
        self.assertTrue(smoke.qualified(tracker.found))
        self.assertTrue(tracker.found['dds'])

    def test_exact_terminal_summary_rejects_counts_quotes_and_stale_progress(self):
        for tail in ('🎉 13 tests passed.', '🎉 30 tests passed.', 'quoted "🎉 3 tests passed."',
                     '🎉 3 tests passed.\n00:04 +3: still running',
                     '00:03 +3: All tests passed!\nloading another test'):
            output = smoke.TEST_ENTRY + '\nANDROID_XRAY_CORE_VERSION=26.10.21\n' + tail
            result, _ = self.attempt(f'print({output!r},flush=True)')
            self.assertEqual(125, result['exit_code']); self.assertEqual('unqualified', result['reason'])

    def test_verbose_host_shutdown_does_not_replace_the_exact_reporter_summary(self):
        output = (PASS + '[  +16 ms] Running 1 shutdown hook\n'
                  '           a host-only continuation\n'
                  '[        ] Shutdown hooks complete\n[   +2 ms] exiting with code 0\n')
        result, raw = self.attempt(f'print({output!r},flush=True)')
        self.assertEqual(0, result['exit_code'])
        self.assertTrue(smoke.qualified(result['markers']))
        self.assertIn(b'exiting with code 0', raw)

    def test_verbose_trace_cannot_manufacture_success_or_hide_a_later_reporter_failure(self):
        for ending in ('[   +1 ms] 🎉 3 tests passed.',
                       '[   +1 ms] 00:03 +3: All tests passed!',
                       '🎉 3 tests passed.\n[   +1 ms] trace\n00:04 +3 -1: Some tests failed.',
                       '🎉 3 tests passed.\nquoted "[   +1 ms] trace"',
                       '🎉 3 tests passed.\n[+1 ms] not a Flutter verbose prefix'):
            output = smoke.TEST_ENTRY + '\nANDROID_XRAY_CORE_VERSION=Xray26.10.21\n' + ending
            result, _ = self.attempt(f'print({output!r},flush=True)')
            self.assertEqual(125, result['exit_code'])
            self.assertEqual('unqualified', result['reason'])

    def test_live_partial_log_precedes_child_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); path = folder / 'live.log'; release = folder / 'release'
            outcome = []
            code = ("import pathlib,time;print('LIVE_PARTIAL',flush=True);"
                    f"p=pathlib.Path({str(release)!r});\nwhile not p.exists():time.sleep(.01)\n"
                    f'print({PASS!r},flush=True)')
            thread = threading.Thread(target=lambda: outcome.append(smoke.stream_attempt(
                [sys.executable, '-u', '-c', code], path, cwd=directory,
                cancellation=smoke.Cancellation(), on_failure=lambda _: None, timeout=3)))
            thread.start()
            try:
                wait_for(lambda: path.exists() and b'LIVE_PARTIAL' in path.read_bytes())
                self.assertTrue(thread.is_alive())
                self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            finally:
                release.touch(); thread.join(5)
            self.assertFalse(thread.is_alive()); self.assertEqual(0, outcome[0]['exit_code'])

    def test_timeout_context_before_group_cleanup_and_partial_output_retained(self):
        observed = []
        def hook(result):
            observed.append((result['exit_code'], result['reason'], result['bytes_written']))
        started = time.monotonic()
        result, output = self.attempt("import time;print('PARTIAL',flush=True);time.sleep(60)",
                                      timeout=.15, hook=hook)
        self.assertEqual(124, result['exit_code']); self.assertEqual('timeout', result['reason'])
        self.assertEqual([(124, 'timeout', 8)], observed)
        self.assertIn(b'PARTIAL', output); self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(result['cleanup']['leader_reaped'])

    def test_terminal_line_without_newline_is_finalized(self):
        tracker = smoke.Markers()
        tracker.feed(PASS.rstrip('\n').encode())
        self.assertFalse(smoke.qualified(tracker.found))
        tracker.finish()
        self.assertTrue(smoke.qualified(tracker.found))

    def test_closed_stdout_with_live_parent_is_still_bounded(self):
        result, _ = self.attempt('import os,time;os.close(1);os.close(2);time.sleep(60)', timeout=.15)
        self.assertEqual('timeout', result['reason']); self.assertEqual(124, result['exit_code'])
        self.assertTrue(result['cleanup']['leader_reaped'])

    def test_parent_exit_grandchild_pipe_and_descendant_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); pidfile = folder / 'pid'; output = folder / 'live.log'
            code = ("import subprocess,sys,pathlib;"
                    "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
                    f"pathlib.Path({str(pidfile)!r}).write_text(str(p.pid));print({PASS!r},flush=True)")
            result = smoke.stream_attempt([sys.executable, '-u', '-c', code], output,
                cwd=directory, cancellation=smoke.Cancellation(), on_failure=lambda _: None,
                timeout=2, pipe_grace=.1)
            pid = int(pidfile.read_text())
            try:
                self.assertEqual('pipe_timeout', result['reason']); self.assertEqual(125, result['exit_code'])
                self.assertEqual(0, result['child_returncode']); wait_for(lambda: not alive(pid))
            finally:
                if alive(pid): os.kill(pid, signal.SIGKILL)

    def test_scan_after_disk_limit_and_failure_exit_are_preserved(self):
        payload = b'A' * 4096 + (smoke.DDS_FAILURE + PASS).encode()
        result, output = self.attempt(f'import os;os.write(1,{payload!r});raise SystemExit(17)', max_bytes=128)
        self.assertEqual(128, len(output)); self.assertTrue(result['truncated'])
        self.assertTrue(smoke.qualified(result['markers'])); self.assertTrue(result['markers']['dds'])
        self.assertEqual(17, result['exit_code'])

    def test_output_limit_refuses_even_qualified_zero_exit(self):
        result, _ = self.attempt(f'print({("A"*512+PASS)!r},flush=True)', max_bytes=64)
        self.assertEqual('output_limit', result['reason']); self.assertEqual(125, result['exit_code'])

    def test_context_exception_or_keyboardinterrupt_never_masks_primary(self):
        for failure in (OSError('fixture context failure'), KeyboardInterrupt()):
            def hook(_): raise failure
            result, _ = self.attempt('raise SystemExit(17)', hook=hook)
            self.assertEqual(17, result['exit_code']); self.assertIsNotNone(result['diagnostic_error'])
            self.assertTrue(result['cleanup']['leader_reaped'])

    def test_keyboardinterrupt_during_cleanup_still_kills_and_reaps(self):
        real = smoke._signal_group
        calls = []
        def interrupted(pid, number):
            calls.append(number)
            if len(calls) == 1: raise KeyboardInterrupt()
            return real(pid, number)
        with patch.object(smoke, '_signal_group', interrupted):
            result, _ = self.attempt('import time;time.sleep(60)', timeout=.1)
        self.assertEqual(124, result['exit_code']); self.assertIn(signal.SIGKILL, calls)
        self.assertTrue(result['cleanup']['leader_reaped'])

    def test_keyboardinterrupt_at_first_kill_cannot_skip_reap_or_pipe_close(self):
        real = smoke._signal_group
        kills = []
        def interrupted(pid, number):
            if number == signal.SIGKILL:
                kills.append(pid)
                if len(kills) == 1: raise KeyboardInterrupt()
            return real(pid, number)
        with patch.object(smoke, '_signal_group', interrupted):
            result, _ = self.attempt('import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("READY",flush=True);time.sleep(60)', timeout=.2)
        self.assertEqual(124, result['exit_code']); self.assertEqual(2, len(kills))
        self.assertTrue(result['cleanup']['leader_reaped']); self.assertTrue(result['cleanup']['pipe_closed'])
        self.assertFalse(alive(kills[0]))

    def test_short_private_log_write_fails_and_still_reaps_owned_child(self):
        original = smoke.os.fdopen
        class ShortWriter:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): return self
            def __exit__(self, *args): return self.stream.__exit__(*args)
            def write(self, value): return self.stream.write(value[:-1])
        with patch.object(smoke.os, 'fdopen', lambda *a, **k: ShortWriter(original(*a, **k))):
            result, output = self.attempt(f'print({PASS!r},flush=True)')
        self.assertEqual(125, result['exit_code']); self.assertEqual('capture_error', result['reason'])
        self.assertTrue(result['cleanup']['leader_reaped']); self.assertTrue(result['cleanup']['pipe_closed'])
        self.assertGreater(len(output), 0); self.assertEqual(len(output), result['bytes_written'])


class SmokeRetryTest(unittest.TestCase):
    def check_case(self, responses, expected, attempts, *, collect_error=False, cleanup_error=False):
        calls = []; order = []; console = io.StringIO()
        def runner(command, path, **kwargs):
            code, text = responses[len(calls)]; calls.append(command)
            return smoke.stream_attempt([sys.executable, '-u', '-c', f'print({text!r},flush=True);raise SystemExit({code})'],
                                         path, timeout=2, **kwargs)
        def collect(*args, **kwargs):
            order.append('context')
            if collect_error: raise OSError('fixture context failed')
            return {'fixture': {'returncode': 0, 'timed_out': False}}
        def cleanup(*args, **kwargs):
            order.append('cleanup')
            return {'returncode': 1 if cleanup_error else 0}
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(console):
            result = smoke.run_smoke('emulator-5554', Path(directory), runner=runner,
                ownership=lambda *args, **kwargs: True, collect=collect, cleanup_app=cleanup, pause=lambda _: None)
            summary = json.loads((Path(directory) / 'summary.json').read_text())
            self.assertEqual(expected, result); self.assertEqual(attempts, len(calls))
            self.assertEqual(expected, summary['exit_code'])
            self.assertNotIn('PRIVATE_SENTINEL', console.getvalue())
            self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in Path(directory).glob('*')))
            if expected != 0: self.assertIn('context', order)
            if cleanup_error and responses[0][0] == 0:
                self.assertEqual(['cleanup', 'context'], order)
            else:
                for index, item in enumerate(order):
                    if item == 'context': self.assertIn('cleanup', order[index + 1:])
        return summary

    def test_only_genuine_pre_entry_dds_retries_once(self):
        self.check_case([(1, smoke.DDS_FAILURE), (0, PASS)], 0, 2)
        self.check_case([(1, smoke.DDS_FAILURE), (1, smoke.DDS_FAILURE)], 1, 2)

    def test_actual_assertion_entry_vm_loss_and_tool_failure_never_retry(self):
        for output in (smoke.TEST_ENTRY + smoke.DDS_FAILURE, PASS + smoke.DDS_FAILURE,
                       "VmServiceDisappearedException PRIVATE_SENTINEL", 'Assertion failed'):
            self.check_case([(17, output)], 17, 1)

    def test_context_failure_prevents_dds_retry_and_preserves_exit(self):
        self.check_case([(17, smoke.DDS_FAILURE)], 17, 1, collect_error=True)

    def test_timeout_after_dds_is_not_a_pre_entry_retry(self):
        calls = []
        def runner(command, path, **kwargs):
            calls.append(command)
            return smoke.stream_attempt([sys.executable, '-u', '-c',
                f'import time;print({smoke.DDS_FAILURE!r},flush=True);time.sleep(60)'],
                path, timeout=.15, **kwargs)
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            result = smoke.run_smoke('emulator-5554', Path(directory), runner=runner,
                ownership=lambda *a, **k: True, collect=lambda *a, **k: {'fixture': {'returncode': 0}},
                cleanup_app=lambda *a, **k: {'returncode': 0}, pause=lambda _: self.fail('must not retry'))
            summary = json.loads((Path(directory) / 'summary.json').read_text())
        self.assertEqual(124, result); self.assertEqual(1, len(calls))
        self.assertEqual('timeout', summary['attempts'][0]['reason'])

    def test_incomplete_context_refuses_dds_retry(self):
        calls = []
        def runner(command, path, **kwargs):
            calls.append(command)
            return smoke.stream_attempt([sys.executable, '-u', '-c',
                f'print({smoke.DDS_FAILURE!r},flush=True);raise SystemExit(1)'], path, timeout=2, **kwargs)
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            result = smoke.run_smoke('emulator-5554', Path(directory), runner=runner,
                ownership=lambda *a, **k: True,
                collect=lambda *a, **k: {'fixture': {'returncode': 0, 'timed_out': True}},
                cleanup_app=lambda *a, **k: {'returncode': 0}, pause=lambda _: self.fail('must not retry'))
            summary = json.loads((Path(directory) / 'summary.json').read_text())
        self.assertEqual(1, result); self.assertEqual(1, len(calls))
        self.assertEqual('RuntimeError', summary['attempts'][0]['diagnostic_error'])

    def test_app_cleanup_failure_preserves_existing_failure(self):
        self.check_case([(17, 'failure')], 17, 1, cleanup_error=True)

    def test_app_cleanup_failure_refuses_success(self):
        self.check_case([(0, PASS)], 125, 1, cleanup_error=True)

    def test_dds_failed_group_cleanup_is_not_retried(self):
        original = smoke._cleanup_group
        for delta in ({'error': 'fixture'}, {'leader_reaped': False}, {'pipe_closed': False}):
            def failed(process):
                return {**original(process), **delta}
            with patch.object(smoke, '_cleanup_group', failed):
                summary = self.check_case([(1, smoke.DDS_FAILURE), (0, PASS)], 1, 1)
            self.assertEqual(1, len(summary['attempts']))
            self.assertEqual(delta, {key: summary['attempts'][0]['cleanup'][key] for key in delta})

    def test_summary_write_failure_preserves_actual_failure_code(self):
        original = smoke.write_private
        def write(path, value):
            if path.name == 'summary.json': raise OSError('fixture filesystem unavailable')
            return original(path, value)
        with tempfile.TemporaryDirectory() as directory, patch.object(smoke, 'write_private', write), contextlib.redirect_stdout(io.StringIO()) as console:
            def runner(command, path, **kwargs):
                return smoke.stream_attempt([sys.executable, '-c', 'raise SystemExit(17)'], path, timeout=2, **kwargs)
            result = smoke.run_smoke('emulator-5554', Path(directory), runner=runner,
                ownership=lambda *a, **k: True, collect=lambda *a, **k: {'fixture': {'returncode': 0}},
                cleanup_app=lambda *a, **k: {'returncode': 0})
            self.assertEqual(17, result); self.assertIn('metadata_error', console.getvalue())

    def test_summary_write_failure_refuses_otherwise_successful_smoke(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(smoke, 'write_private', side_effect=OSError('fixture')), contextlib.redirect_stdout(io.StringIO()):
            def runner(command, path, **kwargs):
                return smoke.stream_attempt([sys.executable, '-u', '-c', f'print({PASS!r},flush=True)'], path, timeout=2, **kwargs)
            result = smoke.run_smoke('emulator-5554', Path(directory), runner=runner,
                ownership=lambda *a, **k: True, collect=lambda *a, **k: {'fixture': {'returncode': 0}},
                cleanup_app=lambda *a, **k: {'returncode': 0})
        self.assertEqual(125, result)

    def test_signal_after_preflight_never_launches_child(self):
        state = smoke.Cancellation()
        def owned(*args, **kwargs): state.receive(signal.SIGTERM, None); return True
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            result = smoke.run_smoke('emulator-5554', Path(directory), ownership=owned, cancellation=state,
                runner=lambda *a, **k: self.fail('must not launch'), cleanup_app=lambda *a, **k: self.fail('must not cleanup'))
            self.assertEqual(143, result)

    def test_fresh_evidence_refuses_overwriting_an_older_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'summary.json'; path.write_text('old evidence')
            with self.assertRaises(ValueError):
                smoke.run_smoke('emulator-5554', Path(directory), ownership=lambda *a, **k: self.fail('must not query'))
            self.assertEqual('old evidence', path.read_text())

    def test_refuses_unknown_package_without_launch_or_cleanup(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            def refused(*args, **kwargs): raise RuntimeError('unknown-preinstalled-example')
            code = smoke.run_smoke('emulator-5554', Path(directory), ownership=refused,
                runner=lambda *a, **k: self.fail('must not launch'), cleanup_app=lambda *a,**k: self.fail('must not cleanup'))
            self.assertEqual(125, code)

    def test_refuses_physical_or_malformed_serial(self):
        for serial in ('physical-device', 'emulator-fixture', 'emulator-5554 extra'):
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError): smoke.run_smoke(serial, Path(directory))


class SmokeContextTest(unittest.TestCase):
    def test_bounded_private_context_uses_only_fixed_example_read_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); adb = folder / 'adb'
            adb.write_text('#!' + sys.executable + '\nimport os,time\nos.write(1,b"x"*200000)\ntime.sleep(60)\n')
            adb.chmod(0o700)
            with patch.dict(os.environ, {'PATH': directory + os.pathsep + os.environ['PATH']}):
                started = time.monotonic()
                result = smoke.collect_failure_context('emulator-5554', folder, 1, timeout=1)
            self.assertLess(time.monotonic() - started, 3)
            self.assertEqual({'crash', 'logcat', 'exit-info', 'activity', 'app-pid'}, set(result))
            for name, report in result.items():
                self.assertTrue(report['timed_out']); self.assertTrue(report['truncated'])
                self.assertEqual(4096 if name == 'app-pid' else smoke.MAX_CONTEXT_BYTES, report['bytes_written'])
                self.assertNotIn('force-stop', report['command']); self.assertNotIn('-c', report['command'])
                self.assertEqual(0o600, stat.S_IMODE((folder / report['file']).stat().st_mode))
            self.assertIn(smoke.EXAMPLE_PACKAGE, result['exit-info']['command'])

    def test_baseline_checks_emulator_hardware_and_refuses_existing_example(self):
        for hardware, qemu, package, expected in [('ranchu','1','',True), ('goldfish','1','',True),
                    ('physical','1','',False), ('ranchu','0','',False), ('ranchu','1','package:/fixture.apk',False)]:
            def fake(command, path, **kwargs):
                value = package if 'path' in command else hardware if 'ro.hardware' in command else qemu
                path.write_text(value)
                return {'returncode': 0}
            with tempfile.TemporaryDirectory() as directory, patch.object(smoke, 'capture', fake):
                if expected: self.assertTrue(smoke.preflight_ownership('emulator-5554', Path(directory)))
                else:
                    with self.assertRaises(RuntimeError): smoke.preflight_ownership('emulator-5554', Path(directory))


class SmokeStartupDiagnosticTest(unittest.TestCase):
    completed_install = b'Installing build/app/outputs/flutter-apk/app-debug.apk...        1,349ms\n'

    def test_completed_install_has_chunk_safe_preentry_stage(self):
        for size in (1, 17, 65536):
            with self.subTest(chunk_size=size):
                tracker = smoke.Markers()
                for offset in range(0, len(self.completed_install), size):
                    tracker.feed(self.completed_install[offset:offset + size])
                tracker.finish()
                self.assertEqual('installed_awaiting_test_entry', tracker.stage())
                self.assertFalse(smoke.qualified(tracker.found))

    def test_verbose_completed_install_keeps_stage_and_private_vm_observation(self):
        output = (b'[+1233 ms] Installing build/app/outputs/flutter-apk/app-debug.apk... (completed in 1,233ms)\n'
                  b'[   +1 ms] Dart VM service is listening on http://PRIVATE_VM_URL\n')
        for size in (1, 17, 65536):
            tracker = smoke.Markers()
            for offset in range(0, len(output), size): tracker.feed(output[offset:offset + size])
            tracker.finish()
            self.assertEqual('installed_awaiting_test_entry', tracker.stage())
            self.assertTrue(tracker.found['vm_service'])
            self.assertFalse(smoke.qualified(tracker.found))

    def test_actual_verbose_device_vm_discovery_is_observed_without_a_public_status_url(self):
        # Fresh Actions trace: Flutter discovers this URL before DDS connects,
        # without emitting either of the user-facing VM-service status lines.
        tracker = smoke.Markers()
        tracker.feed(b'[        ] Waiting for VM Service port to be available...\n')
        self.assertFalse(tracker.found['vm_service'])
        tracker.feed(b'[+2010 ms] VM Service URL on device: http://127.0.0.1:1234/PRIVATE_SENTINEL/\n')
        self.assertTrue(tracker.found['vm_service'])
        self.assertFalse(smoke.qualified(tracker.found))
        for text in (b'quoted VM Service URL on device: http://PRIVATE_SENTINEL\n',
                     b'[   +1 ms] Waiting for VM Service URL on device: http://PRIVATE_SENTINEL\n'):
            negative = smoke.Markers(); negative.feed(text)
            self.assertFalse(negative.found['vm_service'])

    def test_install_start_or_quoted_completion_does_not_claim_installed(self):
        for value in (b'Installing build/app.apk...', b'quoted "' + self.completed_install.rstrip() + b'"\n'):
            tracker = smoke.Markers(); tracker.feed(value); tracker.finish()
            self.assertEqual('installing', tracker.stage())
            self.assertFalse(tracker.found['install_completed'])
        tracker.feed(b'A Dart VM Service on emulator is available at: http://PRIVATE_VM_URL\n')
        self.assertTrue(tracker.found['vm_service'])
        tracker.feed((smoke.TEST_ENTRY + '\n').encode())
        self.assertEqual('test_entered', tracker.stage())

    def test_early_context_once_precedes_timeout_cleanup_without_retry(self):
        order = []; calls = []; budgets = []
        def collect(serial, folder, attempt, **kwargs):
            order.append('installed' if str(attempt).endswith('-installed') else 'failure')
            budgets.append(kwargs['timeout'])
            return {'fixture': {'returncode': 0, 'timed_out': False}}
        def runner(command, path, **kwargs):
            calls.append(command)
            value = {'reason': None, 'exit_code': None, 'stage': 'installed_awaiting_test_entry',
                'bytes_written': 1601, 'elapsed_seconds': 290, 'timeout_seconds': 600,
                'markers': dict.fromkeys(smoke.Markers.patterns, False),
                'owned_process': {'pid': 4321, 'pgid': 4321, 'returncode': None}}
            kwargs['progress'](value); kwargs['progress'](value)
            value = dict(value, reason='timeout', exit_code=124, process_started=True,
                child_returncode=None, truncated=False, diagnostic_error=None,
                cleanup={'leader_reaped': True, 'pipe_closed': True, 'error': None})
            kwargs['on_failure'](value)
            order.append('stream_cleanup')
            return value
        def cleanup(*args, **kwargs): order.append('app_cleanup'); return {'returncode': 0}
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            result = smoke.run_smoke('emulator-5554', Path(directory), runner=runner,
                ownership=lambda *a, **k: True, collect=collect, cleanup_app=cleanup,
                pause=lambda _: self.fail('timeout must never retry'))
        self.assertEqual(124, result); self.assertEqual(1, len(calls))
        self.assertEqual(['installed', 'failure', 'stream_cleanup', 'app_cleanup'], order)
        self.assertLessEqual(budgets[0], 2)

    def test_early_context_uses_remaining_budget_and_keeps_timeout_if_capture_fails(self):
        budgets = []
        def collect(*args, **kwargs):
            budgets.append(kwargs['timeout'])
            raise OSError('PRIVATE_CONTEXT_SENTINEL')
        def runner(command, path, **kwargs):
            value = {'stage': 'installed_awaiting_test_entry', 'elapsed_seconds': 599.75,
                     'timeout_seconds': 600, 'markers': dict.fromkeys(smoke.Markers.patterns, False)}
            kwargs['progress'](value); kwargs['progress'](value)
            return dict(value, reason='timeout', exit_code=124, process_started=True,
                        child_returncode=None, truncated=False, diagnostic_error=None,
                        cleanup={'leader_reaped': True, 'pipe_closed': True, 'error': None})
        console = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(console):
            code = smoke.run_smoke('emulator-5554', Path(directory), runner=runner, collect=collect,
                ownership=lambda *a, **k: True, cleanup_app=lambda *a, **k: {'returncode': 0},
                pause=lambda _: self.fail('timeout must never retry'))
            report = json.loads((Path(directory) / 'summary.json').read_text())
        self.assertEqual(124, code); self.assertEqual([.25], budgets)
        self.assertEqual('OSError', report['attempts'][0]['startup_observation']['error'])
        self.assertNotIn('PRIVATE_CONTEXT_SENTINEL', console.getvalue())

    def test_one_later_launch_snapshot_retains_preentry_window_without_retry_or_deadline_reset(self):
        phases = []; commands = []
        def collect(serial, folder, phase, **kwargs):
            phases.append((phase, kwargs['timeout']))
            return {'fixture': {'returncode': 0, 'timed_out': False}}
        def runner(command, path, **kwargs):
            commands.append(command)
            value = {'stage': 'installed_awaiting_test_entry', 'elapsed_seconds': 100,
                     'timeout_seconds': 600, 'markers': dict.fromkeys(smoke.Markers.patterns, False)}
            for elapsed in (100, 110, 130, 160):
                kwargs['progress'](dict(value, elapsed_seconds=elapsed))
            value = dict(value, reason='timeout', exit_code=124, process_started=True,
                         child_returncode=None, truncated=False, diagnostic_error=None,
                         cleanup={'leader_reaped': True, 'pipe_closed': True, 'error': None})
            kwargs['on_failure'](value)
            return value
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            code = smoke.run_smoke('emulator-5554', Path(directory), runner=runner, collect=collect,
                ownership=lambda *a, **k: True, cleanup_app=lambda *a, **k: {'returncode': 0},
                pause=lambda _: self.fail('pre-entry timeout cannot retry'))
            report = json.loads((Path(directory) / 'summary.json').read_text())
        self.assertEqual(124, code); self.assertEqual(1, len(commands))
        self.assertIn('--verbose', commands[0]); self.assertIn('expanded', commands[0])
        self.assertEqual([('1-installed', 2), ('1-launch', 2), (1, 10)], phases)
        self.assertEqual(100, report['attempts'][0]['startup_observation']['elapsed_seconds'])
        self.assertEqual(130, report['attempts'][0]['launch_observation']['elapsed_seconds'])

    def test_context_pid_metadata_is_numeric_or_absent_and_private(self):
        for raw, code, expected in ((b'123 456\n', 0, {'state': 'running', 'pids': [123, 456]}),
                (b'', 1, {'state': 'absent', 'pids': []}),
                (b'PRIVATE_PID_SENTINEL', 0, {'state': 'unknown', 'pids': []})):
            commands = []
            def fake(command, path, **kwargs):
                commands.append((command, kwargs))
                smoke.write_private(path, raw if 'pidof' in command else b'')
                return {'returncode': code if 'pidof' in command else 0}
            with tempfile.TemporaryDirectory() as directory, patch.object(smoke, 'capture', fake):
                result = smoke.collect_failure_context('emulator-5554', Path(directory), '1-installed', timeout=2)
                self.assertEqual(expected, result['app-pid']['app_process'])
                self.assertNotIn('PRIVATE_PID_SENTINEL', json.dumps(result))
                self.assertTrue(all(0 < item[1]['timeout'] <= 2 for item in commands))
                self.assertTrue(all('force-stop' not in item[0] for item in commands))
                self.assertEqual(4096, next(opts['max_bytes'] for command, opts in commands if 'pidof' in command))
                focused = [command for command, _ in commands if any(arg.startswith('--pid=') for arg in command)]
                self.assertEqual(len(expected['pids']) if expected['state'] == 'running' else 0, len(focused))
                self.assertTrue(any('activities' in command for command, _ in commands))

    def test_focused_logs_share_the_observation_budget_and_never_run_after_it_expires(self):
        for remaining in (0, .25):
            calls = []; now = [0]
            def fake(command, path, **kwargs):
                calls.append((command, kwargs))
                smoke.write_private(path, b'123\n' if 'pidof' in command else b'')
                return {'returncode': 0}
            def clock():
                value = now[0]; now[0] = 2 - remaining
                return value
            with tempfile.TemporaryDirectory() as directory, patch.object(smoke, 'capture', fake), \
                 patch.object(smoke.time, 'monotonic', clock):
                result = smoke.collect_failure_context('emulator-5554', Path(directory), 1, timeout=2)
            focused = [opts for command, opts in calls if '--pid=123' in command]
            if remaining:
                self.assertEqual([remaining], [opts['timeout'] for opts in focused])
            else:
                self.assertEqual([], focused)
                self.assertEqual('observation_budget_exhausted', result['app-logcat']['skipped'])


class SmokeSignalTest(unittest.TestCase):
    def check_signal(self, signum):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); pidfile = folder / 'child.pid'
            code = ("import subprocess,sys,pathlib,time;"
                    "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
                    f"pathlib.Path({str(pidfile)!r}).write_text(str(p.pid));print({smoke.DDS_FAILURE!r},flush=True);time.sleep(60)")
            driver = folder / 'driver.py'
            driver.write_text('''import sys, pathlib, subprocess\nsys.path.insert(0,sys.argv[1])\nimport test_android_flutter_smoke as s\nstate=s.Cancellation()\ndef runner(cmd,path,**kw):\n return s.stream_attempt([sys.executable,'-u','-c',sys.argv[3]],path,timeout=30,**kw)\nwith s.cancellation_handlers(state):\n result=s.run_smoke('emulator-5554',pathlib.Path(sys.argv[2]),runner=runner,cancellation=state,ownership=lambda *a,**k:True,collect=lambda *a,**k:{'fixture':{'returncode':0}},cleanup_app=lambda *a,**k:{'returncode':0})\nraise SystemExit(result)\n''')
            unrelated = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(60)'])
            process = subprocess.Popen([sys.executable, str(driver), str(Path(smoke.__file__).parent), str(folder / 'out'), code],
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                wait_for(pidfile.exists)
                process.send_signal(signum)
                output = process.communicate(timeout=5)[0]
                self.assertEqual(128 + signum, process.returncode)
                summary = json.loads((folder / 'out/summary.json').read_text())
                self.assertEqual(1, len(summary['attempts'])); self.assertEqual('signal', summary['attempts'][0]['reason'])
                wait_for(lambda: not alive(int(pidfile.read_text())))
                self.assertIsNone(unrelated.poll()); self.assertNotIn(smoke.DDS_FAILURE.encode(), output)
            finally:
                if process.poll() is None: os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
                if pidfile.exists() and alive(int(pidfile.read_text())): os.kill(int(pidfile.read_text()), signal.SIGKILL)
                unrelated.kill(); unrelated.wait(timeout=2)

    def test_real_sigterm_cleans_owned_group_and_preserves_unrelated_process(self):
        self.check_signal(signal.SIGTERM)

    def test_real_sigint_cleans_owned_group_and_preserves_unrelated_process(self):
        self.check_signal(signal.SIGINT)

    def test_real_signal_during_context_cancels_owned_capture_groups_and_keeps_primary(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); pids = folder / 'pids'; pids.mkdir()
            adb = folder / 'adb'
            adb.write_text('#!' + sys.executable + '\nimport os,pathlib,time\n'
                'pathlib.Path(os.environ["SMOKE_SYNTHETIC_PIDS"],str(os.getpid())).touch()\n'
                'print("PRIVATE_SENTINEL",flush=True)\ntime.sleep(60)\n')
            adb.chmod(0o700)
            driver = folder / 'driver.py'
            driver.write_text('''import sys,pathlib
sys.path.insert(0,sys.argv[1])
import test_android_flutter_smoke as s
state=s.Cancellation()
def runner(cmd,path,**kw):
 return s.stream_attempt([sys.executable,'-u','-c',f'print({s.DDS_FAILURE!r},flush=True);raise SystemExit(1)'],path,timeout=30,**kw)
with s.cancellation_handlers(state):
 result=s.run_smoke('emulator-5554',pathlib.Path(sys.argv[2]),runner=runner,cancellation=state,ownership=lambda *a,**k:True,cleanup_app=lambda *a,**k:{'returncode':0},pause=lambda _:None)
raise SystemExit(result)
''')
            environment = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'],
                               SMOKE_SYNTHETIC_PIDS=str(pids))
            process = subprocess.Popen([sys.executable, str(driver), str(Path(smoke.__file__).parent), str(folder / 'out')],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                wait_for(lambda: len(list(pids.iterdir())) == 5)
                started = time.monotonic(); process.send_signal(signal.SIGTERM)
                output = process.communicate(timeout=4)[0]
                self.assertLess(time.monotonic() - started, 3)
                # The actual earlier child failure remains authoritative.
                self.assertEqual(1, process.returncode)
                summary = json.loads((folder / 'out/summary.json').read_text())
                self.assertEqual(1, len(summary['attempts']))
                attempt = summary['attempts'][0]
                self.assertEqual(1, attempt['child_returncode']); self.assertEqual(signal.SIGTERM, attempt['observed_signal'])
                self.assertTrue(all(item['cancelled'] for item in attempt['context'].values()))
                for pid in pids.iterdir(): wait_for(lambda: not alive(int(pid.name)))
                self.assertNotIn(b'PRIVATE_SENTINEL', output); self.assertNotIn(smoke.DDS_FAILURE.encode(), output)
            finally:
                if process.poll() is None: os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
                process.stdout.close()
                for pid in pids.iterdir():
                    if alive(int(pid.name)): os.kill(int(pid.name), signal.SIGKILL)


if __name__ == '__main__':
    unittest.main()
