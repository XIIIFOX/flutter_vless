#!/usr/bin/env python3
"""Runner guards and harmless subprocess lifecycle only; never starts Core."""
import importlib.util
import io
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('native_dns_runner', Path(__file__).with_name('test_native_dns_context_runtime.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ErroringSink:
    """Fail one real sink operation without affecting the child pipe."""
    def __init__(self, wrapped, operation, trigger='synthetic child'):
        self.wrapped = wrapped
        self.operation = operation
        self.trigger = trigger
        self.triggered = False

    @property
    def encoding(self):
        return getattr(self.wrapped, 'encoding', None)

    def write(self, value):
        self.triggered = self.triggered or self.trigger in value
        if self.triggered and self.operation == 'write':
            raise OSError('synthetic write failure')
        return self.wrapped.write(value)

    def flush(self):
        if self.triggered and self.operation == 'flush':
            raise OSError('synthetic flush failure')
        return self.wrapped.flush()

    def close(self):
        self.wrapped.close()
        if self.operation == 'close':
            raise OSError('synthetic close failure')


class RunnerGuards(unittest.TestCase):
    def test_runtime_requires_ci(self):
        self.assertFalse(runner.runtime_authorized({}, 'Linux'))
        self.assertTrue(runner.runtime_authorized({'CI': 'true'}, 'Linux'))
        self.assertTrue(runner.runtime_authorized({'CI': 'true'}, 'Windows'))

    def test_darwin_requires_github_actions_too(self):
        self.assertFalse(runner.runtime_authorized({'CI': 'true'}, 'Darwin'))
        self.assertFalse(runner.runtime_authorized({'GITHUB_ACTIONS': 'true'}, 'Darwin'))
        self.assertTrue(runner.runtime_authorized({'CI': 'true', 'GITHUB_ACTIONS': 'true'}, 'Darwin'))

    def test_runtime_pass_requires_exact_selected_test(self):
        for output in ['PASS\n', 'testing: warning: no tests to run\nPASS\n',
                       '--- PASS: WrongTest (0.00s)\nPASS\n',
                       '--- FAIL: TestAcceptanceNativeDNSRuntime (0.00s)\nPASS\n']:
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                runner.require_selected_test_pass(output, 'TestAcceptanceNativeDNSRuntime')
        runner.require_selected_test_pass('--- PASS: TestAcceptanceNativeDNSRuntime (0.00s)\nPASS\n', 'TestAcceptanceNativeDNSRuntime')

    def harmless(self, program, seconds):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        results = []
        with mock.patch.object(runner, 'EVIDENCE', directory):
            try:
                runner.checked('synthetic', [sys.executable, '-c', program], cwd=directory,
                               environment=dict(os.environ), seconds=seconds, results=results)
            except RuntimeError:
                pass
        return results, (directory / 'synthetic.log').read_text(encoding='utf-8')

    def test_output_retained_on_success(self):
        results, output = self.harmless('print("synthetic success",flush=True)', 5)
        self.assertEqual(results[0]['exit_code'], 0)
        self.assertEqual(results[0]['output_errors'], [])
        self.assertTrue(results[0]['output_eof'])
        self.assertIn('synthetic success', output)

    def test_cp1252_console_retains_complete_utf8_artifact(self):
        message = 'synthetic child: DNS → Пример ☃\nsecond 日本語 ✓\ncomplete\n'
        console_bytes = io.BytesIO()
        console = io.TextIOWrapper(console_bytes, encoding='cp1252', errors='strict', write_through=True)
        try:
            program = f'import sys; sys.stdout.buffer.write({message.encode("utf-8")!r}); sys.stdout.buffer.flush()'
            with mock.patch.object(runner.sys, 'stdout', console):
                results, output = self.harmless(program, 5)
            self.assertEqual(results[0]['exit_code'], 0)
            self.assertTrue(results[0]['output_eof'])
            self.assertTrue(results[0]['output_closed'])
            self.assertEqual(results[0]['output_errors'], [])
            self.assertEqual(output, message)
            rendered = console_bytes.getvalue().decode('cp1252')
            self.assertIn(message.encode('cp1252', errors='backslashreplace').decode('cp1252'), rendered)
            self.assertIn('PHASE synthetic: PASS (0)', rendered)
        finally:
            console.close()

    def test_console_io_failure_fails_phase_but_keeps_full_artifact(self):
        # Larger than a pipe buffer: stopping at the failed sink would block
        # the child's exit instead of recording the final marker and EOF.
        program = ('import sys; sys.stdout.buffer.write(b"synthetic child\\n" + b"x" * 262144 + '
                   'b"\\ncomplete\\n"); sys.stdout.buffer.flush()')
        for operation in ['write', 'flush']:
            with self.subTest(operation=operation):
                captured = io.StringIO()
                console = ErroringSink(captured, operation)
                with mock.patch.object(runner.sys, 'stdout', console):
                    results, output = self.harmless(program, 5)
                result = results[0]
                self.assertEqual(result['exit_code'], 126)
                self.assertEqual(result['process_exit_code'], 0)
                self.assertFalse(result['timed_out'])
                self.assertTrue(result['output_eof'])
                self.assertTrue(result['output_closed'])
                self.assertEqual([(item['sink'], item['operation']) for item in result['output_errors']],
                                 [('console', 'write/flush')])
                self.assertEqual(output, 'synthetic child\n' + 'x' * 262144 + '\ncomplete\n')
                self.assertNotIn('PHASE synthetic: PASS', captured.getvalue())

    def test_log_io_failure_fails_phase_but_still_drains_child(self):
        program = ('import sys; sys.stdout.buffer.write(b"synthetic child\\n" + b"x" * 262144 + '
                   'b"\\ncomplete\\n"); sys.stdout.buffer.flush()')
        real_open = Path.open
        for operation in ['write', 'flush', 'close']:
            with self.subTest(operation=operation):
                captured = io.StringIO()

                def erroring_open(path, *args, **kwargs):
                    opened = real_open(path, *args, **kwargs)
                    if path.name == 'synthetic.log' and args and args[0] == 'w':
                        return ErroringSink(opened, operation)
                    return opened

                with mock.patch.object(Path, 'open', erroring_open), mock.patch.object(runner.sys, 'stdout', captured):
                    results, _ = self.harmless(program, 5)
                result = results[0]
                self.assertEqual(result['exit_code'], 126)
                self.assertEqual(result['process_exit_code'], 0)
                self.assertFalse(result['timed_out'])
                self.assertTrue(result['output_eof'])
                self.assertTrue(result['output_closed'])
                self.assertEqual([(item['sink'], item['operation']) for item in result['output_errors']],
                                 [('log', 'close' if operation == 'close' else 'write/flush')])
                self.assertIn('synthetic child\n' + 'x' * 262144 + '\ncomplete\n', captured.getvalue())
                self.assertIn('PHASE synthetic: FAIL (126)', captured.getvalue())

    def test_final_console_failure_cannot_leave_success_result(self):
        console = ErroringSink(io.StringIO(), 'write', trigger='PHASE synthetic: PASS')
        with mock.patch.object(runner.sys, 'stdout', console):
            results, output = self.harmless('print("complete",flush=True)', 5)
        self.assertEqual(results[0]['exit_code'], 126)
        self.assertEqual(results[0]['process_exit_code'], 0)
        self.assertTrue(results[0]['output_eof'])
        self.assertEqual(results[0]['output_errors'][0]['sink'], 'console')
        self.assertEqual(output, 'complete\n')

    def test_log_open_failure_is_recorded_and_child_drained(self):
        real_open = Path.open

        def erroring_open(path, *args, **kwargs):
            if path.name == 'synthetic.log' and args and args[0] == 'w':
                raise OSError('synthetic log open failure')
            return real_open(path, *args, **kwargs)

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        results = []
        console = io.StringIO()
        with (mock.patch.object(runner, 'EVIDENCE', directory),
              mock.patch.object(Path, 'open', erroring_open),
              mock.patch.object(runner.sys, 'stdout', console)):
            with self.assertRaises(RuntimeError):
                runner.checked('synthetic', [sys.executable, '-c', 'print("complete",flush=True)'],
                               cwd=directory, environment=dict(os.environ), seconds=5, results=results)
        self.assertEqual(results[0]['exit_code'], 126)
        self.assertEqual(results[0]['process_exit_code'], 0)
        self.assertTrue(results[0]['output_closed'])
        self.assertTrue(results[0]['output_eof'])
        self.assertEqual(results[0]['output_errors'][0]['operation'], 'open')
        self.assertIn('complete\n', console.getvalue())
        self.assertIn('PHASE synthetic: FAIL (126)', console.getvalue())

    def test_reader_failure_is_not_mistaken_for_eof(self):
        real_popen = subprocess.Popen

        class ErroringReader:
            def __init__(self, wrapped):
                self.wrapped = wrapped

            def __iter__(self):
                yield next(self.wrapped)
                raise OSError('synthetic pipe read failure')

            def close(self):
                self.wrapped.close()

            @property
            def closed(self):
                return self.wrapped.closed

        def erroring_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            process.stdout = ErroringReader(process.stdout)
            return process

        with mock.patch.object(runner.subprocess, 'Popen', erroring_popen), mock.patch.object(runner.sys, 'stdout', io.StringIO()):
            results, output = self.harmless('print("synthetic child",flush=True); print("not consumed",flush=True)', 5)
        self.assertEqual(results[0]['exit_code'], 126)
        self.assertEqual(results[0]['process_exit_code'], 0)
        self.assertFalse(results[0]['output_eof'])
        self.assertFalse(results[0]['output_closed'])
        self.assertEqual(results[0]['output_errors'][0]['operation'], 'read')
        self.assertEqual(output, 'synthetic child\n')

    def test_nonzero_is_not_masked_by_output_capture(self):
        results, output = self.harmless('print("synthetic failure",flush=True); raise SystemExit(9)', 5)
        self.assertEqual(results[0]['exit_code'], 9)
        self.assertIn('synthetic failure', output)

    def test_sink_failure_keeps_nonzero_child_status(self):
        console = ErroringSink(io.StringIO(), 'write')
        with mock.patch.object(runner.sys, 'stdout', console):
            results, output = self.harmless('print("synthetic child",flush=True); raise SystemExit(9)', 5)
        self.assertEqual(results[0]['exit_code'], 9)
        self.assertEqual(results[0]['process_exit_code'], 9)
        self.assertTrue(results[0]['output_eof'])
        self.assertEqual(results[0]['output_errors'][0]['sink'], 'console')
        self.assertIn('synthetic child', output)

    def test_main_records_sink_failure_in_result_json(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        checked = runner.checked
        console = ErroringSink(io.StringIO(), 'write')

        def harmless_first_phase(name, command, **kwargs):
            return checked(name, [sys.executable, '-c', 'print("synthetic child",flush=True)'], **kwargs)

        with (mock.patch.object(runner, 'EVIDENCE', directory),
              mock.patch.object(runner, 'checked', harmless_first_phase),
              mock.patch.object(runner.sys, 'argv', ['synthetic-runner']),
              mock.patch.object(runner.sys, 'stdout', console),
              mock.patch.object(runner.sys, 'stderr', io.StringIO()),
              mock.patch.object(runner.subprocess, 'run', side_effect=AssertionError('Must fail before Go or runtime'))):
            status = runner.main()
        report = json.loads((directory / 'result.json').read_text(encoding='utf-8'))
        self.assertEqual(status, 1)
        self.assertFalse(report['success'])
        self.assertFalse(report['runtime_requested'])
        self.assertEqual(len(report['results']), 1)
        self.assertEqual(report['results'][0]['exit_code'], 126)
        self.assertEqual(report['results'][0]['process_exit_code'], 0)
        self.assertTrue(report['results'][0]['output_eof'])
        self.assertEqual(report['results'][0]['output_errors'][0]['sink'], 'console')
        self.assertIn('failed with status 126', report['error'])

    def test_timeout_stops_only_owned_harmless_child(self):
        results, _ = self.harmless('import time; time.sleep(20)', 0.1)
        self.assertEqual(results[0]['exit_code'], 124)
        self.assertTrue(results[0]['timed_out'])
        self.assertLess(results[0]['elapsed_seconds'], 5)

    @unittest.skipIf(os.name == 'nt', 'Unix process-group lifecycle; runtime fixture has no Windows descendants')
    def test_finished_leader_owned_grandchild_pipe_is_closed(self):
        # An unrelated sentinel is owned by this test in a different group.
        sentinel = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'],
                                    start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            program = ('import subprocess,sys; '
                       'subprocess.Popen([sys.executable,"-c","import time; print(\'owned descendant\',flush=True); time.sleep(20)"]); '
                       'print("leader done",flush=True)')
            with mock.patch.object(runner, 'OUTPUT_JOIN_SECONDS', 0.2):
                results, output = self.harmless(program, 5)
            self.assertEqual(results[0]['exit_code'], 125)
            self.assertTrue(results[0]['output_closed'])
            self.assertFalse(results[0]['timed_out'])
            self.assertLess(results[0]['elapsed_seconds'], 3)
            self.assertIn('owned descendant', output)
            self.assertIsNone(sentinel.poll(), 'Cleanup stopped an unrelated process group')
        finally:
            sentinel.terminate()
            sentinel.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
