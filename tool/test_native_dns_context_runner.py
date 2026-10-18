#!/usr/bin/env python3
"""Runner guards and harmless subprocess lifecycle only; never starts Core."""
import importlib.util
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
        return results, (directory / 'synthetic.log').read_text()

    def test_output_retained_on_success(self):
        results, output = self.harmless('print("synthetic success",flush=True)', 5)
        self.assertEqual(results[0]['exit_code'], 0)
        self.assertIn('synthetic success', output)

    def test_nonzero_is_not_masked_by_output_capture(self):
        results, output = self.harmless('print("synthetic failure",flush=True); raise SystemExit(9)', 5)
        self.assertEqual(results[0]['exit_code'], 9)
        self.assertIn('synthetic failure', output)

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
