import json
import stat
import subprocess
import tempfile
from pathlib import Path
import unittest
from test_android_flutter_smoke import (
    DDS_FAILURE, MAX_CONTEXT_BYTES, TEST_ENTRY, collect_failure_context, run_smoke,
)


class SmokeRetryTest(unittest.TestCase):
    def check_case(self, responses, expected_code, expected_calls):
        calls = []
        collected = []
        def run(command, **kwargs):
            calls.append(command)
            code, output = responses[len(calls) - 1]
            return subprocess.CompletedProcess(command, code, output)
        with tempfile.TemporaryDirectory() as folder:
            code = run_smoke('emulator-fixture', Path(folder), run=run, pause=lambda _: None,
                             collect=lambda serial, output, attempt: collected.append(attempt))
            self.assertEqual(expected_code, code)
            self.assertEqual(expected_calls, len(calls))
            self.assertEqual(expected_calls, len(list(Path(folder).glob('*.log'))))
            self.assertEqual([index for index, (status, _) in enumerate(responses[:expected_calls], 1)
                              if status != 0], collected)
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600
                                for path in Path(folder).glob('*.log')))

    def test_retries_only_pre_test_dds_startup(self):
        self.check_case([(1, DDS_FAILURE), (0, 'ANDROID_XRAY_CORE_VERSION=26.10.17\nPASS')], 0, 2)

    def test_never_retries_an_assertion_or_runtime_failure(self):
        self.check_case([(1, 'ANDROID_XRAY_CORE_VERSION=wrong\nAssertion failed')], 1, 1)
        self.check_case([(1, 'ANDROID_XRAY_CORE_VERSION=wrong\n' + DDS_FAILURE)], 1, 1)
        self.check_case([(1, TEST_ENTRY + '\n' + DDS_FAILURE)], 1, 1)
        self.check_case([(1, "loading smoke_test.dart (failed)\nInstance of 'VmServiceDisappearedException'")], 1, 1)
        self.check_case([(2, 'Tool unavailable')], 2, 1)

    def test_startup_retry_is_bounded(self):
        self.check_case([(1, DDS_FAILURE), (1, DDS_FAILURE)], 1, 2)

    def test_failure_context_is_bounded_private_and_read_only(self):
        calls = []
        def run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, b'prefix' + b'x' * MAX_CONTEXT_BYTES)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            collect_failure_context('emulator-fixture', output, 1, run=run)
            self.assertEqual(3, len(calls))
            for command, kwargs in calls:
                self.assertEqual(['adb', '-s', 'emulator-fixture'], command[:3])
                self.assertEqual(10, kwargs['timeout'])
                self.assertNotIn('-c', command)
                self.assertNotIn('force-stop', command)
            for path in output.glob('*.log'):
                self.assertEqual(MAX_CONTEXT_BYTES, path.stat().st_size)
                self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            context = json.loads((output / 'flutter-smoke-1-context.json').read_text())
            self.assertEqual({'crash', 'logcat', 'exit-info'}, set(context))
            self.assertTrue(all(value['truncated'] for value in context.values()))

    def test_context_timeout_and_missing_adb_are_recorded(self):
        responses = iter([subprocess.TimeoutExpired('adb', 10, output=b'partial crash'),
                          FileNotFoundError('adb unavailable'),
                          subprocess.CompletedProcess('adb', 1, b'disconnected')])
        def run(command, **kwargs):
            response = next(responses)
            if isinstance(response, Exception):
                raise response
            return response
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            collect_failure_context('emulator-fixture', output, 2, run=run)
            context = json.loads((output / 'flutter-smoke-2-context.json').read_text())
            self.assertEqual('timeout', context['crash']['error'])
            self.assertEqual('FileNotFoundError', context['logcat']['error'])
            self.assertEqual(1, context['exit-info']['returncode'])
            self.assertEqual(b'partial crash', (output / 'flutter-smoke-2-crash.log').read_bytes())

    def test_context_write_failure_preserves_smoke_failure(self):
        def run(command, **kwargs):
            return subprocess.CompletedProcess(command, 17, 'Native startup failed')
        def collect(*arguments):
            raise OSError('read-only artifact directory')
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(17, run_smoke('emulator-fixture', Path(folder), run=run,
                                          collect=collect, pause=lambda _: None))

    def test_refuses_physical_device(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                run_smoke('physical-device', Path(folder), run=lambda *args, **kwargs: self.fail())


if __name__ == '__main__':
    unittest.main()
