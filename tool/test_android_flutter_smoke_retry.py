import subprocess
import tempfile
from pathlib import Path
import unittest
from test_android_flutter_smoke import DDS_FAILURE, run_smoke


class SmokeRetryTest(unittest.TestCase):
    def check_case(self, responses, expected_code, expected_calls):
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            code, output = responses[len(calls) - 1]
            return subprocess.CompletedProcess(command, code, output)
        with tempfile.TemporaryDirectory() as folder:
            code = run_smoke('emulator-fixture', Path(folder), run=run, pause=lambda _: None)
            self.assertEqual(expected_code, code)
            self.assertEqual(expected_calls, len(calls))
            self.assertEqual(expected_calls, len(list(Path(folder).glob('*.log'))))

    def test_retries_only_pre_test_dds_startup(self):
        self.check_case([(1, DDS_FAILURE), (0, 'ANDROID_XRAY_CORE_VERSION=26.10.17\nPASS')], 0, 2)

    def test_never_retries_an_assertion_or_runtime_failure(self):
        self.check_case([(1, 'ANDROID_XRAY_CORE_VERSION=wrong\nAssertion failed')], 1, 1)
        self.check_case([(1, 'ANDROID_XRAY_CORE_VERSION=wrong\n' + DDS_FAILURE)], 1, 1)
        self.check_case([(2, 'Tool unavailable')], 2, 1)

    def test_startup_retry_is_bounded(self):
        self.check_case([(1, DDS_FAILURE), (1, DDS_FAILURE)], 1, 2)


if __name__ == '__main__':
    unittest.main()
