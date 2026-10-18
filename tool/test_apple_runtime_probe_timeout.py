import contextlib
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import run_apple_runtime_probe as probe


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
