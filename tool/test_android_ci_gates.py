#!/usr/bin/env python3
"""Mock-only orchestration controls; never launch an Android tool or child."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("android_ci_gates", Path(__file__).with_name("run_android_ci_gates.py"))
GATES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATES)
CI = {"CI": "true", "GITHUB_ACTIONS": "true", "ANDROID_SERIAL": "foreign-device"}


class FakeProcess:
    pid = 71001

    def __init__(self, waits):
        self.waits = iter(waits)
        self.calls = []

    def wait(self, timeout=None):
        self.calls.append(timeout)
        result = next(self.waits)
        if isinstance(result, BaseException):
            raise result
        if callable(result):
            return result()
        return result


class AndroidCIGatesTests(unittest.TestCase):
    def exercise(self, outcomes, *, environment=CI, serial="emulator-5554"):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            processes = [FakeProcess([code]) for code in outcomes]
            with mock.patch.object(GATES.subprocess, "Popen", side_effect=processes) as launch:
                result = GATES.run_gates(serial, Path("build/android-native-routing-preview"), output, environment=environment)
            report = json.loads(output.read_text())
            self.assertLessEqual(output.stat().st_size, 4096)
            return result, report, launch.call_args_list, processes

    def test_success_native_first_and_existing_command_scope(self):
        code, report, calls, processes = self.exercise([0, 0, 0])
        self.assertEqual(0, code)
        self.assertTrue(report["success"])
        self.assertEqual(["native", "flutter", "separate_uid"], [g["name"] for g in report["gates"]])
        self.assertEqual(["passed"] * 3, [g["status"] for g in report["gates"]])
        self.assertEqual([str(GATES.ROOT / "tool/test_android_security_emulator.sh"), "--no-capture", "--native-routing-preview", "build/android-native-routing-preview"], calls[0].args[0])
        self.assertEqual(["--serial", "emulator-5554"], calls[1].args[0][-2:])
        self.assertEqual(["--serial", "emulator-5554", "--output", str(GATES.ROOT / "build/android-separate-uid-results.json")], calls[2].args[0][-4:])
        for call, process in zip(calls, processes):
            self.assertEqual("emulator-5554", call.kwargs["env"]["ANDROID_SERIAL"])
            self.assertEqual(GATES.ROOT, call.kwargs["cwd"])
            self.assertTrue(call.kwargs["start_new_session"])
            self.assertNotIn("shell", call.kwargs)
            self.assertEqual([0.25], process.calls)
        self.assertEqual("foreign-device", CI["ANDROID_SERIAL"])

    def test_native_failure_does_not_hide_other_mandatory_gates(self):
        code, report, calls, _ = self.exercise([7, 0, 0])
        self.assertEqual(1, code)
        self.assertFalse(report["success"])
        self.assertEqual(3, len(calls))
        self.assertEqual([7, 0, 0], [g["exit_code"] for g in report["gates"]])
        self.assertEqual(["failed", "passed", "passed"], [g["status"] for g in report["gates"]])

    def test_flutter_124_keeps_native_evidence_and_runs_uid(self):
        code, report, calls, _ = self.exercise([0, 124, 0])
        self.assertEqual(1, code)
        self.assertEqual(3, len(calls))
        self.assertEqual([0, 124, 0], [g["exit_code"] for g in report["gates"]])
        self.assertEqual("passed", report["gates"][0]["status"])
        self.assertEqual("native", report["gates"][0]["name"])

    def test_all_failures_keep_exact_independent_codes(self):
        code, report, calls, _ = self.exercise([3, 124, 9])
        self.assertEqual(1, code)
        self.assertEqual(3, len(calls))
        self.assertEqual([3, 124, 9], [g["exit_code"] for g in report["gates"]])
        self.assertEqual(["failed"] * 3, [g["status"] for g in report["gates"]])

    def test_launch_failure_is_redacted_and_other_gates_run(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            with mock.patch.object(GATES.subprocess, "Popen", side_effect=[OSError("SECRET-CANARY"), FakeProcess([0]), FakeProcess([0])]) as launch:
                self.assertEqual(1, GATES.run_gates("emulator-5554", Path("preview"), output, environment=CI))
            report = json.loads(output.read_text())
            self.assertEqual(3, launch.call_count)
            self.assertEqual({"name": "native", "status": "launch_failed", "exit_code": None}, report["gates"][0])
            self.assertNotIn("SECRET", output.read_text())

    def test_wait_error_reaps_started_child_before_other_gates(self):
        process = FakeProcess([OSError("SECRET-WAIT-CANARY"), -signal.SIGKILL])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            with mock.patch.object(GATES.subprocess, "Popen", side_effect=[process, FakeProcess([0]), FakeProcess([0])]) as launch, mock.patch.object(GATES.os, "killpg") as kill:
                self.assertEqual(1, GATES.run_gates("emulator-5554", Path("preview"), output, environment=CI))
            kill.assert_called_once_with(process.pid, signal.SIGKILL)
            self.assertEqual([.25, None], process.calls)
            self.assertEqual(3, launch.call_count)
            self.assertEqual({"name": "native", "status": "wait_failed", "exit_code": -signal.SIGKILL}, json.loads(output.read_text())["gates"][0])
            self.assertNotIn("SECRET", output.read_text())

    def test_child_interrupt_does_not_start_later_gates(self):
        for result in [-signal.SIGINT, -signal.SIGTERM, 130, 143]:
            with self.subTest(result=result):
                code, report, calls, _ = self.exercise([result])
                self.assertEqual(128 - result if result < 0 else result, code)
                self.assertEqual(1, len(calls))
                self.assertEqual(result, report["gates"][0]["exit_code"])
                self.assertEqual(["interrupted", "not_run", "not_run"], [g["status"] for g in report["gates"]])

    def test_real_signal_is_forwarded_and_inner_cleanup_reaped(self):
        handlers = {}
        previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        for number in [signal.SIGINT, signal.SIGTERM]:
            with self.subTest(number=number), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "result.json"
                def interrupted():
                    handlers[number](number, None)
                    raise subprocess.TimeoutExpired("fake", .25)
                process = FakeProcess([interrupted, 130])
                with mock.patch.object(GATES.signal, "signal", side_effect=lambda n, h: handlers.__setitem__(n, h)), mock.patch.object(GATES.subprocess, "Popen", return_value=process) as launch, mock.patch.object(GATES.os, "killpg") as kill:
                    self.assertEqual(128 + number, GATES.run_gates("emulator-5554", Path("preview"), output, environment=CI))
                self.assertEqual(1, launch.call_count)
                # The UID Python harness has finally cleanup and no TERM
                # handler. Cooperative INT preserves that cleanup for either
                # parent cancellation, while the aggregate keeps the parent
                # signal and the gate keeps its actual child exit code.
                kill.assert_called_once_with(process.pid, signal.SIGINT)
                self.assertEqual([.25, GATES.CANCEL_GRACE_SECONDS], process.calls)
                self.assertEqual(previous, handlers)
                self.assertEqual({"name": "native", "status": "interrupted", "exit_code": 130}, json.loads(output.read_text())["gates"][0])

    def test_cancel_grace_is_bounded_then_owned_child_reaped(self):
        process = FakeProcess([subprocess.TimeoutExpired("fake", 30), -signal.SIGKILL])
        state = GATES._Cancellation()
        def after_spawn(*args, **kwargs):
            state.signum = signal.SIGTERM
            return process
        with mock.patch.object(GATES.subprocess, "Popen", side_effect=after_spawn), mock.patch.object(GATES.os, "killpg") as kill:
            self.assertEqual(-signal.SIGKILL, GATES._execute(["inert"], CI, state))
        self.assertEqual([GATES.CANCEL_GRACE_SECONDS, None], process.calls)
        self.assertEqual([mock.call(process.pid, signal.SIGINT), mock.call(process.pid, signal.SIGKILL)], kill.call_args_list)
        self.assertIsNone(state.process)

    def test_keyboard_interrupt_stops_and_reaps(self):
        process = FakeProcess([KeyboardInterrupt(), 130])
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(GATES.subprocess, "Popen", return_value=process) as launch, mock.patch.object(GATES.os, "killpg") as kill:
            self.assertEqual(130, GATES.run_gates("emulator-5554", Path("preview"), Path(directory) / "result.json", environment=CI))
        self.assertEqual(1, launch.call_count)
        kill.assert_called_once_with(process.pid, signal.SIGINT)

    def test_no_github_ci_refuses_before_output_or_process(self):
        for environment in [{}, {"CI": "true"}, {"GITHUB_ACTIONS": "true"}, {"CI": "false", "GITHUB_ACTIONS": "true"}]:
            with self.subTest(environment=environment), tempfile.TemporaryDirectory() as directory, mock.patch.object(GATES.subprocess, "Popen") as launch:
                output = Path(directory) / "result.json"
                with self.assertRaisesRegex(ValueError, "github-ci-required"):
                    GATES.run_gates("emulator-5554", Path("preview"), output, environment=environment)
                launch.assert_not_called()
                self.assertFalse(output.exists())

    def test_physical_or_missing_serial_refused_before_process(self):
        for serial in ["", "R58M123ABC", "192.0.2.1:5555", "emulator-5554\n", "emulator-secret"]:
            with self.subTest(serial=serial), tempfile.TemporaryDirectory() as directory, mock.patch.object(GATES.subprocess, "Popen") as launch:
                with self.assertRaisesRegex(ValueError, "dedicated-emulator-required"):
                    GATES.run_gates(serial, Path("preview"), Path(directory) / "result.json", environment=CI)
                launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
