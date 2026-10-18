import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import capture_android_emulator_failure as collector
from capture_android_emulator_failure import capture, collect, TEST_PACKAGE


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tool/test_android_security_emulator.sh"
FAKE_ADB = r'''#!/usr/bin/env python3
import json, os, signal, sys, time
from pathlib import Path
args = sys.argv[1:]
with Path(os.environ['FAKE_ADB_CALLS']).open('a') as log:
    log.write(json.dumps(args) + '\n')
mode = os.environ.get('FAKE_ADB_MODE', '')
if 'logcat' in args or 'exit-info' in args:
    if mode == 'flood':
        sys.stdout.buffer.write(b'private-context-' * 80000)
    elif mode == 'hang' and 'crash' in args:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        print('partial-private-crash', flush=True)
        time.sleep(60)
    elif mode == 'fail' and 'crash' in args:
        print('private-crash-canary', file=sys.stderr)
        sys.exit(17)
    else:
        print('private-context-canary')
elif 'always_on_vpn_app' in args:
    print(os.environ.get('FAKE_ALWAYS_ON_OWNER', 'null'))
else:
    print('OK')
'''


class AndroidFailureCaptureTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.base = Path(self.folder.name)
        self.adb = self.base / "fake-adb"
        self.adb.write_text(FAKE_ADB)
        self.adb.chmod(0o700)
        self.calls = self.base / "calls.jsonl"
        self.output = self.base / "artifacts"
        self.output.mkdir(mode=0o700)
        self.previous = {key: os.environ.get(key) for key in
                         ("FAKE_ADB_CALLS", "FAKE_ADB_MODE", "FAKE_ALWAYS_ON_OWNER")}
        os.environ["FAKE_ADB_CALLS"] = str(self.calls)
        os.environ.pop("FAKE_ADB_MODE", None)
        os.environ.pop("FAKE_ALWAYS_ON_OWNER", None)
        self.addCleanup(self.restore_environment)

    def restore_environment(self):
        for key, value in self.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def recorded_calls(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def run_collector(self, **kwargs):
        return collect(self.adb, "emulator-5554", TEST_PACKAGE, self.output,
                       "system-vpn-policy", **kwargs)

    def test_real_subprocess_capture_is_read_only_bounded_and_private(self):
        os.environ["FAKE_ADB_MODE"] = "flood"
        report = self.run_collector(max_bytes=113)
        self.assertTrue(report["complete"])
        self.assertEqual("system-vpn-policy", report["phase"])
        self.assertEqual(3, len(self.recorded_calls()))
        for item in report["captures"]:
            self.assertEqual(0, item["returncode"])
            self.assertTrue(item["truncated"])
            self.assertFalse(item["timed_out"])
            self.assertEqual(113, item["bytes_written"])
            self.assertEqual(113, (self.output / item["file"]).stat().st_size)
        for path in self.output.iterdir():
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        for args in self.recorded_calls():
            self.assertEqual(["-s", "emulator-5554"], args[:2])
            self.assertNotIn("-c", args)
            self.assertNotIn("force-stop", args)
            self.assertNotIn("uninstall", args)
        self.assertEqual(["logcat", "-b", "crash", "-d", "-t", "400"], self.recorded_calls()[0][2:])
        self.assertEqual(["logcat", "-b", "main", "-b", "system", "-d", "-t", "1000"], self.recorded_calls()[1][2:])
        self.assertEqual(["shell", "dumpsys", "activity", "exit-info", TEST_PACKAGE], self.recorded_calls()[2][2:])

    def test_timeout_kills_only_its_subprocess_group_and_continues(self):
        os.environ["FAKE_ADB_MODE"] = "hang"
        report = self.run_collector(timeout=1)
        self.assertFalse(report["complete"])
        crash, logcat, exit_info = report["captures"]
        self.assertTrue(crash["timed_out"])
        self.assertEqual(-9, crash["returncode"])
        self.assertLess(crash["elapsed_seconds"], 3)
        self.assertEqual(b"partial-private-crash\n", (self.output / crash["file"]).read_bytes())
        self.assertEqual(0, logcat["returncode"])
        self.assertEqual(0, exit_info["returncode"])
        self.assertEqual(3, len(self.recorded_calls()))

    def test_individual_adb_failure_and_missing_executable_are_recorded(self):
        os.environ["FAKE_ADB_MODE"] = "fail"
        report = self.run_collector()
        self.assertFalse(report["complete"])
        self.assertEqual([17, 0, 0], [item["returncode"] for item in report["captures"]])
        missing_output = self.base / "missing-adb"
        missing_output.mkdir()
        missing = collect(self.base / "does-not-exist", "emulator-5554", TEST_PACKAGE,
                          missing_output, "native-authorization")
        self.assertFalse(missing["complete"])
        self.assertEqual(["FileNotFoundError"] * 3, [item["error"] for item in missing["captures"]])

    def test_refuses_physical_device_and_another_package_without_any_subprocess(self):
        for serial, package in (("physical-device", TEST_PACKAGE), ("emulator-5554", "other.package")):
            with self.assertRaises(ValueError):
                collect(self.adb, serial, package, self.output, "preflight")
        self.assertFalse(self.calls.exists())
        self.assertEqual([], list(self.output.iterdir()))

    def run_actual_cleanup(self, code, *, installed=1, validated=1, browser_owned=False, tun_requested=False,
                           tun_wifi_restore=False):
        # Exercise the actual production cleanup and timeout functions without
        # sourcing the harness preflight/build/device actions.
        source = HARNESS.read_text()
        bounded = source[source.index("bounded() {"):source.index("\nstart_capture() {")]
        cleanup = source[source.index("cleanup() {"):source.index("\ntrap cleanup EXIT")]
        (self.output / "checks.tsv").write_text("")
        variables = {
            "ROOT_DIR": str(ROOT), "OUT_DIR": str(self.output), "ADB": str(self.adb),
            "SERIAL": "emulator-5554", "PACKAGE": TEST_PACKAGE,
            "ADVERSARY_PACKAGE": "com.github.tfox.flutter_vless.adversary",
            "PHASE": "complete" if code == 0 else "system-vpn-policy",
            "CAPTURE_DNS": "1", "CAPTURE_STARTED": "0", "CAPTURE_WIFI_DISABLED": "0",
            "NATIVE_TUN_PREVIEW": "/verified-preview" if tun_requested else "",
            "TUN_BROWSER_OWNED": "1" if browser_owned else "0",
            "TUN_WIFI_RESTORE": "1" if tun_wifi_restore else "0",
            "TEST_INSTALLED": str(installed), "EMULATOR_VALIDATED": str(validated),
            "ADVERSARY_INSTALLED": "1", "FIXTURE_PID": "", "DNS_PID": "",
        }
        script = "set -u\n" + "\n".join(f"{key}={shlex.quote(value)}" for key, value in variables.items())
        script += "\n" + bounded + "\n" + cleanup + f"\ntrap cleanup EXIT\nexit {code}\n"
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=15)

    def test_browser_cleanup_requires_explicit_fixture_ownership(self):
        for owned in (False, True):
            with self.subTest(owned=owned):
                self.output = self.base / ('browser-owned-' + str(owned))
                self.output.mkdir(mode=0o700)
                self.calls.unlink(missing_ok=True)
                result = self.run_actual_cleanup(37, browser_owned=owned, tun_requested=True)
                self.assertEqual(37, result.returncode, result.stderr)
                browser_stops = [args for args in self.recorded_calls()
                                 if args[2:] == ['shell', 'am', 'force-stop', 'com.android.chrome']]
                self.assertEqual(1 if owned else 0, len(browser_stops))
                report = json.loads((self.output / 'summary.json').read_text())
                self.assertTrue(report['native_tun_preview_requested'])
                self.assertFalse(report['native_tun_preview_verified'])

    def test_tun_handover_crash_restores_wifi_after_stopping_instrumentation(self):
        result = self.run_actual_cleanup(37, tun_requested=True, tun_wifi_restore=True)
        self.assertEqual(37, result.returncode, result.stderr)
        calls = self.recorded_calls()
        stop = calls.index(['-s', 'emulator-5554', 'shell', 'am', 'force-stop', TEST_PACKAGE])
        enable = calls.index(['-s', 'emulator-5554', 'shell', 'svc', 'wifi', 'enable'])
        connect = calls.index(['-s', 'emulator-5554', 'shell', 'cmd', 'wifi', 'connect-network', 'AndroidWifi', 'open'])
        self.assertLess(stop, enable)
        self.assertLess(enable, connect)
        self.assertLess(0, stop)  # Primary capture still precedes destructive cleanup.

    def test_capture_precedes_force_stop_uninstall_and_preserves_original_failure(self):
        os.environ["FAKE_ADB_MODE"] = "fail"
        os.environ["FAKE_ALWAYS_ON_OWNER"] = TEST_PACKAGE
        result = self.run_actual_cleanup(37)
        self.assertEqual(37, result.returncode, result.stderr)
        calls = self.recorded_calls()
        self.assertTrue(all("logcat" in item or "exit-info" in item for item in calls[:3]))
        self.assertIn("force-stop", calls[3])
        self.assertIn(["-s", "emulator-5554", "uninstall", TEST_PACKAGE], calls)
        self.assertIn(["-s", "emulator-5554", "uninstall", "com.github.tfox.flutter_vless.adversary"], calls)
        report = json.loads((self.output / "failure-context.json").read_text())
        self.assertEqual([17, 0, 0], [item["returncode"] for item in report["captures"]])
        self.assertEqual(37, json.loads((self.output / "summary.json").read_text())["exit_code"])
        self.assertNotIn("private-crash-canary", result.stdout + result.stderr)
        self.assertNotIn("private-context-canary", result.stdout + result.stderr)

    def test_capture_write_failure_cannot_prevent_cleanup(self):
        # A conflicting context directory makes only the first capture fail.
        (self.output / "failure-context-crash.log").mkdir()
        result = self.run_actual_cleanup(23)
        self.assertEqual(23, result.returncode, result.stderr)
        self.assertTrue(any("force-stop" in args for args in self.recorded_calls()))
        self.assertTrue(any("uninstall" in args for args in self.recorded_calls()))
        report = json.loads((self.output / "failure-context.json").read_text())
        self.assertEqual("FileExistsError", report["captures"][0]["error"])
        self.assertEqual([0, 0], [item["returncode"] for item in report["captures"][1:]])

    def test_success_never_collects_failure_context(self):
        result = self.run_actual_cleanup(0)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse((self.output / "failure-context.json").exists())
        self.assertFalse(any("logcat" in args or "exit-info" in args for args in self.recorded_calls()))

    def test_failure_before_validation_or_install_skips_collection_but_cleans_up(self):
        for installed, validated in ((0, 1), (1, 0)):
            with self.subTest(installed=installed, validated=validated):
                if self.calls.exists():
                    self.calls.unlink()
                result = self.run_actual_cleanup(29, installed=installed, validated=validated)
                self.assertEqual(29, result.returncode, result.stderr)
                self.assertFalse(any("logcat" in args or "exit-info" in args for args in self.recorded_calls()))
                self.assertTrue(any("uninstall" in args for args in self.recorded_calls()))


def executing(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A killed orphan waiting for init is no longer an executing child.
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)],
                           capture_output=True, text=True, timeout=1).stdout.strip()
    return bool(state) and not state.startswith("Z")


def await_condition(predicate, seconds=3):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("Synthetic child did not reach the controlled boundary")


class CaptureOwnershipTest(unittest.TestCase):
    def test_short_output_write_records_actual_prefix_and_never_completes(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); output = folder / "out"; output.mkdir()
            adb = folder / "adb"
            adb.write_text("#!" + sys.executable + "\nprint('PRIVATE_PARTIAL',flush=True)\n")
            adb.chmod(0o700)
            original = os.fdopen
            class ShortWriter:
                def __init__(self, stream): self.stream = stream
                def __enter__(self): return self
                def __exit__(self, *args): return self.stream.__exit__(*args)
                def write(self, value): return self.stream.write(value[:-1])
            def opened(*args, **kwargs):
                stream = original(*args, **kwargs)
                return ShortWriter(stream) if args[1] == "wb" else stream
            with patch.object(collector.os, "fdopen", opened):
                report = collect(adb, "emulator-5554", TEST_PACKAGE, output, "synthetic-short-write")
            self.assertFalse(report["complete"])
            for item in report["captures"]:
                self.assertEqual("OSError", item["error"])
                self.assertGreater(item["bytes_written"], 0)
                self.assertEqual(item["bytes_written"], (output / item["file"]).stat().st_size)
                self.assertTrue(item["cleanup"]["leader_reaped"])
                self.assertTrue(item["cleanup"]["pipe_closed"])

    def test_selector_setup_failures_reap_owned_leader_and_descendant(self):
        # The second case proves cleanup even after the group's leader exits;
        # its independent descendant still owns the inherited stdout pipe.
        for phase, exited in [("create", False), ("register", False), ("register", True)]:
            with self.subTest(phase=phase, leader_exited=exited), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory); pidfile = folder / "pids.json"; processes = []
                real_popen = subprocess.Popen
                child = "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"
                code = ("import os,subprocess,sys,json,pathlib,time,signal;"
                        "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                        f"p=subprocess.Popen([sys.executable,'-c',{child!r}]);"
                        f"pathlib.Path({str(pidfile)!r}).write_text(json.dumps([os.getpid(),p.pid]));"
                        + ("raise SystemExit(0)" if exited else "time.sleep(60)"))
                def start(*args, **kwargs):
                    process = real_popen(*args, **kwargs); processes.append(process)
                    await_condition(pidfile.exists)
                    if exited:
                        await_condition(lambda: process.poll() is not None)
                    return process
                class BrokenSelector:
                    def register(self, *args):
                        raise OSError("synthetic-register-failure")
                    def close(self):
                        raise ValueError("secondary-selector-close-failure")
                def selector():
                    if phase == "create":
                        raise OSError("synthetic-selector-failure")
                    return BrokenSelector()
                try:
                    with patch.object(collector.subprocess, "Popen", start), \
                         patch.object(collector.selectors, "DefaultSelector", selector):
                        report = capture([sys.executable, "-u", "-c", code], folder / "capture.log", timeout=30)
                    self.assertEqual("OSError", report["error"])  # Primary, not selector.close.
                    self.assertTrue(report["cleanup"]["leader_reaped"])
                    self.assertTrue(report["cleanup"]["pipe_closed"])
                    for pid in json.loads(pidfile.read_text()):
                        await_condition(lambda pid=pid: not executing(pid))
                finally:
                    for process in processes:
                        try: os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                        process.wait(timeout=2)
                        process.stdout.close()

    def test_parent_exit_and_inherited_pipe_remain_under_capture_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); pidfile = folder / "child.pid"
            code = ("import subprocess,sys,pathlib;"
                    "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
                    f"pathlib.Path({str(pidfile)!r}).write_text(str(p.pid));print('partial',flush=True)")
            try:
                report = capture([sys.executable, "-u", "-c", code], folder / "capture.log", timeout=1)
                self.assertTrue(report["timed_out"]); self.assertEqual(0, report["returncode"])
                self.assertLess(report["elapsed_seconds"], 3)
                self.assertEqual(b"partial\n", (folder / "capture.log").read_bytes())
                await_condition(lambda: not executing(int(pidfile.read_text())))
            finally:
                if pidfile.exists() and executing(int(pidfile.read_text())):
                    os.kill(int(pidfile.read_text()), signal.SIGKILL)

    def test_cancellation_during_running_capture_drains_before_natural_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); path = folder / "capture.log"; cancelled = threading.Event(); outcome = []
            code = "import time;print('LIVE_PARTIAL',flush=True);time.sleep(60)"
            worker = threading.Thread(target=lambda: outcome.append(capture(
                [sys.executable, "-u", "-c", code], path, timeout=30, cancelled=cancelled.is_set)))
            worker.start()
            try:
                await_condition(lambda: path.exists() and b"LIVE_PARTIAL" in path.read_bytes())
                started = time.monotonic(); cancelled.set(); worker.join(2)
                self.assertFalse(worker.is_alive()); self.assertLess(time.monotonic() - started, 2)
                report = outcome[0]
                self.assertTrue(report["cancelled"]); self.assertFalse(report["timed_out"])
                self.assertTrue(report["cleanup"]["leader_reaped"])
                self.assertTrue(report["cleanup"]["pipe_closed"])
            finally:
                cancelled.set(); worker.join(3)

    def test_cancelled_before_spawn_never_creates_a_child(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(collector.subprocess, "Popen", side_effect=AssertionError("must not spawn")):
            report = capture(["synthetic"], Path(directory) / "capture.log", cancelled=lambda: True)
            self.assertTrue(report["cancelled"]); self.assertIsNone(report["returncode"])
            self.assertIsNone(report["cleanup"])

    def test_cli_sigterm_cleans_separate_diagnostic_group_and_preserves_signal(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); output = folder / "out"; output.mkdir(); pidfile = folder / "pids.json"
            adb = folder / "adb"
            child = "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"
            adb.write_text("#!" + sys.executable + "\nimport os,json,pathlib,signal,subprocess,sys,time\n"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                f"p=subprocess.Popen([sys.executable,'-c',{child!r}])\n"
                f"pathlib.Path({str(pidfile)!r}).write_text(json.dumps([os.getpid(),p.pid]))\n"
                "print('PRIVATE_PARTIAL',flush=True)\ntime.sleep(60)\n")
            adb.chmod(0o700)
            unrelated = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"])
            process = subprocess.Popen([sys.executable, str(Path(collector.__file__)), "--adb", str(adb),
                "--serial", "emulator-5554", "--package", TEST_PACKAGE, "--output", str(output), "--phase", "fixture"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                await_condition(lambda: pidfile.exists() and
                    (output / "failure-context-crash.log").read_bytes() == b"PRIVATE_PARTIAL\n")
                started = time.monotonic(); process.send_signal(signal.SIGTERM)
                console = process.communicate(timeout=3)[0]
                self.assertEqual(143, process.returncode); self.assertLess(time.monotonic() - started, 3)
                self.assertNotIn(b"PRIVATE_PARTIAL", console)
                report = json.loads((output / "failure-context.json").read_text())
                self.assertTrue(report["cancelled"]); self.assertFalse(report["complete"])
                self.assertTrue(all(item["cancelled"] for item in report["captures"]))
                for pid in json.loads(pidfile.read_text()):
                    await_condition(lambda pid=pid: not executing(pid))
                self.assertIsNone(unrelated.poll())
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
                if pidfile.exists():
                    for pid in json.loads(pidfile.read_text()):
                        if executing(pid): os.kill(pid, signal.SIGKILL)
                unrelated.kill(); unrelated.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
