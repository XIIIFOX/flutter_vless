import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import unittest

from capture_android_emulator_failure import collect, TEST_PACKAGE


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

    def run_actual_cleanup(self, code, *, installed=1, validated=1):
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
            "TEST_INSTALLED": str(installed), "EMULATOR_VALIDATED": str(validated),
            "ADVERSARY_INSTALLED": "1", "FIXTURE_PID": "", "DNS_PID": "",
        }
        script = "set -u\n" + "\n".join(f"{key}={shlex.quote(value)}" for key, value in variables.items())
        script += "\n" + bounded + "\n" + cleanup + f"\ntrap cleanup EXIT\nexit {code}\n"
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=15)

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


if __name__ == "__main__":
    unittest.main()
