"""Exercise setup and doctor against fresh Flutter consumers."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parent.parent
PLATFORMS = ("macos", "android", "windows", "ios")


def run(args, cwd, expected=0, env=None, timeout=120):
    args = [str(arg) for arg in args]
    batch = os.name == "nt" and Path(args[0]).suffix.lower() in {".bat", ".cmd"}
    result = subprocess.run(
        subprocess.list2cmdline(args) if batch else args,
        cwd=cwd, env=env, shell=batch, encoding="utf-8", errors="replace",
        capture_output=True, timeout=timeout,
    )
    if result.returncode != expected:
        raise AssertionError(f"{args} exited {result.returncode}:\n{result.stdout}{result.stderr}")
    return result.stdout


def snapshot(app):
    return {
        path.relative_to(app).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in app.rglob("*")
        if path.is_file() and ".dart_tool" not in path.relative_to(app).parts
    }


def write_test_pe(path, dll=False):
    data = bytearray(96)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<H", data, 68, 0x8664)
    struct.pack_into("<H", data, 86, 0x2000 if dll else 0)
    path.write_bytes(data)


def create_consumer(flutter, app, platforms):
    run([flutter, "create", "--no-pub", "--project-name", "vless_setup_probe",
         "--org", "com.example", "--platforms", ",".join(platforms), app.name], app.parent)
    pubspec = app / "pubspec.yaml"
    dependencies = f"dependencies:\n  flutter_vless:\n    path: {json.dumps(str(REPO))}\n"
    pubspec.write_text(
        pubspec.read_text(encoding="utf-8").replace("dependencies:\n", dependencies, 1),
        encoding="utf-8",
    )
    (app / "pubspec_overrides.yaml").write_text("dependency_overrides:\n" + "".join(
        f"  {name}:\n    path: {json.dumps(str(REPO / 'packages' / name))}\n"
        for name in ("flutter_vless_platform_interface", "flutter_vless_android",
                     "flutter_vless_macos", "flutter_vless_windows")
    ), encoding="utf-8")
    run([flutter, "pub", "get"], app)


class ProjectSetupTest(unittest.TestCase):
    def test_clean_consumer_modes_and_repeatability(self):
        flutter = shutil.which("flutter")
        dart = shutil.which("dart")
        self.assertTrue(flutter and dart, "Flutter and Dart must be on PATH")
        with tempfile.TemporaryDirectory(prefix="flutter-vless-project-setup-") as tmp:
            root = Path(tmp)
            source = root / "template"
            create_consumer(flutter, source, PLATFORMS)

            env = os.environ.copy()
            if os.name != "nt":
                trap = root / "bin"
                trap.mkdir()
                for command in ("xcodebuild", "xcode-select", "xcrun"):
                    executable = trap / command
                    executable.write_text(
                        '#!/bin/sh\n: > "$FLUTTER_VLESS_XCODE_TRAP"\nexit 97\n',
                        encoding="utf-8",
                    )
                    executable.chmod(0o700)
                env["PATH"] = str(trap) + os.pathsep + env["PATH"]
                env["FLUTTER_VLESS_XCODE_TRAP"] = str(root / "xcode-invoked")

            for platform in PLATFORMS:
                for mode in ("proxy", "vpn"):
                    with self.subTest(platform=platform, mode=mode):
                        app = root / f"{platform}_{mode}"
                        shutil.copytree(source, app, symlinks=True)
                        args = ["--platform", platform, f"--{mode}", "--non-interactive"]
                        if platform == "windows":
                            runtime = app / "custom_runtime"
                            runtime.mkdir()
                            write_test_pe(runtime / "xray.exe")
                            if mode == "vpn":
                                write_test_pe(runtime / "tun2socks.exe")
                                write_test_pe(runtime / "wintun.dll", dll=True)
                            args += ["--arch", "x64", "--runtime-dir", str(runtime)]
                        before = snapshot(app)
                        setup = [dart, "run", "flutter_vless:setup", *args]
                        doctor = [dart, "run", "flutter_vless:doctor", *args]
                        preview = run([*setup, "--dry-run"], app, env=env)
                        self.assertEqual(snapshot(app), before, "dry-run wrote project files")
                        run(doctor, app, expected=int("setup changes pending." in preview), env=env)
                        self.assertEqual(snapshot(app), before, "doctor wrote project files")
                        run(setup, app, env=env)
                        applied = snapshot(app)
                        edit_paths = {
                            key for key in before.keys() | applied.keys()
                            if before.get(key) != applied.get(key)
                        }
                        self.assertTrue(all(path.startswith(f"{platform}/") for path in edit_paths))
                        if platform in ("macos", "ios"):
                            self.assertEqual((app / platform / "XrayTunnel").exists(), mode == "vpn")
                            if platform == "ios" and mode == "vpn":
                                pbx = (app / "ios/Runner.xcodeproj/project.pbxproj").read_text()
                                runner = pbx.split('/* Runner */ = {\n\t\t\tisa = PBXNativeTarget;')[1]
                                phases = runner.split("buildPhases = (", 1)[1].split(");", 1)[0]
                                self.assertLess(phases.index("Embed Foundation Extensions"),
                                                phases.index("Thin Binary"))
                        run(doctor, app, env=env)
                        repeated = run(setup, app, env=env)
                        self.assertIn("up to date", repeated)
                        self.assertEqual(snapshot(app), applied, "repeat setup wrote project files")
                        if platform in ("macos", "ios") and mode == "vpn":
                            provider = app / platform / "XrayTunnel/PacketTunnelProvider.swift"
                            provider.write_text("// App-owned VPN provider\n", encoding="utf-8")
                            custom = snapshot(app)
                            run(setup, app, expected=64, env=env)
                            self.assertEqual(snapshot(app), custom)
            self.assertFalse((root / "xcode-invoked").exists(), "setup must not invoke Xcode")

    @unittest.skipUnless(os.name == "nt", "requires a native Windows toolchain")
    def test_windows_published_runtime_and_build(self):
        flutter = shutil.which("flutter")
        dart = shutil.which("dart")
        self.assertTrue(flutter and dart, "Flutter and Dart must be on PATH")
        with tempfile.TemporaryDirectory(prefix="fv-setup-", dir=os.environ.get("RUNNER_TEMP")) as tmp:
            for mode in ("proxy", "vpn"):
                with self.subTest(mode=mode):
                    app = Path(tmp) / mode
                    create_consumer(flutter, app, ("windows",))
                    cli = [dart, "run"]
                    flags = ["--platform", "windows", f"--{mode}", "--arch", "x64", "--non-interactive"]
                    setup = [*cli, "flutter_vless:setup", *flags]
                    doctor = [*cli, "flutter_vless:doctor", *flags]

                    before = snapshot(app)
                    preview = run([*setup, "--dry-run"], app)
                    self.assertIn("setup changes pending.", preview)
                    self.assertIn("Download and verify Xray", preview)
                    self.assertIn("setup changes pending.", run(doctor, app, expected=1))
                    self.assertEqual(snapshot(app), before)

                    first = run(setup, app, timeout=240)
                    self.assertIn("project configured.", first)
                    stage = app / "windows/.flutter_vless/runtime/x64"
                    expected = {"xray.exe", "geoip.dat", "geosite.dat", "LICENSE.xray-core"}
                    helpers = {"tun2socks.exe", "wintun.dll", "LICENSE.tun2socks", "LICENSE.wintun"}
                    self.assertEqual("Download and verify tun2socks" in first, mode == "vpn")
                    if mode == "vpn":
                        expected.update(helpers)
                    self.assertEqual({entry.name for entry in stage.iterdir()}, expected)

                    configured = snapshot(app)
                    changed = {
                        key for key in before.keys() | configured.keys()
                        if before.get(key) != configured.get(key)
                    }
                    self.assertTrue(changed and all(path.startswith("windows/") for path in changed))
                    for command in (doctor, setup, doctor):
                        output = run(command, app)
                        self.assertIn("project configuration is up to date.", output)
                        self.assertNotIn("Download and verify", output)
                        self.assertEqual(snapshot(app), configured)
                    print(f"{mode}: doctor and dry-run were read-only; repeated setup changed no files.", flush=True)

                    run([flutter, "build", "windows", "--release", "--no-pub"],
                        app, timeout=660)
                    bundle = app / "build/windows/x64/runner/Release"
                    self.assertTrue((bundle / "vless_setup_probe.exe").is_file())
                    self.assertTrue((bundle / "flutter_vless_windows_plugin.dll").is_file())
                    installed = bundle / "xray"
                    self.assertEqual({entry.name for entry in installed.iterdir()}, expected)
                    self.assertEqual(snapshot(installed), snapshot(stage))
                    version = run([installed / "xray.exe", "version"], bundle).splitlines()[0]
                    self.assertRegex(version, r"^Xray \d+\.\d+\.\d+\b")
                    print(f"{mode}: MSVC build and {len(expected)} bundled runtime files verified. {version}", flush=True)


if __name__ == "__main__":
    unittest.main()
