"""Exercise setup and doctor against fresh Flutter consumers."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parent.parent
PLATFORMS = ("macos", "android", "windows", "ios")
SETUP_TIMING_MARKER = "WINDOWS_SETUP_TIMING "


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


def read_setup_timing(output, pre_staged, *, repeat=False):
    timing_lines = [line[len(SETUP_TIMING_MARKER):] for line in output.splitlines()
                    if line.startswith(SETUP_TIMING_MARKER)]
    assert len(timing_lines) == 1, "Expected one Windows setup timing receipt"
    timing = json.loads(timing_lines[0])
    required = {"project_plan", "runtime_prepare", "project_apply", "total"}
    known = set(required)
    if pre_staged:
        required.add("wintun_phases")
        if not repeat:
            required.add("wintun_stage")
        known.update(("wintun_inspect", "wintun_stage", "wintun_phases"))
    assert isinstance(timing, dict) and required <= set(timing) <= known, "Unexpected Windows setup timing fields"
    phases = timing.pop("wintun_phases", None)
    assert all(type(value) is int and value >= 0 for value in timing.values()), "Invalid Windows setup duration"
    assert all(value <= timing["total"] for value in timing.values()), "Windows setup phase exceeds total duration"
    if pre_staged:
        assert isinstance(phases, dict) and phases, "Missing Wintun helper timings"
        for name, value in phases.items():
            phase = f"wintun_{name.partition('_')[0]}"
            assert phase in ("wintun_inspect", "wintun_stage") and phase in timing, "Unknown Wintun helper phase"
            assert type(value) is int and 0 <= value <= timing[phase], "Invalid Wintun helper duration"
        timing["wintun_phases"] = phases
    return timing


def timing_summary(file, label, wall_ms, timing):
    print(f"- VPN setup ({label}): {wall_ms} ms including runtime provisioning.", file=file)
    phases = ", ".join(f"{name} {ms} ms" for name, ms in timing.items() if type(ms) is int)
    print(f"  - Setup CLI timings: {phases}.", file=file)
    if helper := timing.get("wintun_phases"):
        print(f"  - Wintun helper: {', '.join(f'{name} {ms} ms' for name, ms in helper.items())}.", file=file)


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
        live_probe = os.environ.get("FLUTTER_VLESS_WINDOWS_LIVE_PROBE")
        if live_probe:
            from windows import consumer_setup_smoke as smoke
            probe = (REPO / live_probe).resolve()
        benchmark = os.environ.get("FLUTTER_VLESS_WINDOWS_WINTUN_BENCHMARK") or None
        if benchmark:
            self.assertIn(benchmark, ("control", "pre-staged"))
            self.assertTrue(live_probe, "Wintun benchmark needs the live Windows observer")
            self.assertEqual(os.environ.get("RUNNER_ENVIRONMENT"), "github-hosted")
            self.assertEqual(os.environ.get("GITHUB_ACTIONS"), "true")
        with tempfile.TemporaryDirectory(prefix="fv-setup-", dir=os.environ.get("RUNNER_TEMP")) as tmp:
            for mode in ("proxy", "vpn"):
                with self.subTest(mode=mode):
                    app = Path(tmp) / mode
                    create_consumer(flutter, app, ("windows",))
                    cli = [dart, "run"]
                    flags = ["--platform", "windows", f"--{mode}", "--arch", "x64", "--non-interactive"]
                    setup = [*cli, "flutter_vless:setup", *flags]
                    doctor = [*cli, "flutter_vless:doctor", *flags]
                    compare_wintun = benchmark is not None and mode == "vpn"
                    pre_staged = compare_wintun and benchmark == "pre-staged"
                    if pre_staged:
                        setup.append("--stage-wintun")
                        doctor.append("--stage-wintun")
                    timing_env = (dict(os.environ, FLUTTER_VLESS_SETUP_TIMING="1")
                                  if compare_wintun else None)
                    if compare_wintun:
                        self.assertEqual(smoke.wintun_driver_inventory(), [],
                                         "The Windows runner is not cold: Wintun was already staged")
                        setup_network = smoke.wintun_setup_network(probe)

                    before = snapshot(app)
                    preview = run([*setup, "--dry-run"], app)
                    self.assertIn("setup changes pending.", preview)
                    self.assertIn("Download and verify Xray", preview)
                    pending = run(doctor, app, expected=1)
                    self.assertIn("setup changes pending.", pending)
                    if pre_staged:
                        self.assertIn("Stage the pinned Wintun driver.", preview)
                        self.assertIn("Stage the pinned Wintun driver.", pending)
                    self.assertEqual(snapshot(app), before)
                    if compare_wintun:
                        self.assertEqual(smoke.wintun_driver_inventory(), [], "Preview or doctor staged Wintun")
                        self.assertEqual(smoke.wintun_setup_network(probe), setup_network)
                        setup_log = smoke.setupapi_baseline()

                    started = time.monotonic_ns()
                    first = run(setup, app, timeout=240, env=timing_env)
                    setup_ms = (time.monotonic_ns() - started) // 1_000_000
                    self.assertIn("project configured.", first)
                    if compare_wintun:
                        first_timing = read_setup_timing(first, pre_staged)
                        if pre_staged:
                            self.assertIn("Wintun driver staged.", first)
                        packages = smoke.wintun_driver_inventory()
                        self.assertEqual(len(packages), int(pre_staged), "Unexpected Wintun package count after setup")
                        self.assertEqual(smoke.wintun_setup_network(probe), setup_network)
                        setupapi = smoke.setupapi_wintun_delta(setup_log)
                        self.assertIn(setupapi["status"], ("observed", "no_wintun_sections"), setupapi)
                        self.assertEqual(any(row["stage"] == "driver_stage" for row in setupapi["sections"]),
                                         pre_staged, setupapi)
                        repeat_log = smoke.setupapi_baseline()
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
                        started = time.monotonic_ns()
                        output = run(command, app, env=timing_env if command is setup else None)
                        if compare_wintun and command is setup:
                            repeat_setup_ms = (time.monotonic_ns() - started) // 1_000_000
                            repeat_timing = read_setup_timing(output, pre_staged, repeat=True)
                            self.assertEqual(repeat_timing["runtime_prepare"], 0)
                            self.assertEqual(repeat_timing["project_apply"], 0)
                        self.assertIn("project configuration is up to date.", output)
                        self.assertNotIn("Download and verify", output)
                        self.assertEqual(snapshot(app), configured)
                        if pre_staged:
                            self.assertIn("Wintun driver already staged.", output)
                    if compare_wintun:
                        self.assertEqual(smoke.wintun_driver_inventory(), packages, "Repeat setup changed driver inventory")
                        self.assertEqual(smoke.wintun_setup_network(probe), setup_network)
                        repeat_setupapi = smoke.setupapi_wintun_delta(repeat_log)
                        self.assertEqual(repeat_setupapi, dict(status="no_wintun_sections", sections=[]),
                                         "Repeat setup ran Wintun installation again or lost its audit evidence")
                        evidence = dict(wintun_benchmark=benchmark, setup_ms=setup_ms, setup_timing_ms=first_timing,
                                        setupapi_wintun=setupapi, installed_before_first_connect=pre_staged,
                                        repeat_setup_ms=repeat_setup_ms, repeat_setup_timing_ms=repeat_timing)
                        if pre_staged:
                            signature = smoke.wintun_authenticode_status(stage / "wintun.dll")
                            self.assertEqual(signature, "Valid", "Pinned Wintun DLL Authenticode trust failed")
                            evidence["wintun_authenticode"] = signature
                        print("WINDOWS_WINTUN_SETUP " + json.dumps(evidence), flush=True)
                        if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
                            with Path(summary).open("a", encoding="utf-8") as file:
                                timing_summary(file, benchmark, setup_ms, first_timing)
                                phases = ", ".join(f"{row['stage']} {row['elapsed_ms']} ms"
                                                   for row in setupapi["sections"])
                                if phases:
                                    print(f"  - SetupAPI during setup: {phases}.", file=file)
                                if pre_staged:
                                    print(f"  - Pinned Wintun DLL Authenticode: {signature}.", file=file)
                                timing_summary(file, f"{benchmark}, repeat", repeat_setup_ms, repeat_timing)
                    print(f"{mode}: doctor and dry-run were read-only; repeated setup changed no files.", flush=True)

                    if live_probe:
                        shutil.copyfile(REPO / "tool/windows/consumer_setup_smoke_test.dart",
                                        app / "lib/main.dart")
                    run([flutter, "--verbose", "build", "windows", "--release", "--no-pub"],
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
                    if live_probe:
                        smoke.exercise_consumer(bundle, mode, Path(tmp) / f"{mode}-evidence", probe,
                                                wintun_benchmark=benchmark if compare_wintun else None)


if __name__ == "__main__":
    unittest.main()
