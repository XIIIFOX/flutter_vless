#!/usr/bin/env python3
"""Build/install a separate-UID adversary APK and test native local authorization.

The plugin instrumentation APK must already be installed and include
SeparateUidAuthorizationHostTest. No Gradle invocation or host VPN change is
performed. Disposable test credentials never originate in a live VPN session.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
HOST = "com.github.tfox.flutter_vless.test"
ADVERSARY = "com.github.tfox.flutter_vless.adversary"
HOST_CLASS = "com.github.tfox.flutter_vless.xray.service.SeparateUidAuthorizationHostTest"


def run(command, **options):
    result = subprocess.run([str(x) for x in command], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **options)
    if result.returncode:
        raise RuntimeError("Tool failed: " + str(command[0]) + "\n" + result.stdout.decode(errors="replace"))
    return result.stdout.decode(errors="replace")


def version(path):
    return tuple(int(part) for part in re.findall(r"\d+", path.name))


def build_apk(sdk, java, output):
    tools = max((sdk / "build-tools").iterdir(), key=version)
    platform = max((sdk / "platforms").iterdir(), key=version)
    android = platform / "android.jar"
    classes, dex = output / "classes", output / "dex"
    classes.mkdir(); dex.mkdir()
    fixture = ROOT / "tool/fixtures/android_adversary"
    run([java / "bin/javac", "-source", "8", "-target", "8", "-classpath", android,
         "-d", classes, fixture / "Probe.java"])
    env = os.environ.copy(); env["JAVA_HOME"] = str(java)
    run([tools / "d8", "--min-api", "23", "--lib", android, "--output", dex,
         *sorted(classes.rglob("*.class"))], env=env)
    unsigned, aligned, apk = output / "unsigned.apk", output / "aligned.apk", output / "adversary.apk"
    run([tools / "aapt2", "link", "-o", unsigned, "--manifest", fixture / "AndroidManifest.xml",
         "-I", android, "--min-sdk-version", "23", "--target-sdk-version", "35"])
    run([java / "bin/jar", "uf", unsigned, "-C", dex, "classes.dex"])
    run([tools / "zipalign", "-f", "4", unsigned, aligned])
    key = output / "disposable-test.jks"
    run([java / "bin/keytool", "-genkeypair", "-keystore", key, "-storepass", "android", "-keypass", "android",
         "-alias", "test", "-dname", "CN=Disposable VLESS UID Test", "-keyalg", "RSA", "-validity", "2", "-noprompt"])
    run([tools / "apksigner", "sign", "--ks", key, "--ks-pass", "pass:android", "--key-pass", "pass:android",
         "--out", apk, aligned], env=env)
    return apk


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", default="emulator-5554")
    parser.add_argument("--sdk", type=Path, default=Path(os.environ.get("ANDROID_SDK_ROOT", os.environ.get("ANDROID_HOME", str(Path.home() / "Library/Android/sdk")))))
    parser.add_argument("--java", type=Path, default=Path(os.environ.get("JAVA_HOME", "/Applications/Android Studio.app/Contents/jbr/Contents/Home")))
    parser.add_argument("--output", type=Path, default=ROOT / "output/security/android-separate-uid-results.json")
    parser.add_argument("--build-only", action="store_true", help="Compile the adversary without installing or using a device")
    parser.add_argument("--install-only", action="store_true", help="Install the disposable probe for a coordinated OS-lockdown test; caller must uninstall it")
    args = parser.parse_args()
    adb = [args.sdk / "platform-tools/adb", "-s", args.serial]
    with tempfile.TemporaryDirectory(prefix="flutter-vless-adversary-") as temporary:
        directory = Path(temporary)
        apk = build_apk(args.sdk, args.java, directory)
        if args.build_only:
            print("Standalone adversary APK compiled and signed successfully")
            return
        # Never overwrite an unrelated pre-existing installation or leave the test app behind.
        existing = subprocess.run([str(x) for x in adb + ["shell", "pm", "path", ADVERSARY]], capture_output=True).stdout.strip()
        if existing:
            raise RuntimeError("Adversary test package already installed; remove that disposable test APK before running")
        if args.install_only:
            run(adb + ["install", "--no-streaming", apk])
            print("Installed disposable probe: " + ADVERSARY)
            return
        host_process = None
        shell_apk = "/data/local/tmp/" + directory.name + ".apk"
        try:
            run(adb + ["install", "--no-streaming", apk])
            run(adb + ["shell", "run-as", HOST, "rm", "-f", "files/separate-uid-ready.json", "files/separate-uid-done.json"])
            log = directory / "host-instrumentation.txt"
            with log.open("wb") as output:
                host_process = subprocess.Popen([str(x) for x in adb + ["shell", "am", "instrument", "-w", "-e", "separateUidHarness", "true", "-e", "class", HOST_CLASS,
                    HOST + "/androidx.test.runner.AndroidJUnitRunner"]], stdout=output, stderr=subprocess.STDOUT)
                ready = None
                for _ in range(150):
                    probe = subprocess.run([str(x) for x in adb + ["shell", "run-as", HOST, "cat", "files/separate-uid-ready.json"]], capture_output=True)
                    if probe.returncode == 0:
                        ready = json.loads(probe.stdout)
                        break
                    if host_process.poll() is not None:
                        raise RuntimeError("Host instrumentation ended before readiness\n" + log.read_text())
                    time.sleep(0.2)
                if ready is None:
                    raise RuntimeError("Host instrumentation did not become ready")
                command = adb + ["shell", "am", "instrument", "-w"]
                for key in ("hostUid", "socksPort", "httpPort", "originPort", "broker"):
                    command += ["-e", key, str(ready[key])]
                command += [ADVERSARY + "/" + ADVERSARY + ".Probe"]
                text = run(command, timeout=45)
                match = re.search(r"^INSTRUMENTATION_RESULT: report=(.+)$", text, re.MULTILINE)
                if match is None:
                    raise RuntimeError("Adversary returned no structured result\n" + text)
                report = json.loads(match.group(1))
                # Android may reject both app and shell abstract sockets in SELinux before
                # Java sees a connection. Report the reached layer; never weaken SELinux.
                run(adb + ["push", apk, shell_apk])
                run(adb + ["shell", "chmod", "444", shell_apk])
                shell_text = run(adb + ["shell", "CLASSPATH=" + shell_apk, "/system/bin/app_process", "/system/bin",
                    ADVERSARY + ".Probe", ready["broker"], str(ready["hostUid"])], timeout=15)
                shell_reports = [json.loads(line) for line in shell_text.splitlines() if line.startswith('{')]
                if not shell_reports:
                    raise RuntimeError("Separate shell UID broker probe returned no result")
                report["shell_uid_broker_control"] = shell_reports[-1]
                report["passed"] = report.get("passed", False) and shell_reports[-1].get("passed", False)
                run(adb + ["shell", "run-as", HOST, "tee", "files/separate-uid-done.json"], input=json.dumps(report).encode())
                host_process.wait(timeout=20)
            host_text = log.read_text()
            report["host_instrumentation_passed"] = "OK (1 test)" in host_text and "FAILURES!!!" not in host_text
            report["passed"] = report.get("passed", False) and report["host_instrumentation_passed"]
            report["scope"] = "Separate installed app UID; disposable managed native SOCKS/HTTP inputs and FD broker; no production credentials accessed."
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            print(json.dumps(report, indent=2, sort_keys=True))
            if not report["passed"]:
                raise RuntimeError("Separate-UID authorization checks failed\n" + host_text)
        finally:
            if host_process is not None and host_process.poll() is None:
                subprocess.run([str(x) for x in adb + ["shell", "run-as", HOST, "tee", "files/separate-uid-done.json"]],
                               input=b'{"passed":false,"adversary_uid":-1}', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    host_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    host_process.terminate()
            subprocess.run([str(x) for x in adb + ["uninstall", ADVERSARY]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([str(x) for x in adb + ["shell", "rm", "-f", shell_apk]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
