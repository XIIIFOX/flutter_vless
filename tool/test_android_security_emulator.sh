#!/usr/bin/env bash
# Runs the real, checksum-verified native runtime in a dedicated Android emulator.
# All fixture listeners use host loopback; this script never changes the host VPN.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAPTURE_DNS=1
NATIVE_DNS_PREVIEW=""
NATIVE_DNS_PREVIEW_SHA=""
NATIVE_TUN_PREVIEW=""
NATIVE_TUN_PREVIEW_SHA=""
usage() {
  cat <<'USAGE'
Usage: tool/test_android_security_emulator.sh [--no-capture] [--native-dns-preview BUILD_DIRECTORY] [--native-tun-preview BUILD_DIRECTORY]

Use an already booted, dedicated emulator. ANDROID_SERIAL selects it explicitly;
otherwise exactly one online emulator must be present. Physical devices are refused.
Requires Flutter, Python 3, Android SDK, and JDK 17+; runs flutter pub get itself.
The default run verifies physical DNS capture. --no-capture is a narrower local
check and does not establish absence of duplicate plaintext DNS leaks.
Handover is reported as skipped if emulator Wi-Fi/cellular is unavailable.
Physical DNS needs a working emulator upstream resolver.
The computer's current VPN must remain enabled.
The optional preview is verified against this checkout and added only to the
instrumentation APK, never to the ordinary plugin/runtime or release artifacts.
The additional TUN preview requires both separately verified executables. It
runs five actual TUN/browser scenarios on this emulator after the ordinary
regression suites; the default and Core-only paths do not start this service.
USAGE
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-capture) CAPTURE_DNS=0 ;;
    --native-dns-preview)
      shift
      if [ "$#" -eq 0 ] || [ -z "$1" ]; then usage >&2; exit 2; fi
      NATIVE_DNS_PREVIEW="$1"
      ;;
    --native-tun-preview)
      shift
      if [ "$#" -eq 0 ] || [ -z "$1" ]; then usage >&2; exit 2; fi
      NATIVE_TUN_PREVIEW="$1"
      ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
if [ -n "$NATIVE_TUN_PREVIEW" ] && [ -z "$NATIVE_DNS_PREVIEW" ]; then
  echo "Native TUN preview requires --native-dns-preview." >&2
  exit 2
fi

if [ -n "${FLUTTER_VLESS_ANDROID_RUNTIME_REPO:-}" ] ||
   [ -n "${ORG_GRADLE_PROJECT_flutterVlessAndroidRuntimeRepo:-}" ] ||
   [ -n "${ORG_GRADLE_PROJECT_flutterVlessXrayRuntimeVersion:-}" ] ||
   { [ -n "${XRAY_RUNTIME_VERSION:-}" ] && [ "$XRAY_RUNTIME_VERSION" != "26.10.17-protect1" ]; }; then
  echo "Security acceptance requires the committed official runtime; remove runtime overrides." >&2
  exit 2
fi

SDK_DIR="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -z "$SDK_DIR" ] && [ "$(uname -s)" = Darwin ] && [ -d "$HOME/Library/Android/sdk" ]; then
  SDK_DIR="$HOME/Library/Android/sdk"
fi
if [ -z "$SDK_DIR" ] || [ ! -x "$SDK_DIR/platform-tools/adb" ]; then
  echo "Set ANDROID_HOME or ANDROID_SDK_ROOT to an installed Android SDK." >&2
  exit 2
fi
export ANDROID_HOME="$SDK_DIR" ANDROID_SDK_ROOT="$SDK_DIR"
ADB="$SDK_DIR/platform-tools/adb"
if [ -z "${JAVA_HOME:-}" ] && [ "$(uname -s)" = Darwin ] &&
   [ -d "/Applications/Android Studio.app/Contents/jbr/Contents/Home" ]; then
  export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
fi
if [ -n "${JAVA_HOME:-}" ]; then export PATH="$JAVA_HOME/bin:$PATH"; fi
for executable in python3 flutter java; do
  command -v "$executable" >/dev/null || { echo "Missing required executable: $executable" >&2; exit 2; }
done

mkdir -p "$ROOT_DIR/build"
OUT_DIR="$(mktemp -d "$ROOT_DIR/build/android-security-emulator.XXXXXXXX")"
PACKAGE=com.github.tfox.flutter_vless.test
ADVERSARY_PACKAGE=com.github.tfox.flutter_vless.adversary
RUNNER="$PACKAGE/androidx.test.runner.AndroidJUnitRunner"
CLASS_PREFIX=com.github.tfox.flutter_vless.xray.service
PHASE=preflight
SERIAL=""
FIXTURE_PID=""
DNS_PID=""
TEST_INSTALLED=0
EMULATOR_VALIDATED=0
ADVERSARY_INSTALLED=0
CAPTURE_STARTED=0
CAPTURE_WIFI_DISABLED=0
TUN_BROWSER_OWNED=0
TUN_WIFI_RESTORE=0
CAPTURE_SOURCE_PATH="$OUT_DIR/physical-dns.pcap"
CHECKS="$OUT_DIR/checks.tsv"
: > "$CHECKS"

# Python supplies a portable timeout on macOS and Linux. Termination only targets
# the process group created for this command, never another build/ADB process.
bounded() {
  local seconds="$1" log="$2"
  shift 2
  python3 - "$seconds" "$log" "$@" <<'PY'
import os, signal, subprocess, sys
seconds, log, command = float(sys.argv[1]), sys.argv[2], sys.argv[3:]
with open(log, 'wb') as output:
    process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        code = process.wait(timeout=seconds)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        output.write(b'\nHARNESS_ERROR: command timed out or was interrupted\n')
        code = 124
if code:
    print(f'Command failed ({code}); log: {log}', file=sys.stderr)
    with open(log, errors='replace') as output:
        print(''.join(output.readlines()[-60:]), file=sys.stderr)
raise SystemExit(code if code >= 0 else 128 - code)
PY
}

start_capture() {
  # Older emulators accept an absolute path. Emulator 37 restricts this command
  # to a bare filename within the selected AVD's console_out directory. Fall back
  # only for that explicit rejection; other capture failures remain failures.
  bounded 20 "$OUT_DIR/capture-start.log" "$ADB" -s "$SERIAL" emu network capture start "$CAPTURE_SOURCE_PATH" || return "$?"
  local capture_status=0
  python3 - "$OUT_DIR/capture-start.log" <<'PY' || capture_status=$?
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
if text.strip() == ("KO: <file> must be a bare filename (written under the AVD content directory); "
                    "path separators and '..' are not allowed"):
    raise SystemExit(2)
if re.search(r'^KO\b', text, re.M) or not re.search(r'^OK\s*$', text, re.M):
    raise SystemExit('Emulator failed to start network capture: ' + text)
PY
  if [ "$capture_status" -eq 2 ]; then
    bounded 20 "$OUT_DIR/capture-avd-path.log" "$ADB" -s "$SERIAL" emu avd path || return "$?"
    local capture_name="flutter-vless-dns-${OUT_DIR##*.}.pcap"
    CAPTURE_SOURCE_PATH="$(python3 - "$OUT_DIR/capture-avd-path.log" "$capture_name" <<'PY'
import pathlib, re, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
if len(lines) != 2 or lines[1] != 'OK' or not pathlib.Path(lines[0]).is_absolute():
    raise SystemExit('Emulator did not identify its selected AVD content directory.')
directory = pathlib.Path(lines[0]).resolve(strict=True)
if not directory.is_dir() or not re.fullmatch(r'flutter-vless-dns-[A-Za-z0-9]+\.pcap', sys.argv[2]):
    raise SystemExit('Invalid selected AVD directory or unique capture filename.')
capture_directory = directory / 'console_out'
if capture_directory.is_symlink() or (capture_directory.exists() and not capture_directory.is_dir()):
    raise SystemExit('Refusing a redirected or invalid AVD capture directory.')
source = capture_directory / sys.argv[2]
if source.exists() or source.is_symlink():
    raise SystemExit('Refusing to overwrite an existing AVD capture file.')
print(source)
PY
)" || return "$?"
    bounded 20 "$OUT_DIR/capture-start-avd.log" "$ADB" -s "$SERIAL" emu network capture start "$capture_name" || return "$?"
    python3 - "$OUT_DIR/capture-start-avd.log" <<'PY' || return "$?"
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
if re.search(r'^KO\b', text, re.M) or not re.search(r'^OK\s*$', text, re.M):
    raise SystemExit('Emulator failed to start AVD network capture: ' + text)
PY
    CAPTURE_STARTED=1
    python3 - "$OUT_DIR/capture-start-avd.log" "$CAPTURE_SOURCE_PATH" <<'PY' || return "$?"
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
if lines != ['OK: capturing to ' + sys.argv[2], 'OK']:
    raise SystemExit('Emulator did not confirm the expected unique AVD capture path.')
PY
  elif [ "$capture_status" -ne 0 ]; then
    return "$capture_status"
  fi
  CAPTURE_STARTED=1
}

stop_capture() {
  bounded 20 "$OUT_DIR/capture-stop.log" "$ADB" -s "$SERIAL" emu network capture stop || return "$?"
  python3 - "$OUT_DIR/capture-stop.log" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text()
if re.search(r'^KO\b', text, re.M) or not re.search(r'^OK\s*$', text, re.M):
    raise SystemExit('Emulator failed to stop network capture: ' + text)
PY
  local capture_result=$?
  [ "$capture_result" -eq 0 ] || return "$capture_result"
  CAPTURE_STARTED=0
  if [ "$CAPTURE_SOURCE_PATH" != "$OUT_DIR/physical-dns.pcap" ]; then
    # Copy only this run's unique file from the selected emulator's reported
    # directory. Exclusive creation and O_NOFOLLOW avoid replacing other files.
    python3 - "$CAPTURE_SOURCE_PATH" "$OUT_DIR/physical-dns.pcap" <<'PY' || return "$?"
import os, pathlib, shutil, stat, sys
source, destination = map(pathlib.Path, sys.argv[1:])
with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as capture:
    if not stat.S_ISREG(os.fstat(capture.fileno()).st_mode):
        raise SystemExit('Emulator capture is not a regular file.')
    with destination.open('xb') as output:
        shutil.copyfileobj(capture, output)
source.unlink()
PY
  fi
}

cleanup() {
  local result=$?
  local original_result=$result
  trap - EXIT INT TERM
  set +e
  if [ "$original_result" -ne 0 ] && [ "$TEST_INSTALLED" -eq 1 ] && [ "$EMULATOR_VALIDATED" -eq 1 ]; then
    # Preserve primary crash/ANR evidence before force-stop/uninstall can erase
    # live context. Each read is bounded and failures never skip cleanup or
    # change the original test failure. The collector never prints raw logs.
    bounded 40 "$OUT_DIR/failure-capture-command.log" python3 "$ROOT_DIR/tool/capture_android_emulator_failure.py" \
      --adb "$ADB" --serial "$SERIAL" --package "$PACKAGE" --output "$OUT_DIR" --phase "$PHASE"
  fi
  if [ "$CAPTURE_STARTED" -eq 1 ]; then stop_capture; [ "$?" -eq 0 ] || result=1; fi
  if [ "$TEST_INSTALLED" -eq 1 ]; then
    # Stop our instrumentation and VPN before inspecting OS policy, so a timed
    # out test cannot enqueue another policy change during cleanup.
    bounded 20 "$OUT_DIR/cleanup-force-stop.log" "$ADB" -s "$SERIAL" shell am force-stop "$PACKAGE"
    [ "$?" -eq 0 ] || result=1
    bounded 20 "$OUT_DIR/cleanup-always-on-owner.log" "$ADB" -s "$SERIAL" shell settings --user 0 get secure always_on_vpn_app
    if [ "$?" -eq 0 ]; then
      local always_on_owner
      always_on_owner="$(python3 - "$OUT_DIR/cleanup-always-on-owner.log" <<'PY'
import pathlib, sys
print(pathlib.Path(sys.argv[1]).read_text().strip())
PY
)"
      if [ "$always_on_owner" = "$PACKAGE" ]; then
        # Android's live VPN manager must clear lockdown too. Removing our test
        # package does that after a crashed/timed-out OS policy test; writing only
        # secure settings would leave runtime policy in an inconsistent state.
        echo "OS policy cleanup required removal of the harness test package." >&2
        result=1
        bounded 60 "$OUT_DIR/cleanup-owned-lockdown.log" "$ADB" -s "$SERIAL" uninstall "$PACKAGE"
        if [ "$?" -eq 0 ]; then TEST_INSTALLED=0; fi
      fi
    else
      result=1
    fi
  fi
  if [ "$TEST_INSTALLED" -eq 1 ]; then
    bounded 20 "$OUT_DIR/cleanup-vpn-permission.log" "$ADB" -s "$SERIAL" shell appops set "$PACKAGE" ACTIVATE_VPN default
    [ "$?" -eq 0 ] || result=1
  fi
  if [ "$TUN_BROWSER_OWNED" -eq 1 ]; then
    # The dedicated fixture proved Chrome had no process before its suite.
    # A crashed instrumentation process cannot run its own @After cleanup.
    bounded 20 "$OUT_DIR/cleanup-owned-browser.log" "$ADB" -s "$SERIAL" shell am force-stop com.android.chrome
    [ "$?" -eq 0 ] || result=1
  fi
  if [ "$CAPTURE_WIFI_DISABLED" -eq 1 ] || [ "$TUN_WIFI_RESTORE" -eq 1 ]; then
    # Stop instrumentation first: a timed-out handover test must not disable
    # virtual Wi-Fi again after the harness has restored its owned baseline.
    bounded 20 "$OUT_DIR/cleanup-wifi-enable.log" "$ADB" -s "$SERIAL" shell svc wifi enable
    [ "$?" -eq 0 ] || result=1
    bounded 20 "$OUT_DIR/cleanup-wifi-connect.log" "$ADB" -s "$SERIAL" shell cmd wifi connect-network AndroidWifi open
    [ "$?" -eq 0 ] || result=1
  fi
  if [ "$ADVERSARY_INSTALLED" -eq 1 ]; then
    # The standalone installer refuses existing packages. This flag is set only
    # after it confirms that this run successfully installed its disposable APK.
    bounded 30 "$OUT_DIR/cleanup-adversary.log" "$ADB" -s "$SERIAL" uninstall "$ADVERSARY_PACKAGE"
    [ "$?" -eq 0 ] || result=1
  fi
  for fixture in "$FIXTURE_PID" "$DNS_PID"; do
    if [ -n "$fixture" ] && kill -0 "$fixture" 2>/dev/null; then
      kill "$fixture" 2>/dev/null
      wait "$fixture" 2>/dev/null
    fi
  done
  # An interrupted/incomplete script must never become a successful report,
  # even when a shell parser error leaves EXIT with a stale zero status.
  if [ "$result" -eq 0 ] && [ "$PHASE" != complete ]; then result=1; fi
  if [ "$original_result" -ne 0 ]; then result=$original_result; fi
  python3 - "$OUT_DIR" "$SERIAL" "$result" "$PHASE" "$CAPTURE_DNS" "$NATIVE_TUN_PREVIEW" <<'PY'
import json, pathlib, sys
output, serial, code, phase, capture, tun_requested = sys.argv[1:]
checks = []
for line in (pathlib.Path(output) / 'checks.tsv').read_text().splitlines():
    name, count, skipped = line.split('\t')
    checks.append({'name': name, 'passed_tests': int(count), 'skipped_tests': int(skipped)})
summary = {'passed': code == '0', 'exit_code': int(code), 'emulator': serial,
           'checks': checks, 'dns_physical_capture_requested': capture == '1',
           'dns_physical_capture_verified': any(check['name'] == 'physical-dns-capture' for check in checks),
           'native_tun_preview_requested': bool(tun_requested),
           'native_tun_preview_verified': any(check['name'] == 'native-preview-vpn' and check['passed_tests'] == 5 and check['skipped_tests'] == 0 for check in checks),
           'instrumentation_passed_tests': sum(check['passed_tests'] for check in checks if check['name'] != 'physical-dns-capture'),
           'instrumentation_skipped_tests': sum(check['skipped_tests'] for check in checks),
           'last_phase': phase, 'artifacts': output}
(pathlib.Path(output) / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(('PASS' if summary['passed'] else 'FAIL') + ': Android security emulator; artifacts: ' + output)
PY
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Android security acceptance artifacts: $OUT_DIR"
bounded 20 "$OUT_DIR/devices.log" "$ADB" devices
SERIAL="$(python3 - "$OUT_DIR/devices.log" "${ANDROID_SERIAL:-}" <<'PY'
import pathlib, re, sys
rows = [line.split() for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
online = [row[0] for row in rows if len(row) >= 2 and row[1] == 'device']
selected = sys.argv[2]
if selected:
    if not re.fullmatch(r'emulator-[0-9]+', selected) or selected not in online:
        raise SystemExit('ANDROID_SERIAL must identify an online emulator; physical devices are refused.')
else:
    emulators = [serial for serial in online if re.fullmatch(r'emulator-[0-9]+', serial)]
    if len(emulators) != 1:
        raise SystemExit('Set ANDROID_SERIAL to one dedicated, already booted emulator.')
    selected = emulators[0]
print(selected)
PY
)"
bounded 20 "$OUT_DIR/emulator-properties.log" "$ADB" -s "$SERIAL" shell getprop
python3 - "$OUT_DIR/emulator-properties.log" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
if '[ro.kernel.qemu]: [1]' not in text and '[ro.boot.qemu]: [1]' not in text:
    raise SystemExit('Refusing a device that does not report emulator/QEMU identity.')
if '[sys.boot_completed]: [1]' not in text:
    raise SystemExit('Selected emulator has not completed boot.')
PY
EMULATOR_VALIDATED=1

# Connect only the dedicated emulator to its standard virtual access point.
# Physical resolver and handover tests must not inherit a disconnected Wi-Fi
# state left by an earlier test session. This never operates on host Wi-Fi.
bounded 20 "$OUT_DIR/emulator-wifi-enable.log" "$ADB" -s "$SERIAL" shell svc wifi enable
bounded 20 "$OUT_DIR/emulator-wifi-connect.log" "$ADB" -s "$SERIAL" shell cmd wifi connect-network AndroidWifi open

PHASE=build
PREVIEW_GRADLE_ARGS=()
if [ -n "$NATIVE_DNS_PREVIEW" ]; then
  PHASE=verify-native-preview
  bounded 30 "$OUT_DIR/native-preview-verification.json" python3 "$ROOT_DIR/tool/verify_android_dns_preview.py" --directory "$NATIVE_DNS_PREVIEW"
  NATIVE_DNS_PREVIEW="$(python3 - "$NATIVE_DNS_PREVIEW" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).resolve())
PY
)"
  NATIVE_DNS_PREVIEW_SHA="$(python3 - "$OUT_DIR/native-preview-verification.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['artifact_sha256'])
PY
)"
  PREVIEW_GRADLE_ARGS=("-PflutterVlessNativeDnsPreviewDir=$NATIVE_DNS_PREVIEW")
fi
if [ -n "$NATIVE_TUN_PREVIEW" ]; then
  PHASE=verify-native-tun-preview
  bounded 30 "$OUT_DIR/native-tun-preview-verification.json" python3 "$ROOT_DIR/tool/verify_android_tun_preview.py" --directory "$NATIVE_TUN_PREVIEW"
  NATIVE_TUN_PREVIEW="$(python3 - "$NATIVE_TUN_PREVIEW" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).resolve())
PY
)"
  NATIVE_TUN_PREVIEW_SHA="$(python3 - "$OUT_DIR/native-tun-preview-verification.json" "$OUT_DIR/native-preview-verification.json" <<'PY'
import json,sys
tun,core = [json.load(open(path)) for path in sys.argv[1:]]
if tun['arch'] != core['arch']:
    raise SystemExit('Native preview executables require the same ABI.')
print(tun['artifact_sha256'])
PY
)"
fi
# Keep the ordinary APK's VPN service set intact. Android opts the entire app
# out of Always-on if any declared VPN service opts out, as this private host
# deliberately does. Only the final five-case suite receives the second APK.
PHASE=build
echo "Building the Android test APK with strict official-runtime verification..."
(cd "$ROOT_DIR/example" && bounded 300 "$OUT_DIR/flutter-pub-get.log" flutter pub get)
(cd "$ROOT_DIR/example/android" && bounded 1200 "$OUT_DIR/gradle-build.log" ./gradlew \
  :flutter_vless_android:assembleDebugAndroidTest \
  ${PREVIEW_GRADLE_ARGS[@]+"${PREVIEW_GRADLE_ARGS[@]}"} \
  -PflutterVlessOfficialRuntimeVerification=true --dependency-verification=strict --console=plain --stacktrace)
APK="$ROOT_DIR/example/build/flutter_vless_android/outputs/apk/androidTest/debug/flutter_vless_android-debug-androidTest.apk"
if [ ! -f "$APK" ]; then echo "Expected freshly built AndroidTest APK is missing: $APK" >&2; exit 1; fi
if [ -n "$NATIVE_DNS_PREVIEW" ]; then
  PHASE=verify-preview-apk
  PREVIEW_APK_ARGS=(--apk "$APK" --core-verification "$OUT_DIR/native-preview-verification.json")
  bounded 30 "$OUT_DIR/native-preview-apk-verification.json" python3 "$ROOT_DIR/tool/verify_android_preview_apk.py" "${PREVIEW_APK_ARGS[@]}"
fi
PHASE=install
bounded 90 "$OUT_DIR/install.log" "$ADB" -s "$SERIAL" install -r -t "$APK"
TEST_INSTALLED=1
bounded 20 "$OUT_DIR/initial-force-stop.log" "$ADB" -s "$SERIAL" shell am force-stop "$PACKAGE"
bounded 20 "$OUT_DIR/authorize-vpn.log" "$ADB" -s "$SERIAL" shell appops set "$PACKAGE" ACTIVATE_VPN allow
bounded 20 "$OUT_DIR/vpn-permission.log" "$ADB" -s "$SERIAL" shell appops get "$PACKAGE" ACTIVATE_VPN
python3 - "$OUT_DIR/vpn-permission.log" <<'PY'
import pathlib, re, sys
if not re.search(r'ACTIVATE_VPN:\s*allow\b', pathlib.Path(sys.argv[1]).read_text()):
    raise SystemExit('ACTIVATE_VPN was not granted to the test APK.')
PY

PHASE=fixtures
# Refuse occupied fixture ports instead of reusing, replacing, or killing any
# existing listener. Bind checks include the UDP socket used by the native test.
python3 - "$NATIVE_DNS_PREVIEW" <<'PY'
import socket
import sys
sockets = []
try:
    fixture_ports = [(18080, socket.SOCK_STREAM), (18082, socket.SOCK_DGRAM), (18083, socket.SOCK_STREAM)]
    fixture_ports += [(p, socket.SOCK_STREAM) for p in range(18280, 18286 if sys.argv[1] else 18284)]
    for port, kind in fixture_ports:
        sock = socket.socket(socket.AF_INET, kind)
        sockets.append(sock)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', port))
finally:
    for sock in sockets:
        sock.close()
PY
python3 "$ROOT_DIR/tool/android_protection_fixture.py" --relay-readiness > "$OUT_DIR/protection-fixture.log" 2>&1 &
FIXTURE_PID=$!
DNS_FIXTURE_ARGS=()
if [ -n "$NATIVE_DNS_PREVIEW" ]; then DNS_FIXTURE_ARGS=(--native-preview); fi
python3 "$ROOT_DIR/tool/android_dns_fixture.py" --events "$OUT_DIR/dns-events.jsonl" ${DNS_FIXTURE_ARGS[@]+"${DNS_FIXTURE_ARGS[@]}"} > "$OUT_DIR/dns-fixture.log" 2>&1 &
DNS_PID=$!
python3 - "$FIXTURE_PID" "$DNS_PID" "$OUT_DIR" "$NATIVE_DNS_PREVIEW" <<'PY'
import os, pathlib, socket, sys, time
pids = [int(value) for value in sys.argv[1:3]]
directory = pathlib.Path(sys.argv[3])
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    for pid in pids:
        os.kill(pid, 0)
    for name in ('protection-fixture.log', 'dns-fixture.log'):
        if 'Traceback' in (directory / name).read_text():
            raise SystemExit('Fixture startup failed; inspect ' + str(directory / name))
    try:
        ports = [18080, 18083, 18280, 18281, 18282, 18283] + ([18284, 18285] if sys.argv[4] else [])
        for port in ports:
            with socket.create_connection(('127.0.0.1', port), timeout=.5):
                pass
        break
    except OSError:
        time.sleep(.1)
else:
    raise SystemExit('Loopback fixture readiness timed out.')
PY

instrument() {
  local label="$1" selection="$2" expected="$3" allow_skips="$4"
  shift 4
  PHASE="$label"
  echo "Running $label..."
  bounded 600 "$OUT_DIR/$label.log" "$ADB" -s "$SERIAL" shell am instrument -w -r \
    -e class "$selection" "$@" "$RUNNER"
  # ADB often exits zero for failed tests or an instrumentation crash. Require
  # every expected test to finish successfully, plus the final JUnit summary.
  python3 - "$OUT_DIR/$label.log" "$expected" "$allow_skips" "$CHECKS" "$label" <<'PY'
import pathlib, re, sys
text = pathlib.Path(sys.argv[1]).read_text(errors='replace')
expected = int(sys.argv[2])
allow_skips = sys.argv[3] == '1'
statuses = [int(value) for value in re.findall(r'^INSTRUMENTATION_STATUS_CODE:\s*(-?\d+)\s*$', text, re.M)]
summaries = re.findall(r'^OK \((\d+) tests?\)\s*$', text, re.M)
codes = re.findall(r'^INSTRUMENTATION_CODE:\s*(-?\d+)\s*$', text, re.M)
passed, skipped = statuses.count(0), statuses.count(-4)
good = (passed + skipped == expected and statuses.count(1) == expected and
        all(code in ((0, 1, -4) if allow_skips else (0, 1)) for code in statuses) and
        summaries == [str(expected)] and codes == ['-1'])
if re.search(r'INSTRUMENTATION_FAILED|INSTRUMENTATION_ABORTED|shortMsg=|FAILURES!!!|HARNESS_ERROR:', text):
    good = False
if not good:
    print(text, file=sys.stderr)
    raise SystemExit(f'Expected {expected} completed tests without failure; assumption skips allowed: {allow_skips}.')
with open(sys.argv[4], 'a') as checks:
    checks.write(f'{sys.argv[5]}\t{passed}\t{skipped}\n')
print(f'PASS: {passed} tests; SKIP: {skipped} unavailable transport prerequisites')
PY
  # Test @After issues STOP; force-stop also removes any leftover test service
  # before starting another suite without touching another application.
  bounded 20 "$OUT_DIR/$label-force-stop.log" "$ADB" -s "$SERIAL" shell am force-stop "$PACKAGE"
}

install_os_adversary() {
  PHASE=install-os-adversary
  bounded 20 "$OUT_DIR/os-always-on-baseline.log" "$ADB" -s "$SERIAL" shell settings --user 0 get secure always_on_vpn_app
  python3 - "$OUT_DIR/os-always-on-baseline.log" <<'PY'
import pathlib, sys
if pathlib.Path(sys.argv[1]).read_text().strip() not in ('', 'null'):
    raise SystemExit('OS policy acceptance requires a dedicated emulator with no existing always-on VPN.')
PY
  local java_dir="${JAVA_HOME:-}"
  if [ -z "$java_dir" ]; then
    java_dir="$(python3 - <<'PY'
import re, subprocess
result = subprocess.run(['java', '-XshowSettings:properties', '-version'],
                        capture_output=True, text=True, timeout=15, check=True)
match = re.search(r'^\s*java.home\s*=\s*(.+)$', result.stdout + result.stderr, re.M)
if match is None:
    raise SystemExit('Set JAVA_HOME to the JDK used to build the disposable adversary.')
print(match.group(1))
PY
)"
  fi
  bounded 300 "$OUT_DIR/install-os-adversary.log" python3 "$ROOT_DIR/tool/test_android_separate_uid.py" \
    --serial "$SERIAL" --sdk "$SDK_DIR" --java "$java_dir" --install-only
  python3 - "$OUT_DIR/install-os-adversary.log" "$ADVERSARY_PACKAGE" <<'PY'
import pathlib, sys
expected = 'Installed disposable probe: ' + sys.argv[2]
if expected not in pathlib.Path(sys.argv[1]).read_text().splitlines():
    raise SystemExit('Disposable adversary installation was not confirmed.')
PY
  ADVERSARY_INSTALLED=1
}

instrument native-options "$CLASS_PREFIX.NativeOptionsDeviceTest" 2 0
instrument native-quick-tile "$CLASS_PREFIX.NativeQuickTileDeviceTest" 3 0
instrument native-preview-broker "$CLASS_PREFIX.NativePreviewBrokerDeviceTest" 4 0
if [ -n "$NATIVE_DNS_PREVIEW" ]; then
  instrument native-preview-runtime "$CLASS_PREFIX.NativePreviewRuntimeDeviceTest" 2 0 -e previewSha256 "$NATIVE_DNS_PREVIEW_SHA"
fi
instrument native-authorization "$CLASS_PREFIX.NativeLocalAuthorizationTest" 4 0
instrument session-recovery "$CLASS_PREFIX.SessionRecoveryDeviceTest" 3 0
instrument session-replacement "$CLASS_PREFIX.SessionReplacementDeviceTest" 1 0
instrument port-compatibility "$CLASS_PREFIX.PortCompatibilityDeviceTest" 1 0
instrument session-delay "$CLASS_PREFIX.SessionDelayDeviceTest" 1 0
instrument caller-root-dns "$CLASS_PREFIX.CallerRootDnsDeviceTest" 3 0
HOST_CLASS="$CLASS_PREFIX.ProtectedHostTrafficTest"
instrument protected-host "$HOST_CLASS#hostUIDTCPAndUDPTraverseProxy,$HOST_CLASS#explicitHostExclusionAndProxyOnlyRemainExplicit,$HOST_CLASS#refusedProtectionStopsRuntimeBeforeVPN" 3 0
instrument controlled-domain-routing "$CLASS_PREFIX.ControlledDomainRoutingTest#sniffedDomainRulesSelectDirectAndProxyAndSurviveRecovery" 1 0
instrument network-handover "$HOST_CLASS#hostTrafficSurvivesWifiToCellularAndBack" 1 1

PHASE=capture-start
if [ "$CAPTURE_DNS" -eq 1 ]; then
  # The emulator console capture covers its cellular Ethernet backend. Modern
  # virtual Wi-Fi can bypass that capture, so exercise DNS on cellular and demand
  # positive proxy observations. Handover above independently covers Wi-Fi.
  # Reassert the modem's data registration after handover. Some emulator
  # images drop the cellular data call while Wi-Fi is preferred. The following
  # native transport assertion still fails if registration does not recover.
  bounded 20 "$OUT_DIR/capture-cellular-register.log" "$ADB" -s "$SERIAL" emu gsm data home
  bounded 20 "$OUT_DIR/capture-cellular-enable.log" "$ADB" -s "$SERIAL" shell svc data enable
  bounded 20 "$OUT_DIR/capture-cellular-retain.log" "$ADB" -s "$SERIAL" shell settings put global mobile_data_always_on 1
  CAPTURE_WIFI_DISABLED=1
  bounded 20 "$OUT_DIR/capture-wifi-disable.log" "$ADB" -s "$SERIAL" shell svc wifi disable
  python3 - "$ADB" "$SERIAL" <<'PY'
import subprocess, sys, time
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    result = subprocess.run([sys.argv[1], '-s', sys.argv[2], 'shell', 'cmd', 'wifi', 'status'],
                            capture_output=True, text=True, timeout=5, check=True)
    if 'Wifi is disabled' in result.stdout:
        break
    time.sleep(.2)
else:
    raise SystemExit('Emulator Wi-Fi remained active; physical capture would be incomplete.')
PY
  # The modem becomes available asynchronously after virtual Wi-Fi disconnects.
  # Require a real cellular transport before starting a WAN-only packet capture.
  instrument capture-transport "$HOST_CLASS#emulatorCellularCaptureTransportReady" 1 0
  start_capture
fi
instrument system-dns "$CLASS_PREFIX.ProtectedSystemDnsTest" 4 0
if [ "$CAPTURE_DNS" -eq 1 ]; then
  PHASE=capture-verification
  stop_capture
  bounded 60 "$OUT_DIR/dns-capture-verification.json" python3 "$ROOT_DIR/tool/verify_android_dns_capture.py" "$OUT_DIR/physical-dns.pcap"
  printf 'physical-dns-capture\t1\t0\n' >> "$CHECKS"
  bounded 20 "$OUT_DIR/capture-wifi-restore.log" "$ADB" -s "$SERIAL" shell svc wifi enable
  bounded 20 "$OUT_DIR/capture-wifi-reconnect.log" "$ADB" -s "$SERIAL" shell cmd wifi connect-network AndroidWifi open
  python3 - "$ADB" "$SERIAL" <<'PY'
import subprocess, sys, time
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    result = subprocess.run([sys.argv[1], '-s', sys.argv[2], 'shell', 'cmd', 'wifi', 'status'],
                            capture_output=True, text=True, timeout=5, check=True)
    if 'Wifi is connected to' in result.stdout:
        break
    time.sleep(.5)
else:
    raise SystemExit('Emulator Wi-Fi failed to reconnect after physical capture.')
PY
  CAPTURE_WIFI_DISABLED=0
fi
instrument physical-dns "$HOST_CLASS#physicalNetworkResolverControl" 1 0 -e checkPhysicalDns true
install_os_adversary
instrument system-vpn-policy "$CLASS_PREFIX.SessionSystemPolicyDeviceTest" 4 0
if [ -n "$NATIVE_TUN_PREVIEW" ]; then
  # The preceding OS Forget test may revoke consent. Restore only this
  # disposable package's explicitly authorized permission, never OS lockdown.
  PHASE=native-preview-vpn-preconditions
  bounded 20 "$OUT_DIR/native-preview-vpn-owner.log" "$ADB" -s "$SERIAL" shell settings --user 0 get secure always_on_vpn_app
  python3 - "$OUT_DIR/native-preview-vpn-owner.log" <<'PY'
import pathlib,sys
if pathlib.Path(sys.argv[1]).read_text().strip() != 'null':
    raise SystemExit('The ordinary OS-policy suite did not release its VPN owner.')
PY
  bounded 20 "$OUT_DIR/native-preview-vpn-stop-ordinary.log" "$ADB" -s "$SERIAL" shell am force-stop "$PACKAGE"
  PHASE=native-preview-vpn-build
  (cd "$ROOT_DIR/example/android" && bounded 1200 "$OUT_DIR/native-preview-vpn-gradle-build.log" ./gradlew \
    :flutter_vless_android:assembleDebugAndroidTest \
    "${PREVIEW_GRADLE_ARGS[@]}" "-PflutterVlessNativeTunPreviewDir=$NATIVE_TUN_PREVIEW" \
    -PflutterVlessOfficialRuntimeVerification=true --dependency-verification=strict --console=plain --stacktrace)
  PHASE=native-preview-vpn-verify-apk
  bounded 30 "$OUT_DIR/native-preview-vpn-apk-verification.json" python3 "$ROOT_DIR/tool/verify_android_preview_apk.py" \
    --apk "$APK" --core-verification "$OUT_DIR/native-preview-verification.json" \
    --tun-verification "$OUT_DIR/native-tun-preview-verification.json"
  PHASE=native-preview-vpn-install
  bounded 90 "$OUT_DIR/native-preview-vpn-install.log" "$ADB" -s "$SERIAL" install -r -t "$APK"
  bounded 20 "$OUT_DIR/native-preview-vpn-stop-updated.log" "$ADB" -s "$SERIAL" shell am force-stop "$PACKAGE"
  bounded 20 "$OUT_DIR/native-preview-vpn-authorize.log" "$ADB" -s "$SERIAL" shell appops set "$PACKAGE" ACTIVATE_VPN allow
  bounded 20 "$OUT_DIR/native-preview-vpn-permission.log" "$ADB" -s "$SERIAL" shell appops get "$PACKAGE" ACTIVATE_VPN
  python3 - "$OUT_DIR/native-preview-vpn-permission.log" <<'PY'
import pathlib,re,sys
if not re.search(r'ACTIVATE_VPN:\s*allow\b', pathlib.Path(sys.argv[1]).read_text()):
    raise SystemExit('The disposable TUN suite did not receive VPN consent.')
PY
  python3 - "$ADB" "$SERIAL" > "$OUT_DIR/native-preview-browser-ownership.json" <<'PY'
import json,subprocess,sys
result = subprocess.run([sys.argv[1], '-s', sys.argv[2], 'shell', 'ps', '-A', '-o', 'NAME'],
                        text=True,capture_output=True,timeout=10)
lines = result.stdout.splitlines()
if result.returncode != 0 or result.stderr.strip() or not lines or lines[0].strip() != 'NAME':
    raise SystemExit('The dedicated browser fixture could not inventory running process names.')
if any(name.strip() == 'com.android.chrome' or name.strip().startswith('com.android.chrome:') for name in lines[1:]):
    raise SystemExit('The dedicated browser fixture requires Chrome to have no existing process.')
print(json.dumps({'package':'com.android.chrome','preexisting_process':False,'fixture_may_own_browser':True}))
PY
  bounded 20 "$OUT_DIR/native-preview-vpn-wifi-baseline.log" "$ADB" -s "$SERIAL" shell cmd wifi status
  python3 - "$OUT_DIR/native-preview-vpn-wifi-baseline.log" <<'PY'
import pathlib,sys
text = pathlib.Path(sys.argv[1]).read_text()
if 'Wifi is enabled' not in text or 'Wifi is connected to' not in text or 'AndroidWifi' not in text:
    raise SystemExit('The dedicated TUN handover fixture requires its connected AndroidWifi baseline.')
PY
  TUN_BROWSER_OWNED=1
  TUN_WIFI_RESTORE=1
  instrument native-preview-vpn "$CLASS_PREFIX.NativePreviewVpnDeviceTest" 5 0 \
    -e previewSha256 "$NATIVE_DNS_PREVIEW_SHA" -e forwarderSha256 "$NATIVE_TUN_PREVIEW_SHA"
  bounded 20 "$OUT_DIR/native-preview-vpn-browser-stop.log" "$ADB" -s "$SERIAL" shell am force-stop com.android.chrome
  TUN_BROWSER_OWNED=0
fi
PHASE=complete
