#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
XRAY_RUNTIME_VERSION="${XRAY_RUNTIME_VERSION:-26.9.9-protect1}"
if [ "$XRAY_RUNTIME_VERSION" != "26.9.9-protect1" ] || [ -n "${FLUTTER_VLESS_ANDROID_RUNTIME_REPO:-}" ] || [ -n "${ORG_GRADLE_PROJECT_flutterVlessAndroidRuntimeRepo:-}" ] ||
   { [ -n "${ORG_GRADLE_PROJECT_flutterVlessXrayRuntimeVersion:-}" ] && [ "$ORG_GRADLE_PROJECT_flutterVlessXrayRuntimeVersion" != "26.9.9-protect1" ]; }; then
  echo "Official runtime verification rejects repository/version overrides" >&2
  exit 1
fi
XRAY_CORE_VERSION="${XRAY_CORE_VERSION:-26.9.9}"
MAVEN_BASE_URL="https://repo1.maven.org/maven2/dev/tfox/fluttervless/xray-android/$XRAY_RUNTIME_VERSION"
MAVEN_CENTRAL_RETRY_SECONDS="${MAVEN_CENTRAL_RETRY_SECONDS:-600}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"

if [ -d "/Applications/Android Studio.app/Contents/jbr/Contents/Home" ] && [ -z "${JAVA_HOME:-}" ]; then
  export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
fi

if [ -n "${JAVA_HOME:-}" ]; then
  export PATH="$JAVA_HOME/bin:$PATH"
fi
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"

AAR_PATH="$TMP_DIR/xray-android-$XRAY_RUNTIME_VERSION.aar"
POM_URL="$MAVEN_BASE_URL/xray-android-$XRAY_RUNTIME_VERSION.pom"
AAR_URL="$MAVEN_BASE_URL/xray-android-$XRAY_RUNTIME_VERSION.aar"

download_with_retry() {
  local url="$1"
  local output="$2"
  local deadline=$((SECONDS + MAVEN_CENTRAL_RETRY_SECONDS))

  until curl --fail --silent --show-error --location "$url" --output "$output"; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "Timed out waiting for Maven Central artifact: $url" >&2
      return 1
    fi
    echo "Waiting for Maven Central artifact: $url" >&2
    sleep 15
  done
}

download_with_retry "$POM_URL" "$TMP_DIR/runtime.pom"
download_with_retry "$AAR_URL" "$AAR_PATH"
python3 "$ROOT_DIR/tool/test_android_dependency_verification.py" "$AAR_PATH" "$TMP_DIR/runtime.pom"

for entry in \
  "jni/arm64-v8a/libxray.so" \
  "jni/arm64-v8a/libtun2socks.so" \
  "jni/armeabi-v7a/libxray.so" \
  "jni/armeabi-v7a/libtun2socks.so" \
  "jni/x86/libxray.so" \
  "jni/x86/libtun2socks.so" \
  "jni/x86_64/libxray.so" \
  "jni/x86_64/libtun2socks.so" \
  "assets/geoip.dat" \
  "assets/geosite.dat"; do
  if ! unzip -l "$AAR_PATH" "$entry" >/dev/null 2>&1; then
    echo "Maven Central AAR is missing $entry" >&2
    exit 1
  fi
done

for entry in \
  "jni/arm64-v8a/libxray.so" \
  "jni/armeabi-v7a/libxray.so" \
  "jni/x86/libxray.so" \
  "jni/x86_64/libxray.so"; do
  extracted="$TMP_DIR/maven-$(basename "$(dirname "$entry")")-libxray.so"
  version_strings="$extracted.strings"
  unzip -p "$AAR_PATH" "$entry" > "$extracted"
  strings "$extracted" > "$version_strings"
  if ! grep -q "v$XRAY_CORE_VERSION" "$version_strings"; then
    echo "Maven Central AAR $entry does not report Xray v$XRAY_CORE_VERSION" >&2
    exit 1
  fi
done

(
  cd "$ROOT_DIR/example"
  flutter pub get
)

DEPENDENCIES_LOG="$TMP_DIR/dependencies.log"
# Exercise the actual example settings gate, independently of the shell guards.
assert_rejected_override() {
  local name="$1" expected="$2"
  shift 2
  if (cd "$ROOT_DIR/example/android" && ./gradlew help \
      -PflutterVlessOfficialRuntimeVerification=true "$@") > "$TMP_DIR/$name.log" 2>&1; then
    echo "Official runtime unexpectedly accepted $name" >&2
    return 1
  fi
  if ! grep -q "$expected" "$TMP_DIR/$name.log"; then
    cat "$TMP_DIR/$name.log" >&2
    echo "The negative check failed for an unrelated reason: $name" >&2
    return 1
  fi
  echo "PASS official settings rejection: $name"
}
assert_rejected_override repository 'rejects repository overrides' -PflutterVlessAndroidRuntimeRepo="$TMP_DIR/repo" --dependency-verification=strict
assert_rejected_override version 'rejects version overrides' -PflutterVlessXrayRuntimeVersion=unreviewed --dependency-verification=strict
assert_rejected_override verification-mode 'requires strict dependency verification' --dependency-verification=off
(
  cd "$ROOT_DIR/example/android"
  ./gradlew :flutter_vless_android:dependencies \
    --configuration debugRuntimeClasspath \
    -PflutterVlessXrayRuntimeVersion="$XRAY_RUNTIME_VERSION" \
    -PflutterVlessOfficialRuntimeVerification=true --dependency-verification=strict \
    > "$DEPENDENCIES_LOG"
)

if ! grep -q "dev.tfox.fluttervless:xray-android:$XRAY_RUNTIME_VERSION" "$DEPENDENCIES_LOG"; then
  echo "Gradle did not resolve dev.tfox.fluttervless:xray-android:$XRAY_RUNTIME_VERSION from Maven Central" >&2
  exit 1
fi

(
  cd "$ROOT_DIR/example/android"
  ./gradlew :app:assembleDebug \
    -PflutterVlessXrayRuntimeVersion="$XRAY_RUNTIME_VERSION" \
    -PflutterVlessOfficialRuntimeVerification=true --dependency-verification=strict
)

# Check the output of this build, not an older APK elsewhere under build/.
APK_PATH="$ROOT_DIR/example/build/app/outputs/apk/debug/app-debug.apk"
if [ ! -f "$APK_PATH" ]; then
  echo "Could not find the example debug APK after Android build: $APK_PATH" >&2
  exit 1
fi

python3 - "$AAR_PATH" "$APK_PATH" <<'PYVERIFY'
import os, subprocess, sys, tempfile, zipfile
from pathlib import Path
# AGP runs the Android NDK stripper even for already-stripped libraries, which
# can rewrite non-runtime ELF string tables. Require exact published bytes or
# reproduce that transformation; never accept a version-string-only match.
ndk = Path(os.environ["ANDROID_HOME"]) / "ndk"
strippers = sorted(p for p in ndk.glob("*/toolchains/llvm/prebuilt/*/bin/llvm-strip*")
                   if p.name in ("llvm-strip", "llvm-strip.exe"))
def matches_packaged(source, packaged):
    if source == packaged:
        return True
    with tempfile.TemporaryDirectory(prefix="xray-strip-verification-") as directory:
        raw, stripped = Path(directory) / "source.so", Path(directory) / "stripped.so"
        raw.write_bytes(source)
        for tool in strippers:
            result = subprocess.run([str(tool), "--strip-unneeded", "-o", str(stripped), str(raw)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0 and stripped.read_bytes() == packaged:
                return True
    return False
with zipfile.ZipFile(sys.argv[1]) as aar, zipfile.ZipFile(sys.argv[2]) as apk:
    for abi in ['arm64-v8a', 'armeabi-v7a', 'x86_64']:
        for library in ['libxray.so', 'libtun2socks.so']:
            assert matches_packaged(aar.read(f'jni/{abi}/{library}'), apk.read(f'lib/{abi}/{library}')), f'Packaged runtime differs from published bytes/NDK strip output: {abi}/{library}'
    for asset in ['geoip.dat', 'geosite.dat']:
        assert apk.read(f'assets/{asset}') == aar.read(f'assets/{asset}'), f'Packaged geodata differs: {asset}'
print('PASS: APK runtime matches published Maven bytes or their exact NDK strip output; geodata matches byte for byte')
PYVERIFY

for entry in \
  "lib/arm64-v8a/libxray.so" \
  "lib/arm64-v8a/libtun2socks.so" \
  "lib/armeabi-v7a/libxray.so" \
  "lib/armeabi-v7a/libtun2socks.so" \
  "lib/x86_64/libxray.so" \
  "lib/x86_64/libtun2socks.so" \
  "assets/geoip.dat" \
  "assets/geosite.dat"; do
  if ! unzip -l "$APK_PATH" "$entry" >/dev/null 2>&1; then
    echo "Debug APK is missing $entry" >&2
    exit 1
  fi
done

for entry in \
  "lib/arm64-v8a/libxray.so" \
  "lib/armeabi-v7a/libxray.so" \
  "lib/x86_64/libxray.so"; do
  extracted="$TMP_DIR/apk-$(basename "$(dirname "$entry")")-libxray.so"
  version_strings="$extracted.strings"
  unzip -p "$APK_PATH" "$entry" > "$extracted"
  strings "$extracted" > "$version_strings"
  if ! grep -q "v$XRAY_CORE_VERSION" "$version_strings"; then
    echo "Debug APK $entry does not report Xray v$XRAY_CORE_VERSION" >&2
    exit 1
  fi
done

echo "Maven Central runtime smoke passed: $APK_PATH"
