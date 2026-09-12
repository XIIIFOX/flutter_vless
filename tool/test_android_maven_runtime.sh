#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
XRAY_RUNTIME_VERSION="${XRAY_RUNTIME_VERSION:-26.7.28-protect1}"
XRAY_CORE_VERSION="${XRAY_CORE_VERSION:-26.7.28}"
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
(
  cd "$ROOT_DIR/example/android"
  ./gradlew :flutter_vless_android:dependencies \
    --configuration debugRuntimeClasspath \
    -PflutterVlessXrayRuntimeVersion="$XRAY_RUNTIME_VERSION" \
    > "$DEPENDENCIES_LOG"
)

if ! grep -q "dev.tfox.fluttervless:xray-android:$XRAY_RUNTIME_VERSION" "$DEPENDENCIES_LOG"; then
  echo "Gradle did not resolve dev.tfox.fluttervless:xray-android:$XRAY_RUNTIME_VERSION from Maven Central" >&2
  exit 1
fi

(
  cd "$ROOT_DIR/example/android"
  ./gradlew :app:assembleDebug \
    -PflutterVlessXrayRuntimeVersion="$XRAY_RUNTIME_VERSION"
)

APK_SEARCH_DIRS=()
for dir in "$ROOT_DIR/build" "$ROOT_DIR/example/build"; do
  if [ -d "$dir" ]; then
    APK_SEARCH_DIRS+=("$dir")
  fi
done

APK_PATH="$(
  find "${APK_SEARCH_DIRS[@]}" -type f -name 'app-debug.apk' -print | head -n 1
)"

if [ -z "$APK_PATH" ]; then
  echo "Could not find app-debug.apk after Android build" >&2
  exit 1
fi

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
