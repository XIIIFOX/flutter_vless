#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Final releases are compiled in an owned CI tree. The stock-input path below
# remains available for historical fake-JVM fixtures, never for a new version.
if [ "${XRAY_BUILD_FRESH_RELEASE:-0}" = 1 ]; then
  test "${XRAY_RUNTIME_VERSION:-26.10.29-protect2}" = "26.10.29-protect2"
  test "${XRAY_CORE_VERSION:-26.10.29}" = "26.10.29"
  RELEASE_HEAD="$(git -C "$ROOT_DIR" rev-parse HEAD)"
  python3 "$ROOT_DIR/tool/build_android_runtime_preview.py" \
    --output "$ROOT_DIR/build/android-runtime-release" --head "$RELEASE_HEAD" --release
  python3 "$ROOT_DIR/tool/package_android_runtime_preview.py" \
    --preview "$ROOT_DIR/build/android-runtime-release" \
    --output "$ROOT_DIR/build/android-runtime-release-artifact" --head "$RELEASE_HEAD" --release
  python3 "$ROOT_DIR/tool/package_android_runtime_preview.py" \
    --preview "$ROOT_DIR/build/android-runtime-release" \
    --output "$ROOT_DIR/build/android-runtime-release-artifact" --head "$RELEASE_HEAD" --release --verify-only
  exit 0
fi
PROJECT_DIR="$ROOT_DIR/android_runtime/xray_android"
GRADLE_WRAPPER="${GRADLE_WRAPPER:-$ROOT_DIR/example/android/gradlew}"
XRAY_RUNTIME_VERSION="${XRAY_RUNTIME_VERSION:-26.10.17-protect1}"
XRAY_CORE_VERSION="${XRAY_CORE_VERSION:-26.10.17}"
if [ "$XRAY_RUNTIME_VERSION" != "26.10.17-protect1" ] || [ "$XRAY_CORE_VERSION" != "26.10.17" ]; then
  echo "New runtime versions require the fresh CI release producer; stock binaries cannot be relabelled." >&2
  exit 2
fi

python3 "$ROOT_DIR/tool/verify_android_runtime_inputs.py"

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"

if [ -d "/Applications/Android Studio.app/Contents/jbr/Contents/Home" ] && [ -z "${JAVA_HOME:-}" ]; then
  export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
fi

if [ -n "${JAVA_HOME:-}" ]; then
  export PATH="$JAVA_HOME/bin:$PATH"
fi

"$GRADLE_WRAPPER" \
  -p "$PROJECT_DIR" \
  -PxrayRuntimeVersion="$XRAY_RUNTIME_VERSION" \
  clean verifyRuntimeInputs publishReleasePublicationToLocalBuildRepository

REPO_DIR="$PROJECT_DIR/build/repo"
AAR_PATH="$REPO_DIR/dev/tfox/fluttervless/xray-android/$XRAY_RUNTIME_VERSION/xray-android-$XRAY_RUNTIME_VERSION.aar"
BUNDLE_PATH="$PROJECT_DIR/build/xray-android-$XRAY_RUNTIME_VERSION-central-bundle.zip"
CENTRAL_STAGING_DIR="$PROJECT_DIR/build/central-staging"
ARTIFACT_REPO_PATH="dev/tfox/fluttervless/xray-android"
VERSION_REPO_DIR="$REPO_DIR/$ARTIFACT_REPO_PATH/$XRAY_RUNTIME_VERSION"

if [ ! -f "$AAR_PATH" ]; then
  echo "AAR was not created at $AAR_PATH" >&2
  exit 1
fi

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
    echo "AAR is missing $entry" >&2
    exit 1
  fi
done

VERIFY_TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$VERIFY_TMP_DIR"' EXIT

for entry in \
  "jni/arm64-v8a/libxray.so" \
  "jni/armeabi-v7a/libxray.so" \
  "jni/x86/libxray.so" \
  "jni/x86_64/libxray.so"; do
  extracted="$VERIFY_TMP_DIR/$(basename "$(dirname "$entry")")-libxray.so"
  version_strings="$extracted.strings"
  unzip -p "$AAR_PATH" "$entry" > "$extracted"
  strings "$extracted" > "$version_strings"
  if ! grep -q "v$XRAY_CORE_VERSION" "$version_strings"; then
    echo "AAR $entry does not report Xray v$XRAY_CORE_VERSION" >&2
    exit 1
  fi
done

checksum_md5() {
  if command -v md5sum >/dev/null 2>&1; then
    md5sum "$1" | awk '{print $1}'
  else
    md5 -q "$1"
  fi
}

checksum_sha1() {
  if command -v sha1sum >/dev/null 2>&1; then
    sha1sum "$1" | awk '{print $1}'
  else
    shasum -a 1 "$1" | awk '{print $1}'
  fi
}

find "$REPO_DIR" -type f -name 'maven-metadata.xml*' -delete
find "$REPO_DIR" -type f -name '*.module*' -delete

while IFS= read -r -d '' artifact; do
  checksum_md5 "$artifact" > "$artifact.md5"
  checksum_sha1 "$artifact" > "$artifact.sha1"
done < <(find "$REPO_DIR" -type f ! -name '*.md5' ! -name '*.sha1' ! -name '*.sha256' ! -name '*.sha512' -print0)

rm -f "$BUNDLE_PATH"
rm -rf "$CENTRAL_STAGING_DIR"
mkdir -p "$CENTRAL_STAGING_DIR/$ARTIFACT_REPO_PATH"
cp -R "$VERSION_REPO_DIR" "$CENTRAL_STAGING_DIR/$ARTIFACT_REPO_PATH/"
(cd "$CENTRAL_STAGING_DIR" && find dev -type f -print | LC_ALL=C sort | zip -q "$BUNDLE_PATH" -@)

echo "Android runtime AAR: $AAR_PATH"
echo "Local Maven repo: $REPO_DIR"
echo "Central bundle: $BUNDLE_PATH"
unzip -l "$BUNDLE_PATH"
