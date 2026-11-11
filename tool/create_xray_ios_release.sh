#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

XRAY_VERSION="${XRAY_VERSION:-v26.11.9}"
RELEASE_TAG="${RELEASE_TAG:-xray-ios-$XRAY_VERSION-r1}"
XCFRAMEWORK_PATH="${XCFRAMEWORK_PATH:-$REPO_ROOT/ios/XRay.xcframework}"
OUTPUT_DIR="${OUTPUT_DIR:-$REPO_ROOT/build/xray-ios-release}"
NOTES_FILE="${NOTES_FILE:-$REPO_ROOT/doc/release/$RELEASE_TAG.md}"
ARCHIVE_PATH="$OUTPUT_DIR/XRay.xcframework.zip"

if [ ! -d "$XCFRAMEWORK_PATH" ]; then
  echo "Error: XRay.xcframework not found at $XCFRAMEWORK_PATH"
  echo "Build it first with: cd ios && ./build_xray_ios.sh"
  exit 1
fi

PREPARATION_RECEIPT="${PREPARATION_RECEIPT:-$REPO_ROOT/ios/build_xray_ios/classic-core-inputs.json}"
: "${SOURCE_HEAD:?Set SOURCE_HEAD to the exact committed producer revision}"
[[ "$XRAY_VERSION" == v26.11.9 && "$RELEASE_TAG" == xray-ios-v26.11.9-r1 ]] || { echo 'Unexpected canonical runtime release tag' >&2; exit 1; }
python3 "$REPO_ROOT/tool/package_apple_runtime_release.py" --platform ios \
    --framework "$XCFRAMEWORK_PATH" --preparation "$PREPARATION_RECEIPT" \
    --output "$OUTPUT_DIR" --head "$SOURCE_HEAD"

CHECKSUM="$(swift package compute-checksum "$ARCHIVE_PATH")"
ARCHIVE_SIZE="$(du -h "$ARCHIVE_PATH" | awk '{print $1}')"

cat <<EOF
Created:  $ARCHIVE_PATH
Size:     $ARCHIVE_SIZE
Tag:      $RELEASE_TAG
Checksum: $CHECKSUM
Notes:    $NOTES_FILE

1. Create this new immutable GitHub prerelease:

   gh release create "$RELEASE_TAG" "$ARCHIVE_PATH" "$OUTPUT_DIR/manifest.json" "$OUTPUT_DIR/SHA256SUMS" \\
     --repo XIIIFOX/flutter_vless --target "$SOURCE_HEAD" --prerelease \\
     --title "XRay iOS $XRAY_VERSION" \\
     --notes-file "$NOTES_FILE"

   If this tag already exists, keep its assets unchanged and choose a new
   reviewed native revision; do not replace a published archive.

2. Update ios/flutter_vless/Package.swift and ios/flutter_vless.podspec with:

   url:      https://github.com/XIIIFOX/flutter_vless/releases/download/$RELEASE_TAG/XRay.xcframework.zip
   checksum: $CHECKSUM

EOF
