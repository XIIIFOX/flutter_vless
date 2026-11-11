#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

XRAY_VERSION="${XRAY_VERSION:-v26.11.9}"
RELEASE_TAG="${RELEASE_TAG:-xray-macos-$XRAY_VERSION-r1}"
XCFRAMEWORK_PATH="${XCFRAMEWORK_PATH:-$REPO_ROOT/packages/flutter_vless_macos/macos/XRay.xcframework}"
OUTPUT_DIR="${OUTPUT_DIR:-$REPO_ROOT/build/xray-macos-release}"
NOTES_FILE="${NOTES_FILE:-$REPO_ROOT/doc/release/$RELEASE_TAG.md}"
ARCHIVE_PATH="$OUTPUT_DIR/XRay.xcframework.zip"

if [ ! -d "$XCFRAMEWORK_PATH" ]; then
  echo "Error: XRay.xcframework not found at $XCFRAMEWORK_PATH"
  echo "Build it first with: cd packages/flutter_vless_macos/macos && ./build_xray_macos.sh"
  exit 1
fi

PREPARATION_RECEIPT="${PREPARATION_RECEIPT:-$REPO_ROOT/build/xray_macos/classic-core-inputs.json}"
: "${SOURCE_HEAD:?Set SOURCE_HEAD to the exact committed producer revision}"
[[ "$XRAY_VERSION" == v26.11.9 && "$RELEASE_TAG" == xray-macos-v26.11.9-r1 ]] || { echo 'Unexpected canonical runtime release tag' >&2; exit 1; }
python3 "$REPO_ROOT/tool/package_apple_runtime_release.py" --platform macos \
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
     --title "XRay macOS $XRAY_VERSION" \\
     --notes-file "$NOTES_FILE"

   If this tag already exists, keep its assets unchanged and choose a new
   reviewed native revision; do not replace a published archive.

2. Update packages/flutter_vless_macos/macos/flutter_vless_macos/Package.swift and packages/flutter_vless_macos/macos/flutter_vless_macos.podspec with:

   url:      https://github.com/XIIIFOX/flutter_vless/releases/download/$RELEASE_TAG/XRay.xcframework.zip
   checksum: $CHECKSUM

EOF
