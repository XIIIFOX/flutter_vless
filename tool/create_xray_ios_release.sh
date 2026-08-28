#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

XRAY_VERSION="${XRAY_VERSION:-v26.7.28}"
RELEASE_TAG="${RELEASE_TAG:-xray-ios-$XRAY_VERSION-r2}"
XCFRAMEWORK_PATH="${XCFRAMEWORK_PATH:-$REPO_ROOT/ios/XRay.xcframework}"
OUTPUT_DIR="${OUTPUT_DIR:-$REPO_ROOT/build/xray-ios-release}"
NOTES_FILE="${NOTES_FILE:-$REPO_ROOT/doc/release/$RELEASE_TAG.md}"
ARCHIVE_PATH="$OUTPUT_DIR/XRay.xcframework.zip"

if [ ! -d "$XCFRAMEWORK_PATH" ]; then
  echo "Error: XRay.xcframework not found at $XCFRAMEWORK_PATH"
  echo "Build it first with: cd ios && ./build_xray_ios.sh"
  exit 1
fi

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

(
  cd "$(dirname "$XCFRAMEWORK_PATH")"
  /usr/bin/zip -r -X "$ARCHIVE_PATH" "$(basename "$XCFRAMEWORK_PATH")" >/dev/null
)

CHECKSUM="$(swift package compute-checksum "$ARCHIVE_PATH")"
ARCHIVE_SIZE="$(du -h "$ARCHIVE_PATH" | awk '{print $1}')"

cat <<EOF
Created:  $ARCHIVE_PATH
Size:     $ARCHIVE_SIZE
Tag:      $RELEASE_TAG
Checksum: $CHECKSUM
Notes:    $NOTES_FILE

1. Create or update this GitHub release:

   gh release create "$RELEASE_TAG" "$ARCHIVE_PATH" \\
     --repo XIIIFOX/flutter_vless \\
     --title "XRay iOS $XRAY_VERSION" \\
     --notes-file "$NOTES_FILE"

   If the release already exists:

   gh release edit "$RELEASE_TAG" \\
     --repo XIIIFOX/flutter_vless \\
     --notes-file "$NOTES_FILE"

   gh release upload "$RELEASE_TAG" "$ARCHIVE_PATH" \\
     --repo XIIIFOX/flutter_vless \\
     --clobber

2. Update ios/flutter_vless/Package.swift and ios/flutter_vless.podspec with:

   url:      https://github.com/XIIIFOX/flutter_vless/releases/download/$RELEASE_TAG/XRay.xcframework.zip
   checksum: $CHECKSUM

EOF
