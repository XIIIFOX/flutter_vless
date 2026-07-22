#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
XRAY_MOBILE_DIR="${XRAY_MOBILE_DIR:-$REPO_ROOT/third_party/xray-mobile}"
XRAY_CORE_VERSION="${XRAY_CORE_VERSION:-v26.7.11}"
XRAY_CORE_REF="${XRAY_CORE_REF:-50231eaff98ccc31b5cbd247a721c16e97fe5ec1}"
IOS_VERSION="${IOS_VERSION:-15.0}"
BUILD_DIR="${BUILD_DIR:-$SCRIPT_DIR/build_xray_ios}"
OUTPUT_XCFRAMEWORK="${OUTPUT_XCFRAMEWORK:-$SCRIPT_DIR/XRay.xcframework}"

if ! command -v go >/dev/null 2>&1; then
    echo "Error: Go is required."
    exit 1
fi

if ! command -v gomobile >/dev/null 2>&1; then
    echo "gomobile not found, installing it with go install..."
    go install golang.org/x/mobile/cmd/gomobile@latest
    go install golang.org/x/mobile/cmd/gobind@latest
    export PATH="$HOME/go/bin:$PATH"
    gomobile init
fi

if ! xcrun --sdk iphoneos --show-sdk-path >/dev/null 2>&1; then
    echo "Error: full Xcode with iOS SDK is required. Command Line Tools are not enough."
    exit 1
fi

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

if [ ! -f "$XRAY_MOBILE_DIR/go.mod" ]; then
    echo "Error: vendored xray-mobile source not found at $XRAY_MOBILE_DIR"
    exit 1
fi

mkdir -p "$BUILD_DIR/xray-mobile"
cp -R "$XRAY_MOBILE_DIR"/. "$BUILD_DIR/xray-mobile"
cd "$BUILD_DIR/xray-mobile"
echo "Using vendored xray-mobile source from $XRAY_MOBILE_DIR"

# Xray-core uses calendar release tags but keeps the original module path.
# Pin by the release commit so Go resolves it to the matching v1.YYMMDD.0 module version.
go get "github.com/xtls/xray-core@$XRAY_CORE_REF"
go get -tool golang.org/x/mobile/cmd/gobind
go mod tidy

rm -rf "$OUTPUT_XCFRAMEWORK"
gomobile bind \
    -a \
    -ldflags="-s -w -extldflags -lresolv" \
    -target=ios \
    -iosversion="$IOS_VERSION" \
    -o "$OUTPUT_XCFRAMEWORK" \
    github.com/EbrahimTahernejad/xray-mobile

echo "Created $OUTPUT_XCFRAMEWORK"
