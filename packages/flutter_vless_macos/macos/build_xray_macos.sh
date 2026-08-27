#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
XRAY_MOBILE_DIR="${XRAY_MOBILE_DIR:-$REPO_ROOT/third_party/xray-mobile}"
XRAY_CORE_VERSION="${XRAY_CORE_VERSION:-v26.7.28}"
XRAY_CORE_REF="${XRAY_CORE_REF:-5ca6f4b7d4dc20a881d4330e498892697627ec0c}"
XRAY_MACOS_DEPLOYMENT_TARGET="${XRAY_MACOS_DEPLOYMENT_TARGET:-13.0}"
BUILD_DIR="${BUILD_DIR:-$SCRIPT_DIR/build_xray_macos}"
OUTPUT_XCFRAMEWORK="${OUTPUT_XCFRAMEWORK:-$SCRIPT_DIR/XRay.xcframework}"

export MACOSX_DEPLOYMENT_TARGET="$XRAY_MACOS_DEPLOYMENT_TARGET"
export CGO_CFLAGS="${CGO_CFLAGS:-} -mmacosx-version-min=$XRAY_MACOS_DEPLOYMENT_TARGET"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:-} -mmacosx-version-min=$XRAY_MACOS_DEPLOYMENT_TARGET"
export CGO_LDFLAGS="${CGO_LDFLAGS:-} -mmacosx-version-min=$XRAY_MACOS_DEPLOYMENT_TARGET"

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

if ! xcrun --sdk macosx --show-sdk-path >/dev/null 2>&1; then
    echo "Error: full Xcode with macOS SDK is required. Command Line Tools are not enough."
    exit 1
fi

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Use a temporary name for gomobile output to avoid confusion
GOMOBILE_XCFW="$BUILD_DIR/Gomobile.xcframework"

if [ ! -f "$XRAY_MOBILE_DIR/go.mod" ]; then
    echo "Error: vendored xray-mobile source not found at $XRAY_MOBILE_DIR"
    exit 1
fi

mkdir -p "$BUILD_DIR/xray-mobile"
cp -R "$XRAY_MOBILE_DIR"/. "$BUILD_DIR/xray-mobile"
cd "$BUILD_DIR/xray-mobile"
echo "Using vendored xray-mobile source from $XRAY_MOBILE_DIR"

# Xray-core uses calendar release tags but keeps the original module path.
go get "github.com/xtls/xray-core@$XRAY_CORE_REF"
go get -tool golang.org/x/mobile/cmd/gobind
go mod tidy

# Verify our file compiles before proceeding
echo "Verifying Go compilation..."
go build ./... && echo "Go build OK" || { echo "ERROR: Go build failed"; exit 1; }

gomobile bind \
    -a \
    -ldflags="-s -w -extldflags -lresolv" \
    -target=macos \
    -o "$GOMOBILE_XCFW" \
    github.com/EbrahimTahernejad/xray-mobile

echo "gomobile bind completed. Rebuilding as static-library xcframework..."

# --- Find the framework inside the gomobile-produced xcframework ---
# gomobile names the .framework after the -o filename, so we need to discover it.
SLICE_DIR=$(find "$GOMOBILE_XCFW" -type d -name "macos-*" | head -1)
if [ -z "$SLICE_DIR" ]; then
    echo "Error: no macos slice found in $GOMOBILE_XCFW"
    exit 1
fi

# Find the .framework inside the slice
FW_DIR=$(find "$SLICE_DIR" -maxdepth 1 -type d -name "*.framework" | head -1)
if [ -z "$FW_DIR" ]; then
    echo "Error: no .framework found in $SLICE_DIR"
    exit 1
fi
FW_NAME=$(basename "$FW_DIR" .framework)
echo "Found framework: $FW_NAME in $FW_DIR"

# --- Extract static archive and headers ---
STAGING="$BUILD_DIR/staging"
rm -rf "$STAGING"
mkdir -p "$STAGING/Headers" "$STAGING/Modules"

# Find the static archive binary (could be in Versions/A/ or at top level)
BINARY=""
if [ -f "$FW_DIR/Versions/A/$FW_NAME" ]; then
    BINARY="$FW_DIR/Versions/A/$FW_NAME"
elif [ -f "$FW_DIR/$FW_NAME" ]; then
    BINARY="$FW_DIR/$FW_NAME"
fi

if [ -z "$BINARY" ]; then
    echo "Error: could not find binary '$FW_NAME' inside $FW_DIR"
    find "$FW_DIR" -type f
    exit 1
fi

cp "$BINARY" "$STAGING/libXRay.a"
echo "Extracted static archive from $BINARY"

# Copy headers
HEADERS_DIR=""
if [ -d "$FW_DIR/Versions/A/Headers" ]; then
    HEADERS_DIR="$FW_DIR/Versions/A/Headers"
elif [ -d "$FW_DIR/Headers" ]; then
    HEADERS_DIR="$FW_DIR/Headers"
fi
if [ -n "$HEADERS_DIR" ]; then
    cp "$HEADERS_DIR/"*.h "$STAGING/Headers/"
fi

# Create modulemap for a non-framework (static library) module
cat > "$STAGING/Modules/module.modulemap" <<'EOF'
module XRay {
    header "ref.h"
    header "XRay.objc.h"
    header "Universe.objc.h"
    export *
}
EOF

# Also create an umbrella header
# Check what the gomobile umbrella header looks like
UMBRELLA="$STAGING/Headers/XRay.h"
if [ ! -f "$UMBRELLA" ]; then
    # The umbrella header may have been named after the framework
    if [ -f "$STAGING/Headers/${FW_NAME}.h" ]; then
        cp "$STAGING/Headers/${FW_NAME}.h" "$UMBRELLA"
    else
        cat > "$UMBRELLA" <<'HEOF'
#import "ref.h"
#import "XRay.objc.h"
#import "Universe.objc.h"
HEOF
    fi
fi

# --- Create the static-library xcframework ---
rm -rf "$OUTPUT_XCFRAMEWORK"
xcodebuild -create-xcframework \
    -library "$STAGING/libXRay.a" \
    -headers "$STAGING/Headers" \
    -output "$OUTPUT_XCFRAMEWORK"

# Copy modulemap into the final xcframework slice
FINAL_SLICE=$(find "$OUTPUT_XCFRAMEWORK" -type d -name "macos-*" | head -1)
if [ -n "$FINAL_SLICE" ]; then
    mkdir -p "$FINAL_SLICE/Modules"
    cp "$STAGING/Modules/module.modulemap" "$FINAL_SLICE/Modules/module.modulemap"
fi

echo ""
echo "=== SUCCESS ==="
echo "Created $OUTPUT_XCFRAMEWORK (static library xcframework)"
echo ""
echo "Contents:"
find "$OUTPUT_XCFRAMEWORK" -type f | sed "s|$OUTPUT_XCFRAMEWORK/||"
