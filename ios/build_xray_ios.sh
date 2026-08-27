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

GO_VERSION="$(go env GOVERSION)"
if [[ ! "$GO_VERSION" =~ ^go([0-9]+)\.([0-9]+) ]]; then
    echo "Error: unable to parse Go version '$GO_VERSION'. Go 1.27 or newer is required."
    exit 1
fi
GO_MAJOR="${BASH_REMATCH[1]}"
GO_MINOR="${BASH_REMATCH[2]}"
if [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 27 ]; }; then
    echo "Error: Go 1.27 or newer is required for the stdlib http2 layout used by the H2BUF patch."
    echo "Your Go version: $(go version)"
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

# ---------------------------------------------------------------------------
# H2BUF patch: cap the Go http2 client's per-stream upload scratch buffer.
#
# Why: Go's h2 client sizes this buffer as min(server-advertised
# SETTINGS_MAX_FRAME_SIZE, 512 KiB) and never shrinks it for streaming POSTs
# without Content-Length (the XHTTP uplink). Xray's XHTTP server advertises
# the Go default of 1 MiB, so every concurrent upload stream costs 512 KiB.
# Inside an iOS Network Extension (hard 50 MB limit) 35-45 concurrent streams
# exceed the budget and the extension is jetsam-killed. See issue #23.
#
# How: clone the live GOROOT (APFS copy-on-write, instant) and patch the
# stdlib file in the clone only; the system Go installation is never touched.
# The patch targets the Go >= 1.27 stdlib layout (http2 vendored at
# net/http/internal/http2); tested with Go 1.27. If the layout or the anchor
# line changes in a future Go release, the build fails loudly below instead
# of silently shipping an unpatched framework.
#
# Override the cap with H2BUF_CAP_KB (default 128; 16-512 accepted).
# ---------------------------------------------------------------------------
H2BUF_CAP_KB="${H2BUF_CAP_KB:-128}"
case "$H2BUF_CAP_KB" in
    ''|*[!0-9]*) echo "Error: H2BUF_CAP_KB must be a number (got '$H2BUF_CAP_KB')"; exit 1 ;;
esac
if [ "$H2BUF_CAP_KB" -lt 16 ] || [ "$H2BUF_CAP_KB" -gt 512 ]; then
    echo "Error: H2BUF_CAP_KB must be between 16 and 512 (got $H2BUF_CAP_KB)"
    exit 1
fi

GOROOT_LIVE="$(go env GOROOT)"
GOROOT_PATCHED="$BUILD_DIR/goroot-patched"
H2_REL="src/net/http/internal/http2/transport.go"
if [ ! -f "$GOROOT_LIVE/$H2_REL" ]; then
    echo "Error: $H2_REL not found in GOROOT ($GOROOT_LIVE)."
    echo "The H2BUF patch requires the Go >= 1.27 stdlib http2 layout."
    echo "Your Go version: $(go version)"
    exit 1
fi
rm -rf "$GOROOT_PATCHED"
cp -Rc "$GOROOT_LIVE" "$GOROOT_PATCHED" 2>/dev/null || cp -R "$GOROOT_LIVE" "$GOROOT_PATCHED"
# Toolchains downloaded through GOTOOLCHAIN live in the read-only module cache.
# Make only the temporary clone writable so it can be patched and removed later.
chmod -R u+w "$GOROOT_PATCHED"
H2_FILE="$GOROOT_PATCHED/$H2_REL"
H2BUF_CAP_KB="$H2BUF_CAP_KB" python3 - "$H2_FILE" <<'PYEOF'
import os, sys
path = sys.argv[1]
cap = os.environ["H2BUF_CAP_KB"]
src = open(path).read()
old = "const max = 512 << 10"
n = src.count(old)
if n != 1:
    sys.stderr.write(
        f"Error: expected exactly one occurrence of '{old}' in {path}, found {n}.\n"
        "The Go stdlib http2 source has changed; update the H2BUF patch anchor.\n")
    sys.exit(1)
open(path, "w").write(src.replace(old, f"const max = {cap} << 10 // H2BUF patch (flutter_vless issue #23)"))
print(f"H2BUF: capped h2 upload scratch buffer at {cap} KiB in GOROOT clone")
PYEOF
export GOROOT="$GOROOT_PATCHED"
export PATH="$GOROOT_PATCHED/bin:$PATH"
grep -q "H2BUF patch" "$H2_FILE" || { echo "Error: H2BUF patch verification failed"; exit 1; }
echo "H2BUF: building with $(go version) from patched GOROOT clone"

rm -rf "$OUTPUT_XCFRAMEWORK"
gomobile bind \
    -a \
    -ldflags="-s -w -extldflags -lresolv" \
    -target=ios \
    -iosversion="$IOS_VERSION" \
    -o "$OUTPUT_XCFRAMEWORK" \
    github.com/EbrahimTahernejad/xray-mobile

echo "Created $OUTPUT_XCFRAMEWORK"
