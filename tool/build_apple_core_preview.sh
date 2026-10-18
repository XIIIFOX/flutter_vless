#!/usr/bin/env bash
# Build-only local artifacts. Never creates or uploads a GitHub release.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLATFORM="${1:?Usage: build_apple_core_preview.sh ios|macos OUTPUT_DIRECTORY}"
OUTPUT="${2:?An explicit output directory is required}"
case "$PLATFORM" in ios|macos) ;; *) echo 'Expected ios or macos' >&2; exit 2 ;; esac
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd)"
test ! -e "$OUTPUT/XRay.xcframework" || { echo 'Output already exists; preserve or remove it explicitly' >&2; exit 2; }
cd "$ROOT/third_party/xray-mobile"
mkdir -p "$OUTPUT/tools"
go build -mod=readonly -o "$OUTPUT/tools/gomobile" golang.org/x/mobile/cmd/gomobile
go build -mod=readonly -o "$OUTPUT/tools/gobind" golang.org/x/mobile/cmd/gobind
export PATH="$OUTPUT/tools:$PATH"
if [[ "$PLATFORM" == ios ]]; then
    gomobile bind -target=ios -iosversion=15.0 -ldflags='-s -w -extldflags -lresolv' \
        -o "$OUTPUT/XRay.xcframework" github.com/EbrahimTahernejad/xray-mobile
else
    mkdir -p "$OUTPUT/framework"
    gomobile bind -target=macos -macosversion=13.0 -ldflags='-s -w -extldflags -lresolv' \
        -o "$OUTPUT/framework/XRay.xcframework" github.com/EbrahimTahernejad/xray-mobile
    FRAMEWORK="$OUTPUT/framework/XRay.xcframework/macos-arm64_x86_64/XRay.framework"
    # Keep the existing static-library XCFramework layout used by CXRay.
    cp -L "$FRAMEWORK/XRay" "$OUTPUT/libXRay.a"
    cp -RL "$FRAMEWORK/Headers" "$OUTPUT/Headers"
    xcodebuild -create-xcframework -library "$OUTPUT/libXRay.a" \
        -headers "$OUTPUT/Headers" -output "$OUTPUT/XRay.xcframework"
fi
python3 - "$OUTPUT" "$PLATFORM" <<'PY'
from pathlib import Path
import json, subprocess, sys
output, platform = Path(sys.argv[1]), sys.argv[2]
pin = subprocess.check_output(['go','list','-m','-f','{{.Version}}','github.com/xtls/xray-core'],text=True).strip()
assert pin.endswith('92ccc939aaf4'), 'Unexpected Xray Core pin'
headers=list((output/'XRay.xcframework').rglob('XRay.objc.h'))
assert headers and all('XRayCheckPrivate' in p.read_text() for p in headers), 'Missing preflight bridge'
(output/'preview.json').write_text(json.dumps({'platform':platform,'core':pin,'preflightABI':1,'published':False},indent=2)+'\n')
PY
echo "Built $PLATFORM preview: $OUTPUT/XRay.xcframework"
