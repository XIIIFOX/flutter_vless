#!/usr/bin/env bash
# Pure cross-module codec checks. No Core, sockets, provider or device launch.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IOS="$ROOT/ios/flutter_vless/Sources/flutter_vless_privacy"
MAC="$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_privacy"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
cmp "$IOS/NativeRoutingSpec.swift" "$MAC/NativeRoutingSpec.swift"
for PLATFORM in ios macos; do
    if [[ "$PLATFORM" == ios ]]; then
        SOURCE="$IOS"
        MODULE=flutter_vless_privacy
        FLAGS=()
    else
        SOURCE="$MAC"
        MODULE=flutter_vless_macos_privacy
        FLAGS=(-DROUTING_MACOS)
    fi
    mkdir "$OUT/$PLATFORM"
    xcrun swiftc -O -parse-as-library -module-name "$MODULE" -emit-library -emit-module \
        -emit-module-path "$OUT/$PLATFORM/$MODULE.swiftmodule" \
        "$SOURCE/LocalProxyAccessPolicy.swift" "$SOURCE/XrayServiceTags.swift" "$SOURCE/NativeRoutingSpec.swift" \
        -o "$OUT/$PLATFORM/lib$MODULE.dylib"
    xcrun swiftc -O -parse-as-library ${FLAGS[@]+"${FLAGS[@]}"} -I "$OUT/$PLATFORM" -L "$OUT/$PLATFORM" \
        -l"$MODULE" -Xlinker -rpath -Xlinker "$OUT/$PLATFORM" \
        "$ROOT/tool/native_routing_spec_test.swift" -o "$OUT/$PLATFORM/probe"
    "$OUT/$PLATFORM/probe"
done
