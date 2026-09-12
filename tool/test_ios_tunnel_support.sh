#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$ROOT_DIR/build/ios_tunnel_support_swiftpm"

rm -rf "$WORK_DIR"
mkdir -p \
  "$WORK_DIR/Sources/flutter_vless_privacy" \
  "$WORK_DIR/Sources/flutter_vless_tunnel_support" \
  "$WORK_DIR/Tests/flutter_vless_tunnel_supportTests"

cp "$ROOT_DIR"/ios/flutter_vless/Sources/flutter_vless_privacy/*.swift \
  "$WORK_DIR/Sources/flutter_vless_privacy/"
cp "$ROOT_DIR"/ios/flutter_vless/Sources/flutter_vless_tunnel_support/*.swift \
  "$WORK_DIR/Sources/flutter_vless_tunnel_support/"
cp "$ROOT_DIR"/ios/flutter_vless/Tests/flutter_vless_tunnel_supportTests/*.swift \
  "$WORK_DIR/Tests/flutter_vless_tunnel_supportTests/"

cat > "$WORK_DIR/Package.swift" <<'SWIFT'
// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "flutter_vless_tunnel_support_test_package",
    platforms: [
        .macOS("13.0")
    ],
    products: [
        .library(
            name: "flutter_vless_tunnel_support",
            targets: ["flutter_vless_tunnel_support"]
        )
    ],
    targets: [
        .target(name: "flutter_vless_privacy"),
        .target(name: "flutter_vless_tunnel_support", dependencies: ["flutter_vless_privacy"]),
        .testTarget(
            name: "flutter_vless_tunnel_supportTests",
            dependencies: ["flutter_vless_tunnel_support"]
        )
    ]
)
SWIFT

swift test --package-path "$WORK_DIR" "$@"
