#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

for store in \
  "$REPO_ROOT/ios/flutter_vless/Sources/flutter_vless/BoundedNativeLogStore.swift" \
  "$REPO_ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos/BoundedNativeLogStore.swift"
do
  output="$BUILD_DIR/$(basename "$(dirname "$store")")-test"
  swiftc "$store" "$SCRIPT_DIR/bounded_native_log_store_test.swift" -o "$output"
  "$output"
done
