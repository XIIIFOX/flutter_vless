#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROBE_DIR="$ROOT_DIR/build/ios_operation_queue_probe"
mkdir -p "$PROBE_DIR"
xcrun swiftc -O -parse-as-library \
  "$ROOT_DIR/ios/flutter_vless/Sources/flutter_vless/NativeOperationQueue.swift" \
  "$ROOT_DIR/tool/fixtures/ios_operation_queue/main.swift" \
  -o "$PROBE_DIR/probe"
"$PROBE_DIR/probe"
