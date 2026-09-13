#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HEV_DIR="${1:?Pass the macos-arm64_x86_64 directory of the shipped HevSocks5Tunnel.xcframework}"
OUT="$ROOT/build/macos_packet_bridge_probe"
mkdir -p "$OUT"
xcrun swiftc -O -parse-as-library \
  -I "$HEV_DIR/Headers" -L "$HEV_DIR" -lhev-socks5-tunnel \
  "$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_tunnel_support/TunnelPacketBridge.swift" \
  "$ROOT/tool/fixtures/macos_packet_bridge_probe.swift" -o "$OUT/probe"
"$OUT/probe"
