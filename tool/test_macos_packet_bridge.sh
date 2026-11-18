#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HEV_DIR="${1:?Pass the macos-arm64_x86_64 directory of the shipped HevSocks5Tunnel.xcframework}"
MODE="${2:-}"
case "$MODE" in ''|--compile-only) ;; *) echo 'Unknown packet proof argument' >&2; exit 2 ;; esac
OUT="$ROOT/build/macos_packet_bridge_probe"
mkdir -p "$OUT"
xcrun swiftc -O -parse-as-library \
  -I "$HEV_DIR/Headers" -L "$HEV_DIR" -lhev-socks5-tunnel \
  "$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_tunnel_support/TunnelPacketBridge.swift" \
  "$ROOT/tool/fixtures/macos_packet_bridge_probe.swift" -o "$OUT/probe"
if [[ "$MODE" == --compile-only ]]; then exit 0; fi
[[ "${CI:-}" == true && "${GITHUB_ACTIONS:-}" == true ]] || {
  echo 'Actual HEV packet proof requires CI=true and GITHUB_ACTIONS=true' >&2; exit 1;
}
python3 "$ROOT/tool/run_apple_runtime_probe.py" --timeout 120 -- "$OUT/probe" 2>&1 | tee "$OUT/runtime.log"
python3 - "$OUT/runtime.log" <<'PY'
from pathlib import Path
import os, re, sys
text=Path(sys.argv[1]).read_text()
for marker in ['PASS bulk integrity: 8 MiB download',
    'PASS shipped HEV: IPv6 TCP exact target and nonce through IPv4 SOCKS and AF_INET6 packetFlow',
    'PASS shipped HEV: IPv6 UDP exact target and nonce through IPv4 SOCKS and AF_INET6 packetFlow',
    'PASS shipped HEV: packetFlow -> owned datagram bridge -> HEV TCP -> loopback SOCKS -> packetFlow; clean shutdown']:
    assert marker in text, marker
assert 'FAIL' not in text, 'HEV packet proof reported failure'
timing = re.findall(r'^APPLE_HEV_LIFECYCLE firstPacketMs=([0-9]+) stoppedMs=([0-9]+)$', text, re.M)
assert len(timing) == 1, 'Missing or duplicate macOS packet lifecycle timing'
first, stopped = map(int, timing[0])
assert first < 5000 and stopped < 5000, 'HEV packet lifecycle exceeded its deadline'
if summary := os.environ.get('GITHUB_STEP_SUMMARY'):
    with Path(summary).open('a', encoding='utf-8') as stream:
        stream.write(f'\n- macOS local HEV bridge returned its first packet in {first} ms and stopped in {stopped} ms.\n')
print('PASS macOS shipped HEV: IPv4 TCP bulk, IPv6 TCP/UDP over IPv4 proxy, clean shutdown')
PY
