#!/usr/bin/env bash
# CI-only iOS simulator HEV binary proof using the macOS bridge as a test adapter.
# This does not exercise the iOS provider's utun descriptor discovery or NE path.
# --compile-only builds the exact app without installing or executing it.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HEV_DIR="${1:?Pass the ios-arm64_x86_64-simulator directory of the shipped HevSocks5Tunnel.xcframework}"
MODE="${2:-}"
case "$MODE" in ''|--compile-only) ;; *) echo 'Unknown packet proof argument' >&2; exit 2 ;; esac
OUT="$ROOT/build/ios_packet_bridge_probe"
BUNDLE=dev.tfox.security-runtime-probe
mkdir -p "$OUT/Probe.app"
python3 - "$ROOT" "$OUT" <<'PY'
from pathlib import Path
import plistlib, sys
root,out=map(Path,sys.argv[1:])
fixture=(root/'tool/fixtures/macos_packet_bridge_probe.swift').read_text()
wrapper='''
import UIKit
final class PacketBridgeDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey:Any]?) -> Bool {
        DispatchQueue.global().async {
            do {
                try PacketBridgeProbe.main()
                print("HEV_IOS_SIMULATOR_PACKET_BRIDGE_PASS")
                fflush(stdout); exit(0)
            } catch {
                fputs("HEV_IOS_SIMULATOR_PACKET_BRIDGE_FAILED\\n", stderr)
                exit(1)
            }
        }
        return true
    }
}
UIApplicationMain(CommandLine.argc, CommandLine.unsafeArgv, nil, NSStringFromClass(PacketBridgeDelegate.self))
'''
(out/'main.swift').write_text(fixture+'\n'+wrapper)
with (out/'Probe.app/Info.plist').open('wb') as file:
    plistlib.dump({'CFBundleIdentifier':'dev.tfox.security-runtime-probe','CFBundleExecutable':'Probe',
        'CFBundleName':'HEV Packet Probe','CFBundlePackageType':'APPL','CFBundleVersion':'1',
        'CFBundleShortVersionString':'1.0','MinimumOSVersion':'15.0','LSRequiresIPhoneOS':True,
        'UIDeviceFamily':[1,2]},file)
PY
SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"
ARCH="$(uname -m)"
case "$ARCH" in arm64|x86_64) ;; *) echo "Unsupported simulator architecture: $ARCH" >&2; exit 1 ;; esac
xcrun swiftc -O -D PACKET_BRIDGE_IOS_APPLICATION -target "$ARCH-apple-ios15.0-simulator" -sdk "$SDK" \
    -I "$HEV_DIR/Headers" -L "$HEV_DIR" -lhev-socks5-tunnel -framework UIKit -framework NetworkExtension \
    "$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_tunnel_support/TunnelPacketBridge.swift" \
    "$OUT/main.swift" -o "$OUT/Probe.app/Probe"
echo 'PROBE_PHASE=ios-hev-compile-complete'
if [[ "$MODE" == --compile-only ]]; then exit 0; fi
[[ "${CI:-}" == true && "${GITHUB_ACTIONS:-}" == true ]] || {
    echo 'Actual HEV packet proof requires CI=true and GITHUB_ACTIONS=true' >&2; exit 1;
}
: "${SIMULATOR_UDID:?Set SIMULATOR_UDID to an already booted disposable iOS simulator}"
# Run sequentially after the privacy probe, which owns the same fixed bundle
# and has already uninstalled it. The existing supervisor knows this identity.
trap 'xcrun simctl uninstall "$SIMULATOR_UDID" "$BUNDLE" >/dev/null 2>&1 || true' EXIT
codesign --force --sign - "$OUT/Probe.app"
xcrun simctl install "$SIMULATOR_UDID" "$OUT/Probe.app"
python3 "$ROOT/tool/run_apple_runtime_probe.py" --timeout 120 --ios-simulator "$SIMULATOR_UDID" -- \
    xcrun simctl launch --console "$SIMULATOR_UDID" "$BUNDLE" 2>&1 | tee "$OUT/runtime.log"
python3 - "$OUT/runtime.log" <<'PY'
from pathlib import Path
import sys
text=Path(sys.argv[1]).read_text()
for marker in ['PASS bulk integrity: 8 MiB download',
    'PASS shipped HEV: IPv6 TCP exact target and nonce through IPv4 SOCKS and AF_INET6 packetFlow',
    'PASS shipped HEV: IPv6 UDP exact target and nonce through IPv4 SOCKS and AF_INET6 packetFlow',
    'PASS shipped HEV: packetFlow -> owned datagram bridge -> HEV TCP -> loopback SOCKS -> packetFlow; clean shutdown',
    'HEV_IOS_SIMULATOR_PACKET_BRIDGE_PASS']:
    assert marker in text, marker
assert 'FAIL' not in text, 'HEV packet proof reported failure'
print('PASS iOS simulator HEV binary with test adapter: IPv4 TCP bulk, IPv6 TCP/UDP over IPv4 proxy, clean shutdown')
PY
