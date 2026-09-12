#!/usr/bin/env bash
# Actual iOS simulator XRay runtime + native preparation modes, localhost only.
# Does not install a NetworkExtension or change routes/DNS/VPN. HEV is not tested.
set -euo pipefail
: "${SIMULATOR_UDID:?Set SIMULATOR_UDID to an already booted disposable iOS simulator}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/ios_privacy_runtime_probe"
BUNDLE=dev.tfox.security-runtime-probe
mkdir -p "$OUT/modules" "$OUT/Probe.app"
trap 'xcrun simctl uninstall "$SIMULATOR_UDID" "$BUNDLE" >/dev/null 2>&1 || true' EXIT
python3 - "$ROOT" "$OUT" <<'PY'
from pathlib import Path
import plistlib, sys
root,out=map(Path,sys.argv[1:])
source=(root/'ios/flutter_vless/Sources/flutter_vless/FlutterVlessPlugin.swift').read_text()
# Preserve actual runner implementations; no duplicated config transformation.
head=source[:source.index('public class FlutterVlessPlugin:')].replace('import Flutter\n','')
asset=source[source.index('private func configureXrayAssetLocation'):source.index('final class PacketTunnelManager:')]
harness=(root/'tool/fixtures/ios_privacy_probe.swift').read_text()
(out/'main.swift').write_text(head+asset+'\nimport flutter_vless_tunnel_support\n'+harness)
with (out/'Probe.app/Info.plist').open('wb') as file:
 plistlib.dump({'CFBundleIdentifier':'dev.tfox.security-runtime-probe','CFBundleExecutable':'Probe','CFBundleName':'Privacy Probe','CFBundlePackageType':'APPL','CFBundleVersion':'1','CFBundleShortVersionString':'1.0','MinimumOSVersion':'15.0','LSRequiresIPhoneOS':True,'UIDeviceFamily':[1,2],'NSAppTransportSecurity':{'NSAllowsArbitraryLoads':True}},file)
PY
SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"
COMMON=(-O -target arm64-apple-ios15.0-simulator -sdk "$SDK")
xcrun swiftc "${COMMON[@]}" -parse-as-library -module-name flutter_vless_privacy -emit-module -emit-object -whole-module-optimization -emit-module-path "$OUT/modules/flutter_vless_privacy.swiftmodule" "$ROOT"/ios/flutter_vless/Sources/flutter_vless_privacy/*.swift -o "$OUT/modules/privacy.o"
xcrun swiftc "${COMMON[@]}" -parse-as-library -I "$OUT/modules" -module-name flutter_vless_tunnel_support -emit-module -emit-object -whole-module-optimization -emit-module-path "$OUT/modules/flutter_vless_tunnel_support.swiftmodule" "$ROOT"/ios/flutter_vless/Sources/flutter_vless_tunnel_support/*.swift -o "$OUT/modules/support.o"
xcrun swiftc "${COMMON[@]}" -I "$OUT/modules" -F "$ROOT/ios/XRay.xcframework/ios-arm64_x86_64-simulator" -framework XRay -framework UIKit -lresolv "$OUT/main.swift" "$ROOT/ios/flutter_vless/Sources/flutter_vless/BoundedNativeLogStore.swift" "$OUT/modules/privacy.o" "$OUT/modules/support.o" -o "$OUT/Probe.app/Probe"
codesign --force --sign - "$OUT/Probe.app"
xcrun simctl install "$SIMULATOR_UDID" "$OUT/Probe.app"
xcrun simctl launch --console "$SIMULATOR_UDID" "$BUNDLE" > "$OUT/runtime.log" 2>&1
python3 - "$OUT/runtime.log" <<'PY'
import sys
from pathlib import Path
text=Path(sys.argv[1]).read_text()
for marker in ['privacy-canary.invalid','synthetic-password-canary','d2719f44-f51f-4c35-aeae-246230d21f38']:
 assert marker not in text, 'Private marker escaped'
for mode in ['tunnel','proxy-only','delay']:
 for level in ['debug','warning','error','none']:
  assert f'MODE_PASS={mode};LEVEL={level}' in text, f'Missing mode {mode}/{level}'
assert 'LOCAL_ACCESS_PROBE_DONE' in text
assert 'BUILD_RESULT=false; ERROR=Xray startup failed: build configuration' in text
assert 'RUNNER_SNAPSHOT_AND_DELAY_PASS' in text
print('PASS: actual runtime stdout/callback, 12 preparation/runtime cases, proxy snapshot, standalone delay runner')
PY
