#!/usr/bin/env bash
# Actual iOS simulator XRay runtime + native preparation modes, localhost only.
# Does not install a NetworkExtension or change routes/DNS/VPN. HEV is not tested.
set -euo pipefail
: "${SIMULATOR_UDID:?Set SIMULATOR_UDID to an already booted disposable iOS simulator}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/ios_privacy_runtime_probe"
BUNDLE=dev.tfox.security-runtime-probe
mkdir -p "$OUT/modules" "$OUT/Probe.app"
PROBE_LAUNCHED_AT=
cleanup_probe() {
    local status=$?
    trap - EXIT
    if [ "$status" -ne 0 ] && [ -n "$PROBE_LAUNCHED_AT" ]; then
        python3 "$ROOT/tool/run_apple_runtime_probe.py" --collect-ios-termination "$OUT/runtime.log" --launched-at "$PROBE_LAUNCHED_AT" || true
    fi
    xcrun simctl uninstall "$SIMULATOR_UDID" "$BUNDLE" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup_probe EXIT
python3 - "$ROOT" "$OUT" <<'PY'
from pathlib import Path
import base64, plistlib, sys
root,out=map(Path,sys.argv[1:])
source=(root/'ios/flutter_vless/Sources/flutter_vless/FlutterVlessPlugin.swift').read_text()
# Preserve actual runner implementations; no duplicated config transformation.
head=source[:source.index('public class FlutterVlessPlugin:')].replace('import Flutter\n','')
asset=source[source.index('private func configureXrayAssetLocation'):source.index('final class PacketTunnelManager:')]
harness=(root/'tool/fixtures/ios_local_auth_probe.swift').read_text()+'\n'+(root/'tool/fixtures/ios_dns_runtime_probe.swift').read_text()+'\n'+(root/'tool/fixtures/apple_native_routing_runtime.swift').read_text()+'\n'+(root/'tool/fixtures/ios_privacy_probe.swift').read_text()
harness=harness.replace('__ASSET_FIXTURE_JSON_BASE64__', base64.b64encode((root/'tool/fixtures/compatibility/asset-files.json').read_bytes()).decode('ascii'))
harness=harness.replace('__DIRECT_ONLY_FIXTURE_JSON_BASE64__', base64.b64encode((root/'tool/fixtures/compatibility/direct-only.json').read_bytes()).decode('ascii'))
harness=harness.replace('__SELECTOR_TRAFFIC_FIXTURE_JSON_BASE64__', base64.b64encode((root/'tool/fixtures/compatibility/selector-traffic.json').read_bytes()).decode('ascii'))
(out/'main.swift').write_text(head+asset+'\nimport flutter_vless_tunnel_support\n'+harness)
with (out/'Probe.app/Info.plist').open('wb') as file:
 plistlib.dump({'CFBundleIdentifier':'dev.tfox.security-runtime-probe','CFBundleExecutable':'Probe','CFBundleName':'Privacy Probe','CFBundlePackageType':'APPL','CFBundleVersion':'1','CFBundleShortVersionString':'1.0','MinimumOSVersion':'15.0','LSRequiresIPhoneOS':True,'UIDeviceFamily':[1,2],'NSAppTransportSecurity':{'NSAllowsArbitraryLoads':True}},file)
PY
SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"
SIMULATOR_ARCH="$(uname -m)"
case "$SIMULATOR_ARCH" in arm64|x86_64) ;; *) echo "Unsupported simulator architecture: $SIMULATOR_ARCH" >&2; exit 1 ;; esac
COMMON=(-O -target "$SIMULATOR_ARCH-apple-ios15.0-simulator" -sdk "$SDK")
echo 'PROBE_PHASE=ios-compile-begin'
xcrun swiftc "${COMMON[@]}" -parse-as-library -module-name flutter_vless_privacy -emit-module -emit-object -whole-module-optimization -emit-module-path "$OUT/modules/flutter_vless_privacy.swiftmodule" "$ROOT"/ios/flutter_vless/Sources/flutter_vless_privacy/*.swift -o "$OUT/modules/privacy.o"
xcrun swiftc "${COMMON[@]}" -parse-as-library -I "$OUT/modules" -module-name flutter_vless_tunnel_support -emit-module -emit-object -whole-module-optimization -emit-module-path "$OUT/modules/flutter_vless_tunnel_support.swiftmodule" "$ROOT"/ios/flutter_vless/Sources/flutter_vless_tunnel_support/*.swift -o "$OUT/modules/support.o"
COMPAT="$ROOT/ios/flutter_vless/Sources/flutter_vless_core_compat"
xcrun clang -fobjc-arc -target "$SIMULATOR_ARCH-apple-ios15.0-simulator" -isysroot "$SDK" \
    -c "$COMPAT/FlutterVlessCoreCompat.m" -o "$OUT/modules/compat.o"
xcrun swiftc "${COMMON[@]}" -I "$OUT/modules" -F "$ROOT/ios/XRay.xcframework/ios-arm64_x86_64-simulator" -framework XRay -framework UIKit -lresolv -import-objc-header "$COMPAT/include/FlutterVlessCoreCompat.h" "$OUT/main.swift" "$ROOT/ios/flutter_vless/Sources/flutter_vless/BoundedNativeLogStore.swift" "$OUT/modules/privacy.o" "$OUT/modules/support.o" "$OUT/modules/compat.o" -o "$OUT/Probe.app/Probe"
codesign --force --sign - "$OUT/Probe.app"
echo 'PROBE_PHASE=ios-compile-complete'
echo 'PROBE_PHASE=ios-install-begin'
xcrun simctl install "$SIMULATOR_UDID" "$OUT/Probe.app"
echo 'PROBE_PHASE=ios-install-complete'
echo 'PROBE_PHASE=ios-runtime-begin'
PROBE_LAUNCHED_AT="$(python3 -c 'import time; print(time.time())')"
SIMCTL_CHILD_REQUIRE_CORE_PREFLIGHT="${REQUIRE_CORE_PREFLIGHT:-0}" \
SIMCTL_CHILD_REQUIRE_VPN_ROUTING="${REQUIRE_VPN_ROUTING:-0}" \
    python3 "$ROOT/tool/run_apple_runtime_probe.py" --timeout 600 --ios-simulator "$SIMULATOR_UDID" -- \
    xcrun simctl launch --console "$SIMULATOR_UDID" "$BUNDLE" 2>&1 | tee "$OUT/runtime.log"
echo 'PROBE_PHASE=ios-runtime-complete'
python3 - "$OUT/runtime.log" <<'PY'
import os, sys
from pathlib import Path
text=Path(sys.argv[1]).read_text()
assert "RUNTIME=26.10.17" in text, "Unexpected embedded Xray version"
for marker in ['privacy-canary.invalid','synthetic-password-canary','d2719f44-f51f-4c35-aeae-246230d21f38','local-user-canary','local-password-canary']:
 assert marker not in text, 'Private marker escaped'
for mode in ['tunnel','proxy-only','delay']:
 for level in ['debug','warning','error','none']:
  assert f'MODE_PASS={mode};LEVEL={level}' in text, f'Missing mode {mode}/{level}'
if os.environ.get('REQUIRE_VPN_ROUTING') == '1':
    for marker in ['NATIVE_ROUTING_RUNTIME_PASS=0','NATIVE_ROUTING_RUNTIME_PASS=1','NATIVE_ROUTING_RUNTIME_DRAIN_PASS','APPLE_PRIVATE_PORT_OCCUPIED_RUNTIME_PASS=2']:
        assert marker in text, marker
if os.environ.get('REQUIRE_CORE_PREFLIGHT') == '1':
 for generation in [0,1]:
  assert f'PREFLIGHT_RUNNING_SESSION_PASS={generation}' in text
assert 'LOCAL_ACCESS_PROBE_DONE' in text
assert 'BUILD_RESULT=false; ERROR=Xray startup failed: build configuration' in text
assert 'RUNNER_SNAPSHOT_AND_DELAY_PASS' in text
assert 'ASSET_CUSTOM_ROOT_RUNTIME_PASS' in text
assert 'DIRECT_ONLY_RUNTIME_PASS=0' in text and 'DIRECT_ONLY_RUNTIME_PASS=1' in text and 'DIRECT_ONLY_RUNTIME_PASS=2' in text
assert 'AUTH_RUNTIME_PASS=0' in text and 'AUTH_RUNTIME_PASS=1' in text
assert 'SERVICE_TAG_RUNTIME_PASS=0' in text and 'SERVICE_TAG_RUNTIME_PASS=1' in text
assert 'API_PORT_RESERVATION_PASS=0' in text and 'API_PORT_RESERVATION_PASS=1' in text
assert 'METRICS_PORT_RESERVATION_PASS=0' in text and 'METRICS_PORT_RESERVATION_PASS=1' in text
assert 'DELAY_API_ISOLATION_PASS' in text
assert 'METRICS_PASSTHROUGH_PASS=0' in text and 'METRICS_PASSTHROUGH_PASS=1' in text
assert 'AUTH_ORIGIN_HEADERS_PRIVATE_PASS' in text
assert 'AUTH_ROTATION_PASS' in text
assert 'RUNNER_DEFAULTS_AND_EXPLICIT_AUTH_PASS' in text
assert 'DOMAIN_ROUTING_PASS=0' in text and 'DOMAIN_ROUTING_PASS=1' in text
for proxy in ['http', 'socks']:
 for generation in [0, 1, 2]:
  assert f'DNS_RUNTIME_PASS={proxy};GENERATION={generation}' in text
  assert f'DNS_IPV4_ONLY_PASS={proxy};GENERATION={generation}' in text
  assert f'DNS_IMPORTED_CONTEXT_PASS={proxy};GENERATION={generation}' in text
 assert f'DNS_REFUSAL_NO_FALLBACK_PASS={proxy}' in text
 assert f'DNS_ROOT_CLIENT_REFUSED_NON_IP_PASS={proxy}' in text
print('PASS: actual runtime stdout/callback, 12 preparation/runtime cases, proxy snapshot, standalone delay runner')
PY
