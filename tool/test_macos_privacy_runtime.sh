#!/usr/bin/env bash
# Real macOS Xray + production preparation/runners, localhost fixtures only.
# SystemConfiguration is replaced at the test boundary: no host VPN, proxy,
# DNS, routes, NetworkExtension or Keychain preferences are changed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/macos_privacy_runtime_probe"
SOURCE="$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources"
mkdir -p "$OUT/modules"
python3 - "$ROOT" "$OUT" <<'PY'
from pathlib import Path
import sys
root,out=map(Path,sys.argv[1:])
source=(root/'packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos/FlutterVlessPlugin.swift').read_text()
head=source[:source.index('public class FlutterVlessPlugin:')].replace('import FlutterMacOS\n','')
begin=head.index('private struct SystemProxyHelper {')
end=head.index('private func normalizeXrayRuntimeConfig',begin)
head=head[:begin]+'''private struct SystemProxyHelper {
    static func setSystemProxy(config: String) throws {}
    static func clearSystemProxy() {}
}
'''+head[end:]
asset=source[source.index('private func configureXrayAssetLocation'):]
harness='\n'.join((root/'tool/fixtures'/name).read_text() for name in ['ios_local_auth_probe.swift','ios_dns_runtime_probe.swift','ios_privacy_probe.swift'])
harness=(root/'tool/fixtures/macos_runtime_regressions.swift').read_text()+'\n'+harness
harness=harness.replace('    let markers = [', '    do { try await runMacCounterChecks() } catch { print("MACOS_COUNTERS_FAILED"); exit(1) }\n    let markers = [')
harness=harness[:harness.index('class ModeDelegate:')]+ '\nTask { await runModes() }; dispatchMain()\n'
(out/'main.swift').write_text(head+asset+'\nimport flutter_vless_macos_tunnel_support\n'+harness)
PY
SDK="$(xcrun --sdk macosx --show-sdk-path)"
COMMON=(-O -target "$(uname -m)-apple-macos13.0" -sdk "$SDK")
xcrun swiftc "${COMMON[@]}" -parse-as-library -module-name flutter_vless_macos_privacy -emit-module -emit-object -whole-module-optimization -emit-module-path "$OUT/modules/flutter_vless_macos_privacy.swiftmodule" "$SOURCE"/flutter_vless_macos_privacy/*.swift -o "$OUT/modules/privacy.o"
SUPPORT=()
for file in "$SOURCE"/flutter_vless_macos_tunnel_support/*.swift; do
    [[ "$(basename "$file")" == FlutterVlessPacketTunnelProvider.swift ]] || SUPPORT+=("$file")
done
xcrun swiftc "${COMMON[@]}" -parse-as-library -I "$OUT/modules" -module-name flutter_vless_macos_tunnel_support -emit-module -emit-object -whole-module-optimization -emit-module-path "$OUT/modules/flutter_vless_macos_tunnel_support.swiftmodule" "${SUPPORT[@]}" -o "$OUT/modules/support.o"
xcrun swiftc "${COMMON[@]}" -I "$OUT/modules" -I "$SOURCE/CXRay/include" -framework AppKit -framework SystemConfiguration -framework NetworkExtension -lresolv "$OUT/main.swift" "$SOURCE/flutter_vless_macos/BoundedNativeLogStore.swift" "$OUT/modules/privacy.o" "$OUT/modules/support.o" "$ROOT/packages/flutter_vless_macos/macos/XRay.xcframework/macos-arm64_x86_64/libXRay.a" -o "$OUT/probe"
"$OUT/probe" > "$OUT/runtime.log" 2>&1
python3 - "$OUT/runtime.log" <<'PY'
from pathlib import Path
import sys
text=Path(sys.argv[1]).read_text()
assert "RUNTIME=26.9.9" in text, "Unexpected embedded Xray version"
assert 'MACOS_COUNTERS_AND_API_BOUNDARY_PASS' in text
for marker in ['privacy-canary.invalid','synthetic-password-canary','d2719f44-f51f-4c35-aeae-246230d21f38','local-user-canary','local-password-canary']:
    assert marker not in text, 'Private marker escaped'
for mode in ['tunnel','proxy-only','delay']:
    for level in ['debug','warning','error','none']:
        assert f'MODE_PASS={mode};LEVEL={level}' in text
for marker in ['LOCAL_ACCESS_PROBE_DONE','BUILD_RESULT=false; ERROR=Xray startup failed: build configuration','RUNNER_SNAPSHOT_AND_DELAY_PASS','AUTH_RUNTIME_PASS=0','AUTH_RUNTIME_PASS=1','AUTH_ORIGIN_HEADERS_PRIVATE_PASS','AUTH_ROTATION_PASS','RUNNER_DEFAULTS_AND_EXPLICIT_AUTH_PASS','DOMAIN_ROUTING_PASS=0','DOMAIN_ROUTING_PASS=1']:
    assert marker in text, marker
for proxy in ['http','socks']:
    for generation in [0,1]:
        assert f'DNS_RUNTIME_PASS={proxy};GENERATION={generation}' in text
        assert f'DNS_IPV4_ONLY_PASS={proxy};GENERATION={generation}' in text
    assert f'DNS_REFUSAL_NO_FALLBACK_PASS={proxy}' in text
print('PASS macOS Xray runtime: privacy, 12 modes, local authentication, rotation, domain routing, DNS relay/refusal and delay')
PY
