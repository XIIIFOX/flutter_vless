#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROBE_DIR="$ROOT_DIR/build/ios_manager_policy_probe"
mkdir -p "$PROBE_DIR"
cat "$ROOT_DIR/tool/fixtures/ios_manager_policy/SDK.swift" > "$PROBE_DIR/Manager.swift"
sed -n '/^final class PacketTunnelManager/,$p' \
  "$ROOT_DIR/ios/flutter_vless/Sources/flutter_vless/FlutterVlessPlugin.swift" >> "$PROBE_DIR/Manager.swift"
# Execute the actual provider's entry guards without NetworkExtension side effects.
python3 - "$ROOT_DIR" "$PROBE_DIR" <<'PYTHON'
from pathlib import Path
import sys
root,out=map(Path,sys.argv[1:])
s=(root/'example/ios/XrayTunnel/PacketTunnelProvider.swift').read_text()
a=s.index('    override func startTunnel(options:')
b=s.index('        TunnelDebugStore.shared.configure',a)
entry=s[a:b].replace('override func','func').replace('configuration.providerBundleIdentifier ?? ""', 'configuration.providerBundleIdentifier ?? "", client: keychain')
(out/'Provider.swift').write_text('import Foundation\nfinal class ProviderEntryProbe {\n var protocolConfiguration: NEVPNProtocol?\n var keychain = FixtureKeychain()\n var reachedBootstrap = false\n func tunnelError(_ message: String) -> NSError { NSError(domain: "fixture.provider", code: 1) }\n'+entry+'        reachedBootstrap = true\n    }\n}\n')
s=(root/'ios/flutter_vless/Sources/flutter_vless/FlutterVlessPlugin.swift').read_text()
helper_start=s.index('    fileprivate static func buildProxyOnlyConfigData')
helper_end=s.index('\n    }\n',helper_start)+6
delay_start=s.index('    private static func findDelayEndpoint')
delay_end=s.index('\n    }\n',delay_start)+6
helper='enum ProxyOnlyRunner {\n'+s[delay_start:delay_end]+'\n'+s[helper_start:helper_end]+'\n}\n'
a=s.index('        let proxyOnly = arguments["proxy_only"]')
b=s.index('        let operation = commands.submit',a)
(out/'NativeStart.swift').write_text('import Foundation\n'+helper+'struct FlutterError { let code: String; let message: String; let details: Any? }\nfinal class NativeStartEntryProbe {\n var reachedQueue = false\n func result(_ error: FlutterError) {}\n func start(arguments: [String: Any]) {\n let configData = try! JSONSerialization.data(withJSONObject: ["inbounds": [["protocol": "socks", "listen": "127.0.0.1", "port": 10808]]])\n'+s[a:b]+'        reachedQueue = true\n    }\n}\n')

PYTHON
xcrun swiftc -O -parse-as-library \
  "$ROOT_DIR/ios/flutter_vless/Sources/flutter_vless_privacy/TunnelSecretStore.swift" \
  "$ROOT_DIR/ios/flutter_vless/Sources/flutter_vless_privacy/LocalProxyAccessPolicy.swift" \
  "$ROOT_DIR/ios/flutter_vless/Sources/flutter_vless_privacy/XrayPrivacyConfig.swift" \
  "$ROOT_DIR/tool/fixtures/ios_manager_policy/Keychain.swift" \
  "$PROBE_DIR/Manager.swift" \
  "$PROBE_DIR/Provider.swift" \
  "$PROBE_DIR/NativeStart.swift" \
  "$ROOT_DIR/ios/flutter_vless/Sources/flutter_vless/NativeOperationQueue.swift" \
  "$ROOT_DIR/tool/fixtures/ios_manager_policy/main.swift" \
  -o "$PROBE_DIR/probe"
"$PROBE_DIR/probe"
