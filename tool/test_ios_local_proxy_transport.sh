#!/usr/bin/env bash
# macOS execution of the same Swift iOS socket/TLS helpers; localhost fixtures
# only, unless TEST_REAL_HTTPS=1 explicitly enables a trusted public TLS probe.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/ios_local_proxy_transport"
mkdir -p "$OUT"
cat > "$OUT/main.swift" <<'SWIFT'
import Foundation
let credentials = try LocalProxyCredentials(username: "transport-user", password: "transport-password")
let group = DispatchGroup()
group.enter()
LocalProxyDelayClient.measure(url: URL(string: CommandLine.arguments[3])!,
    port: Int(CommandLine.arguments[2])!, credentials: credentials,
    proxyProtocol: CommandLine.arguments[1]) { delay in
    print("DELAY_RESULT=\(delay)")
    group.leave()
}
if group.wait(timeout: .now() + 20) != .success { exit(2) }
SWIFT
xcrun swiftc -O "$ROOT/ios/flutter_vless/Sources/flutter_vless_privacy/LocalProxyAccessPolicy.swift" \
  "$ROOT/ios/flutter_vless/Sources/flutter_vless_privacy/LocalSOCKS5Client.swift" \
  "$ROOT/ios/flutter_vless/Sources/flutter_vless_privacy/LocalHTTPProxyClient.swift" \
  "$ROOT/ios/flutter_vless/Sources/flutter_vless_privacy/LocalProxyDelayClient.swift" \
  "$OUT/main.swift" -o "$OUT/probe" 2> "$OUT/compiler.log"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$OUT/key.pem" -out "$OUT/cert.pem" \
  -days 1 -subj '/CN=probe.invalid' > /dev/null 2>&1
python3 "$ROOT/tool/fixtures/ios_local_proxy_transport.py" "$OUT"
