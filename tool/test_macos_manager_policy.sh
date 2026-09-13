#!/usr/bin/env bash
# Production manager with in-memory NetworkExtension and Keychain backends.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/macos_manager_policy_probe"
SOURCE="$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources"
mkdir -p "$OUT"
python3 - "$ROOT" "$OUT" <<'PY'
from pathlib import Path
import sys
root,out=map(Path,sys.argv[1:])
source=(root/'packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos/FlutterVlessPlugin.swift').read_text()
manager=source[source.index('final class PacketTunnelManager:'):source.index('private func configureXrayAssetLocation')]
(out/'Manager.swift').write_text((root/'tool/fixtures/ios_manager_policy/SDK.swift').read_text()+manager)
PY
xcrun swiftc -O -parse-as-library \
  "$SOURCE/flutter_vless_macos_privacy/TunnelSecretStore.swift" \
  "$SOURCE/flutter_vless_macos_privacy/LocalProxyAccessPolicy.swift" \
  "$SOURCE/flutter_vless_macos_privacy/DesktopBypassPolicy.swift" \
  "$SOURCE/flutter_vless_macos/NativeOperationQueue.swift" \
  "$ROOT/tool/fixtures/ios_manager_policy/Keychain.swift" \
  "$ROOT/tool/fixtures/macos_manager_policy.swift" "$OUT/Manager.swift" -o "$OUT/probe"
"$OUT/probe"
