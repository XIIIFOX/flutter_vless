#!/usr/bin/env bash
# Compile the production helper against an in-memory OS boundary.
# Never authorize or change the real computer's proxy/VPN settings.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/macos_system_proxy_probe"
SOURCE="$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources"
mkdir -p "$OUT"
python3 - "$ROOT" "$OUT" <<'PY'
from pathlib import Path
import sys
root, out = map(Path, sys.argv[1:])
source = (root/'packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos/FlutterVlessPlugin.swift').read_text()
helper = source[source.index('private struct SystemProxyHelper {'):source.index('private func normalizeXrayRuntimeConfig')]
fixtures = root/'tool/fixtures/macos_system_proxy'
(out/'main.swift').write_text((fixtures/'SDK.swift').read_text() + '\n' + helper + '\n' + (fixtures/'Checks.swift').read_text())
PY
xcrun swiftc -parse-as-library -module-name flutter_vless_macos_privacy -emit-module -emit-object -whole-module-optimization -emit-module-path "$OUT/flutter_vless_macos_privacy.swiftmodule" "$SOURCE"/flutter_vless_macos_privacy/*.swift -o "$OUT/privacy.o"
xcrun swiftc -I "$OUT" "$OUT/main.swift" "$OUT/privacy.o" -o "$OUT/probe"
"$OUT/probe"
