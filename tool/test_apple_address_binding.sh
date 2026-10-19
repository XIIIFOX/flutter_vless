#!/usr/bin/env bash
# Real app-side binding expression, linked only with production privacy sources.
# All executed controls are JSON/file/environment only: no Core, HEV or OS APIs.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/apple_address_binding_probe"
mkdir -p "$OUT/ios" "$OUT/macos"
python3 - "$ROOT" "$OUT" <<'PY'
from pathlib import Path
import sys
root, out = map(Path, sys.argv[1:])
for platform, relative, module in [
    ('ios', 'ios/flutter_vless/Sources/flutter_vless/FlutterVlessPlugin.swift', 'flutter_vless_privacy'),
    ('macos', 'packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos/FlutterVlessPlugin.swift', 'flutter_vless_macos_privacy'),
]:
    source = (root / relative).read_text()
    matches = [line.strip().split('= try ', 1)[1] for line in source.splitlines()
               if line.strip().startswith('effectiveConfigData = try ')]
    assert len(matches) == 1, 'expected exactly one production app Address binding expression'
    (out / platform / 'AppBinding.swift').write_text(
        'import Foundation\nimport ' + module + '\n'
        'func actualAppBinding(_ listenerBound: Data) throws -> Data {\n'
        '    return try ' + matches[0] + '\n}\n')
PY
status=0
for platform in ios macos; do
  if [ "$platform" = ios ]; then
    MODULE=flutter_vless_privacy
    SOURCE="$ROOT/ios/flutter_vless/Sources/flutter_vless_privacy"
  else
    MODULE=flutter_vless_macos_privacy
    SOURCE="$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_privacy"
  fi
  xcrun swiftc -O -parse-as-library -module-name "$MODULE" \
    -emit-module -emit-object -whole-module-optimization \
    -emit-module-path "$OUT/$platform/$MODULE.swiftmodule" \
    "$SOURCE"/*.swift -o "$OUT/$platform/privacy.o"
  # Deliberately no support search path/library: this is the actual Runner's
  # module boundary, rather than a same-module fixture that can hide visibility.
  if ! xcrun swiftc -O -parse-as-library -I "$OUT/$platform" \
    "$OUT/$platform/AppBinding.swift" "$ROOT/tool/fixtures/apple_address_binding.swift" \
    "$OUT/$platform/privacy.o" -o "$OUT/$platform/probe"; then
    status=1
    continue
  fi
  if ! "$OUT/$platform/probe" "$ROOT" "$platform"; then status=1; fi
done
exit "$status"
