#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

for store in \
  "$REPO_ROOT/ios/flutter_vless/Sources/flutter_vless/BoundedNativeLogStore.swift" \
  "$REPO_ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos/BoundedNativeLogStore.swift"
do
  output="$BUILD_DIR/$(basename "$(dirname "$store")")-test"
  plugin_dir="$(dirname "$store")"
  python3 - "$plugin_dir/FlutterVlessPlugin.swift" "$BUILD_DIR/Boundary.swift" <<'PY'
from pathlib import Path
import sys
source=Path(sys.argv[1]).read_text()
start=source.index('    private func configuredDiagnosticsSnapshot(')
end=source.index('\n    }',start)+6
method=source[start:end].replace('private func','func')
snapshot_start=source.index('    private func getProviderDebugSnapshot(')
snapshot_end=source.index('\n    private func getServerDelay(',snapshot_start)
assert 'boundedNativeDiagnosticsSnapshot(' not in source[snapshot_start:snapshot_end], 'Every response path must honor the configured budget'
Path(sys.argv[2]).write_text('import Foundation\nfinal class DiagnosticsBoundaryProbe {\n let nativeOptions: VlessNativeOptions\n init(options: VlessNativeOptions) { nativeOptions = options }\n'+method+'\n}\n')
PY
  swiftc "$store" "$plugin_dir/../$(basename "$plugin_dir")_privacy/VlessNativeOptions.swift" \
    "$BUILD_DIR/Boundary.swift" "$SCRIPT_DIR/bounded_native_log_store_test.swift" -o "$output"
  "$output"
done
