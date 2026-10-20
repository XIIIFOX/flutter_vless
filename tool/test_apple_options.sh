#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/options-quick-tile/apple-tests"
mkdir -p "$OUT"
IOS="$ROOT/ios/flutter_vless/Sources/flutter_vless_privacy"
MAC="$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_privacy"
for file in VlessNativeOptions.swift VlessSystemControl.swift; do cmp "$IOS/$file" "$MAC/$file"; done
xcrun swiftc -O -parse-as-library "$IOS/VlessNativeOptions.swift" "$ROOT/tool/native_options_test.swift" -o "$OUT/options"
"$OUT/options"
python3 - "$ROOT" "$OUT" <<'PY'
from pathlib import Path
import sys
root,out=map(Path,sys.argv[1:])
s=(root/'ios/flutter_vless/Sources/flutter_vless_privacy/VlessSystemControl.swift').read_text()
s=s.replace('import NetworkExtension','').replace('import WidgetKit','').replace('public ','')
(out/'Control.swift').write_text(s+'\nstruct ControlCenter { static let shared = ControlCenter(); func reloadControls(ofKind: String) {} }\n')
PY
xcrun swiftc -O -parse-as-library "$IOS/VlessNativeOptions.swift" "$ROOT/tool/fixtures/ios_manager_policy/SDK.swift" "$OUT/Control.swift" "$ROOT/tool/fixtures/apple_system_control_test.swift" -o "$OUT/control"
"$OUT/control"
python3 "$ROOT/tool/test_apple_system_control_transactions.py"
bash "$ROOT/tool/test_ios_acceptance_provider.sh"
