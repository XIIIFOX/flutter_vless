#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
SOURCE="$ROOT/ios/flutter_vless/Sources/flutter_vless_core_compat"
cat > "$OUT/probe.m" <<'OBJC'
#import "FlutterVlessCoreCompat.h"
#include <assert.h>
extern void XRayStartPrivate(void);
int main(void) { @autoreleasepool {
    XRayStartPrivate(); // Force the same archive member as real gomobile users.
    NSData *data = [@"abc" dataUsingEncoding:NSUTF8StringEncoding];
#ifdef WITH_RUNTIME
    assert(FLVlessHasCorePreflight());
    assert(FLVlessCheckCorePrivate(data) == 0);
#else
    assert(!FLVlessHasCorePreflight());
    assert(FLVlessCheckCorePrivate(data) == -1);
#endif
} return 0; }
OBJC
cat > "$OUT/runtime.m" <<'OBJC'
#import <Foundation/Foundation.h>
#include <stdint.h>
void XRayStartPrivate(void) {}
#ifdef WITH_RUNTIME
int64_t XRayCheckPrivate(NSData *configuration) { return configuration.length == 3 ? 0 : 1; }
#endif
OBJC
for variant in legacy current; do
    FLAGS=(-DLEGACY_RUNTIME)
    if [[ "$variant" == current ]]; then FLAGS=(-DWITH_RUNTIME); fi
    xcrun clang -O2 -fobjc-arc -Wall -Wextra -Werror "${FLAGS[@]}" -c "$OUT/runtime.m" -o "$OUT/runtime.o"
    xcrun libtool -static -o "$OUT/$variant.a" "$OUT/runtime.o"
    xcrun clang -O2 -fobjc-arc -Wall -Wextra -Werror "${FLAGS[@]}" -framework Foundation -I "$SOURCE/include" \
        "$SOURCE/FlutterVlessCoreCompat.m" "$OUT/probe.m" "$OUT/$variant.a" -Wl,-dead_strip -o "$OUT/$variant"
    "$OUT/$variant"
done
echo 'PASS: optional Apple preflight bridge with legacy and capable runtime symbols'

IOS="$ROOT/ios/flutter_vless/Sources/flutter_vless_privacy/CorePreflightPolicy.swift"
MAC="$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_privacy/CorePreflightPolicy.swift"
cmp "$IOS" "$MAC"
cmp "$SOURCE/FlutterVlessCoreCompat.m" "$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_core_compat/FlutterVlessCoreCompat.m"
xcrun swiftc -O -parse-as-library "$IOS" "$ROOT/tool/core_preflight_policy_test.swift" -o "$OUT/policy"
"$OUT/policy"
python3 - "$ROOT" "$OUT" <<'PY'
from pathlib import Path
import sys
root, out = map(Path,sys.argv[1:])
sources = [root/'ios/flutter_vless/Sources/flutter_vless/FlutterVlessPlugin.swift',
 root/'packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos/FlutterVlessPlugin.swift']
bodies=[]
for path in sources:
 s=path.read_text()
 a=s.index('        let operation = commands.submit {\n            // Do not replace the app-process singleton')
 b=s.index('\n        Task {',a)
 bodies.append(s[a:b])
assert bodies[0] == bodies[1], 'Both Apple start paths must use the checked transaction'
probe='''private final class StartProbe {
 let commands = NativeOperationQueue()
 let proxyOnlyRunner = Proxy()
 let packetTunnelManager: Manager? = Manager()
 let controlGroup: String? = nil
 func start(proxyOnly: Bool) -> Task<Void, Error> {
 let effectiveConfigData = Data("new".utf8)
 let geoAssetsDirectory: String? = nil
 let bypassSubnets: [String]? = []
 let remark = "new"
'''+bodies[0]+'''
 return operation
 }
}
'''
fixture=(root/'tool/fixtures/apple_preflight_transaction.swift').read_text()
(out/'transaction.swift').write_text(fixture.replace('// PREFLIGHT_TRANSACTION_SOURCE is replaced by the production operation body.',probe))
PY
xcrun swiftc -O -parse-as-library "$IOS" "$ROOT/ios/flutter_vless/Sources/flutter_vless/NativeOperationQueue.swift" "$OUT/transaction.swift" -o "$OUT/transaction"
"$OUT/transaction"
