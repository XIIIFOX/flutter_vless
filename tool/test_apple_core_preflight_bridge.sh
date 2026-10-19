#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
SOURCE="$ROOT/ios/flutter_vless/Sources/flutter_vless_core_compat"
cat > "$OUT/probe.m" <<'OBJC'
#import "FlutterVlessCoreCompat.h"
#include <assert.h>
@protocol XRayLogger;
// Match the real gomobile ABI; this ordinary strong call pulls its archive
// member into the binary so optional strong definitions can be discovered.
extern BOOL XRayStartPrivate(NSData *, id<XRayLogger> _Nullable, NSError * _Nullable * _Nullable);
extern int64_t XRayRoutingCapability(void);
extern int64_t XRayCheckRoutingPrivate(NSData *, NSData *);
extern BOOL XRayStartRoutingPrivate(NSData *, NSData *, id<XRayLogger> _Nullable, NSError * _Nullable * _Nullable);
extern int MockRoutingCheckCalls(void);
extern int MockRoutingStartCalls(void);
int main(void) { @autoreleasepool {
    NSData *data = [@"abc" dataUsingEncoding:NSUTF8StringEncoding];
    assert(XRayStartPrivate(data, nil, NULL));
#ifdef WITH_RUNTIME
    assert(FLVlessHasCorePreflight());
    assert(FLVlessCheckCorePrivate(data) == 0);
#else
    assert(!FLVlessHasCorePreflight());
    assert(FLVlessCheckCorePrivate(data) == -1);
#endif
    NSData *spec = [@"private-routing-spec-canary" dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error = [NSError errorWithDomain:@"private-canary" code:42 userInfo:nil];
#ifdef ROUTING_AVAILABLE
    assert(FLVlessCoreRoutingCapability() == 1);
    assert(FLVlessCheckCoreRoutingPrivate(data, spec) == 0);
    assert(FLVlessStartCoreRoutingPrivate(data, spec, nil, &error));
    assert(error == nil);
    assert(MockRoutingCheckCalls() == 1 && MockRoutingStartCalls() == 1);
#else
    assert(FLVlessCoreRoutingCapability() == 0);
    assert(FLVlessCheckCoreRoutingPrivate(data, spec) == 32);
    assert(!FLVlessStartCoreRoutingPrivate(data, spec, nil, &error));
    assert([error.domain isEqualToString:@"flutter_vless.core.routing"] && error.code == 32);
    assert([error.localizedDescription isEqualToString:@"Native VPN routing is unavailable in this Xray runtime."]);
    assert(error.userInfo.count == 1);
    assert(![error.localizedDescription containsString:@"canary"]);
    assert(!FLVlessStartCoreRoutingPrivate(data, spec, nil, NULL));
    assert(MockRoutingCheckCalls() == 0 && MockRoutingStartCalls() == 0);
#endif
#ifndef ROUTING_CAP
    assert(XRayRoutingCapability() == 0);
#endif
#ifndef ROUTING_CHECK
    assert(XRayCheckRoutingPrivate(data, spec) == 32);
#endif
#ifndef ROUTING_START
    error = nil;
    assert(!XRayStartRoutingPrivate(data, spec, nil, &error));
    assert([error.domain isEqualToString:@"flutter_vless.core.routing"] && error.code == 32);
    assert([error.localizedDescription isEqualToString:@"Native VPN routing is unavailable in this Xray runtime."]);
    assert(!XRayStartRoutingPrivate(data, spec, nil, NULL));
#endif
} return 0; }
OBJC
cat > "$OUT/runtime.m" <<'OBJC'
#import <Foundation/Foundation.h>
#include <stdint.h>
@protocol XRayLogger;
BOOL XRayStartPrivate(NSData *configuration, id<XRayLogger> logger, NSError **error) {
    (void)configuration; (void)logger; (void)error; return YES;
}
#ifdef WITH_RUNTIME
int64_t XRayCheckPrivate(NSData *configuration) { return configuration.length == 3 ? 0 : 1; }
#endif
static int checkCalls, startCalls;
int MockRoutingCheckCalls(void) { return checkCalls; }
int MockRoutingStartCalls(void) { return startCalls; }
#ifdef ROUTING_CAP
int64_t XRayRoutingCapability(void) { return ROUTING_CAP; }
#endif
#ifdef ROUTING_CHECK
int64_t XRayCheckRoutingPrivate(NSData *configuration, NSData *spec) {
    checkCalls++; return configuration.length == 3 && spec.length != 0 ? 0 : 17;
}
#endif
#ifdef ROUTING_START
BOOL XRayStartRoutingPrivate(NSData *configuration, NSData *spec, id<XRayLogger> logger, NSError **error) {
    (void)logger; startCalls++; if (error) *error = nil;
    return configuration.length == 3 && spec.length != 0;
}
#endif
OBJC
LINKED=0
EXECUTED=0
for ARCH in arm64 x86_64; do
    CAN_RUN=0
    if /usr/bin/arch "-$ARCH" /usr/bin/true 2>/dev/null; then CAN_RUN=1; fi
for variant in legacy current routing cap0 unknown missing-cap missing-check missing-start; do
    FLAGS=(-DLEGACY_RUNTIME)
    case "$variant" in
        current) FLAGS=(-DWITH_RUNTIME) ;;
        routing) FLAGS=(-DWITH_RUNTIME -DROUTING_CAP=1 -DROUTING_CHECK -DROUTING_START -DROUTING_AVAILABLE) ;;
        cap0) FLAGS=(-DWITH_RUNTIME -DROUTING_CAP=0 -DROUTING_CHECK -DROUTING_START) ;;
        unknown) FLAGS=(-DWITH_RUNTIME -DROUTING_CAP=2 -DROUTING_CHECK -DROUTING_START) ;;
        missing-cap) FLAGS=(-DWITH_RUNTIME -DROUTING_CHECK -DROUTING_START) ;;
        missing-check) FLAGS=(-DWITH_RUNTIME -DROUTING_CAP=1 -DROUTING_START) ;;
        missing-start) FLAGS=(-DWITH_RUNTIME -DROUTING_CAP=1 -DROUTING_CHECK) ;;
    esac
    xcrun clang -arch "$ARCH" -O2 -fobjc-arc -Wall -Wextra -Werror "${FLAGS[@]}" -c "$OUT/runtime.m" -o "$OUT/runtime.o"
    xcrun libtool -static -o "$OUT/$ARCH-$variant.a" "$OUT/runtime.o"
    xcrun clang -arch "$ARCH" -O2 -fobjc-arc -Wall -Wextra -Werror "${FLAGS[@]}" -framework Foundation -I "$SOURCE/include" \
        "$SOURCE/FlutterVlessCoreCompat.m" "$OUT/probe.m" "$OUT/$ARCH-$variant.a" -Wl,-dead_strip -o "$OUT/$ARCH-$variant"
    LINKED=$((LINKED + 1))
    if [[ "$CAN_RUN" == 1 ]]; then
        /usr/bin/arch "-$ARCH" "$OUT/$ARCH-$variant"
        EXECUTED=$((EXECUTED + 1))
    fi
done
done
echo 'PASS: optional Apple preflight bridge with legacy and capable runtime symbols'
echo "PASS: optional Apple routing bridge requires all symbols and exact capability one; linked=$LINKED executed=$EXECUTED (available host architectures only)"

IOS="$ROOT/ios/flutter_vless/Sources/flutter_vless_privacy/CorePreflightPolicy.swift"
MAC="$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_privacy/CorePreflightPolicy.swift"
cmp "$IOS" "$MAC"
cmp "$SOURCE/FlutterVlessCoreCompat.m" "$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_core_compat/FlutterVlessCoreCompat.m"
cmp "$SOURCE/include/FlutterVlessCoreCompat.h" "$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_core_compat/include/FlutterVlessCoreCompat.h"
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
 let certificateAssetsDirectory: String? = "/fixture/new-certificate-assets"
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
