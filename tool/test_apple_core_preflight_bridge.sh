#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
SOURCE="$ROOT/ios/flutter_vless/Sources/flutter_vless_core_compat"
cat > "$OUT/probe.m" <<'OBJC'
#import "FlutterVlessCoreCompat.h"
#include <assert.h>
#ifdef FLVLESS_TEST_CORE_ROUTING_DIAGNOSTICS
#include <stdio.h>
#endif
@protocol XRayLogger;
// Match the real gomobile ABI; this ordinary strong call pulls its archive
// member into the binary so optional strong definitions can be discovered.
extern BOOL XRayStartPrivate(NSData *, id<XRayLogger> _Nullable, NSError * _Nullable * _Nullable);
extern int64_t XRayRoutingCapability(void);
extern int64_t XRayCheckRoutingPrivate(NSData *, NSData *);
extern BOOL XRayStartRoutingPrivate(NSData *, NSData *, id<XRayLogger> _Nullable, NSError * _Nullable * _Nullable);
extern int MockRoutingCheckCalls(void);
extern int MockRoutingStartCalls(void);
#ifdef FLVLESS_TEST_CORE_ROUTING_DIAGNOSTICS
extern void FLVlessTestCoreRoutingDiagnostics(int *, int *, int64_t *);
#endif
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
#ifdef FLVLESS_TEST_CORE_ROUTING_DIAGNOSTICS
    int checkMissing, startMissing;
    int64_t rawCapability;
    FLVlessTestCoreRoutingDiagnostics(&checkMissing, &startMissing, &rawCapability);
    fprintf(stderr, "BRIDGE_ROUTING_DIAGNOSTIC check_missing=%d start_missing=%d raw_cap=%lld result=%lld\n",
            checkMissing, startMissing, (long long)rawCapability, (long long)FLVlessCoreRoutingCapability());
#endif
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
run_bridge_diagnostics() {
    printf 'BRIDGE_DIAGNOSTIC_CASE arch=%s variant=%s\n' "$ARCH" "$variant"
    if ! xcrun clang -arch "$ARCH" -O2 -fobjc-arc -Wall -Wextra -Werror -DFLVLESS_TEST_CORE_ROUTING_DIAGNOSTICS "${FLAGS[@]}" -framework Foundation -I "$SOURCE/include" \
        "$SOURCE/FlutterVlessCoreCompat.m" "$OUT/probe.m" "$OUT/$ARCH-$variant.a" -Wl,-dead_strip -o "$OUT/$ARCH-$variant-diagnostic"; then
        return 1
    fi
    /usr/bin/arch "-$ARCH" "$OUT/$ARCH-$variant-diagnostic"
}
run_bridge_probe() {
    local baseline_status=0
    "$@" || baseline_status=$?
    if [[ "$baseline_status" != 0 ]]; then
        printf 'BRIDGE_BASELINE_FAILURE status=%s\n' "$baseline_status"
        run_bridge_diagnostics || true
    fi
    return "$baseline_status"
}
for ARCH in arm64 x86_64; do
    CAN_RUN=0
    if /usr/bin/arch "-$ARCH" /usr/bin/true 2>/dev/null; then CAN_RUN=1; fi
    ENTRY_OFFSET=1
    if [[ "$ARCH" == arm64 ]]; then ENTRY_OFFSET=4; fi
    # This object is inspected only, never linked into the baseline probes.
    # Distinct symbol addresses plus N_ALT_ENTRY prevent the old same-address
    # sentinel atom shape, but the archive matrix below must still pass.
    xcrun clang -arch "$ARCH" -O2 -fobjc-arc -Wall -Wextra -Werror -c "$SOURCE/FlutterVlessCoreCompat.m" -o "$OUT/$ARCH-anchor.o"
    xcrun nm -m "$OUT/$ARCH-anchor.o" > "$OUT/$ARCH-anchor-symbols"
    python3 - "$OUT/$ARCH-anchor-symbols" "$ENTRY_OFFSET" <<'PY'
from pathlib import Path
import sys
lines = Path(sys.argv[1]).read_text().splitlines()
offset = int(sys.argv[2])
def symbol(name):
    found = [line for line in lines if line.split()[-1:] == [name]]
    assert len(found) == 1, name
    return int(found[0].split()[0], 16), found[0]
for suffix in ("Check", "Start"):
    anchor, anchor_line = symbol("_FLVlessMissingRouting" + suffix)
    entry, entry_line = symbol("_XRay" + suffix + "RoutingPrivate")
    assert "private external" in anchor_line, anchor_line
    assert "weak external" in entry_line and "[alt entry]" in entry_line, entry_line
    assert entry == anchor + offset, (suffix, anchor, entry, offset)
PY
    printf 'BRIDGE_ANCHOR_SHAPE arch=%s offset=%s\n' "$ARCH" "$ENTRY_OFFSET"
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
    printf 'BRIDGE_CASE arch=%s variant=%s execute=%s\n' "$ARCH" "$variant" "$CAN_RUN"
    if [[ "$CAN_RUN" == 1 ]]; then
        run_bridge_probe /usr/bin/arch "-$ARCH" "$OUT/$ARCH-$variant"
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
 a=s.index('        let preparationChanges = Array(changes)') + len('        let preparationChanges = Array(changes)\n')
 b=s.index('\n        Task {',a)
 bodies.append(s[a:b])
assert bodies[0] == bodies[1], 'Both Apple start paths must use the checked transaction'
probe='''private final class StartProbe {
 let commands = NativeOperationQueue()
 let proxyOnlyRunner = Proxy()
 let packetTunnelManager: Manager? = Manager()
 let controlGroup: String? = nil
 func start(proxyOnly: Bool, data: Data = Data("new".utf8), changes: [NativePreparationReport.Change] = []) -> Task<NativePreparationReport, Error> {
 let effectiveConfigData = data
 let preparationChanges = changes
 let vpnRouting: NativeRoutingIntent? = nil
 let preparedProxyConfig: Proxy.Prepared? = proxyOnly ? Proxy.Prepared(data: Data("prepared-new".utf8)) : nil
 let geoAssetsDirectory: String? = nil
 let certificateAssetsDirectory: String? = "/fixture/new-certificate-assets"
 let bypassSubnets: [String]? = []
 let remark = "new"
'''+bodies[0]+'''
 return operation
 }
}
'''
success_start=sources[0].read_text().index('\n            do {', sources[0].read_text().index('\n        Task {', sources[0].read_text().index('        let operation = commands.submit {\n            // Do not replace the app-process singleton')))+len('\n            do {')
success_end=sources[0].read_text().index('\n            } catch', success_start)
success=sources[0].read_text()[success_start:success_end]
probe=probe.replace('\n}\n', '''
 func refreshRuntimePolling(reason: String) {}
 func startReply(proxyOnly: Bool) async throws -> Any? {
 let operation = start(proxyOnly: proxyOnly)
 var response: Any?
 let result: (Any?) -> Void = { response = $0 }
'''+success+'''
 return response
 }
}
''', 1)
fixture=(root/'tool/fixtures/apple_preflight_transaction.swift').read_text()
for index, path in enumerate(sources):
 source=path.read_text()
 a=source.index('private final class ProxyOnlyRunner {')
 b=source.index('\n    func stop()',a)
 runner=source[a:b].replace('private final class ProxyOnlyRunner {', 'private final class ActualProxyRunner {')
 helper_start=source.index('    fileprivate static func buildProxyOnlyConfigData', a)
 helper_end=source.index('\n    }\n', helper_start)+6
 prepare=source[helper_start:helper_end].replace('buildProxyOnlyConfigData', 'fixtureRealProxyPreparation', 1)
 endpoint_start=source.index('    private static func findDelayEndpoint', a)
 endpoint_end=source.index('\n    }\n', endpoint_start)+6
 endpoint=source[endpoint_start:endpoint_end].replace('findDelayEndpoint', 'fixtureRealDelayEndpoint', 1)
 runner+='\n'+prepare+'\n'+endpoint+'\n'
 counter_start=source.index('    private(set) var totalUpload: Int64', a)
 counter_end=source.index('    func forceCleanup()' if index == 1 else '    func debugSnapshot()', counter_start)
 runner+='\n'+source[counter_start:counter_end]
 stop_start=source.index('    func stop()', a)
 stop_end=source.index('\n    }\n', stop_start)+6
 runner+='\n'+source[stop_start:stop_end]
 runner+='''
    func fixtureSetRunning() { isRunning = true }
    func fixtureCounterDirections() -> (Int64?, Int64?) {
        proxyCounterLock.lock(); defer { proxyCounterLock.unlock() }
        return (previousUpload, previousDownload)
    }
    fileprivate static func buildProxyOnlyConfigData(configData: Data, onChange: ((NativePreparationReport.Change) -> Void)? = nil) throws -> Data {
        prepareCount += 1
        // Preserve admission sentinels; JSON counter cases use real preparation.
        if configData == Data("new".utf8) { return Data("prepared-new".utf8) }
        return try fixtureRealProxyPreparation(configData: configData, onChange: onChange)
    }
    private static func findDelayEndpoint(_ data: Data) throws -> (protocolName: String, port: Int, credentials: LocalProxyCredentials?)? {
        if data == Data("prepared-new".utf8) { return nil }
        return try fixtureRealDelayEndpoint(data)
    }
}
'''
 (out/f'transaction-{index}.swift').write_text(fixture.replace('// PREFLIGHT_TRANSACTION_SOURCE is replaced by the production operation body.',probe).replace('// PROXY_RUNNER_START_SOURCE is replaced by the production runner methods.',runner))
PY
for PLATFORM in 0 1; do
    PRIVACY="$ROOT/ios/flutter_vless/Sources/flutter_vless_privacy"
    COUNTER_FLAGS=(-DAPPLE_PROXY_COUNTER_TEST)
    if [[ "$PLATFORM" == 1 ]]; then
        PRIVACY="$ROOT/packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_privacy"
    fi
    xcrun swiftc -O -parse-as-library "${COUNTER_FLAGS[@]}" "$IOS" \
        "$PRIVACY/LocalProxyAccessPolicy.swift" "$PRIVACY/XrayPrivacyConfig.swift" "$PRIVACY/XrayServiceTags.swift" \
        "$ROOT/ios/flutter_vless/Sources/flutter_vless/NativeOperationQueue.swift" "$OUT/transaction-$PLATFORM.swift" -o "$OUT/transaction-$PLATFORM"
    APPLE_TRAFFIC_COUNTER_FIXTURE="$ROOT/tool/fixtures/compatibility/traffic-counters.json" "$OUT/transaction-$PLATFORM"
done

# Execute the real provider final admission/start branches against inert APIs.
python3 "$ROOT/tool/test_apple_native_routing_admission.py"

# Actual host admission must use the injected, bounded TCP chooser.
python3 "$ROOT/tool/test_apple_private_port_availability.py"

# Reinitialization cannot redirect a queued start into another options/profile owner.
python3 "$ROOT/tool/test_apple_start_owner.py"
