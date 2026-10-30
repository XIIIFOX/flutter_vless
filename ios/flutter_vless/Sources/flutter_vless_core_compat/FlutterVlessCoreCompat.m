#import "include/FlutterVlessCoreCompat.h"

// Gomobile places its exported Objective-C functions in the same archive
// member. A strong reference to StartPrivate pulls that member into the app;
// its new strong CheckPrivate definition then replaces this legacy fallback.
// No dynamic lookup or unresolved symbols are needed with an older runtime.
__attribute__((weak)) int64_t XRayCheckPrivate(NSData *configuration) {
    (void)configuration;
    return -1;
}

BOOL FLVlessHasCorePreflight(void) { return XRayCheckPrivate(nil) != -1; }
int64_t FLVlessCheckCorePrivate(NSData *configuration) {
    return XRayCheckPrivate(configuration);
}

// Static libraries need definitions for absent entries. Keep each weak entry
// at a nonzero offset from its strong hidden anchor: linkers can rebind every
// symbol sharing the overridden weak symbol's address. The alternate-entry
// directive fixes its offset/liveness relative to the preceding anchor. Strong
// generated entries then replace only the weak name. No consumer linker flags,
// runtime lookup or trial Check/Start is needed.
__attribute__((weak)) int64_t XRayRoutingCapability(void) { return 0; }
__attribute__((weak)) int64_t XRayDarwinInterfaceBindingCapability(void) { return 0; }

// Distinct negative sentinels prevent identical weak fallback bodies from
// sharing an address and being rebound by another capability's strong entry.
__attribute__((weak)) int64_t XRayGeodataLifetimeCapability(void) { return -41; }
__attribute__((weak)) int64_t XRayXdriveLifetimeCapability(void) { return -42; }
int64_t FLVlessCoreGeodataLifetimeCapability(void) {
    int64_t (*volatile capability)(void) = XRayGeodataLifetimeCapability;
    return capability() == 1 ? 1 : 0;
}
int64_t FLVlessCoreXdriveLifetimeCapability(void) {
    int64_t (*volatile capability)(void) = XRayXdriveLifetimeCapability;
    return capability() == 2 ? 2 : 0;
}


int64_t FLVlessCoreDarwinInterfaceBindingCapability(void) {
    int64_t (*volatile capability)(void) = XRayDarwinInterfaceBindingCapability;
    return capability() == 1 ? 1 : 0;
}

__attribute__((used, noinline, visibility("hidden")))
int64_t FLVlessUnavailableRoutingCheck(NSData *configuration, NSData *specification) {
    (void)configuration; (void)specification;
    return 32;
}

__attribute__((used, noinline, visibility("hidden")))
BOOL FLVlessUnavailableRoutingStart(NSData *configuration, NSData *specification,
                                   id<XRayLogger> logger, NSError **error) {
    (void)configuration; (void)specification; (void)logger;
    if (error) {
        *error = [NSError errorWithDomain:@"flutter_vless.core.routing" code:32
                                userInfo:@{NSLocalizedDescriptionKey: @"Native VPN routing is unavailable in this Xray runtime."}];
    }
    return NO;
}

#if defined(__arm64__)
#define FLVLESS_CHECK_TAIL "b _FLVlessUnavailableRoutingCheck"
#define FLVLESS_START_TAIL "b _FLVlessUnavailableRoutingStart"
#define FLVLESS_ROUTING_ENTRY_OFFSET 4u
#elif defined(__x86_64__)
#define FLVLESS_CHECK_TAIL "jmp _FLVlessUnavailableRoutingCheck"
#define FLVLESS_START_TAIL "jmp _FLVlessUnavailableRoutingStart"
#define FLVLESS_ROUTING_ENTRY_OFFSET 1u
#else
#error Unsupported Apple routing ABI architecture
#endif

__attribute__((used, naked, noinline, visibility("hidden")))
int64_t FLVlessMissingRoutingCheck(NSData *configuration __attribute__((unused)), NSData *specification __attribute__((unused))) {
    __asm__("nop\n.globl _XRayCheckRoutingPrivate\n.weak_definition _XRayCheckRoutingPrivate\n.alt_entry _XRayCheckRoutingPrivate\n_XRayCheckRoutingPrivate:\n" FLVLESS_CHECK_TAIL);
}

__attribute__((used, naked, noinline, visibility("hidden")))
BOOL FLVlessMissingRoutingStart(NSData *configuration __attribute__((unused)), NSData *specification __attribute__((unused)),
                               id<XRayLogger> logger __attribute__((unused)), NSError **error __attribute__((unused))) {
    __asm__("nop\n.globl _XRayStartRoutingPrivate\n.weak_definition _XRayStartRoutingPrivate\n.alt_entry _XRayStartRoutingPrivate\n_XRayStartRoutingPrivate:\n" FLVLESS_START_TAIL);
}
#undef FLVLESS_CHECK_TAIL
#undef FLVLESS_START_TAIL

extern int64_t XRayCheckRoutingPrivate(NSData * _Nullable configuration, NSData * _Nullable specification);
extern BOOL XRayStartRoutingPrivate(NSData * _Nullable configuration, NSData * _Nullable specification,
                                   id<XRayLogger> _Nullable logger, NSError * _Nullable * _Nullable error);

int64_t FLVlessCoreRoutingCapability(void) {
    // Volatile loads prevent assuming distinct external function identities.
    // Compare the weak entry to anchor+offset, never to a same-address alias.
    int64_t (*volatile check)(NSData *, NSData *) = XRayCheckRoutingPrivate;
    int64_t (*volatile missingCheck)(NSData *, NSData *) = FLVlessMissingRoutingCheck;
    BOOL (*volatile start)(NSData *, NSData *, id<XRayLogger>, NSError **) = XRayStartRoutingPrivate;
    BOOL (*volatile missingStart)(NSData *, NSData *, id<XRayLogger>, NSError **) = FLVlessMissingRoutingStart;
    if ((uintptr_t)check == (uintptr_t)missingCheck + FLVLESS_ROUTING_ENTRY_OFFSET ||
        (uintptr_t)start == (uintptr_t)missingStart + FLVLESS_ROUTING_ENTRY_OFFSET) { return 0; }
    return XRayRoutingCapability() == 1 ? 1 : 0;
}

#if defined(FLVLESS_TEST_CORE_ROUTING_DIAGNOSTICS)
// Inert link-fixture diagnostics only. Keep sentinel references in this same
// translation unit so observing them does not add external strong references
// from the probe and change weak-atom extraction/coalescing behavior.
__attribute__((visibility("hidden")))
void FLVlessTestCoreRoutingDiagnostics(int *checkMissing, int *startMissing, int64_t *rawCapability) {
    int64_t (*volatile check)(NSData *, NSData *) = XRayCheckRoutingPrivate;
    int64_t (*volatile missingCheck)(NSData *, NSData *) = FLVlessMissingRoutingCheck;
    BOOL (*volatile start)(NSData *, NSData *, id<XRayLogger>, NSError **) = XRayStartRoutingPrivate;
    BOOL (*volatile missingStart)(NSData *, NSData *, id<XRayLogger>, NSError **) = FLVlessMissingRoutingStart;
    int64_t (*volatile capability)(void) = XRayRoutingCapability;
    *checkMissing = (uintptr_t)check == (uintptr_t)missingCheck + FLVLESS_ROUTING_ENTRY_OFFSET;
    *startMissing = (uintptr_t)start == (uintptr_t)missingStart + FLVLESS_ROUTING_ENTRY_OFFSET;
    *rawCapability = capability();
}
#endif

int64_t FLVlessCheckCoreRoutingPrivate(NSData *configuration, NSData *specification) {
    if (FLVlessCoreRoutingCapability() != 1) { return 32; }
    return XRayCheckRoutingPrivate(configuration, specification);
}

BOOL FLVlessStartCoreRoutingPrivate(NSData *configuration, NSData *specification,
                                  id<XRayLogger> logger, NSError **error) {
    if (FLVlessCoreRoutingCapability() != 1) {
        return FLVlessUnavailableRoutingStart(configuration, specification, logger, error);
    }
    return XRayStartRoutingPrivate(configuration, specification, logger, error);
}
