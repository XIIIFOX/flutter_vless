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
