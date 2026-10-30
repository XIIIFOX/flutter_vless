#import <Foundation/Foundation.h>
#include <stdint.h>
@protocol XRayLogger;

NS_ASSUME_NONNULL_BEGIN
FOUNDATION_EXPORT BOOL FLVlessHasCorePreflight(void);
// -1 means the loaded runtime predates the additive preflight capability.
FOUNDATION_EXPORT int64_t FLVlessCheckCorePrivate(NSData *configuration);
// Only a complete optional ABI reporting version one is supported. Older,
// untagged and partially linked runtimes report zero; never emulate routing.
FOUNDATION_EXPORT int64_t FLVlessCoreRoutingCapability(void);
// Stock SDKs safely report zero for the separately patched Darwin binding path.
FOUNDATION_EXPORT int64_t FLVlessCoreDarwinInterfaceBindingCapability(void);
FOUNDATION_EXPORT int64_t FLVlessCoreGeodataLifetimeCapability(void);
FOUNDATION_EXPORT int64_t FLVlessCoreXdriveLifetimeCapability(void);
FOUNDATION_EXPORT int64_t FLVlessCheckCoreRoutingPrivate(NSData * _Nullable configuration, NSData * _Nullable specification);
FOUNDATION_EXPORT BOOL FLVlessStartCoreRoutingPrivate(NSData * _Nullable configuration, NSData * _Nullable specification,
                                                    id<XRayLogger> _Nullable logger, NSError * _Nullable * _Nullable error);
NS_ASSUME_NONNULL_END
