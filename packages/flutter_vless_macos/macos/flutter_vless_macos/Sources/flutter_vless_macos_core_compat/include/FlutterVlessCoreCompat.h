#import <Foundation/Foundation.h>
#include <stdint.h>

NS_ASSUME_NONNULL_BEGIN
FOUNDATION_EXPORT BOOL FLVlessHasCorePreflight(void);
// -1 means the loaded runtime predates the additive preflight capability.
FOUNDATION_EXPORT int64_t FLVlessCheckCorePrivate(NSData *configuration);
NS_ASSUME_NONNULL_END
