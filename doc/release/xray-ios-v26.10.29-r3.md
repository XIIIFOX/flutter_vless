# Xray iOS 26.10.29, native revision r3

Upstream Core remains **v26.10.29** at
`0afec66085a85191e9dd2a4a6646c7c9a94688d1`.
This revision fixes idle XDRIVE connection/listener workers surviving Core
shutdown. Worker cancellation follows the separate service owner while
preserving caller metadata and the parent/Core feature context.

The executed SDK reports XDRIVE lifetime capability **2** and GeoDAT lifetime
capability **1**. Existing native routing, Darwin interface binding,
Classic/XHTTP cleanup, Go 1.27.3 and the 128 KiB H2BUF bound are retained.
Earlier native assets remain unchanged.

Producer: `3fffc1d1700889f216f8f02d51a809ec670b21ba`.
[Canonical Apple SDK build and executed capability checks](https://github.com/XIIIFOX/flutter_vless/actions/runs/41050075922).
[Core regressions on Linux, macOS and Windows](https://github.com/XIIIFOX/flutter_vless/actions/runs/41050075901).
The identical actual-Core idle fixture [failed before the fix](https://github.com/XIIIFOX/flutter_vless/actions/runs/41047188984)
and [passes after it](https://github.com/XIIIFOX/flutter_vless/actions/runs/41049190758).

`XRay.xcframework.zip` SHA-256:
`66dd910e9969b3a3718976efbdd832f0538b1387b27a4f8a7531445bc076b4e1`.
The release includes its exact producer manifest and checksum file.

Cloud fixtures use controlled endpoints and synthetic credentials. Live cloud
accounts, a complete relay deployment, HTTP/3/ECH and physical NAT64 remain
separate acceptance. Physical-device checks are recorded separately.
Flutter packages remain **1.1.7**; this release does not publish the plugin.
