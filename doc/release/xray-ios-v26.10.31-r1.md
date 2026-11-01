# Xray iOS 26.10.31, native revision r1

Upstream Core is **v26.10.31**, commit
`a4a3dff5b20c2faae567b742c172c7b95e75c083`.
The shared listener retains upstream's MPTCP default-off security change and
explicit caller opt-in. Classic DNS, XHTTP/H3, XDRIVE and GeoDAT lifetime fixes,
native routing and Darwin interface binding are preserved.

Producer: `13c47ed2caabd70b082449ed4917ce65574df91e`.
[Canonical SDK build and executed simulator checks](https://github.com/XIIIFOX/flutter_vless/actions/runs/41349615824).
[Core routing/compatibility checks on Linux, Windows and macOS](https://github.com/XIIIFOX/flutter_vless/actions/runs/41350987225).
The later validation commit changes verification scripts only; native sources
are identical to the producer.

The SDK contains device arm64 and simulator arm64/x86_64 slices, with all
16 expected C exports verified per architecture. The executed SDK reports Core
26.10.31, GeoDAT capability **1**, XDRIVE capability **2**, routing **1** and
Darwin interface binding **1**. Go **1.27.3** and the **128 KiB H2BUF** limit
are retained; custom-root and preflight checks pass.

`XRay.xcframework.zip` SHA-256:
`22813f46cd978341a2f6aa61f8d346fb57393c53a9f271d5f42b6b1a3371b9cc`.
The release includes the exact archive, producer manifest and checksum file.
Earlier release assets remain unchanged. Physical-device acceptance is recorded
separately after publication.

Flutter package versions remain **1.1.7**. This release publishes native runtime
assets only and does not publish the plugin.
