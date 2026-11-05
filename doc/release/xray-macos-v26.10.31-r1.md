# Xray macOS 26.10.31, native revision r1

Upstream Core is **v26.10.31**, commit
`a4a3dff5b20c2faae567b742c172c7b95e75c083`.
The shared listener retains upstream's MPTCP default-off security change and
explicit caller opt-in. Classic DNS, XHTTP/H3, XDRIVE and GeoDAT lifetime fixes,
native routing and Darwin interface binding are preserved.

Producer: `13c47ed2caabd70b082449ed4917ce65574df91e`.
[Canonical SDK build and executed macOS checks](https://github.com/XIIIFOX/flutter_vless/actions/runs/41349615824).
[Core routing/compatibility checks on Linux, Windows and macOS](https://github.com/XIIIFOX/flutter_vless/actions/runs/41350987225).
The later validation commit changes verification scripts only; native sources
are identical to the producer.

Both arm64 and x86_64 slices have all 16 expected C exports. The executed SDK
reports Core 26.10.31, GeoDAT capability **1**, XDRIVE capability **2**, routing
**1** and Darwin interface binding **1**. Go **1.27.3** and the **128 KiB H2BUF**
limit are retained; custom-root and preflight checks pass. Runtime execution
takes place on disposable Actions runners; the owner's Mac VPN is untouched.

`XRay.xcframework.zip` SHA-256:
`15de3fed0dc69604ba0a76172ff0d1550f2d64ebc1c173109e2308ef657cb07c`.
The release includes the exact archive, producer manifest and checksum file.
Earlier release assets remain unchanged. Live macOS VPN acceptance remains a
separately scheduled check.
