# Xray Android v26.10.29-protect3

Native runtime only. Flutter packages stay **1.1.7**; no pub.dev package or
plugin GitHub release is published.

Core remains [v26.10.29](https://github.com/XTLS/Xray-core/releases/tag/v26.10.29),
commit `0afec66085a85191e9dd2a4a6646c7c9a94688d1`, built with Go 1.27.3.
This revision fixes idle XDRIVE connection/listener workers surviving Core
shutdown while preserving caller metadata and parent/Core feature contexts.
GeoDAT scheduler/download teardown and the existing protected sockets,
native routing, Classic/XHTTP cleanup and 16 KiB ELF alignment are retained.
The exact existing HEV libraries and full project GeoDAT bytes are preserved.

Maven: `dev.tfox.fluttervless:xray-android:26.10.29-protect3`.
Producer: `3fffc1d1700889f216f8f02d51a809ec670b21ba`.
[The signed four-ABI candidate](https://github.com/XIIIFOX/flutter_vless/actions/runs/41050075902)
was qualified before [the same Central deployment was published](https://github.com/XIIIFOX/flutter_vless/actions/runs/41051628652),
without rebuilding. [Core regressions pass on three operating systems](https://github.com/XIIIFOX/flutter_vless/actions/runs/41050075901).

AAR SHA-256:
`45254b316f761cfd390843dc267c404d4c7f6d1dae2f686e3ef38d23d88580d0`.

The attached AAR, POM, sources, javadoc and detached signatures are the exact
signed candidate. Verify all eight payloads against `SHA256SUMS`.
Earlier native releases remain unchanged. Guest capability values, device
routing and live cloud-account acceptance are separate checks.
