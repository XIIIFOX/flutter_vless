# Xray macos 26.10.29, native revision r2

Upstream Core remains **v26.10.29** at
`0afec66085a85191e9dd2a4a6646c7c9a94688d1`. This separate native revision
adds per-Core XDRIVE S3/Google Drive resource ownership and cancellation,
plus bounded GeoDAT scheduler/download teardown. Cloud cancellation uses a
separate service context and preserves the Core/parent feature context.

The SDK exports managed lifetime capabilities for XDRIVE and GeoDAT. Both
return `1`; version text alone does not establish this support. Native routing,
Darwin physical interface binding, Classic/XHTTP cleanup, Go 1.27.3 and the
128 KiB H2BUF bound are retained.

Producer: `ed3932ff69da47c6f0cdc4ad871da6ba7d032e5e`.
[Canonical SDK build and executed capability checks](https://github.com/XIIIFOX/flutter_vless/actions/runs/41041993623).
[Core regression and cancellation checks on Linux, macOS and Windows](https://github.com/XIIIFOX/flutter_vless/actions/runs/41041992418).

`XRay.xcframework.zip` SHA-256:
`5ab6e5d0955f0896e3b0a979cd951599824353bbcf8f6f61aa3839acad34d83f`.
The release includes the exact producer manifest and checksum file. Earlier
26.10.29 assets are retained unchanged.

Cloud fixtures use controlled HTTP/TLS endpoints and synthetic credentials;
they do not certify a live cloud account, complete relay, HTTP/3/ECH, physical
NAT64 network or a live macOS VPN. Device acceptance is recorded separately.

Flutter plugin packages remain **1.1.7** and are not published by this release.
