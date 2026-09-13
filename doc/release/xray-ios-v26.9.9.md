# XRay ios v26.9.9

Native runtime for the flutter_vless 1.1.6 release train; Flutter packages remain unreleased.

- Xray-core [v26.9.9](https://github.com/XTLS/Xray-core/releases/tag/v26.9.9), commit `52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120`.
- iOS 15+, arm64 devices and arm64/x86_64 simulators.
- Preserves private logging/startup, asset location and authenticated local proxy support.
- Go 1.27.0; pinned gomobile tooling; HTTP/2 upload scratch buffer capped at 128 KiB per stream.
- `XRay.xcframework.zip` is used by SwiftPM and CocoaPods. Verify it against the attached `SHA256SUMS`.

This is a prerelease native artifact for integration testing, matching the upstream prerelease status.

Archive SHA-256: `dd07e1897bdff4c3e4e1a3958629ad5d9517676ecd470bfd99ec35e46184549e`.

Use with the updated flutter_vless 1.1.6 sources: generated DNS chaining now uses `streamSettings.sockopt.dialerProxy`. Xray v26.9.9 rejects the removed `proxySettings` field in older configurations.
