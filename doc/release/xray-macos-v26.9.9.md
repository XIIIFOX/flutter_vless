# XRay macos v26.9.9

Native runtime for the flutter_vless 1.1.6 release train; Flutter packages remain unreleased.

- Xray-core [v26.9.9](https://github.com/XTLS/Xray-core/releases/tag/v26.9.9), commit `52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120`.
- macOS 13+, universal arm64/x86_64 static library.
- Preserves private logging/startup, asset location and authenticated local proxy support.
- Go 1.27.0; pinned gomobile tooling; HTTP/2 upload scratch buffer capped at 128 KiB per stream.
- `XRay.xcframework.zip` is used by SwiftPM and CocoaPods. Verify it against the attached `SHA256SUMS`.

This is a prerelease native artifact for integration testing, matching the upstream prerelease status.

Archive SHA-256: `6824b49be5f4b123d8116e57d9154efcd2ed66a252dc84a0788ab2b9e1997475`.

Use with the updated flutter_vless 1.1.6 sources: generated DNS chaining now uses `streamSettings.sockopt.dialerProxy`. Xray v26.9.9 rejects the removed `proxySettings` field in older configurations.
