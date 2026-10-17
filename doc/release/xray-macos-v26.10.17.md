# XRay macos v26.10.17

Native runtime for the flutter_vless 1.1.7 release train.

- Xray-core [v26.10.17](https://github.com/XTLS/Xray-core/releases/tag/v26.10.17), commit `92ccc939aaf4f8965f369cf0b142e005aeaa11d5`.
- This runtime follows the upstream **pre-release** tag; it is not an upstream stable release.
- macOS 13+, universal arm64/x86_64 static library.
- Preserves private startup/logging, asset selection and authenticated local proxies.
- Go 1.27.0 with pinned gomobile tooling; HTTP/2 upload scratch cap remains 128 KiB per stream.
- `XRay.xcframework.zip` is consumed by SwiftPM and CocoaPods. Verify it against attached `SHA256SUMS`.

Archive SHA-256: `358fee3fd828657b0ea70ad97d1bb6370f3cddaca92c7c6871c3851e9e0d106e`.
