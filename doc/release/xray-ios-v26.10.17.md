# XRay ios v26.10.17

Native runtime for the flutter_vless 1.1.7 release train.

- Xray-core [v26.10.17](https://github.com/XTLS/Xray-core/releases/tag/v26.10.17), commit `92ccc939aaf4f8965f369cf0b142e005aeaa11d5`.
- This runtime follows the upstream **pre-release** tag; it is not an upstream stable release.
- iOS 15+, arm64 devices and arm64/x86_64 simulators.
- Preserves private startup/logging, asset selection and authenticated local proxies.
- Go 1.27.0 with pinned gomobile tooling; HTTP/2 upload scratch cap remains 128 KiB per stream.
- `XRay.xcframework.zip` is consumed by SwiftPM and CocoaPods. Verify it against attached `SHA256SUMS`.

Archive SHA-256: `d61ce94cc2f6f982606c52df03be577838b9caaa3bea5981ef300c83976b77cc`.
