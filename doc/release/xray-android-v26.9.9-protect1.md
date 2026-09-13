# XRay Android v26.9.9-protect1

Native runtime for the flutter_vless 1.1.6 release train; Flutter packages remain unreleased.

- Xray-core [v26.9.9](https://github.com/XTLS/Xray-core/releases/tag/v26.9.9), commit `52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120`.
- Maven Central: `dev.tfox.fluttervless:xray-android:26.9.9-protect1`.
- Includes arm64-v8a, armeabi-v7a, x86 and x86_64; 16 KiB native page alignment.
- Retains required socket protection, protected bootstrap DNS and failure propagation.
- Retains the existing tun2socks runtime and refreshes geodata from the verified upstream release archive.
- GitHub hosts the same AAR published to Maven Central; verify it against `SHA256SUMS`.

This is a prerelease native artifact for integration testing, matching the upstream prerelease status.

Use with the updated flutter_vless 1.1.6 sources: generated DNS chaining now uses `streamSettings.sockopt.dialerProxy`. Xray v26.9.9 rejects the removed `proxySettings` field in older configurations.
