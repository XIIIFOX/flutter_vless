# XRay android v26.10.17-protect1

Native runtime for the flutter_vless 1.1.7 release train.

- Xray-core [v26.10.17](https://github.com/XTLS/Xray-core/releases/tag/v26.10.17), commit `92ccc939aaf4f8965f369cf0b142e005aeaa11d5`.
- This runtime follows the upstream **pre-release** tag; it is not an upstream stable release.
- Maven coordinates: `dev.tfox.fluttervless:xray-android:26.10.17-protect1`.
- Includes arm64-v8a, armeabi-v7a, x86 and x86_64 with 16 KiB page alignment.
- Adapts the protection overlay to upstream TCP/UDP controller failure propagation; retains protected bootstrap DNS, listener protection and fallback dialers.
- Retains the tun2socks binaries and refreshes geodata from a digest-verified upstream archive.
- The GitHub AAR and Maven Central publication must contain identical runtime bytes. Verify attached files against `SHA256SUMS`.

AAR SHA-256: `d1df973a19757c2a73683d8a5409c2f20cc1bc33059f48d6ddb1057790511afb`.
