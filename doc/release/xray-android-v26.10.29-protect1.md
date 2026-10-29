# XRay Android v26.10.29-protect1

Native runtime only for the unreleased flutter_vless 1.1.7 work. No Flutter
package, pub.dev package or plugin 1.1.7 GitHub release is published.

- Xray-core [v26.10.29](https://github.com/XTLS/Xray-core/releases/tag/v26.10.29),
  commit `0afec66085a85191e9dd2a4a6646c7c9a94688d1`; Go 1.27.3.
- Maven Central: `dev.tfox.fluttervless:xray-android:26.10.29-protect1`.
- Four freshly compiled ABIs, protected sockets, native routing capability 1,
  Classic DNS/XHTTP lifetime cleanup and 16 KiB ELF LOAD alignment.
- Retain the exact existing HEV libraries and full project GeoDAT bytes.
- Producer revision: `c381b13dd694ba415ef7d55302abdd0e43b86e2b`.
  [One signed candidate](https://github.com/XIIIFOX/flutter_vless/actions/runs/40956105136)
  was built and checked, then [the same Central deployment](https://github.com/XIIIFOX/flutter_vless/actions/runs/40957965701)
  reached PUBLISHED without rebuilding or uploading another bundle.

AAR SHA-256: `ac498513218e640c6524e59eb5bba5431ff51c396f114931ada1837f79561ecb`.

The attached AAR, POM, sources, javadoc and detached signatures are the exact
signed candidate. Verify all eight payloads against `SHA256SUMS`.
Public Maven byte verification and device acceptance are recorded separately in
[validation and remaining work](xray-v26.10.29-validation.md).
