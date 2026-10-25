# XRay Android v26.10.21-protect1

Native runtime only for the unreleased flutter_vless 1.1.7 work. No Flutter package or pub.dev implementation package is published by this release.

- Xray-core [v26.10.21](https://github.com/XTLS/Xray-core/releases/tag/v26.10.21), commit `1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`.
- Go 1.27.3 and updated fallback RootCAs for the upstream certificate-trust security update.
- Maven Central: `dev.tfox.fluttervless:xray-android:26.10.21-protect1`.
- Fresh arm64-v8a, armeabi-v7a, x86 and x86_64 binaries with protected sockets, routing capability 1 and 16 KiB ELF alignment. Retains the existing HEV and full project GeoDAT bytes.
- One signed candidate was compiled, verified and published in [GitHub Actions](https://github.com/XIIIFOX/flutter_vless/actions/runs/40216656997) from `2113330771844fc63248ad8eafd0b0ce6cdb757a`. The same Central deployment reached PUBLISHED; all eight public signed payload bodies independently match its CI receipt hashes.
- Device acceptance is separate from build/static verification.

AAR SHA-256: `d719bad4a15d99af8aa13f37295b9b86f7e58dd962338075151a4530d4b54810`.

The attached AAR, POM, sources, javadoc and detached signatures are byte-identical to Maven Central. Verify the four payload files against `SHA256SUMS`.
