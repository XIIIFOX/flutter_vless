# XRay macOS v26.7.28

Release tag: `xray-macos-v26.7.28`

Changes:

* Rebuilt `XRay.xcframework` against XTLS/Xray-core `v26.7.28`.
* Updated the macOS SwiftPM binary target and CocoaPods default release tag to `xray-macos-v26.7.28`.
* Kept the static-library xcframework packaging used by the macOS plugin and tunnel-support target.
* Build source comes from the vendored `third_party/xray-mobile` Go wrapper.

Upstream:

* XTLS/Xray-core `v26.7.28` was published on 2026-07-28 and is marked as a pre-release on GitHub.
* Release commit: `5ca6f4b7d4dc20a881d4330e498892697627ec0c`.

Verification:

* Run `cd packages/flutter_vless_macos/macos && GOTOOLCHAIN=go1.27.0 ./build_xray_macos.sh`.
* Run `tool/create_xray_macos_release.sh` and copy the printed checksum into `packages/flutter_vless_macos/macos/flutter_vless_macos/Package.swift` and `packages/flutter_vless_macos/macos/flutter_vless_macos.podspec`.
