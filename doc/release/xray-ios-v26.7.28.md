# XRay iOS v26.7.28

Release tag: `xray-ios-v26.7.28`

Changes:

* Rebuilt `XRay.xcframework` against XTLS/Xray-core `v26.7.28`.
* Kept the 128 KiB HTTP/2 upload scratch-buffer cap used to protect the iOS Network Extension memory budget.
* Updated the iOS SwiftPM binary target and CocoaPods default release tag to `xray-ios-v26.7.28`.
* Kept the iOS minimum deployment target at 15.0.
* Build source comes from the vendored `third_party/xray-mobile` Go wrapper.

Upstream:

* XTLS/Xray-core `v26.7.28` was published on 2026-07-28 and is marked as a pre-release on GitHub.
* Release commit: `5ca6f4b7d4dc20a881d4330e498892697627ec0c`.

Verification:

* Run `cd ios && GOTOOLCHAIN=go1.27.0 ./build_xray_ios.sh`.
* Run `tool/create_xray_ios_release.sh` and copy the printed checksum into `ios/flutter_vless/Package.swift` and `ios/flutter_vless.podspec`.
