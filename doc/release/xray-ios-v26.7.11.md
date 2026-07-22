# XRay iOS v26.7.11

Release tag: `xray-ios-v26.7.11`

Changes:

* Rebuilt `XRay.xcframework` against XTLS/Xray-core `v26.7.11`.
* Updated the iOS SwiftPM binary target and CocoaPods default release tag to `xray-ios-v26.7.11`.
* Kept the iOS minimum deployment target at 15.0.
* Build source comes from the vendored `third_party/xray-mobile` Go wrapper.

Upstream:

* XTLS/Xray-core `v26.7.11` was published on 2026-07-11 and is marked as a pre-release on GitHub.
* Release commit: `50231eaff98ccc31b5cbd247a721c16e97fe5ec1`.

Verification:

* Run `cd ios && ./build_xray_ios.sh`.
* Run `tool/create_xray_ios_release.sh` and copy the printed checksum into `ios/flutter_vless/Package.swift` and `ios/flutter_vless.podspec`.
