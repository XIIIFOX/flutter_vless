# XRay iOS v26.7.28-r2

Release tag: `xray-ios-v26.7.28-r2`

Changes:

* Rebuilt `XRay.xcframework` against XTLS/Xray-core `v26.7.28`.
* Added the `XRaySetAssetLocation` gomobile bridge used to load `geoip.dat`
  and `geosite.dat` dynamically from an iOS App Group directory.
* Kept the 128 KiB HTTP/2 upload scratch-buffer cap used to protect the iOS
  Network Extension memory budget.
* Kept the iOS minimum deployment target at 15.0.

Verification:

* Run `cd ios && GOTOOLCHAIN=go1.27.0 ./build_xray_ios.sh`.
* Run `go test ./...` in `third_party/xray-mobile`.
* Run `tool/create_xray_ios_release.sh`; the expected SwiftPM checksum is
  `2998d736ad253def6d24e0c09010e5364f3405545a4cfad795ad1fc3ed443517`.
* Run `flutter build ios --debug --no-codesign` in `example`.
