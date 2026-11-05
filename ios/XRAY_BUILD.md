# Build XRay.xcframework

The iOS plugin uses `XRay.xcframework`, generated with `gomobile bind` from
`third_party/xray-mobile`.

- Xray-core: `v26.10.31`, commit `a4a3dff5b20c2faae567b742c172c7b95e75c083`
- Runtime tag: `xray-ios-v26.10.31-r2`
- [Archive](https://github.com/XIIIFOX/flutter_vless/releases/download/xray-ios-v26.10.31-r2/XRay.xcframework.zip)
- SHA-256: `8d693bc767b8f292f0ec0459850287f752c40499fa6542caef5b749c8bdc5f00`

SwiftPM and CocoaPods use this pinned artifact. Update both manifests and the
repository's `ios/XRay.xcframework` together: local framework selection prefers
an existing directory. A rebuild can change the archive checksum and needs a new
runtime revision with matching consumer pins.

Retain `XRayStartPrivate`, `XRaySetAssetLocation` and the routing/interface/managed
service capability exports. App and extension entry points use private startup
and asset selection; an older framework must not bypass those requirements.
The runtime disables raw access/error output and secret-bearing debug files.
Revision r2 also releases the XHTTP listener after invalid server `h2Params`.

Requirements:

- Full Xcode with `iphoneos` and `iphonesimulator` SDKs selected.
- Go 1.27.3, selected by default through `GOTOOLCHAIN`.
- The script installs pinned `gomobile` and `gobind` in its isolated build directory.

```bash
cd ios
./build_xray_ios.sh
```

If Command Line Tools are selected, set Xcode for this build:

```bash
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer ./build_xray_ios.sh
```

Source and deployment overrides:

```bash
XRAY_MOBILE_DIR=../third_party/xray-mobile XRAY_CORE_REF=a4a3dff5b20c2faae567b742c172c7b95e75c083 IOS_VERSION=15.0 ./build_xray_ios.sh
```

The script copies the wrapper into `ios/build_xray_ios/xray-mobile` before
updating Go dependencies, preserving the tracked source. Unsupported toolchain
versions or stdlib layouts fail explicitly. Test a rebuilt SDK with a signed
Packet Tunnel host as described in the [iOS guide](../doc/platform/ios.md).

## H2BUF scratch-buffer patch

Before binding, the script copies GOROOT into
`ios/build_xray_ios/goroot-patched` and limits the HTTP/2 per-stream upload
scratch buffer to **128 KiB**. The system Go installation is not modified.
Keep this safeguard when rebuilding: it reduces Network Extension memory
pressure during concurrent XHTTP uploads.

See [release preparation](../doc/release/README.md) for archive qualification and
consumer pin updates. Native SDK and Flutter package versions are independent.
