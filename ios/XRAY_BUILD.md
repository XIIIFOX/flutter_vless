# Build XRay.xcframework

The iOS plugin uses `XRay.xcframework`, generated with `gomobile bind` from
the vendored `third_party/xray-mobile` Go wrapper.

The wrapper exports `XRaySetAssetLocation` in addition to the lifecycle API.
Keep this symbol when rebuilding: the iOS app and Packet Tunnel use it to set
Xray's asset directory from inside the Go runtime.

Current target Xray-core version: `v26.7.28`.
Release commit used by the script: `5ca6f4b7d4dc20a881d4330e498892697627ec0c`.
Current wrapper artifact tag: `xray-ios-v26.7.28-r3`.
The privacy revision adds `XRayStartPrivate`; all iOS entry points require this
symbol so an older cached framework fails to link instead of bypassing policy.
It disables raw access/error output, sanitizes startup/runtime callbacks, and
turns off REALITY debug prints and TLS key files, including XHTTP downloads and
Realm finalmask TLS. Xray-core remains 26.7.28; the H2BUF cap remains 128 KiB.

The release archive is available at
`https://github.com/XIIIFOX/flutter_vless/releases/download/xray-ios-v26.7.28-r3/XRay.xcframework.zip`
with SHA-256 `3792dc3ae6ffa42922c4604827812e48e29307d381d5db40a2c3932e0b779a60`.
SwiftPM and CocoaPods verify this checksum when downloading the framework.
A rebuild may produce a different archive checksum; use a new revision and
coordinate both manifests with the exact artifact.

Requirements:

- Full Xcode with iOS SDK installed and selected with `xcode-select`.
- Go 1.27 or newer installed.
- `gomobile` installed, or let the script install it into `$HOME/go/bin`.

Build:

```bash
cd ios
./build_xray_ios.sh
```

If `xcode-select -p` points to Command Line Tools, either switch Xcode globally:

```bash
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
```

or run only this build with Xcode selected:

```bash
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer ./ios/build_xray_ios.sh
```

Useful overrides:

```bash
XRAY_MOBILE_DIR=../third_party/xray-mobile XRAY_CORE_REF=5ca6f4b7d4dc20a881d4330e498892697627ec0c IOS_VERSION=15.0 ./build_xray_ios.sh
```

The build script copies `XRAY_MOBILE_DIR` into `ios/build_xray_ios/xray-mobile`
before running `go get` and `go mod tidy`, so the tracked vendored source is not
mutated by release builds.

Note: Xcode Command Line Tools are not enough because `gomobile bind -target=ios` needs the `iphoneos` and `iphonesimulator` SDKs.

## H2BUF scratch-buffer patch

The build script patches a temporary copy of the Go standard library before
`gomobile bind`: it clones the live GOROOT into `ios/build_xray_ios/goroot-patched`
and lowers the http2 client's per-stream upload scratch buffer cap from 512 KiB
to 128 KiB (`H2BUF_CAP_KB` overrides the value, range 16-512). The system Go
installation is never modified.

Without this cap, Xray's XHTTP server advertises a 1 MiB SETTINGS_MAX_FRAME_SIZE
and iOS Network Extensions (50 MB hard limit) are jetsam-killed under concurrent
uploads. See issue #23 for the full analysis and on-device measurements.

Required and tested toolchain: **Go 1.27 or newer**. The build fails with a
clear error if the Go version, stdlib layout, or anchor line is unsupported.
