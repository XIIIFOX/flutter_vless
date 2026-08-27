# Build XRay.xcframework

The iOS plugin uses `XRay.xcframework`, generated with `gomobile bind` from
the vendored `third_party/xray-mobile` Go wrapper.

Current target Xray-core version: `v26.7.28`.
Release commit used by the script: `5ca6f4b7d4dc20a881d4330e498892697627ec0c`.

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
