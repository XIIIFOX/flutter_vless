# Build XRay.xcframework

The iOS plugin uses `XRay.xcframework`, generated with `gomobile bind` from
the vendored `third_party/xray-mobile` Go wrapper.

Current target Xray-core version: `v26.7.11`.
Release commit used by the script: `45cf2898ab12e97a55dd8f1f3d78d903340bdc9e`.

Requirements:

- Full Xcode with iOS SDK installed and selected with `xcode-select`.
- Go installed.
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
XRAY_MOBILE_DIR=../third_party/xray-mobile XRAY_CORE_REF=45cf2898ab12e97a55dd8f1f3d78d903340bdc9e IOS_VERSION=15.0 ./build_xray_ios.sh
```

The build script copies `XRAY_MOBILE_DIR` into `ios/build_xray_ios/xray-mobile`
before running `go get` and `go mod tidy`, so the tracked vendored source is not
mutated by release builds.

Note: Xcode Command Line Tools are not enough because `gomobile bind -target=ios` needs the `iphoneos` and `iphonesimulator` SDKs.
