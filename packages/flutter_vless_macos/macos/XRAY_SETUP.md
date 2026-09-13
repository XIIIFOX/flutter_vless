# Xray-core Setup for macOS

The plugin runs Xray-core `v26.9.9` through `XRay.xcframework`. Both the app and
Packet Tunnel link the native library; a standalone `xray` executable is not
required for normal plugin operation.

## Native runtime

The universal framework supports Apple Silicon and Intel on macOS 13 or newer.
SwiftPM and CocoaPods use the bundled framework when present, otherwise they
download the pinned [macOS native release](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-macos-v26.9.9)
and verify its SHA-256 checksum. Keep the release tag and checksum in
`flutter_vless_macos/Package.swift` and `flutter_vless_macos.podspec` together.

Build the framework from the pinned vendored Go wrapper:

```bash
./packages/flutter_vless_macos/macos/build_xray_macos.sh
```

The build selects Go 1.27.0 and the wrapper's pinned mobile tooling. It preserves
private startup and asset-location bridges and caps HTTP/2 upload scratch buffers
at 128 KiB using an isolated toolchain copy.

## Packet Tunnel integration

Configure the extension, shared App Group and signing with the package's
`setup_macos_vpn` tool. The app and extension must use matching plugin support
sources and the same framework. Set `geoAssetsDirectory` to an extension-readable
directory containing `geoip.dat` and `geosite.dat` when using custom geodata.

## Standalone manual checks

The example also includes the upstream Apple Silicon executable for manual
checks. It is separate from the framework used by the plugin:

```bash
./example/macos/Runner/xray/xray version
# Xray 26.9.9 ... 52a412d
```

For an Intel standalone executable, use the matching archive from the
[upstream v26.9.9 release](https://github.com/XTLS/Xray-core/releases/tag/v26.9.9).
