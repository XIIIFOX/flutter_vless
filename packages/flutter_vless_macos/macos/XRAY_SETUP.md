# Xray-core Setup for macOS

The plugin runs Xray-core `v26.11.9` through the verified `XRay.xcframework`. Both the app and
Packet Tunnel link the native library; a standalone `xray` executable is not
required for normal plugin operation.

## Native runtime

The universal framework supports Apple Silicon and Intel on macOS 13 or newer.
SwiftPM and CocoaPods use the bundled framework when present, otherwise they
download the pinned [macOS native release](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-macos-v26.11.9-r1)
and verify its SHA-256 checksum. Keep the release tag and checksum in
`flutter_vless_macos/Package.swift` and `flutter_vless_macos.podspec` together.

The release ZIP has SHA-256
`3a9c5b3c18a9706539d44c74cc176ba6232f663cf662d1cf2ce13ac40f3096c7`
and uses Core commit `676eaf66f8f05d4d558ee7a74b4736623d3feeb9`.
The complete tracked `XRay.xcframework` tree matches those public bytes. Replace
that tree along with the manifests, since an existing local framework takes
precedence over downloading. The canonical producer uses Go 1.27.3; artifact
qualification verifies 16 C exports for each architecture. Its disposable macOS
runner checks routing/interface capabilities 1, GeoDAT lifetime 1 and XDRIVE
lifetime 2.

Build the framework from the pinned vendored Go wrapper:

```bash
./packages/flutter_vless_macos/macos/build_xray_macos.sh
```

The build selects Go 1.27.3 and the wrapper's pinned mobile tooling. It preserves
private startup and asset-location bridges and caps HTTP/2 upload scratch buffers
at 128 KiB using an isolated toolchain copy. Older toolchains are refused for
root CA filtering. Canonical builds also retain routing capability 1, mandatory
Darwin interface binding and the Classic DNS/XHTTP HTTP/3 lifetime fixes from
the qualified previews. The manual Apple runtime workflow verifies both
platforms without publishing; exact consumer URL/checksum updates follow public
asset verification. No Flutter package is released by this build.

## Packet Tunnel integration

Configure the extension, shared App Group and signing with the package's
`setup_macos_vpn` tool. The app and extension must use matching plugin support
sources and the same framework. Set `geoAssetsDirectory` to an extension-readable
directory containing the data files actually referenced by the configuration.
Custom-only or asset-free directories are supported by the verified 26.11.9
runtime; older published frameworks require both standard GeoDAT files.
Certificate/key lookup uses Core's separate certificate root.

## Standalone manual checks

The example also includes the upstream Apple Silicon executable for manual
checks. It is separate from the framework used by the plugin:

```bash
./example/macos/Runner/xray/xray version
# Xray 26.11.9 ... 676eaf6
```

For an Intel standalone executable, use the matching archive from the
[upstream v26.11.9 release](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9).
