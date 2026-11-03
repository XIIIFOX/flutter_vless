# flutter_vless_windows

The Windows implementation of the [`flutter_vless`](https://pub.dev/packages/flutter_vless) plugin.

This package is intended to be used through the main `flutter_vless` package. It provides the Windows platform backend for Xray/V2Ray proxy-only and VPN/tunnel flows.

The working `1.1.7+1` source supports the published managed
`xray-windows-v26.10.31-r2` companion for native routing and XDRIVE/GeoDAT
services. Supply the matching runtime/helper files as described in the guide;
the plugin checks the executable it actually selects. Ordinary compatible
external Core builds remain supported for profiles without managed services.
The `1.1.7+1` implementation update is not yet published; the existing pub.dev
`1.1.7` wrapper remains unchanged.

For setup details, see the [Windows platform guide](https://github.com/XIIIFOX/flutter_vless/blob/main/doc/platform/windows.md).
