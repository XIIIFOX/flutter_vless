# flutter_vless_macos

The macOS implementation of the [`flutter_vless`](https://pub.dev/packages/flutter_vless) plugin.

This package is intended to be used through the main `flutter_vless` package. It provides the macOS platform backend for Xray/V2Ray proxy-only and VPN/tunnel flows.

The validated Packet Tunnel path for `1.1.5` uses:

- `127.0.0.1` as the Network Extension remote label
- `198.18.0.1/24` as the local TUN address
- `198.18.0.1` as the IPv4 default route gateway
- explicit Packet Tunnel DNS servers `1.1.1.1` and `8.8.8.8`
- no DNS host-route exclusions

For setup details, see the [macOS platform guide](https://github.com/XIIIFOX/flutter_vless/blob/main/doc/platform/macos.md).
