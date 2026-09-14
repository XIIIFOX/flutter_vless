# flutter_vless_macos

The macOS implementation of the [`flutter_vless`](https://pub.dev/packages/flutter_vless) plugin.

This package is intended to be used through the main `flutter_vless` package. It provides the macOS platform backend for Xray/V2Ray proxy-only and VPN/tunnel flows.

In `1.1.6`, VPN mode captures traffic through the Packet Tunnel and uses the
protected virtual DNS server `198.18.0.2`. DNS requests are handled through
Xray without a physical DNS fallback. IPv6 traffic is captured and blocked
while forwarding remains IPv4-only.

For setup details, see the [macOS platform guide](https://github.com/XIIIFOX/flutter_vless/blob/main/doc/platform/macos.md).
