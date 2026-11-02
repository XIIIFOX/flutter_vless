# flutter_vless_macos

The macOS implementation of the [`flutter_vless`](https://pub.dev/packages/flutter_vless) plugin.

This package is intended to be used through the main `flutter_vless` package. It provides the macOS platform backend for Xray/V2Ray proxy-only and VPN/tunnel flows.

The working 1.1.7 source uses published `xray-macos-v26.10.31-r2`. VPN mode captures IPv4/IPv6 traffic through the Packet Tunnel and uses the
protected virtual DNS server `10.0.85.53`. DNS requests are handled through
caller Core DNS policy without a failed-remote-query system fallback. Native
readiness checks the live packet worker and authenticated local listener; use a
caller-allowed connected delay URL to check remote reachability. Live IPv6-only,
NAT64 and handover remain separate qualification work.

This repository revision has not republished the existing pub.dev 1.1.7 wrapper.
Use matching source packages through the main package when testing these changes.

For setup details, see the [macOS platform guide](https://github.com/XIIIFOX/flutter_vless/blob/main/doc/platform/macos.md).
