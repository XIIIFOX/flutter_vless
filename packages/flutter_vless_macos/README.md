# flutter_vless_macos

The macOS implementation of the [`flutter_vless`](https://pub.dev/packages/flutter_vless) plugin.
Use this package through the main `flutter_vless` dependency.

The pinned `xray-macos-v26.11.9-r1` runtime supports proxy-only mode and a signed
Packet Tunnel with IPv4/IPv6 capture, caller DNS/routing and protected virtual
DNS `10.0.85.53`. Native readiness checks the current packet worker and
managed local listener; test a permitted URL separately for remote reachability.

See the [macOS platform guide](https://github.com/XIIIFOX/flutter_vless/blob/main/doc/platform/macos.md)
for signing, App Groups, menu-bar and optional Control Center setup, and the
[compatibility guide](https://github.com/XIIIFOX/flutter_vless/blob/main/doc/compatibility.md)
for network limitations.
