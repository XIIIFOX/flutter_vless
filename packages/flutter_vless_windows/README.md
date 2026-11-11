# flutter_vless_windows

The Windows implementation of the [`flutter_vless`](https://pub.dev/packages/flutter_vless) plugin.
Use this package through the main `flutter_vless` dependency.

Supply the managed `xray-windows-v26.11.9-r1` runtime for native routing and
XDRIVE/GeoDAT services, plus compatible tunnel helpers. Ordinary compatible
external Core builds support profiles that do not require those capabilities.
VPN mode requires administrator privileges; the plugin does not download
missing runtime files.

See the [Windows platform guide](https://github.com/XIIIFOX/flutter_vless/blob/main/doc/platform/windows.md)
for file layout, protection and tray controls.
