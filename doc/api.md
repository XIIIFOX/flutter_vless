# API Contract

This document describes the app-facing Dart contract exposed by
`package:flutter_vless/flutter_vless.dart`.

Use this page when you need to know what a method expects, what it returns, and
which parts are platform-specific.

## Import

```dart
import 'package:flutter_vless/flutter_vless.dart';
```

## `FlutterVless`

`FlutterVless` is the app-facing controller for Xray/V2Ray proxy and
VPN/tunnel sessions.

Create one instance and keep it for the lifetime of the screen, service, or app
component that owns the connection.

```dart
final flutterVless = FlutterVless(
  onStatusChanged: (status) {
    // Update app state from VlessStatus.
  },
);
```

## `initializeVless()`

Initializes the native backend and subscribes to status events.

```dart
await flutterVless.initializeVless(
  notificationIconResourceType: 'mipmap',
  notificationIconResourceName: 'ic_launcher',
  providerBundleIdentifier: 'com.example.myapp',
  groupIdentifier: 'group.com.example.myapp',
);
```

Parameters:

- `notificationIconResourceType`: Android notification resource type.
- `notificationIconResourceName`: Android notification resource name.
- `providerBundleIdentifier`: base app bundle id on iOS/macOS.
- `groupIdentifier`: Apple App Group shared by the app and Packet Tunnel
  extension.
- `quickSettingsTile`: optional Android Quick Settings tile label and icon.
  Icons must be Android resource names in the host app. The tile reconnects with
  the last profile saved by `startVless()`. VPN mode still needs consent through
  `requestPermission()` (the tile can also request it). Proxy-only profiles skip
  VPN consent. Users add the tile manually in system Quick Settings.

Apple platforms append the Packet Tunnel extension suffix internally. Pass the
base app bundle id, not the extension bundle id.

## `requestPermission()`

Requests platform permission or profile state required for tunnel mode.

```dart
final allowed = await flutterVless.requestPermission();
```

Use it before VPN/tunnel startup. Proxy-only mode usually does not need it.

Platform notes:

- Android uses this path for VPN and notification permission flows.
- iOS and macOS depend on signing, App Groups, and Network Extension setup.
- Windows may require elevated permissions for system routing changes.

## `startVless()`

Starts an Xray-backed proxy-only or VPN/tunnel session.

```dart
await flutterVless.startVless(
  remark: parsed.remark,
  config: parsed.getFullConfiguration(),
  proxyOnly: false,
  geoAssetsDirectory: appGroupGeoDirectory,
);
```

Required parameters:

- `remark`: human-readable profile name used by native UI, notifications, and
  logs.
- `config`: JSON-encoded Xray configuration object.

Optional parameters:

- `blockedApps`: Android package names excluded from the VPN route.
- `bypassSubnets`: CIDR routes excluded from the tunnel where supported.
- `proxyOnly`: starts local proxy behavior without installing a VPN route.
- `geoAssetsDirectory`: iOS-only absolute path to a directory containing
  non-empty `geoip.dat` and `geosite.dat`. Use an App Group directory for VPN
  mode so both the app and Packet Tunnel extension can read it. Omit this
  parameter to keep Xray's default/bundled asset lookup.
- `notificationDisconnectButtonName`: Android notification action label.

Validation:

`startVless()` validates `config` before forwarding it to native code. It throws
`ArgumentError` when the string is not valid JSON, is not a JSON object, has an
invalid `inbounds` section, or does not contain at least one valid outbound.

## `stopVless()`

Stops the active proxy or VPN/tunnel session.

```dart
await flutterVless.stopVless();
```

Platform implementations also use this call to clean up foreground services,
system proxy settings, local Xray processes, and tunnel state.

## `getServerDelay()`

Measures delay for a provided Xray config without relying on an active session.

```dart
final delayMs = await flutterVless.getServerDelay(
  config: parsed.getFullConfiguration(),
  url: 'https://google.com/generate_204',
  geoAssetsDirectory: appGroupGeoDirectory,
);
```

The config is validated with the same validator used by `startVless()`.
On iOS, `geoAssetsDirectory` has the same validation and lookup behavior as
the parameter on `startVless()`.

## `getConnectedServerDelay()`

Measures delay through the currently active runtime.

```dart
final delayMs = await flutterVless.getConnectedServerDelay();
```

Use this after `startVless()` when the app needs a health signal for the active
profile.

## `getCoreVersion()`

Returns the Xray core version reported by the active platform backend.

```dart
final version = await flutterVless.getCoreVersion();
```

The exact value can differ by platform package, release version, or externally
supplied Windows `xray.exe`.

## `parse()`

Parses one supported input into a `FlutterVlessURL`.

```dart
final parsed = FlutterVless.parse(input);
final config = parsed.getFullConfiguration();
```

Supported input:

- `vmess://`
- `vless://`
- `trojan://`
- `ss://`
- `socks://`
- `hysteria2://`
- `hy2://`
- raw Xray JSON
- base64 subscription payloads
- Clash YAML
- sing-box JSON

Clash YAML and sing-box JSON imports can also produce generated Xray configs
for supported profile objects such as WireGuard, Hysteria2, and HTTP proxy
outbounds.

If a subscription contains multiple supported profiles, `parse()` returns the
first one. Use `parseMany()` to keep the full list.

## `parseMany()`

Parses every supported profile from a subscription-style payload.

```dart
final profiles = FlutterVless.parseMany(subscriptionText);
```

Unsupported or not-yet-mapped protocols are skipped intentionally instead of
being converted into broken Xray JSON.

## `parseFromURL()`

Parses one share URL.

```dart
final parsed = FlutterVless.parseFromURL(vlessLink);
```

Use this only when the input is already known to be one of:

- `vmess://`
- `vless://`
- `trojan://`
- `ss://`
- `socks://`
- `hysteria2://`
- `hy2://`

For clipboard imports, subscriptions, raw JSON, Clash YAML, or sing-box JSON,
prefer `parse()` or `parseMany()`.

## `VlessStatus`

`VlessStatus` is the stable Dart model for runtime status events.

Fields:

- `duration`: seconds since session start.
- `uploadSpeed`: current upload speed reported by the platform.
- `downloadSpeed`: current download speed reported by the platform.
- `upload`: total uploaded bytes.
- `download`: total downloaded bytes.
- `state`: raw native state string.
- `connectionState`: normalized `VlessConnectionState`.

Example:

```dart
void handleStatus(VlessStatus status) {
  switch (status.connectionState) {
    case VlessConnectionState.connected:
      // Show connected UI.
      break;
    case VlessConnectionState.connecting:
      // Show progress UI.
      break;
    case VlessConnectionState.disconnected:
    case VlessConnectionState.disconnecting:
    case VlessConnectionState.unknown:
      // Show idle or fallback UI.
      break;
  }
}
```
