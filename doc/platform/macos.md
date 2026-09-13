# macOS

macOS uses a Packet Tunnel Network Extension path for VPN mode and a separate local proxy path for proxy-only mode.

## VPN protection in 1.1.6

Packet Tunnel traffic protection is mandatory. It retains capture and virtual DNS
while native workers recover; `CONNECTED` also requires the provider's forwarding
readiness. Explicit stop disables on-demand recovery before stopping the tunnel.

Use one loopback SOCKS inbound. The plugin provides private session credentials
and removes imported management APIs. IPv6 is captured and blocked while the
forwarding path is IPv4-only. System DNS uses the selected Xray proxy without a
physical resolver fallback. Domain-based direct rules remain supported, and
IPv4 `bypassSubnets` become direct rules inside Xray below DNS/IPv6 protection.
Stop the current VPN before replacing its configuration.

Profiles are stored using Keychain persistent references. The app and extension
must share a registered `group.` App Group or the same dedicated Keychain access
group. An optional `keychainAccessGroup` initialization value selects the latter;
both targets must have the corresponding entitlement. Legacy plaintext profiles
are migrated when loaded.

Update the plugin and the Packet Tunnel support product together. Runtime
revision `xray-macos-v26.9.9` supplies the required private startup and asset
location bridges. Repository builds use the bundled XCFramework; the hosted
fallback requires that revision to have been published before distribution.

## Quick Run The Example

Use the example app first if you want to verify that Xcode signing, the Packet
Tunnel target, and the Swift package products are wired correctly.

```bash
cd example
flutter pub get
../tool/prepare_apple_swiftpm.sh
open macos/Runner.xcworkspace
```

Open `Runner.xcworkspace`, not `Runner.xcodeproj`. Set your Apple Team on both
macOS targets, then run from Xcode or:

```bash
flutter run -d macos
```

## What You Need

- macOS 13 or newer for the validated setup
- a Packet Tunnel extension target
- App Groups enabled
- the setup command from the package

## Proxy-Only Setup

If you only need proxy-only mode in your own app, run this once from the Flutter
app root after `flutter pub get`:

```bash
dart run flutter_vless:setup_macos_vpn --prepare-only
```

This updates Flutter's generated macOS SwiftPM metadata and the Runner
deployment target to macOS 13.0. It does not add a Packet Tunnel target,
entitlements, signing settings, or App Groups.

## Recommended Setup Command

For Packet Tunnel VPN mode in your own app, run the full setup command from
your Flutter app root:

```bash
dart run flutter_vless:setup_macos_vpn \
  --bundle-id com.example.myapp \
  --group-id group.com.example.myapp \
  --team-id ABCDE12345
```

## Bundle Id Convention

Pass the base app bundle id to `initializeVless()`:

```dart
await flutterVless.initializeVless(
  providerBundleIdentifier: 'com.example.myapp',
  groupIdentifier: 'group.com.example.myapp',
);
```

## What To Read Next

- [macos_packet_tunnel_architecture.md](../macos_packet_tunnel_architecture.md)

That note explains the routing, DNS, and packet-tunnel invariants that matter when you touch the macOS backend.

## Runtime Notes

- proxy-only mode and tunnel mode are different code paths
- the packet tunnel is more sensitive to DNS and route configuration than a normal proxy-only start
- the provider captures IPv4 and IPv6, publishes virtual DNS `198.18.0.2`, and excludes only prepared transport endpoint addresses
- provider readiness combines the HEV worker state with authenticated SOCKS forwarding checks; Network Extension's connected status alone is insufficient
- use the architecture note before changing packet tunnel logic

## PacketTunnelProvider.swift

The example's macOS tunnel target uses a thin provider wrapper:

```text
example/macos/XrayTunnel/PacketTunnelProvider.swift
```

The shared implementation lives in the package support target. That keeps app
projects from copying the full provider manually.

## Common Pitfalls

- mixing up the base bundle id and the extension bundle id
- changing routing without checking DNS reachability
- assuming proxy-only delay results prove packet-tunnel health
