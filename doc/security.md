# Security And Runtime Boundaries

`flutter_vless` starts local Xray-backed proxy or VPN/tunnel runtimes from a
Flutter app. This page documents what the package does locally and what remains
the app developer's responsibility.

## What The Package Does

- Parses supported proxy links, subscriptions, Clash YAML, sing-box JSON, and
  raw Xray JSON into Xray-compatible configuration.
- Starts local Xray-backed proxy-only or tunnel mode through native platform
  code.
- Requests platform permissions needed for VPN/tunnel mode.
- Emits runtime status, byte counters, and delay measurements through Dart.
- Cleans up platform runtime state where the backend controls it, such as local
  Xray processes, foreground services, tunnel state, or system proxy settings.

## Native Binaries

The package relies on native Xray artifacts.

Platform notes:

- Android device runtimes are packaged in the Maven Central `dev.tfox.fluttervless:xray-android` AAR.
- iOS and macOS use Xray framework artifacts through CocoaPods/Swift Package
  integration.
- Windows expects a local `xray.exe`; the plugin does not download it at
  runtime.

Treat native binary updates as release-sensitive work. Keep checksums, release
tags, and platform package versions aligned.

## User And Server Responsibility

The app or end user is responsible for the proxy server configuration being
legal, trusted, and operational.

The package can validate that a config is structurally usable as Xray JSON. It
cannot prove that:

- the remote server is trustworthy
- the subscription source is safe
- the server owner permits the intended usage
- the config is legal in the user's jurisdiction
- the network path is private against every attacker model

Do not treat successful startup as a security audit of the server.

## Permissions

VPN/tunnel mode may request sensitive operating-system permissions:

- Android VPN service and notification-related permission flows.
- iOS/macOS Network Extension profile and App Group access.
- Windows system proxy or routing changes, depending on mode.

Proxy-only mode is lighter because it starts local proxy behavior without
installing a VPN route, but it can still affect system proxy settings on desktop
platforms depending on the backend path.

## Config Handling

`startVless()` and `getServerDelay()` validate config structure before sending
the JSON to native code. This catches malformed JSON and missing outbound
sections early, but it is not a full semantic validator for every Xray protocol
combination.

Recommended app behavior:

- show the imported profile name and server host before connecting
- handle `ArgumentError` from invalid configs
- let users remove imported subscriptions and profiles
- avoid logging full configs when they contain credentials, UUIDs, keys, or
  server addresses

## Logging

The iOS runtime uses structured, bounded diagnostics instead of forwarding raw
Xray logs. Imported log destinations, credentials, endpoint values, and arbitrary
native error text are omitted from the provider snapshot. HEV retains bounded
error-level file logging. This policy also covers iOS proxy-only and delay probes.

On other backends, debug logs can contain server addresses, transport details, route decisions,
and runtime errors. Avoid uploading logs automatically unless the user has
reviewed them.

For support flows, prefer redacting:

- UUIDs
- passwords
- private keys
- subscription URLs
- server hostnames or IPs when the user asks for privacy

## iOS Traffic Protection

With the current example Packet Tunnel provider, traffic protection is mandatory
for VPN sessions. The saved profile enables `includeAllNetworks`
and on-demand recovery. The provider keeps its routes and virtual DNS while
retrying a failed transport or restarting its HEV/Xray workers. A rejected runtime
configuration also keeps installed routes in place and blocks forwarding. To
replace it, explicitly stop the session and start with a corrected configuration.
On-demand rules request a restart after termination of the entire provider. iOS
controls when that restart occurs and can defer it after a process crash. Traffic
remains blocked in that state; `startVless()` can retry the connection, and
`stopVless()` explicitly releases protection. The Dart status remains
`CONNECTING` until the provider confirms forwarding readiness; the system VPN
icon alone does not establish this. Health checks cover the local SOCKS and test forwarding
paths; they do not establish the health of every outbound in a custom config.

Xray `direct` rules intentionally send matching destinations through the physical
network from inside the provider. They remain compatible with this policy.
System route exclusions in `bypassSubnets` are incompatible with this policy.
Non-empty values are rejected before changing the current session; they never
automatically disable protection. Reconnect from the app to update an older saved
VPN profile. The current provider rejects profiles without `includeAllNetworks`
before endpoint bootstrap or runtime startup.

An explicit `stopVless()` or switch to proxy-only mode disables on-demand
recovery and releases the VPN policy. Requesting VPN permission alone does not
enable recovery. Validation rejected before profile activation, or an operating
system failure to install the tunnel network settings, does not establish the
provider's routing and DNS protection. Apps should handle startup errors and
offer an explicit stop action.

This is a Network Extension policy, not an unconditional device-wide guarantee.
Apple reserves traffic needed to establish network connectivity and certain
system services; device/companion communication retains its system exception.
The plugin disables the configurable local-network, APNs, and cellular-service
exclusions where the iOS version supports them. Removing or disabling the profile
in system settings also releases its policy. See Apple's
[VPN routing documentation](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)
and [`includeAllNetworks`](https://developer.apple.com/documentation/networkextension/nevpnprotocol/includeallnetworks).

## Recommended Production Checklist

- Pin package versions in the app.
- Verify native binary checksums during release work.
- Test VPN/tunnel mode on real devices.
- Keep proxy-only and tunnel mode clearly separated in UI.
- Provide a user-visible disconnect action.
- Avoid silently importing unsupported protocols.
- Document what traffic the app routes and when the local runtime is active.
