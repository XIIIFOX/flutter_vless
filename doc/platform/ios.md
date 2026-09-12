# iOS

iOS uses a Network Extension packet tunnel path.

## Quick Run The Example

The bundled example already contains an `XrayTunnel` target. Use it first when
you want to verify signing, App Groups, and Packet Tunnel behavior before
copying setup into your own app.

```bash
cd example
flutter pub get
open ios/Runner.xcworkspace
```

In Xcode, select a real iPhone and set the same Apple Team on:

- `Runner`
- `XrayTunnel`

Then run from Xcode. After signing is configured, CLI runs can also work:

```bash
flutter run -d <your-iphone-id>
```

## What You Need

- a real Apple Developer account and a signing-capable iPhone
- iOS 15.0 or newer as the deployment target
- a Packet Tunnel extension target
- App Groups enabled on both the app and the tunnel target
- one shared Keychain access group entitlement on both targets
- the same base app bundle id passed from Dart

## Bundle Id Convention

Pass the base app bundle id to `initializeVless()`:

```dart
await flutterVless.initializeVless(
  providerBundleIdentifier: 'com.example.myapp',
  groupIdentifier: 'group.com.example.myapp',
);
```

The plugin appends `.XrayTunnel` internally for the tunnel extension.

## Runtime Notes

- real-device testing is strongly preferred
- `proxyOnly: true` avoids the tunnel path
- VPN sessions require traffic protection; recovery reports
  `CONNECTING` until the provider's forwarding health checks pass
- use Xray `direct` domain rules for split routing, including `domain:ru`
  or `domain:io`; the provider still routes these connections directly
- non-empty system `bypassSubnets` are rejected before the current session changes;
  there is no option to disable VPN traffic protection
- app-level blocking is not the same thing as tunnel routing

Use the current example provider when updating an existing integration. The
manager policy and provider recovery behavior work together. Reconnect from the
app to update older saved profiles; the current provider rejects profiles without
the required system protection. See
[iOS traffic protection](../security.md#ios-traffic-protection) for lifecycle
behavior and operating-system exceptions.

## Updating `geoip.dat` And `geosite.dat`

The iOS runtime can load geodata from a shared App Group directory, so these
files can be updated without rebuilding or releasing the application. Download
and validate both files in the containing app, then pass the absolute directory
path when starting Xray:

```dart
await flutterVless.startVless(
  remark: parsed.remark,
  config: parsed.getFullConfiguration(),
  geoAssetsDirectory: appGroupGeoDirectory,
);
```

The directory must be an absolute path and must contain readable, non-empty,
regular files named exactly `geoip.dat` and `geosite.dat`. For Packet Tunnel
mode it must be inside the App Group shared by `Runner` and `XrayTunnel`.
Invalid custom assets fail startup instead of silently falling back to stale
bundle files.

Update the files while Xray is stopped. Download to temporary names, validate
the complete pair, and atomically replace the live files before the next
`startVless()` call. Do not overwrite a `.dat` file in place while Xray may be
reading it. Passing a new directory on a later start switches the next runtime
session; omitting `geoAssetsDirectory` restores Xray's default/bundled lookup.

The Packet Tunnel provider must forward `geoAssetsDirectory` from its
`providerConfiguration` and call `XRaySetAssetLocation` before `XRayStart`.
Use the current provider implementation from:

```text
example/ios/XrayTunnel/PacketTunnelProvider.swift
```

Calling Darwin `setenv()` in Swift is not equivalent: after gomobile has
initialized the Go runtime, Xray's Go-side `os.LookupEnv()` does not observe
that change. `XRaySetAssetLocation` performs the update inside Go and validates
the file pair first.

## Rebuilding the Xray Framework

Most application integrators use the prebuilt `XRay.xcframework` and do not
need this step. It is for maintainers rebuilding the iOS runtime.

The build requires full Xcode and Go 1.27 or newer. To keep concurrent XHTTP
uploads within the iOS Network Extension memory budget, the build patches a
temporary clone of Go's standard library and caps the HTTP/2 upload scratch
buffer at 128 KiB per stream. Your installed Go toolchain is never modified.

The cap can be adjusted only for a deliberate runtime experiment:

```bash
cd ios
H2BUF_CAP_KB=128 ./build_xray_ios.sh
```

Accepted values are 16–512 KiB. The build verifies its Go stdlib patch anchor
and fails instead of creating an unprotected framework if a future Go release
changes that source layout. For the complete build command, supported
overrides, and rationale, see [Build XRay.xcframework](../../ios/XRAY_BUILD.md).

## Suggested Setup Flow

1. Run the bundled example on a real iPhone.
2. Add the package to your own app.
3. Create a Packet Tunnel extension named `XrayTunnel`.
4. Enable App Groups, shared Keychain access, and Network Extensions on both targets.
5. Set `Runner`, `XrayTunnel`, and generated SwiftPM integration to iOS 15.0+.
6. Pass the base bundle id and App Group from Dart.
7. Test on a real device.

When you add the SwiftPM product for the tunnel target, use the package path
that Flutter generated under:

```text
ios/Flutter/ephemeral/Packages/.packages/flutter_vless-<version>
```

Avoid adding `ios/flutter_vless` directly from the Pub cache on old releases;
that can make SwiftPM search for a missing sibling `ios/FlutterFramework`
directory.

## PacketTunnelProvider.swift

Your tunnel target needs a `PacketTunnelProvider.swift`. The example has a
working provider here:

```text
example/ios/XrayTunnel/PacketTunnelProvider.swift
```

Use the same target membership shape in your app: the provider file belongs to
the `XrayTunnel` target, not the Flutter `Runner` target.

## Common Pitfalls

- signing the app but not the extension
- using the extension bundle id instead of the base app bundle id
- expecting simulator behavior to match a real device

## Keychain profile migration (1.2.0)

Configure the **same** `keychain-access-groups` entitlement on Runner and
XrayTunnel, for example `$(AppIdentifierPrefix)com.example.myapp.vpn-secrets`.
This is separate from the App Group used for geodata and bounded diagnostics.
The sample provides this entitlement on both targets and a Runner Info.plist
`FlutterVlessKeychainAccessGroup` string with the same build-expanded value.
Alternatively pass the fully expanded group to `initializeVless(keychainAccessGroup: ...)`.
Do not derive a Team ID from an App Group name.

The containing app migrates old profiles when loading/activating them. The VPN
profile stores schema version 2 and an opaque persistent Keychain reference;
the full config is stored with `AfterFirstUnlockThisDeviceOnly` and no iCloud
synchronization. Missing entitlements/items and a device that has not been
unlocked after reboot fail with `VPN_KEYCHAIN_ERROR`, without plaintext fallback.
A new provider rejects an unmigrated legacy profile and asks the user to open
the containing app. No protection is claimed before network settings succeed.

Updates retain the old item while an active provider could use it. Interrupted
updates and failed deletions are reconciled after disconnect and disarming
on-demand. Stop preserves the profile secret; profile removal waits for teardown
and deletes owned items. Changing the shared group requires removing the existing
profile first. Large values are stored whole or rejected; no temporary plaintext
file or truncation is used.

Update **both** the Swift support package and the copied
`PacketTunnelProvider.swift`. Updating only the Dart package cannot replace
source in another application's extension target. Both CocoaPods plugin builds
and the SwiftPM plugin/tunnel-support products include the shared security module.

## Local proxy access and DNS

VPN mode requires one loopback SOCKS inbound. Native runtime credentials are
random per provider session, remain consistent across internal worker restarts,
and are passed to Xray, HEV and every readiness/delay client. Extra SOCKS/HTTP
listeners and incompatible managed listeners are rejected before changing the
profile. The SOCKS port's embedded HTTP handler also requires authentication.
Credentials are not inserted into exported subscription/config snapshots.

`proxyOnly: true` preserves the explicitly configured local proxy access policy.
An intentional `auth: noauth` proxy can be used by other local applications;
VPN listener-isolation guarantees do not apply. Explicit local accounts are
supported by the configuration model. Standalone delay returns -1 while an
app-process proxy-only runtime is active, so a probe cannot replace it.

The current provider installs virtual system DNS `198.18.0.2`. Its requests pass
through authenticated local SOCKS and a TCP DNS outbound chained to the selected
remote proxy, including HTTP/SOCKS servers without UDP support. Service DNS rules
precede application `UDP -> direct` rules. Proxy endpoint names are resolved
before routes are installed; user DNS never falls back to the system resolver
when proxy DNS fails. No public resolver is excluded from VPN routes.

DNS through a plain HTTP/SOCKS server does not encrypt that transport. `CONNECTED`
means the maintained forwarding path passed an authenticated data check, not that
every outbound in arbitrary raw JSON is reachable. Delay probes validate HTTPS
certificates and hostnames; the iOS 15-compatible socket TLS probe supports TLS 1.2
and returns -1 for a TLS-1.3-only destination rather than bypassing the proxy.
