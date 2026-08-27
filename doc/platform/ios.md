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
- `bypassSubnets` is the route-level knob to understand first
- app-level blocking is not the same thing as tunnel routing

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
4. Enable App Groups and Network Extensions on both targets.
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
