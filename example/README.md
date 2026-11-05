# flutter_vless Example

The example app is the fastest way to verify that platform setup, native Xray
integration, proxy-only mode, tunnel mode, import parsing, and status updates
work before copying the plugin into your own app.

If you downloaded a source archive, rename the top-level folder to
`flutter_vless` before running the bundled example. Flutter's SwiftPM
integration derives the root plugin package identity from the path dependency
directory name.

## What It Demonstrates

- Clipboard import for share links, full JSON and subscription profiles
- Configuration and domain-routing editors
- Proxy-only and VPN startup/Stop
- Connection duration, upload/download totals, speed and Core version
- Notification, quick access, reconnect, protection and diagnostics options
- `Delay` for the active session and `Profile delay` for an isolated profile
  measurement; Windows standalone profile delay returns `-1`

For a normal connection, use **Import (clipboard)** and **Connect**. Leave
**VPN routing** off and **Certificate files** empty unless the profile needs
those advanced settings. A subscription imports its first supported profile.

## Per-session VPN routing

Use `VpnRoutingOptions` when VPN traffic should inherit an imported input's
inbound-tag context or use a particular default outbound:

```dart
await flutterVless.startVless(
  remark: 'Imported profile',
  config: fullJson,
  vpnRouting: const VpnRoutingOptions(
    sourceInboundIndex: 0,
    defaultOutboundTag: 'proxy',
  ),
);
```

The index refers to the original `inbounds` array. These controls require VPN
mode and native routing capability; an arbitrary external Windows Core may not
provide it. Turning the control off retains ordinary startup.

## External data files

Pass `geoAssetsDirectory` for referenced GeoIP/GeoSite files and
`certificateAssetsDirectory` for relative TLS certificate/key files. Omit both
for the platform's default lookup. The two directories have separate purposes;
selecting a data directory does not relocate certificates.

Use existing absolute paths readable by the app and keep the referenced files
available through Stop, recovery and reload. Apple VPN extensions need shared
App Group storage. Setting these paths does not copy or replace files. See
the [API contract](../doc/api.md) for startup and delay lookup rules.

## Android

Run on a device:

```bash
cd example
flutter pub get
flutter run -d android
```

For Android emulators, the main Maven runtime AAR already provides x86/x86_64
binaries.

The app Gradle file enables extracted native executables for the Xray runtime:

```kotlin
android {
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}
```

## iOS

iOS tunnel mode requires a signed real device.

```bash
cd example
flutter pub get
../tool/prepare_apple_swiftpm.sh
open ios/Runner.xcworkspace
```

Open `Runner.xcworkspace`, not `Runner.xcodeproj`, so Xcode loads the generated
CocoaPods and Swift package products.

In Xcode:

1. Select a real iPhone.
2. Set the same Apple Team for `Runner` and `XrayTunnel`.
3. Confirm App Groups and Network Extension capabilities.
4. Run from Xcode.

After signing is configured, CLI runs can also work:

```bash
flutter run -d <your-iphone-id>
```

## macOS

macOS tunnel mode requires the Packet Tunnel target and signing setup.

```bash
cd example
flutter pub get
../tool/prepare_apple_swiftpm.sh
open macos/Runner.xcworkspace
```

Open `Runner.xcworkspace`, not `Runner.xcodeproj`. The project file alone can
fail with stale SwiftPM platform metadata or `Pods_Runner` linker errors.

Set your Apple Team on both macOS targets, then run from Xcode or:

```bash
flutter run -d macos
```

Read `doc/macos_packet_tunnel_architecture.md` before changing macOS routing,
DNS, or Packet Tunnel behavior.

If Xcode reports that `flutter-vless` or `flutter-vless-macos` requires a
higher minimum platform than `FlutterGeneratedPluginSwiftPackage`, run
`../tool/prepare_apple_swiftpm.sh` again and reopen the workspace. The generated
Flutter Swift package lives under `Flutter/ephemeral/` and is not committed.

## Windows

Supply the runtime and tunnel helper files described in the
[Windows setup guide](windows/README.md), then run:

```bash
cd example
flutter pub get
flutter run -d windows
```

VPN mode requires an elevated application. The plugin does not download missing
runtime files.

## Common Checks

- Complete platform signing, permissions and runtime setup before VPN testing.
- Import a known-good share link or full Xray JSON and verify a fresh request.
- Check duration, totals and speed while uploading/downloading data.
- Test direct/proxy domain routing in both directions using fresh browser requests.
- Preserve caller DNS settings; check the [DNS and IPv6 limits](../doc/compatibility.md#dns-and-ipv6)
  for the target platform rather than adding blanket DNS bypasses.
- Use [system controls](../doc/options-and-system-controls.md) only after their
  native setup is complete. The example restores its saved Options on launch.
- Stop the session from the app and confirm ordinary connectivity returns.
