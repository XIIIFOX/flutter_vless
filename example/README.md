# flutter_vless Example

The example app is the fastest way to verify that platform setup, native Xray
integration, proxy-only mode, tunnel mode, import parsing, and status updates
work before copying the plugin into your own app.

If you downloaded a source archive, rename the top-level folder to
`flutter_vless` before running the bundled example. Flutter's SwiftPM
integration derives the root plugin package identity from the path dependency
directory name.

## What It Demonstrates

- Clipboard import through `FlutterVless.parse()`
- Generated Xray config preview and editing
- Proxy-only startup
- VPN/tunnel startup
- Runtime `VlessStatus` updates
- Upload/download counters
- Server core version display
- Android `blockedApps`
- Route/domain editing helpers in `lib/routing.dart`
- `Delay` measures the current session when connected; `Profile delay` always
  measures the editor's profile in an isolated native session. Apple/Android
  omit imported API/metrics listeners in that temporary measurement to avoid
  rebinding ports owned by the active VPN. Normal VPN profiles keep those fields.
  Standalone profile delay on Windows is still unimplemented and returns `-1`.

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

Open `Runner.xcworkspace`, not `Runner.xcodeproj`. The example still has
CocoaPods integration metadata, and opening the project file directly can make
Xcode miss generated package/framework products.

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

Windows needs a local `xray.exe`.

Expected example layout:

```text
example/
  windows/
    xray/
      xray.exe
```

Then run:

```bash
cd example
flutter pub get
flutter run -d windows
```

The Windows backend does not download Xray automatically.

## Common Checks

- For the DNS preservation check, import full Xray JSON with `dns.hosts` and
  per-domain `dns.servers`, then keep Android's default `config` DNS policy.
  The explicit `proxy` policy intentionally overrides system DNS. See the
  [DNS MVP behavior and current limits](../doc/compatibility.md#incremental-delivery-order-2026-10-19)
  before testing localhost defaults, IPv6 or FakeDNS. Use a fresh browser
  connection after changing a DNS or routing rule.
- Use proxy-only mode first when you want the smallest runtime path.
- Use VPN/tunnel mode only after platform setup is complete.
- Import a known-good share link or raw Xray config from the clipboard.
- Watch `state`, `connectionState`, upload, and download counters after
  startup.
- Stop the session from the app before closing the example during testing.
