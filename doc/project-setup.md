# Project setup

Add the dependency to an existing Flutter app, then run setup from its root.
Choose one platform per invocation. Proxy mode is the default.

```bash
flutter pub add flutter_vless
dart run flutter_vless:setup --platform macos --proxy
dart run flutter_vless:doctor --platform macos --proxy
```

`setup` configures native project files for the selected platform. Use
`--dry-run` to list the files and downloads first. `doctor` evaluates the same
configuration without editing files, fetching runtime binaries, or building
the app. It returns `0` for an up-to-date project, `1` for pending changes,
and a different nonzero exit code for invalid input or an unsupported layout.
Use `--project-dir` to select another app and `--non-interactive` for CI.

Choose the matching mode in Dart. The app starts the VPN and follows the
platform's normal permission flow.

```dart
await flutterVless.startVless(
  remark: profile.remark,
  config: profile.getFullConfiguration(),
  proxyOnly: true,
);
```

## macOS and iOS

The setup command uses Flutter 3.44+ with Swift Package Manager enabled.
Proxy setup prepares the project files from Dart and needs no Xcode invocation,
Apple Team ID, App Group, or Packet Tunnel target. Building the Apple app
still requires Xcode on macOS. Flutter generates its SwiftPM files during the
build. Existing projects that use CocoaPods can follow the platform guides.

For VPN mode, run setup for each Apple platform that needs a tunnel.

```bash
dart run flutter_vless:setup --platform macos --vpn \
  --bundle-id com.example.app --group-id group.com.example.app \
  --team-id ABCDE12345 --non-interactive
dart run flutter_vless:setup --platform ios --vpn \
  --bundle-id com.example.app --group-id group.com.example.app \
  --team-id ABCDE12345 --non-interactive
```

The command can infer the app's Bundle ID and configured team. If the team
is missing, it can be supplied later. It suggests `group.<bundle-id>` for a
new App Group and prints the values for `initializeVless()`. Register the
App Group and enable the required capabilities for the app and its extension
in the Apple Developer team. Use valid provisioning profiles for a signed
VPN build. A real iPhone is required to confirm iOS VPN behavior.

The generator supports standard Flutter Runner configurations. Projects with
custom schemes or manually maintained tunnel targets can use the
[macOS](platform/macos.md) or [iOS](platform/ios.md) guide. Rerun `doctor`
after updating dependencies to check that the tunnel project reference still
matches the resolved Swift package.

## Android

```bash
dart run flutter_vless:setup --platform android --vpn
dart run flutter_vless:doctor --platform android --vpn
```

Both modes use the Android plugin's Maven runtime. Setup checks the app's
minimum SDK and extraction of the executable native libraries in Gradle.
Build an APK or app bundle to verify dependency resolution and packaging.

## Windows

```bash
dart run flutter_vless:setup --platform windows --vpn --arch x64
dart run flutter_vless:doctor --platform windows --vpn --arch x64
flutter build windows
```

Setup verifies the pinned x64 Xray runtime and GeoDAT files, and includes
Wintun and tun2socks for VPN mode. CMake places the files in the app bundle's
`xray/` directory. Rerun setup after a fresh checkout to populate the local
runtime cache. Supply an existing runtime with `--runtime-dir`; a matching
user-supplied runtime is required for `--arch arm64`. Flutter builds for the
Windows host architecture. Use Visual Studio C++ tools and run the app with
administrator rights for VPN.

On Windows x64, an administrator can prepare the signed Wintun driver before
the app's first VPN connection. Use the pinned VPN runtime and run:

```powershell
dart run flutter_vless:setup --platform windows --vpn --stage-wintun
dart run flutter_vless:doctor --platform windows --vpn --stage-wintun
```

Setup creates and closes a temporary Wintun adapter without starting a tunnel.
The signed driver remains in Windows Driver Store. Repeated setup reuses it.
`doctor` and `--dry-run` only check the driver state. The optional staging
step reports a conflict when a different Wintun package or an existing device
is present and the expected package is missing.
