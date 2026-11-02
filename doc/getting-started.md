# Getting Started

This guide is for developers who want to add `flutter_vless` to an app and get a working connection with the smallest possible amount of setup.

These instructions describe the repository's working 1.1.7 API. The main 1.1.7
plugin is not published yet; use the bundled example or the matching
[Git source dependencies](../README.md#unreleased-117-from-github) for its new APIs.

## Quick Run From The Example

The fastest way to verify your environment is to run the bundled example app
first, then copy the same setup shape into your project.

If you downloaded a source archive, rename the top-level folder to
`flutter_vless` before running the bundled example. Flutter's SwiftPM
integration derives the root plugin package identity from the path dependency
directory name.

```bash
cd example
flutter pub get
```

For iOS or macOS, prepare the generated SwiftPM package metadata before opening
Xcode if package resolution looks stale:

```bash
../tool/prepare_apple_swiftpm.sh
```

Then run the target you care about:

```bash
flutter run -d android
flutter run -d ios
flutter run -d windows
```

Platform caveats still apply: iOS needs a real signed device for VPN mode,
macOS needs the Packet Tunnel setup and a valid Apple Team on both macOS
targets, and Windows needs `xray.exe` in place. For macOS, run
`flutter run -d macos` after the workspace signing is valid.

## 1. Add The Dependency

```bash
flutter pub add flutter_vless
```

That command installs the latest published stable package. For the working
1.1.7 API, use the coherent Git setup linked above instead, including the
platform-interface and Android/macOS/Windows source dependencies, then run
`flutter pub get`. Do not mix this checkout's main package with older published
platform wrappers when testing new options or runtime capabilities.

For macOS, run the metadata preparation step before the first build:

```bash
dart run flutter_vless:setup_macos_vpn --prepare-only
```

Use the full macOS setup command instead when you need Packet Tunnel VPN mode.

Android emulator support is included through the main Android runtime AAR.

## 2. Complete Platform Setup

Read the platform-specific guide that matches your target:

- [Android](platform/android.md)
- [iOS](platform/ios.md)
- [macOS](platform/macos.md)
- [Windows](platform/windows.md)

For version requirements, native binaries, and known platform limits, read
[Compatibility](compatibility.md).

## 3. Initialize The Plugin

The snippet below assumes these imports:

```dart
import 'package:flutter/foundation.dart';
import 'package:flutter_vless/flutter_vless.dart';
```

```dart
final flutterVless = FlutterVless(
  onStatusChanged: (status) {
    debugPrint(
      'state=${status.state} connection=${status.connectionState.name} '
      'download=${status.download}',
    );
  },
);

await flutterVless.initializeVless(
  providerBundleIdentifier: 'com.example.myapp',
  groupIdentifier: 'group.com.example.myapp',
);
```

## 4. Import A Share Link Or Subscription

```dart
final parsed = FlutterVless.parse(shareLink);
final config = parsed.getFullConfiguration();
```

Use `FlutterVless.parseMany(subscriptionText)` when you want every supported profile from a subscription payload.

## 5. Start The Connection

```dart
if (await flutterVless.requestPermission()) {
  await flutterVless.startVless(
    remark: parsed.remark,
    config: config,
  );
}
```

If you are running proxy-only mode, you can skip the VPN permission step on the paths that do not require a tunnel.

## 6. Stop The Connection

```dart
await flutterVless.stopVless();
```

## A Practical Mental Model

1. Parse user input into a `FlutterVlessURL`.
2. Turn that into a JSON Xray config.
3. Initialize the platform implementation.
4. Start proxy-only mode or VPN/tunnel mode.
5. Read status updates and delay metrics from the platform channel.

Next reads:

- [API Contract](api.md)
- [Examples](examples.md)
- [Security And Runtime Boundaries](security.md)
