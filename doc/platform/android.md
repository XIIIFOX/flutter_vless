# Android

Android supports both VPN mode and proxy-only mode.

## Quick Run The Example

Use the example app when you want to confirm that the native Android pieces are
working before wiring the plugin into your own app.

```bash
cd example
flutter pub get
flutter run -d android
```

The Android runtime AAR includes both device and emulator ABIs, so the example
can run on Android devices and emulators with the main Android dependency.

## What You Need

- Flutter package dependency
- Android project configured for the plugin
- `minSdkVersion` of at least 23
- Gradle native-library extraction enabled when required by your packaging setup
- Maven Central access, which is normally already present in Flutter Android projects

## Native Library Packaging

Use the Android Gradle plugin packaging DSL for native-library extraction.
Do not configure this directly in `AndroidManifest.xml`.

Kotlin DSL:

```kotlin
android {
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}
```

Groovy DSL:

```groovy
android {
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}
```

The bundled example uses this setting in:

```text
example/android/app/build.gradle.kts
```

## Gradle Settings

Make sure your app target can run the plugin:

```kotlin
android {
    defaultConfig {
        minSdk = 23
        targetSdk = flutter.targetSdkVersion
    }
}
```

If your app already uses Flutter's generated values, check what
`flutter.minSdkVersion` resolves to before relying on it.

## Runtime AAR

The Android runtime is delivered as a Maven Central AAR:

```text
dev.tfox.fluttervless:xray-android:26.7.11
```

The AAR contains `libxray.so` and `libtun2socks.so` for `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`, plus `geoip.dat` and `geosite.dat`. Keeping the runtime in Maven Central avoids Pub.dev archive limits while preserving the same files in the final Android app.

The `flutter_vless_android` Pub.dev package intentionally does not include raw `android/src/main/jniLibs` or geodata files. Runtime updates are made in `android_runtime/xray_android/src/main`, published to Maven Central first, and then consumed by the Android wrapper.

For the strict runtime update and publishing checklist, see `doc/release/android-runtime-maven-central.md`.

## Runtime Notes

- `blockedApps` is supported on Android.
- `requestPermission()` is relevant for VPN mode.
- `proxyOnly: true` starts the local proxy path without installing the VPN route.

## Quick Settings Tile

Android exposes an optional Quick Settings tile through `VlessTileService`. The
service is merged from the plugin manifest; host apps should not declare it
again.

Setup:

1. Pass `notificationIconResourceType` / `notificationIconResourceName` to
   `initializeVless()` — used for notifications and as the default tile icon.
2. Optionally pass `quickSettingsTile` for a custom label and tile icon
   override (`tileIconResource*`); when omitted, the notification icon is used.
3. Ask the user to add the tile manually in system Quick Settings.
4. Call `startVless()` at least once so the tile can reuse the saved profile.
   For VPN mode, also call `requestPermission()`. Proxy-only mode does not need
   VPN consent.

Behavior:

- Tile toggle uses the last profile persisted by `startVless`.
- Tile label stays constant (no `On`/`Off` suffix); VPN state is shown by tile
  highlight (`ACTIVE` / `INACTIVE`).
- While connecting, the tile is unavailable (gray icon) and ignores taps until
  `CONNECTED` or `DISCONNECTED`.
- Tile state follows VPN broadcasts and updates while Quick Settings is closed
  when the tile has been added (`ACTIVE_TILE`).
- Without a saved profile, tapping the tile opens the host app.
- VPN-mode taps without consent open a transparent permission activity.
  Proxy-only profiles skip VPN consent and start the local proxy directly.
- Connect/disconnect from the tile does not collapse Quick Settings. The shade
  only closes when the device is locked or the tile has to open an activity.
- The tile works when the Flutter UI is not running, as long as profile and
  appearance were saved earlier via `initializeVless` / `startVless`.

Example:

```dart
await flutterVless.initializeVless(
  onStatusChanged: onStatusChanged,
  notificationIconResourceType: 'mipmap',
  notificationIconResourceName: 'ic_launcher',
  quickSettingsTile: QuickSettingsTile(
    tileLabel: 'My VPN',
    tileIconResourceType: 'mipmap',
    tileIconResourceName: 'ic_launcher', // optional override
  ),
);
```

## Suggested Setup Flow

1. Run the example on a device or emulator.
2. Add the dependency to your own app.
3. Enable Gradle native-library extraction with `useLegacyPackaging = true` when your app packaging requires extracted native executables.
4. Set `minSdk` to 23 or newer.
5. Initialize the plugin and start proxy-only mode or VPN mode.

## Common Pitfalls

- Using too low a `minSdkVersion`
- Forgetting the Gradle native-library extraction setting when needed
- Copying iOS or macOS tunnel steps into an Android project
