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
dev.tfox.fluttervless:xray-android:26.7.28-protect1
```

The AAR contains `libxray.so` and `libtun2socks.so` for `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`, plus `geoip.dat` and `geosite.dat`. Keeping the runtime in Maven Central avoids Pub.dev archive limits while preserving the same files in the final Android app.

The `flutter_vless_android` Pub.dev package intentionally does not include raw `android/src/main/jniLibs` or geodata files. Runtime updates are made in `android_runtime/xray_android/src/main`, published to Maven Central first, and then consumed by the Android wrapper.

For the strict runtime update and publishing checklist, see `doc/release/android-runtime-maven-central.md`.

## Runtime Notes

- `blockedApps` is supported on Android.
- `requestPermission()` is relevant for VPN mode.
- `proxyOnly: true` starts the local proxy path without installing the VPN route.

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

## Session protection and local proxy access (1.2.0)

The VPN service owns its session, native credentials and workers. Internal Xray,
tun2socks, FD transfer or connectivity failures retain an already established
TUN and report `CONNECTING`; retries use capped backoff. A replacement config is
validated before switching workers. Late callbacks from earlier workers cannot
own the current session. `CONNECTED` requires an authenticated data request and
the captured packet path; process existence and upload counters are insufficient.

Explicit stop disarms library restoration and frees the session. A system start
with no app command restores only the authorized profile encrypted with an
Android Keystore key in the app's no-backup directory. Missing data or lost keys
produce a safe diagnostic failure. Killing the entire service loses its old FD:
continuous blocking across process death requires Android's **Always-on VPN**
with **Block connections without VPN**. The library cannot disable administrator
or user OS policy. Permission revocation terminates the session.

VPN sessions authenticate the managed loopback SOCKS with fresh native
credentials and do not insert an HTTP listener. StatsService remains on loopback.
Additional incompatible SOCKS/HTTP listeners are rejected before session mutation.
Connected delay executes in the owning service process; no global Java
Authenticator or shared plaintext password is used. Xray and tun2socks configs
are private no-backup session files; argv contains only config paths.

Proxy-only mode retains its separately configured authentication/noauth behavior
and has no system VPN isolation promise. The plugin does not exclude its own UID
from the VPN. User-requested `blockedApps` and Xray `direct` rules remain supported.

## Explicit DNS policy

Default `AndroidDnsPolicy.config` preserves the supplied config's semantics and
does not promise protected DNS. Choose proxy DNS explicitly:

```dart
await flutterVless.startVless(
  remark: parsed.remark,
  config: parsed.getFullConfiguration(),
  androidDnsPolicy: AndroidDnsPolicy.proxy,
  // Optional when several proxy outbounds are present:
  androidDnsProxyOutboundTag: 'proxy',
);
```

The protected mode advertises `198.18.0.2` as system DNS and forwards its queries
over TCP through the selected proxy. A suitable `proxy` tag or a unique supported
outbound is selected; ambiguity and reserved-tag/virtual-address conflicts fail
before changing a working session. Service DNS rules precede user `UDP -> direct`
rules while other direct routing is preserved. Physical-network bootstrap resolves
only the remote transport endpoints; it is not a fallback for user queries.

This policy protects the virtual system resolver. It does not override intentional
direct rules to other DNS/DoH destinations or encrypt a plaintext remote proxy
transport. Unsupported/older native backends reject the explicit option.

Use root Gradle dependency verification as described in
[the runtime release guide](../release/android-runtime-maven-central.md).
Published library metadata alone does not enable verification in consuming apps.

### Граница готовности при холодном запуске

Завершение `startVless` подтверждает принятие запроса. Ждите состояния `CONNECTED`: оно
выставляется после авторизации SOCKS, передачи FD и проверки настоящего пути через TUN.
Появление VPN-сети в ConnectivityManager само по себе не подтверждает готовность.
На эмуляторе обнаружен короткий переход между объявлением сети и готовностью, когда
первый пакет мог пройти через прежний физический маршрут. Для блокировки до запуска
VPN и при уничтожении всего service нужна системная политика always-on/lockdown.
Уже установленный TUN сохраняется при внутреннем восстановлении workers.
