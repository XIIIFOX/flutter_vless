# flutter_vless_android

The Android implementation of the [`flutter_vless`](https://pub.dev/packages/flutter_vless) plugin.
Use this package through the main `flutter_vless` dependency.

## Runtime

Native libraries and geodata resolve through the pinned Maven Central AAR
`dev.tfox.fluttervless:xray-android:26.11.9-protect1`, keeping the Dart package
small while providing the complete runtime in the Android app.

## Emulator Support

The runtime includes `armeabi-v7a`, `arm64-v8a`, `x86` and `x86_64`, with 16 KiB
page alignment for both device and emulator builds.

See the [Android platform guide](https://github.com/XIIIFOX/flutter_vless/blob/main/doc/platform/android.md)
for VPN permission, packaging and system-control setup.
