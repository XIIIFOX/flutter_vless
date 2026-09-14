# flutter_vless_android

The Android implementation of the `flutter_vless` plugin.

## Runtime

Android runtime binaries and geodata are delivered through the Maven Central AAR dependency `dev.tfox.fluttervless:xray-android:26.9.9-protect1`. This keeps the Pub.dev package lightweight while preserving the same packaged Xray files in the final Android app.

## Emulator Support

The current Maven runtime AAR includes `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`.
This covers both physical Android devices and Android emulators.
