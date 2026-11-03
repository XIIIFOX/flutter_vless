# flutter_vless_android

The Android implementation of the `flutter_vless` plugin.

## Runtime

Android runtime binaries and geodata are delivered through the Maven Central AAR dependency `dev.tfox.fluttervless:xray-android:26.10.31-protect2`. This keeps the Pub.dev package lightweight while preserving the same packaged Xray files in the final Android app.

The native AAR is already published. The matching wrapper changes in this
repository are versioned `1.1.7+1` and are not yet published; the existing
pub.dev wrapper numbered `1.1.7` remains unchanged. Use matching source
packages through the main package for its new APIs.

## Emulator Support

The current Maven runtime AAR includes `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`.
This covers both physical Android devices and Android emulators.
