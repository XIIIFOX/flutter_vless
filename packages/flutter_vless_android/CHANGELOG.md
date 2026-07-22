## 1.1.5

* Updated the Android runtime dependency to `dev.tfox.fluttervless:xray-android:26.7.11`.
* Rebuilt Android `libxray.so` binaries for `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64` against Xray-core `v26.7.11`.
* Fixed Android VPN app routing: all configured blocked apps are now applied to `VpnService.Builder` as disallowed applications and bypass the Xray VPN tunnel.

## 1.1.4

* Updated the Android runtime dependency to `dev.tfox.fluttervless:xray-android:26.6.27.1`.
* Rebuilt Android `libxray.so` binaries for `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64` against Xray-core `v26.6.27`.

## 1.1.3

* Updated the Android runtime dependency to `dev.tfox.fluttervless:xray-android:26.6.22`.
* Rebuilt Android `libxray.so` binaries for `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64` against Xray-core `v26.6.22`.

## 1.1.2

* Clarified that Android device and emulator runtime binaries are delivered through the main Maven `xray-android` AAR.
* Kept the Android runtime dependency on `dev.tfox.fluttervless:xray-android:26.6.1.1`.

## 1.1.1

* Updated the Android device runtime `libxray.so` binaries to Xray-core `v26.6.1`.
* Kept Android 15+ 16KB page-size linker alignment for the rebuilt ARM binaries.
* Moved Android runtime binaries and geodata into the Maven `dev.tfox.fluttervless:xray-android:26.6.1.1` AAR dependency.
* Included device and emulator ABIs (`armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`) in the main Maven runtime AAR.
* Removed raw device `jniLibs` and geodata files from the Pub.dev wrapper package; the wrapper now resolves the runtime from Maven Central.

## 1.1.0

* Replaced Android Dart boilerplate with the shared `VlessMethodChannelAdapter`.
* Removed template `getPlatformVersion` scaffold files.
* Moved `flutter_lints` to `dev_dependencies`.
* Removed publish-time dependency overrides from `pubspec.yaml`.

## 1.0.2

* XRay version up

## 1.0.1

*   XRay version up

## 1.0.0

*   Initial release of the Android implementation for `flutter_vless`.
*   Supports VLESS/VMESS protocols using Xray core.
*   Implements `VlessPlatform` interface.
