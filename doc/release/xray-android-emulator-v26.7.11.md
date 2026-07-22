# XRay Android Emulator Compatibility v26.7.11

Changes:

* Rebuilt bundled emulator `libxray.so` binaries against XTLS/Xray-core `v26.7.11` for `x86` and `x86_64`.
* Kept this package marked as legacy because the main Maven runtime `dev.tfox.fluttervless:xray-android:26.7.11` includes emulator ABIs.

Upstream:

* XTLS/Xray-core `v26.7.11` was published on 2026-07-11 and is marked as a pre-release on GitHub.
* Release commit: `50231eaff98ccc31b5cbd247a721c16e97fe5ec1`.

Verification:

* Copy rebuilt `x86` and `x86_64` `libxray.so` files from `android_runtime/xray_android/src/main/jniLibs` into `packages/flutter_vless_android_emulator/android/src/main/jniLibs`.
* Verify both binaries report Xray `v26.7.11`.
