# XRay Android v26.7.11

Maven runtime: `dev.tfox.fluttervless:xray-android:26.7.11`

Changes:

* Rebuilt `libxray.so` against XTLS/Xray-core `v26.7.11` for `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`.
* Kept `libtun2socks.so` and Xray geodata packaged in the same runtime AAR.
* Kept Android 15+ 16KB page-size linker alignment for rebuilt Android binaries.
* Updated the Android wrapper default runtime dependency to `dev.tfox.fluttervless:xray-android:26.7.11`.

Upstream:

* XTLS/Xray-core `v26.7.11` was published on 2026-07-11 and is marked as a pre-release on GitHub.
* Release commit: `50231eaff98ccc31b5cbd247a721c16e97fe5ec1`.

Verification:

* Run `cd packages/flutter_vless_android/android && ./build_xray.sh`.
* Run `tool/build_android_runtime_maven.sh` and verify the AAR contains all four Android ABIs plus `geoip.dat` and `geosite.dat`.
