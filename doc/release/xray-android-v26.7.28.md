# XRay Android v26.7.28

Maven runtime: `dev.tfox.fluttervless:xray-android:26.7.28`

Changes:

* Rebuilt `libxray.so` against XTLS/Xray-core `v26.7.28` for `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`.
* Kept `libtun2socks.so` and Xray geodata packaged in the same runtime AAR.
* Kept Android 15+ 16KB page-size linker alignment for rebuilt Android binaries.
* Updated the Android wrapper default runtime dependency to `dev.tfox.fluttervless:xray-android:26.7.28`.

Upstream:

* XTLS/Xray-core `v26.7.28` was published on 2026-07-28 and is marked as a pre-release on GitHub.
* Release commit: `5ca6f4b7d4dc20a881d4330e498892697627ec0c`.

Verification:

* Run `cd packages/flutter_vless_android/android && ./build_xray.sh`.
* Run `tool/build_android_runtime_maven.sh` and verify the AAR contains all four Android ABIs plus `geoip.dat` and `geosite.dat`.
