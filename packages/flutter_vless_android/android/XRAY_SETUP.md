# Xray & Tun2socks Android Build Guide

This guide explains how to build the native libraries (`libxray.so` and `libtun2socks.so`) for the Flutter Vless plugin.

Android runtime files are stored in `android_runtime/xray_android/src/main` and published as the Maven Central AAR `dev.tfox.fluttervless:xray-android`. They are not stored in the `flutter_vless_android` Pub.dev package.

**Key Features:**
- ✅ **Android 15+ Support**: Builds with 16KB page size alignment.
- ✅ **Socket FD Passing**: `tun2socks` is patched to receive the TUN file descriptor via a Unix socket (bypassing Android process restrictions).

## Prerequisites

1. **Go (Golang)**: Version 1.21+ installed.
2. **Android NDK**: Version r27+ (recommended).
3. **macOS/Linux**: Build scripts are designed for Unix-like environments.

## 1. Environment Setup

Export the path to your Android NDK.

```bash
# Example (Adjust path to your NDK installation)
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/27.0.12077973"
```

## 2. Build Xray (`libxray.so`)

This script builds the Xray core for Android device and emulator architectures (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`) by default and writes them to the Maven runtime module.

```bash
cd android
chmod +x build_xray.sh
./build_xray.sh
```

## 3. Build Tun2socks (`libtun2socks.so`)

We use a custom Go-based build script (`build_tun2socks.sh`) instead of the old C-based one. This ensures 16KB page alignment and includes the socket-based FD passing logic.

```bash
cd android
chmod +x build_tun2socks.sh
./build_tun2socks.sh
```

## 4. Verification (16KB Page Size)

To confirm that the libraries are compatible with Android 15+ (16KB page size), check the `LOAD` segment alignment using `llvm-readelf`.

```bash
# Check alignment (should be 0x4000)
$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-readelf -l ../../../android_runtime/xray_android/src/main/jniLibs/arm64-v8a/libtun2socks.so | grep LOAD | head -1
```

**Expected Output:**
```
LOAD           ... 0x4000
```
If you see `0x1000`, it is **NOT** compatible with 16KB devices.

## 5. Package The Maven Runtime AAR

The `flutter_vless_android` Pub.dev package consumes the Android device runtime through the Maven artifact:

```text
dev.tfox.fluttervless:xray-android:26.7.11
```

After rebuilding `libxray.so`, `libtun2socks.so`, or the geodata files in `android_runtime/xray_android/src/main`, build the local Maven repository from the repository root:

```bash
tool/build_android_runtime_maven.sh
```

For local Android wrapper or example builds before Maven Central publication, pass the local repository path:

```bash
cd example/android
./gradlew :app:assembleDebug \
  -PflutterVlessAndroidRuntimeRepo="$PWD/../../android_runtime/xray_android/build/repo"
```

To upload the signed bundle to Maven Central, configure the Central Portal and signing environment variables documented in `android_runtime/xray_android/README.md`, then run:

```bash
tool/publish_android_runtime_maven.sh
```

## 6. Troubleshooting

- **"bad file descriptor"**: This means the socket FD passing failed. Ensure `XrayVPNService.kt` is correctly sending the FD to the socket path specified in `-sock-path`.
- **"permission denied"**: Ensure the app has permissions to write to the socket file in its private directory.
