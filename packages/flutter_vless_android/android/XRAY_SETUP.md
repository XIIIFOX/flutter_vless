# Xray & Tun2socks Android Build Guide

This guide explains how to build the native libraries (`libxray.so` and `libtun2socks.so`) for the Flutter Vless plugin.

Android runtime files are stored in `android_runtime/xray_android/src/main` and published as the Maven Central AAR `dev.tfox.fluttervless:xray-android`. They are not stored in the `flutter_vless_android` Pub.dev package.

The current revision is `26.10.21-protect1`. The same AAR and its SHA-256 checksum are also available in [GitHub Releases](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-android-v26.10.21-protect1).

**Key Features:**
- ✅ **Android 15+ Support**: Builds with 16KB page size alignment.
- ✅ **Socket FD Passing**: `tun2socks` is patched to receive the TUN file descriptor via a Unix socket (bypassing Android process restrictions).

## Prerequisites

1. **Go (Golang)**: Version 1.27.3, including the upstream security certificate filtering.
2. **Android NDK**: Version 28.2.13676358 (the release pin).
3. **macOS/Linux**: Build scripts are designed for Unix-like environments.

## 1. Environment Setup

Export the path to your Android NDK.

```bash
# Example (Adjust path to your NDK installation)
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/28.2.13676358"
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
dev.tfox.fluttervless:xray-android:26.10.21-protect1
```

Final releases use the manual **Publish Android Runtime AAR** workflow with
`xray_runtime_version=26.10.21-protect1` and `publishing_type=AUTOMATIC`.
It compiles all four routing-capable Core ABIs from pinned source in GitHub
Actions, retains reviewed HEV/geodata bytes, verifies the AAR and signs the exact
Maven files. One bundle is uploaded; the workflow waits for that deployment to
reach `PUBLISHED` and retains the signed artifacts and provenance on failure.

The default `tool/build_android_runtime_maven.sh` path is a historical
`26.10.17-protect1` stock-input fixture for fake JVM tests. It refuses new version
labels. It is not the source of the current published runtime.

Verify an example build against the published dependency and committed checksums:

```bash
cd example/android
./gradlew :app:assembleDebug \
  -PflutterVlessOfficialRuntimeVerification=true --dependency-verification=strict
```

To upload the signed bundle to Maven Central, configure the Central Portal and signing environment variables documented in `android_runtime/xray_android/README.md`, then run:

```bash
tool/publish_android_runtime_maven.sh
```

## Protected VPN runtime

`26.10.21-protect1` retains protected socket integration and adds native routing
to Xray `v26.10.21`, with the reviewed Classic DNS and XHTTP lifecycle fixes.
Use the matching plugin and Maven runtime revision together.
An older runtime fails the VPN capability handshake; there is no implicit UID bypass.
Proxy-only does not enable the socket broker. Explicit `BLOCKED_APPS` still bypass VPN.

`xray-protect/apply.py` patches only the pinned disposable source. Every transport FD
is transferred with SCM_RIGHTS and acknowledged after `VpnService.protect()` succeeds.
The broker uses Android's physical-Network DNS API, including Private DNS; it never
substitutes a cleartext resolver. On Android 23–28, system A/AAAA queries are supported;
other system record types require an explicit Xray DNS server. VPN mode rejects
`xicmp` and `quic+local://` DNS because those upstream paths bypass controllers.
Use protected `https+local://` or `tcp+local://` DNS instead.

The repository's Maven pin update is separate from a Pub.dev package release;
the already-published `flutter_vless_android` `1.1.7` package is unchanged.

## 6. Troubleshooting

- **"bad file descriptor"**: This means the socket FD passing failed. Ensure `XrayVPNService.kt` is correctly sending the FD to the socket path specified in `-sock-path`.
- **"permission denied"**: Ensure the app has permissions to write to the socket file in its private directory.
