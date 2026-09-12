# Android Runtime Maven Central Release Checklist

This checklist is the source of truth for updating the Android Xray runtime.
Follow it before publishing `flutter_vless_android` or the root `flutter_vless`
package to Pub.dev.

## Ownership

The Android device runtime is published as a Maven Central AAR:

```text
dev.tfox.fluttervless:xray-android:<runtime-version>
```

Runtime source files live in:

```text
android_runtime/xray_android/src/main/jniLibs/
android_runtime/xray_android/src/main/assets/
```

The Pub.dev Android wrapper intentionally must not contain raw device runtime
files under `packages/flutter_vless_android/android/src/main/jniLibs` or
`packages/flutter_vless_android/android/src/main/assets`.

The runtime AAR should contain both device and emulator ABIs:

```text
armeabi-v7a
arm64-v8a
x86
x86_64
```

Older release trains used an emulator-only compatibility package. Current
`flutter_vless_android` releases must not require that package because the main
runtime AAR carries emulator ABIs as part of the normal Android dependency.

## Central Portal Setup

1. Verify the Central namespace before uploading.
2. Use `dev.tfox` as the parent namespace.
3. `dev.tfox.fluttervless` is valid after the parent DNS namespace is verified.
4. Do not use underscores in a namespace.
5. DNS verification must be visible from the authoritative nameservers before Central can verify it.

Check DNS directly when needed:

```bash
dig @ns1.beget.com +short TXT tfox.dev
dig @ns1.beget.com +short TXT fluttervless.tfox.dev
```

GitHub Actions uses the `maven-central` environment secrets:

```text
MAVEN_CENTRAL_USERNAME
MAVEN_CENTRAL_PASSWORD
SIGNING_IN_MEMORY_KEY
SIGNING_IN_MEMORY_KEY_PASSWORD
```

`SIGNING_IN_MEMORY_KEY` must be the ASCII-armored private key block. The workflow
does not pass a key id to Gradle signing because Gradle in-memory signing is
less brittle when it reads the key block directly.

## Bundle Rules

The Central upload zip must contain one Maven component only:

```text
dev/tfox/fluttervless/xray-android/<version>/
```

Keep:

- `xray-android-<version>.pom`
- `xray-android-<version>.aar`
- `xray-android-<version>-sources.jar`
- `xray-android-<version>-javadoc.jar`
- `.asc`, `.md5`, `.sha1`, `.sha256`, and `.sha512` files for those artifacts

Remove before upload:

- `maven-metadata.xml*`
- `*.module*`
- checksum-of-checksum files such as `*.sha256.md5`
- directory entries or files outside the version directory

If Central shows two components, especially one with `?type=aar`, the bundle is
wrong. Drop that deployment, fix the bundle, and upload a new deployment.

## Update Flow

1. Rebuild Android device and emulator `libxray.so` and `libtun2socks.so` into `android_runtime/xray_android/src/main/jniLibs`.
2. Update `geoip.dat` and `geosite.dat` in `android_runtime/xray_android/src/main/assets`.
3. Update the Maven runtime version in `packages/flutter_vless_android/android/build.gradle`.
4. If republishing the same upstream Xray version with packaging changes, use a Maven patch version such as `26.6.27.1` because Maven Central artifacts are immutable.
5. Update release notes in `doc/release/` and package changelogs.
6. Run the local Maven build:

   ```bash
   tool/build_android_runtime_maven.sh
   ```

7. Run CI or the GitHub workflow `Publish Android Runtime AAR` with `USER_MANAGED`.
8. In Central Portal, confirm the deployment validates as one component.
9. Click `Publish`.
10. Verify public Maven availability:

    ```bash
    curl -I https://repo1.maven.org/maven2/dev/tfox/fluttervless/xray-android/<version>/xray-android-<version>.pom
    curl -I https://repo1.maven.org/maven2/dev/tfox/fluttervless/xray-android/<version>/xray-android-<version>.aar
    ```

11. Run the Maven/APK smoke test:

    ```bash
    tool/test_android_maven_runtime.sh
    ```

12. Run the Android emulator smoke test:

    ```bash
    cd example
    flutter test integration_test/android_xray_runtime_smoke_test.dart -d <android-device-id>
    ```

13. Publish Pub.dev packages in order:

    ```text
    flutter_vless_android
    flutter_vless_macos
    flutter_vless
    ```

Skip a package only when the same version is already published.

## Required Evidence

Before publishing the Android wrapper to Pub.dev, keep these checks green:

- Maven `.pom` returns `HTTP 200`.
- Maven `.aar` returns `HTTP 200`.
- The AAR contains `libxray.so`, `libtun2socks.so`, `geoip.dat`, and `geosite.dat` for all required ABIs.
- The example APK builds without a local Maven override.
- The example APK contains ARM and emulator runtime files from the Maven AAR.
- The emulator smoke test prints an Xray version matching the runtime release.
