# Xray Android Runtime

This Android library packages the native Xray runtime used by `flutter_vless_android`.

For the full release procedure, see `doc/release/android-runtime-maven-central.md`.

The runtime files live here, not in the Pub.dev Android wrapper package:

```text
android_runtime/xray_android/src/main/jniLibs/
android_runtime/xray_android/src/main/assets/
```

Maven coordinates:

```text
dev.tfox.fluttervless:xray-android:26.6.1
```

The published 26.6.1 device-only artifact and 26.6.1.1 all-ABI artifact are
immutable. The current runtime revision that includes all Android ABIs is:

```text
dev.tfox.fluttervless:xray-android:26.7.28
```

The AAR contains Android native libraries and Xray geodata assets:

- `jni/arm64-v8a/libxray.so`
- `jni/arm64-v8a/libtun2socks.so`
- `jni/armeabi-v7a/libxray.so`
- `jni/armeabi-v7a/libtun2socks.so`
- `jni/x86/libxray.so`
- `jni/x86/libtun2socks.so`
- `jni/x86_64/libxray.so`
- `jni/x86_64/libtun2socks.so`
- `assets/geoip.dat`
- `assets/geosite.dat`

Build a local Maven repo before publishing or testing the Android wrapper locally:

```bash
tool/build_android_runtime_maven.sh
```

Publish to Maven Central after the `dev.tfox` namespace, Central Portal token, and GPG signing key are configured:

```bash
tool/publish_android_runtime_maven.sh
```

Required environment variables for Maven Central upload:

```text
MAVEN_CENTRAL_USERNAME
MAVEN_CENTRAL_PASSWORD
SIGNING_IN_MEMORY_KEY
SIGNING_IN_MEMORY_KEY_PASSWORD
```

`SIGNING_IN_MEMORY_KEY` must be an ASCII-armored private key block. Do not pass a key id to Gradle in-memory signing unless you have verified that the exported key format works with Gradle signing.

Central Portal setup:

1. Register and verify the namespace `dev.tfox`.
2. Add the DNS TXT record requested by Central Portal to `tfox.dev`.
3. Generate a Central Portal user token.
4. Store the token username/password and signing key values as GitHub Secrets in the `maven-central` environment.

The Maven `groupId` used by this project is `dev.tfox.fluttervless`. It is valid after the parent `dev.tfox` namespace is verified.

Central bundle rules:

1. The upload zip must contain only Maven version files under `dev/tfox/fluttervless/xray-android/<version>/`.
2. Do not include `maven-metadata.xml*`; Central treats metadata at the artifact root as content without a `.pom`.
3. Do not include Gradle `.module*` files for this AAR; Central can split the AAR into a second `type=aar` component.
4. Keep `.pom`, `.aar`, `sources.jar`, `javadoc.jar`, their `.asc` signatures, and checksums.

When Xray is updated:

1. Rebuild Android device `libxray.so` into `android_runtime/xray_android/src/main/jniLibs`.
2. Rebuild Android device `libtun2socks.so` into `android_runtime/xray_android/src/main/jniLibs`.
3. Rebuild emulator `x86`/`x86_64` binaries into `android_runtime/xray_android/src/main/jniLibs`.
4. Keep `geoip.dat` and `geosite.dat` in `android_runtime/xray_android/src/main/assets`.
5. Set `XRAY_RUNTIME_VERSION` to the new Maven artifact version without the leading `v`.
6. Run `tool/build_android_runtime_maven.sh` and verify the example against the local Maven repo.
7. Run the `Publish Android Runtime AAR` GitHub workflow with `USER_MANAGED`.
8. In Central Portal, ensure the deployment validates as one component, then click `Publish`.
9. Verify Maven Central public availability:

   ```bash
   curl -I https://repo1.maven.org/maven2/dev/tfox/fluttervless/xray-android/<version>/xray-android-<version>.pom
   curl -I https://repo1.maven.org/maven2/dev/tfox/fluttervless/xray-android/<version>/xray-android-<version>.aar
   ```

10. Publish Pub.dev packages in order: Android wrapper, macOS package, root `flutter_vless`.
