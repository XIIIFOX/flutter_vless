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
dev.tfox.fluttervless:xray-android:26.10.29-protect1
```

This revision requires the matching Android socket broker;
see `packages/flutter_vless_android/android/XRAY_SETUP.md` for builds and compatibility limits.

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

The default local packaging path below is the historical `26.10.17-protect1`
stock-input fixture used by fake JVM tests. Its binaries/checksum manifest stay
immutable; it cannot relabel those inputs as a newer runtime:

```bash
tool/build_android_runtime_maven.sh
```

Final publication uses the manual **Publish Android Runtime AAR** workflow. It
rebuilds all four native-routing-capable Core ABIs with Go `1.27.3`, retains
reviewed HEV/geodata, verifies source and AAR bytes, signs the isolated Maven
repository and uploads that exact bundle. `AUTOMATIC` waits for the same
deployment to reach `PUBLISHED`; a status failure never reuploads it.

The workflow invokes the following publisher after the `dev.tfox` namespace,
Central Portal token and GPG signing key are configured:

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

1. Review the exact upstream Core/module/checksum pins and required overlays.
2. Run the workflow once at the reviewed commit, using its fixed final version.
3. Independently verify the downloaded signed repository, provenance, four-ABI
   AAR/ELF bytes and public Maven AAR/POM. Retain existing HEV/geodata pins.
4. Update consumer version defaults and strict checksums from those actual bytes.
5. Create the native-only GitHub runtime release from the same payloads.
6. Verify Maven Central public availability:

   ```bash
   curl -I https://repo1.maven.org/maven2/dev/tfox/fluttervless/xray-android/<version>/xray-android-<version>.pom
   curl -I https://repo1.maven.org/maven2/dev/tfox/fluttervless/xray-android/<version>/xray-android-<version>.aar
   ```

7. Run app-only and device checks against the published, checksum-pinned runtime.

Runtime publication does not publish any Pub.dev package or the plugin's GitHub
release. The existing package versions, including `1.1.7`, are unchanged.
