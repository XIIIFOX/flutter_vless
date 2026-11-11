# Xray Android Runtime

This library packages the native runtime used by `flutter_vless_android`.
Native libraries and geodata live here rather than in the Dart wrapper:

```text
android_runtime/xray_android/src/main/jniLibs/
android_runtime/xray_android/src/main/assets/
```

Maven coordinates:

```text
dev.tfox.fluttervless:xray-android:26.11.9-protect1
```

The AAR includes `libxray.so` and `libtun2socks.so` for `armeabi-v7a`, `arm64-v8a`,
`x86` and `x86_64`, plus full `geoip.dat` and `geosite.dat`. Native libraries
retain 16 KiB page alignment. The runtime requires the matching Android socket
broker; see [Android integration](../../packages/flutter_vless_android/android/XRAY_SETUP.md).

For build provenance, checksums and the full publication procedure, use the
[Android Maven release guide](../../doc/release/android-runtime-maven-central.md).

The manual **Publish Android Runtime AAR** workflow rebuilds all four
native-routing-capable Core ABIs with Go 1.27.3, retains the selected HEV/geodata,
verifies the AAR and source inputs, signs an isolated Maven repository and uploads
that exact bundle. Local fixture packaging does not rebuild the native Core.

The publisher requires a verified `dev.tfox` namespace and these GitHub Secrets
in the `maven-central` environment:

```text
MAVEN_CENTRAL_USERNAME
MAVEN_CENTRAL_PASSWORD
SIGNING_IN_MEMORY_KEY
SIGNING_IN_MEMORY_KEY_PASSWORD
```

Use a Central Portal token for the username/password pair and an ASCII-armored
private key block for in-memory signing. The Maven `groupId` is
`dev.tfox.fluttervless`.

The upload ZIP contains only version files below
`dev/tfox/fluttervless/xray-android/<version>/`: POM, AAR, sources/javadoc JARs,
signatures and checksums. Exclude `maven-metadata.xml*` and Gradle `.module*`
files. Published coordinates are immutable.

When updating Core, review the pinned source and overlays, verify all ABIs and
signatures, then publish the already verified payload. Compare public Maven and
GitHub bytes before changing consumer defaults and checksums. The workflow waits
for its existing Central deployment instead of uploading another bundle after a
status error. Native runtime and Dart package versions remain independent.
