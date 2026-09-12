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
## Consumer verification (1.1.6)

The official runtime is `dev.tfox.fluttervless:xray-android:26.7.28-protect1`.
Copy [verification-metadata.xml](../../example/android/gradle/verification-metadata.xml)
into **your application's root** `android/gradle/` directory, and run Gradle with
`--dependency-verification=strict`. Merge the component pins into any broader
existing dependency policy. The sample's trust rule excludes unrelated groups
from this narrowly scoped runtime check; it does not trust any other artifact or
version in `dev.tfox.fluttervless`. Library publication alone cannot enable a
consumer's root Gradle verification.

The AAR's pinned SHA-256 is
`54785c3c5437473d8f9c8071a6138ae781ed2038e57beb47b6a46de3545c3ad8`,
from [the release asset](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-android-v26.7.28-protect1)
(GitHub asset 547535638). Maven Central bytes were checked against that release
digest, and all packaged native binaries/geodata were independently matched to
the repository inputs. The POM was reviewed against the committed publication
definition (no dependencies or repositories), then pinned to
`7ce7fc19a20d33dfed9579c057a2218f8bb95ad34eb482b8584fc87d12624957`.
No Gradle module metadata is published for this revision; a later unexpected
module file is not trusted. These pins are intentionally not generated in CI.

`tool/test_android_maven_runtime.sh` verifies the published bytes, exercises real
Gradle rejection of changed AAR/POM files with identical coordinates, and builds
the consuming example with strict verification. The official mode rejects runtime
repository/version overrides; local development builds are a separate workflow.

For development, build the local Maven repository with
`tool/build_android_runtime_maven.sh`, then use
`python3 tool/with_android_local_runtime.py :flutter_vless_android:testDebugUnitTest`.
The build first verifies the committed native input manifest. The wrapper checks
the local AAR's contents against those inputs, temporarily pins its exact local
AAR/POM bytes while holding a build lock, runs strict Gradle verification, and
restores the official metadata. It is explicitly labelled development verification
and does not prove the published AAR. Never run another example Gradle build in
parallel with that temporary development wrapper.

To update a trusted release: review runtime source changes, reproduce and check
all ABIs, publish the intended immutable artifact, compare the release-pipeline
digest with Maven bytes, review the POM/any module metadata, and commit the new
coordinates, input manifest and checksums together. `--write-verification-metadata`
must not automatically accept new checksums in ordinary CI. See Gradle's
[dependency verification guide](https://docs.gradle.org/current/userguide/dependency_verification.html).
