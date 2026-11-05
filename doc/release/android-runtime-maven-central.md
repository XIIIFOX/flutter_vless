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

## Update flow

1. Freeze and review the Core source revision, Android toolchain, overlays,
   runtime version and dataset inputs. A changed Maven component needs a new
   immutable runtime revision; never overwrite an existing coordinate.
2. Build and qualify a source-bound candidate with the
   `Unpublished Android runtime preview` Actions workflow. Verify all four
   ABIs, 16 KiB ELF alignment, exact source/packager provenance and expected
   HEV/geodata inputs. A preview is not a published release artifact.
3. Use the reviewed canonical release producer in `Publish Android Runtime AAR`
   for that frozen source. Set `publishing_type=USER_MANAGED` explicitly for a
   reviewable Central deployment; the workflow's default is `AUTOMATIC`.
   Check the signed bundle and recorded candidate bytes before publication.
4. In Central Portal, verify the single intended component and validation
   result. Publish that same deployment after review. The workflow's
   `existing_deployment_id` input publishes an existing validated deployment
   without rebuilding/reuploading; do not accidentally create a second one.
5. Verify public POM/AAR/signature/checksum availability, then compare the
   anonymous Maven bytes with the exact reviewed candidate and GitHub assets.
6. Update wrapper coordinates, strict verification metadata, source manifests
   and release notes together. Run the strict Maven/APK check and an owned
   Android device/emulator acceptance, including actual traffic and Stop.
7. Flutter publication is a separate release decision. Select available package
   versions and matching constraints, then publish the platform-interface,
   changed Android/macOS/Windows implementations and root package in dependency
   order. An already published wrapper version cannot be overwritten or skipped
   when its code has changed.

The legacy local `tool/build_android_runtime_maven.sh` stock-input path is kept
for historical fixtures. It is not the canonical producer or verification of
the current release; use the source-bound Actions/packager flow above.

## Required Evidence

Before publishing the Android wrapper to Pub.dev, keep these checks green:

- Maven `.pom` returns `HTTP 200`.
- Maven `.aar` returns `HTTP 200`.
- The AAR contains `libxray.so`, `libtun2socks.so`, `geoip.dat`, and `geosite.dat` for all required ABIs.
- The example APK builds without a local Maven override.
- The example APK contains ARM and emulator runtime files from the Maven AAR.
- The emulator smoke test prints an Xray version matching the runtime release.
## Consumer verification

The current published runtime is `dev.tfox.fluttervless:xray-android:26.10.31-protect2`, based on Core 26.10.31.
Copy [verification-metadata.xml](../../example/android/gradle/verification-metadata.xml)
into **your application's root** `android/gradle/` directory, and run Gradle with
`--dependency-verification=strict`. Merge the component pins into any broader
existing dependency policy. The sample's trust rule excludes unrelated groups
from this narrowly scoped runtime check; it does not trust any other artifact or
version in `dev.tfox.fluttervless`. Library publication alone cannot enable a
consumer's root Gradle verification.

The AAR's pinned SHA-256 is
`3280118949aa5fa05fa58d233642af5ebd3b7eb484bb3d30fffa29271cddcc12`,
from [the release asset](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-android-v26.10.31-protect2)
and Maven Central. The GitHub AAR is the same published file; every AAR entry
and all native binaries/geodata were independently matched to
the repository inputs. The POM was reviewed against the committed publication
definition (no dependencies or repositories), then pinned to
`7b5a26e33ed27725fe38301a36268e7cc549085167027a39794762aea1ae5107`.
The empty sources/javadoc JARs are also pinned for IDE dependency resolution.
No Gradle module metadata is published for this revision; a later unexpected
module file is not trusted. These pins are intentionally not generated in CI.

`tool/test_android_maven_runtime.sh` verifies the published bytes, exercises real
Gradle rejection of changed AAR/POM files with identical coordinates, and builds
the consuming example with strict verification. The official mode rejects runtime
repository/version overrides; local development builds are a separate workflow.

For new native development, use the manual unpublished Android runtime preview
workflow and its isolated, source-bound output. Canonical release candidates use
the fresh CI producer, strict provenance checks and one signed Central deployment.
The current producer source is
`2505694c4001e7d52f06d6a63f29780da8dc7d49`; the published payload is immutable.
Do not treat a historical local wrapper run as verification of those bytes.
See [Core31 validation](https://github.com/XIIIFOX/flutter_vless/blob/main/doc/release/core31-five-followups-validation.md) for exact producer,
publication and public-artifact evidence.

To update a trusted release: review runtime source changes, reproduce and check
all ABIs, publish the intended immutable artifact, compare the release-pipeline
digest with Maven bytes, review the POM/any module metadata, and commit the new
coordinates, input manifest and checksums together. `--write-verification-metadata`
must not automatically accept new checksums in ordinary CI. See Gradle's
[dependency verification guide](https://docs.gradle.org/current/userguide/dependency_verification.html).
