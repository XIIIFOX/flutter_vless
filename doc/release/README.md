# Package releases

Keep the root and federated changelogs aligned with their package metadata.
Native runtime versions, Dart package versions and example build numbers are
separate values.

<a id="selected-build-suffix-version-plan"></a>

## Package versions

| Package | Version |
| --- | --- |
| `flutter_vless_platform_interface` | `1.1.7` |
| `flutter_vless_android` | `1.1.7+1` |
| `flutter_vless_macos` | `1.1.7+1` |
| `flutter_vless_windows` | `1.1.7+1` |
| `flutter_vless` | `1.1.7` |

The root requires the implementation packages at `^1.1.7+1` and the platform
interface at `^1.1.7`. Pub treats the build suffix as part of package version
ordering; published package versions cannot be overwritten. Do not copy a Dart
build suffix into a Maven version or native application build number.

## Native runtimes

The repository uses Xray-core **26.11.9**, pinned to
`676eaf66f8f05d4d558ee7a74b4736623d3feeb9` and built with Go 1.27.3.
The published 1.1.7 packages shipped Core 26.10.31.

| Platform | Runtime notes |
| --- | --- |
| Android | [26.11.9-protect1](xray-android-v26.11.9-protect1.md) |
| iOS | [26.11.9-r1](xray-ios-v26.11.9-r1.md) |
| macOS | [26.11.9-r1](xray-macos-v26.11.9-r1.md) |
| Windows | [26.11.9-r1](xray-windows-v26.11.9-r1.md) |

Verify public archive/AAR checksums and loaded capabilities before updating
consumer pins. Update Apple SwiftPM and CocoaPods references together. Keep
Android device/emulator ABIs and 16 KiB alignment, Apple memory safeguards,
private startup interfaces and managed-service ownership intact.

## Release workflow

1. Review user-visible changes in the root and platform changelogs. Keep setup,
   API documentation and examples consistent with the exported interfaces.
2. Run relevant Dart and native tests, platform builds and controlled runtime
   tests. Use the [VPN matrix](../device_matrix.md) for live DNS, routing,
   statistics, lifecycle and recovery checks on the affected systems.
3. Inspect package contents with a publication dry run. Exclude build outputs,
   credentials, private profiles and internal validation records.
4. Check clean dependency resolution using the version constraints above,
   without local overrides. Confirm registry availability before publishing.
5. Publish the platform interface, updated implementations and root package in
   dependency order. Native runtime distribution follows its own
   [Android Maven checklist](android-runtime-maven-central.md) and
   [Apple SDK build guide](../../ios/XRAY_BUILD.md).

For Apple provider changes, update existing host extensions as described in the
platform guides. A new package dependency does not replace an iOS provider file
previously copied into an application.
