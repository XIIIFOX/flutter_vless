# Package Release Preparation

This guide is the local checklist for preparing a `flutter_vless` release. It
does not publish packages, create tags, or change GitHub releases.

## Source Of Truth For Changes

The root [CHANGELOG](../../CHANGELOG.md) records every user-visible change in
the public `flutter_vless` package. Each publishable federated package keeps a
separate `CHANGELOG.md` beside its `pubspec.yaml`; add a versioned entry there
only when that package itself is being released.

For 1.1.6, the iOS implementation lives in the root package, so PR #24 belongs
in the root changelog. The Android, macOS, Windows, and platform-interface
packages have no code change in this release and must not receive artificial
1.1.6 entries or version bumps.

## Local Checklist

1. Update the root package version in `pubspec.yaml`, the matching iOS
   CocoaPods version in `ios/flutter_vless.podspec`, and the example app
   version when it ships with the release.
2. Add the user-visible change, linked PR, issue, and contributor credit to
   the top of the root `CHANGELOG.md`.
3. Update every documentation page that describes changed setup, runtime
   limits, or validation. Keep the root README and `doc/getting-started.md`
   dependency snippets on the same version.
4. For each federated package that is actually published, bump its own
   `pubspec.yaml` and add a matching versioned entry to its own changelog.
5. Run the relevant local tests and dry-run package validation before creating
   a tag or publishing. Use the Android runtime checklist when the Maven AAR
   changes: [Android Runtime Maven Central Release Checklist](android-runtime-maven-central.md).

## iOS Runtime Changes

When an iOS Xray framework change affects XHTTP or the Network Extension,
rebuild and test the framework on a signed physical device. The required
toolchain and the HTTP/2 memory safeguard are documented in
[Build XRay.xcframework](../../ios/XRAY_BUILD.md); use the real-device cases in
[the VPN matrix](../device_matrix.md) for regression coverage.
