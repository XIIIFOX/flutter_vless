# Package Release Preparation

This guide is the local checklist for preparing a `flutter_vless` release. It
does not publish packages, create tags, or change GitHub releases.

## Source Of Truth For Changes

The root [CHANGELOG](../../CHANGELOG.md) records every user-visible change in
the public `flutter_vless` package. Each publishable federated package keeps a
separate `CHANGELOG.md` beside its `pubspec.yaml`; add a versioned entry there
only when that package itself is being released.

For the 1.1.7 worktree, Android, iOS and macOS target Xray-core `v26.10.21`,
pinned to commit `1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`. Native runtimes are
rebuilt with Go 1.27.3 and the updated fallback RootCAs for the upstream
certificate-trust security update. Windows uses the checksum-pinned official
release and its separately tested routing-enabled runtime. Existing full
project GeoDAT files remain selected; the upstream ZIP now contains lite GeoIP.
This update publishes native runtime assets only. It does not publish a Flutter
package or create a `v1.1.7` plugin release.

Runtime release notes for this train:

* [Android v26.10.21-protect1](xray-android-v26.10.21-protect1.md)
* [iOS v26.10.21](xray-ios-v26.10.21.md)
* [macOS v26.10.21](xray-macos-v26.10.21.md)

### Registry blockers before publishing the plugin

All five local package versions remain `1.1.7` under the owner's current
version constraint. A fresh pub.dev registry audit on 2026-10-25 confirms that
Android, macOS and Windows implementation packages **already occupy version
1.1.7**, and their published source differs from the current worktree. Those
versions cannot be overwritten. The published interface is still `1.1.2` and
does not contain the new Options, routing or preparation-report API.

Before any future package publication, choose free implementation versions
(for example `1.1.8`), update the root minimum implementation constraints to
exclude the old `1.1.7` packages, and publish in this order: interface `1.1.7`,
updated implementations, then root `flutter_vless` `1.1.7`. This runtime update
does not make those version changes or publish those packages. Repository/Git
consumers of the current work need the matching implementation and interface
sources, as supplied by the example's local dependency overrides; published
implementation `1.1.7` packages do not acquire new wrapper code from a root Git
dependency.

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
