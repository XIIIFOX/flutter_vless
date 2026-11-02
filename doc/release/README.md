# Package Release Preparation

This guide is the local checklist for preparing a `flutter_vless` release. It
does not publish packages, create tags, or change GitHub releases.

## Source Of Truth For Changes

The root [CHANGELOG](../../CHANGELOG.md) records every user-visible change in
the public `flutter_vless` package. Each publishable federated package keeps a
separate `CHANGELOG.md` beside its `pubspec.yaml`; add a versioned entry there
only when that package itself is being released.

For the 1.1.7 worktree, Android, iOS, macOS and Windows target Xray-core
`v26.10.31`, pinned to `a4a3dff5b20c2faae567b742c172c7b95e75c083`.
Native artifacts use Go 1.27.3, retain managed-service ownership and native
routing, and preserve the shared MPTCP default-off change. Public Maven/GitHub
bytes are verified before consumer defaults and vendored SDKs are updated.
The project's full GeoDAT remains selected. Native publication is complete;
the current Flutter wrapper changes and root `v1.1.7` plugin release remain
unpublished. Earlier platform-package `1.1.7` releases already exist.

Current native release notes:

* [Android v26.10.31-protect2](xray-android-v26.10.31-protect2.md)
* [iOS v26.10.31-r2](xray-ios-v26.10.31-r2.md)
* [macOS v26.10.31-r2](xray-macos-v26.10.31-r2.md)
* [Windows v26.10.31-r2](xray-windows-v26.10.31-r2.md)
* [Published runtime qualification](core31-five-followups-validation.md)
* [Apple readiness, DNS and nine physical iPhone cases](apple-readiness-dns-validation.md)
* [Remaining release preparation and wider coverage](xray-v26.10.31-plugin-followups.md)

Earlier native releases and their dated qualification records remain unchanged.

### Registry blockers before publishing the plugin

All five local package versions remain `1.1.7`; no package version changes or
publication are authorized as part of the documentation cleanup. An official
registry check on **2026-11-03** confirms that `1.1.7` is already occupied for
[Android](https://pub.dev/api/packages/flutter_vless_android),
[macOS](https://pub.dev/api/packages/flutter_vless_macos) and
[Windows](https://pub.dev/api/packages/flutter_vless_windows); it is free for
[the root package](https://pub.dev/api/packages/flutter_vless) and
[the interface](https://pub.dev/api/packages/flutter_vless_platform_interface).
Published versions cannot be overwritten.

### Candidate build-suffix version plan

Pub accepts build suffixes such as `1.1.7+1` as distinct package versions and
includes them in version ordering: `1.1.7 < 1.1.7+1 < 1.1.7+2`.
This behavior is specific to Pub's version policy; do not assume that build
suffixes are ordered by every SemVer consumer. The Dart versioning guide
recommends ordinary version increments after 1.0.0 for simplicity, but does
not prohibit build suffixes.
[Pubspec version format](https://dart.dev/tools/pub/pubspec#version),
[Pub ordering and constraints](https://pub.dev/packages/pub_semver),
[Dart versioning guidance](https://dart.dev/tools/pub/versioning).

The following is a candidate for the owner's next release decision, not the
current package metadata:

| Package | Candidate version |
| --- | --- |
| `flutter_vless_platform_interface` | `1.1.7` |
| `flutter_vless_android` | `1.1.7+1` |
| `flutter_vless_macos` | `1.1.7+1` |
| `flutter_vless_windows` | `1.1.7+1` |
| `flutter_vless` | `1.1.7` |

The three implementation `1.1.7+1` version endpoints return HTTP 404 on
2026-11-03. Recheck availability immediately before any future publication.
When adopting this plan, set the root's three implementation constraints to
`^1.1.7+1`; a lower bound of `^1.1.7` also admits the old implementations and
does not require an existing lockfile to select the new build. Keep the
interface constraint at `^1.1.7`. Update version-contract checks and each
implementation changelog heading together with its actual package version.
The Dart build suffix does not change native Xray/Maven release tags or an
example application's Android/iOS build number; keep native metadata valid for
its own toolchain instead of copying a Pub suffix automatically.

After reviewing and validating the selected versions, the future publication
order is interface, the updated implementations, then the root package.
Rehearse package contents and clean dependency resolution first. Repository/Git
consumers of the current work need the matching implementation and interface
sources, as supplied by the example's local dependency overrides; published
implementation `1.1.7` packages do not acquire new wrapper code from a root Git
dependency.

## Local Checklist

1. Confirm the chosen Dart package versions and dependencies. Review the iOS
   and macOS CocoaPods versions and the example app's native version/build
   separately; a Pub build suffix is not a native app build-number instruction.
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
