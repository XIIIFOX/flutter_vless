## 1.1.6

* Updated the macOS XRay core target to upstream `v26.7.28`.
* Updated the default macOS SwiftPM/CocoaPods release tag and checksum to `xray-macos-v26.7.28`.

## 1.1.5

* Updated the macOS XRay core target to upstream `v26.7.11`.
* Updated the default macOS SwiftPM/CocoaPods release tag and checksum to `xray-macos-v26.7.11`.
* Updated Packet Tunnel support to Tun2SocksKit `5.15.0` / HEV `2.15.0` and hardened long-running tunnel health checks, shutdown handling, and diagnostics.

## 1.1.4

* Updated the macOS XRay core target to upstream `v26.6.27`.
* Updated the default macOS SwiftPM/CocoaPods release tag and checksum to `xray-macos-v26.6.27`.
* Made local SwiftPM builds prefer the checked-in `XRay.xcframework` artifact while keeping the hosted release fallback for published consumers.

## 1.1.3

* Updated the macOS XRay core target to upstream `v26.6.22`.
* Updated the default macOS SwiftPM/CocoaPods release tag to `xray-macos-v26.6.22`.
* Fixed macOS Packet Tunnel VPN routing for VLESS + XHTTP + TLS configs by using the validated local TUN gateway model (`127.0.0.1` remote label, `198.18.0.1/24` local address, default gateway `198.18.0.1`).
* Published explicit Packet Tunnel DNS with `matchDomains = [""]` and kept DNS host-route exclusions disabled for the working macOS route model.
* Added provider/app diagnostics for raw `utun` TCP reachability, interface-bound probes, HEV fd selection, Xray/SOCKS health checks, and expanded shared provider logs.
* Fixed macOS SwiftPM builds by explicitly importing the `CXRay` shim before using `XRayLoggerProtocol`.
* Restored Xcode 15.x compatibility for the bundled macOS example project by replacing newer synchronized project groups with legacy Xcode project groups.
* Hardened `prepare_apple_swiftpm.sh` for copied repository checkouts by resolving the local macOS Swift package through the repository path instead of depending on the generated `Flutter/ephemeral/Packages/.packages/flutter_vless_macos` link, normalizing generated SwiftPM paths, and clearing stale DerivedData package caches.
* Hardened `setup_macos_vpn` so newly configured apps resolve the real macOS Swift package directory from `package_config.json` and repair stale generated `.packages/flutter_vless_macos` references.
* Removed generated example SwiftPM `Package.resolved` files so older Xcode versions regenerate a compatible pins file instead of failing on newer `PinsStorage` formats.
* Fixed macOS CocoaPods fallback builds by exporting the `CXRay` Clang shim module to both the plugin pod target and the host app target.
* Added `setup_macos_vpn --prepare-only` for macOS apps that need only generated SwiftPM metadata and deployment-target repair before building proxy-only mode.

## 1.1.2

* Fixed Packet Tunnel setup for hosted Pub packages whose generated SwiftPM symlink includes the package version.
* Patched existing Xcode local Swift package references when they still point at a stale unversioned package path.

## 1.1.1

* Updated the macOS XRay core target to upstream `v26.6.1`.
* Updated the default macOS SwiftPM/CocoaPods release tag to `xray-macos-v26.6.1`.
* Kept the static-library `XRay.xcframework` packaging path for Apple Silicon and Intel macOS targets.

## 1.1.0

* Added the macOS implementation package for `flutter_vless`.
* Added support for Xray-backed proxy-only and Packet Tunnel flows.
* Added shared platform-channel integration through `flutter_vless_platform_interface`.
