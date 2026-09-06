## 1.1.6 (Unreleased)

### General

* Added `getProviderDebugSnapshot()` across Android, iOS, macOS, and Windows,
  with bounded native diagnostics available after stop or failure.

### iOS

* Made iOS VPN traffic protection mandatory using the saved Network
  Extension routing and on-demand policy. Tunnels retain their routes and virtual
  DNS while retrying transports or restarting HEV/Xray workers; rejected runtime
  configurations keep forwarding blocked. On-demand requests a restart after
  termination of the entire provider. Recovery
  reports `CONNECTING`; iOS can defer restart after a process crash.
* Serialized start, stop, and permission operations. Explicit stop disables
  automatic recovery before stopping the tunnel; proxy-only startup waits for
  tunnel shutdown before reusing its ports. Provider replies have a deadline.
* Avoided signalling HEV again after its worker exits, which could otherwise hang
  shutdown, and required provider readiness before publishing `CONNECTED`.
* Domain rules with Xray `direct` remain supported. Non-empty system
  `bypassSubnets` are rejected before changing the current session. Starting from
  the app updates legacy VPN profiles; the provider rejects unprotected profiles.
* Routed tunnel DNS through the selected proxy without a physical DNS fallback,
  and captured IPv6 traffic for blocking when IPv6 forwarding is unavailable.
* Replaced raw native Xray diagnostics with bounded, structured messages that
  omit config credentials and imported log destinations. Kept HEV error logging
  bounded while preserving open append handles during rotation.
* Added dynamic `geoip.dat` and `geosite.dat` loading through
  `geoAssetsDirectory`. The Go bridge validates the files and supports restoring
  the default asset lookup; VPN mode uses an extension-readable App Group path.
* Published runtime revision `xray-ios-v26.7.28-r3` with Xray-core `v26.7.28`,
  the asset and private logging bridges, and updated SwiftPM/CocoaPods checksums.
* Capped Go HTTP/2 upload scratch buffers at 128 KiB per stream to reduce memory
  pressure during concurrent XHTTP uploads. Builds require Go 1.27 or newer,
  patch an isolated `GOROOT`, and accept `H2BUF_CAP_KB` values from 16 to 512 KiB.
  The build fails if the expected standard-library patch anchor changes.
* Includes [Myo Thura](https://github.com/myothura)'s XHTTP upload-buffer fix in
  [PR #24](https://github.com/XIIIFOX/flutter_vless/pull/24), resolving
  [#23](https://github.com/XIIIFOX/flutter_vless/issues/23).

### Android

* Kept the host application's traffic inside the VPN instead of excluding its
  entire UID. Only runtime transport and bootstrap sockets bypass the VPN through
  the native socket protection bridge; configured blocked applications still bypass it.
* Made required socket protection failures reject runtime startup or socket use.
* Published `dev.tfox.fluttervless:xray-android:26.7.28-protect1` with Xray-core
  `v26.7.28` for `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`.
* Added bounded cross-process Xray/tun2socks diagnostics.

### macOS

* Updated Xray-core to `v26.7.28` and the SwiftPM/CocoaPods runtime tag and
  checksum to `xray-macos-v26.7.28`.
* Exposed bounded Packet Tunnel and proxy-only Xray diagnostics through the
  shared Dart API.

### Windows

* Preserved domain routing, DNS settings, and outbound server ports when preparing
  Xray configurations. SOCKS listener detection now uses JSON structure and is
  independent of property order; occupied ports are replaced only on inbounds.
* Used Xray's dedicated API listener without inserting duplicate routing blocks.
* Joined failed service workers during stop and reflected service failure in
  the Windows running status. Removed raw config fragments from endpoint errors.

* Exposed thread-safe, bounded Xray/tun2socks diagnostics through the shared
  Dart API.
* Fixed the native registration header path for the federated Windows package.

## 1.1.5

* Updated bundled and packaged Xray runtimes to upstream Xray-core `v26.7.11` for Android, iOS, and macOS.
* Rebuilt the Android runtime AAR as `dev.tfox.fluttervless:xray-android:26.7.11` with Xray-core `v26.7.11` for device and emulator ABIs.
* Updated the default hosted Apple runtime release tags and checksums to `xray-ios-v26.7.11` and `xray-macos-v26.7.11`.
* Updated the vendored Go dependency pin, native runtime build scripts, release notes, package metadata, docs, and smoke tests for the `1.1.5` release train.
* Updated iOS and macOS Packet Tunnel support to Tun2SocksKit `5.15.0` / HEV `2.15.0`.
* Hardened long-running VPN sessions: the Packet Tunnel now detects unexpected HEV exits and repeated SOCKS/HTTP health-check failures, records the cause, and terminates the stale system VPN state instead of leaving a false connected status.
* Added periodic and post-wake/network-change tunnel health checks, orderly HEV shutdown handling, bounded App Group diagnostics, and error-level log rotation to avoid unbounded extension I/O and memory growth.
* Added the iOS/macOS example **VPN Diagnostics** action, including persisted provider/HEV log tails after the extension has stopped.
* Fixed first-run iOS builds from Xcode by using CocoaPods for the main Flutter plugin when Flutter's generated Swift package is pinned to iOS 13 despite the example's iOS 15 deployment target.
* Fixed Android VPN app routing: every configured blocked app is now added to `VpnService.Builder` as a disallowed application, so it correctly bypasses the Xray VPN tunnel. Thanks by [AbdulManan](https://github.com/AbdulManan-official) PR #18
* Removed the legacy `flutter_vless_android_emulator` package because emulator ABIs are included in the main Android Maven runtime AAR.

## 1.1.4

* Updated bundled and packaged Xray runtimes to upstream Xray-core `v26.6.27` for Android, iOS, and macOS.
* Rebuilt the Android runtime AAR as `dev.tfox.fluttervless:xray-android:26.6.27.1` with Xray-core `v26.6.27` and refreshed the legacy emulator `x86` / `x86_64` `libxray.so` copies.
* Updated the default hosted Apple runtime release tags and checksums to `xray-ios-v26.6.27` and `xray-macos-v26.6.27`.
* Made the local iOS and macOS SwiftPM manifests prefer checked-in `XRay.xcframework` artifacts during repository builds while keeping the hosted release fallback for published consumers.
* Refreshed release scripts, release notes, docs, package metadata, and smoke tests for the `1.1.4` release train.

## 1.1.3

* Update Android native library packaging instructions
* Updated bundled and packaged Xray runtimes to upstream Xray-core `v26.6.22` for Android, iOS, and macOS.
* Fixed macOS VPN mode for VLESS + XHTTP + TLS Packet Tunnel configs by matching the validated Apple route model: `tunnelRemoteAddress = 127.0.0.1`, `198.18.0.1/24` local TUN address, default route gateway `198.18.0.1`, explicit Packet Tunnel DNS, and no DNS host-route exclusions.
* Added macOS route/DNS diagnostics that distinguish a healthy Xray/SOCKS path from a broken app-side `utun` route, including raw TCP probes bound to the selected interface.
* Documented the working macOS Packet Tunnel invariants and golden log lines in `doc/macos_packet_tunnel_architecture.md` so future route/DNS changes do not regress the VLESS XHTTP path.
* Added subscription import coverage and documentation for WireGuard, Hysteria2 / `hy2`, HTTPUpgrade, and modern raw transport mappings.
* Fixed macOS SwiftPM builds by updating the macOS package dependency to the release that explicitly imports the `CXRay` shim.
* Fixed repeated macOS Packet Tunnel setup so existing Xcode and generated SwiftPM package references update their paths to versioned hosted package symlinks.
* Restored Xcode 15.x compatibility for the bundled iOS and macOS example projects by replacing newer synchronized project groups with legacy Xcode project groups.
* Hardened the macOS example SwiftPM preparation flow for copied repository checkouts by resolving the local macOS Swift package through the repository path instead of depending on the generated `Flutter/ephemeral/Packages/.packages/flutter_vless_macos` link, normalizing generated package paths, and clearing stale DerivedData package caches.
* Hardened `setup_macos_vpn` so newly configured apps resolve the real macOS Swift package directory from `package_config.json` and repair stale generated `.packages/flutter_vless_macos` references.
* Removed generated example SwiftPM `Package.resolved` files so older Xcode versions regenerate a compatible pins file instead of failing on newer `PinsStorage` formats.
* Fixed macOS CocoaPods fallback builds by exporting the `CXRay` Clang shim module to both the plugin pod target and the host app target.
* Added `setup_macos_vpn --prepare-only` for macOS apps that need only generated SwiftPM metadata and deployment-target repair before building proxy-only mode.

## 1.1.2

* Fixed macOS Packet Tunnel setup for hosted Pub packages whose generated SwiftPM symlink includes the package version.
* Added an iOS SwiftPM `FlutterFramework` fallback so direct local package references can resolve the tunnel support product.
* Documented the iOS 15.0 deployment target requirement and generated SwiftPM package path guidance for manual Xcode integration.
* Clarified that Android emulator binaries are included in the main Maven runtime AAR.
* Updated Android and macOS platform package constraints to the `1.1.2` release train.

## 1.1.1

* Updated the iOS XRay core target to upstream `v26.6.1`.
* Updated the default iOS SwiftPM/CocoaPods release tag to `xray-ios-v26.6.1`.
* Updated Android and macOS platform package constraints to the `1.1.1` release train.

## 1.1.0

**Major Release: Desktop Support (macOS & Windows)**

* **macOS Implementation**:
  * Added full support for `ProxyOnly` mode via macOS system proxy configuration (`networksetup`), intercepting TCP traffic across all network interfaces.
  * Implemented dynamic port allocation and robust XRay config injection for local HTTP and SOCKS inbounds.
  * Added `XRayQueryStats` C-bindings via an internal gRPC interceptor to support real-time upload/download speed monitoring directly from the XRay core.
  * Re-engineered the `XRay.xcframework` build pipeline to support dynamic linking for macOS native targets (Apple Silicon & Intel).
  * Implemented robust lifecycle management to ensure macOS system proxy settings are cleanly restored upon app termination, preventing orphan proxy configurations.
  * Added extensive in-code documentation explaining the limitations of macOS System Proxy (lack of UDP support) and how it affects QUIC/HTTP3 traffic fallback mechanisms in modern browsers.
  * Documented the macOS Packet Tunnel routing model, DNS invariants, Xray config
  normalization rules, provider health checks, golden logs, and regression
  checklist in `doc/macos_packet_tunnel_architecture.md`.

* **Windows Implementation**:
  * Added full support for `ProxyOnly` mode via Windows Registry modification to configure the system proxy.
  * Built robust background process management to start, monitor, and cleanly terminate the `XRay.exe` core.
  * Implemented real-time traffic statistics polling using XRay's gRPC Stats API.
  * Added automatic Windows system proxy cleanup on application exit to prevent network disconnection issues.

* **General / Architecture**:
  * Stabilized the federated plugin architecture (`flutter_vless_platform_interface`), ensuring seamless API consistency across Android, iOS, macOS, and Windows.
  * Fixed an issue where injecting XRay API routing rules without a corresponding `api` outbound would break the XRay internal dispatcher and cause connection drops.
  * Ensured `sniffing` is strictly enabled for injected HTTP/SOCKS proxies to support domain-based routing rules correctly across all platforms.
  * Updated dependencies and improved general codebase documentation for edge cases.
  * Added typed Xray configuration models and schema validation for generated and raw configs.
  * Hardened `startVless` and server-delay config validation beyond basic JSON parsing.
  * Shared the Dart MethodChannel/EventChannel implementation across platform packages.
  * Added robust `VlessStatus` parsing with typed connection states and value semantics.
  * Cleaned publish-time pubspec metadata and moved local path overrides out of package pubspecs.

## 1.0.5

* Fixed Android VPN startup with configs that already include custom SOCKS/HTTP inbounds.
* Added automatic port conflict handling for local SOCKS, HTTP, and Xray API inbounds.
* Added support for flat VLESS outbound configs by normalizing them to Xray `vnext/users` format.
* Fixed server IP exclusion parsing for flat VLESS configs to avoid VPN routing loops.
* Sanitized Android Xray log paths so desktop/macOS paths do not break startup.
* Improved Xray startup validation to avoid reporting connected state when the core exits immediately.
* Added a fallback notification icon for Android foreground service notifications.
* Updated the bundled XRay core version.
* Added Swift Package Manager support for the iOS implementation.
* Added automatic download and checksum validation for the prebuilt `XRay.xcframework`.
* Added a separate `flutter-vless-tunnel-support` SwiftPM product for iOS Packet Tunnel extensions.
* Reworked the iOS plugin source layout for SwiftPM and CocoaPods compatibility.
* Updated the iOS CocoaPods spec with proper package metadata, iOS 15 minimum target, and XRay release handling.
* Updated the example iOS project to use local Swift packages instead of manually embedded XRay and Tun2Socks frameworks.
* Updated iOS setup documentation with SwiftPM, Packet Tunnel, App Groups, and CocoaPods fallback instructions.
* Updated README examples to pass the base app bundle identifier; the plugin now appends `.XrayTunnel` internally.
* Excluded local `ios/XRay.xcframework` artifacts from the published package.
* Documented Xray VLESS Encryption handling for `mlkem768x25519plus...` values and why they cannot be inferred from bare `vless://` links.
* Added raw Xray JSON/JSON-array import support so Happ-style configs preserve server-provisioned `users[].encryption` values 1:1.
* Updated the example importer and real-device smoke test to use the universal parser for both share URLs and raw Xray JSON.
* Added Dart coverage for VLESS XHTTP/none, VLESS Encryption passthrough, raw Xray JSON import, SS/SOCKS compatibility formats, and iOS/Android MethodChannel arguments.
* Extracted iOS Packet Tunnel Xray JSON preparation into a Swift testable helper with coverage for log/DNS cleanup, XHTTP UDP/443 routing, proxy server parsing, and VLESS Encryption preservation.
* Added `FlutterVless.parseMany` subscription import support for base64 share-link lists, Clash YAML, and sing-box JSON for supported Xray protocols.
* Added Android native Kotlin unit tests for runtime Xray config injection, local port conflict handling, flat VLESS normalization, and log path sanitization.
* Added CI coverage for Flutter tests, Android native unit tests, Swift PacketTunnel helper tests, and an iOS no-codesign example build.
* Added a physical-device VPN matrix script/documentation for TCP/Reality, XHTTP/Reality, XHTTP/none with VLESS Encryption, Shadowsocks, Trojan, and VMess.
* Fixed universal parsing of single VLESS Reality share links so example clipboard import does not route them through subscription heuristics.
* Fixed Android server-delay probing to reuse the same runtime Xray config normalization as normal startup.
* Added iOS proxy-only startup through in-app Xray without starting the Packet Tunnel, and skipped VPN permission in the example when proxy-only mode is selected.
* Forced iOS CocoaPods generated targets to deployment target 15.0 and added an example reset script so integration tests cannot leave the app launching Flutter's test listener.

## 1.0.4

* feat: XRay version up

## 1.0.3

* fix: no such module 'XRay' 

* feat: code formatted

## 1.0.2

*   **Refactor**: Migrated to a Federated Plugin architecture.
    *   Split into `flutter_vless` (app-facing), `flutter_vless_platform_interface` (common), and `flutter_vless_android` (Android implementation).
    *   This structure improves maintainability.

*   **Android**:
    *   **Migration to Kotlin**: Complete rewrite of Android native code from Java to Kotlin.
    *   **16KB Page Size**: Added support for Android devices with 16KB page sizes (API 35+).

*   **Docs**: Added comprehensive documentation to Android native code.

## 1.0.1

* feat: upgrade xray version and update documentation

* refactor: modify V2rayCoreManager to use CoreController and improve lifecycle management

* fix: enhance error handling in V2rayProxyOnlyService and V2rayVPNService

* style: adjust spacing in main.dart for better UI layout

* docs: improve descriptions and comments in V2ray services for clarity

* chore: update pubspec.yaml with additional tags and improved description

## 1.0.0

* init
