## 1.1.7+1

Unpublished implementation update for the main plugin 1.1.7 release train.
The existing pub.dev package numbered 1.1.7 remains unchanged.

* Use the published checksum-pinned Maven runtime `26.10.31-protect2` for all four device/emulator ABIs with 16 KiB alignment, protected sockets, native routing and managed-service cleanup.
* Close Classic DNS/XHTTP/XDRIVE/GeoDAT resources with the owning runtime, including rejected XHTTP `h2Params` listener cleanup.
* Add native Quick Tile, Android 13+ add-tile dialog, notification customization, validated options/capabilities, independent quick-profile authorization, bounded reconnect and OS Always-on/lockdown handling.
* Retain immutable pending actions across unlock, permission and startup; cancel obsolete starts/network callbacks after Stop, replacement or successful options reconfiguration.
* Preserve complete caller profiles, imported listeners/API/services/statistics, DNS dictionaries, transport headers, effective XHTTP chains and environment-backed port/address values. Allocate collision-safe authenticated adapters and private statistics only when appropriate.
* Resolve system A/AAAA queries through caller Core DNS, retain explicit proxy-DNS override, capture IPv6 payload and prepare compatible FakeDNS without changing caller pools/query strategy.
* Add per-session VPN routing, typed preparation reports and separate data/certificate asset roots through preflight, recovery and delay. Preserve caller datasets and validate scheduled GeoDAT targets and XDRIVE capabilities.
* Bound startup, delay, watchdog and statistics I/O to owned deadlines, preserving strict authentication, packet readiness, cancellation and child/socket cleanup.
* Add shared preparation/native/TUN regressions and live emulator coverage for full profiles, both routing directions, Quick Tile and Stop recovery. Physical HTTP/3, IPv6-only/NAT64 and broader server coverage remain separate acceptance work.

## 1.1.7

* Update the runtime to `dev.tfox.fluttervless:xray-android:26.10.17-protect1`, based on Xray-core `v26.10.17` (upstream pre-release).
* Rebuild armeabi-v7a, arm64-v8a, x86 and x86_64 binaries with 16 KiB page alignment.
* Adapt the socket-protection overlay to upstream dialer changes, preserving protected DNS, fallback sockets and failure propagation.

## 1.1.6

* In protected proxy DNS mode, return AAAA NODATA to match the VPN service's IPv6 blocking. Preserve proxy transport endpoint resolution and IPv4 DNS relay.

* Chain protected DNS with `streamSettings.sockopt.dialerProxy`, replacing the `proxySettings` field removed in Xray-core v26.9.9.

* Show the VPN Diagnostics button in the Android example, including release builds.

* Check readiness through an owned local packet path independent of public-site routing, avoid FakeDNS probe collisions, and restore opening the app from its VPN notification.

* Authenticate service-owned local SOCKS, avoid an unsolicited HTTP listener, and measure delay in the owning process.
* Preserve TUN on worker failures; coordinate bounded recovery and encrypted authorized-profile restoration.
* Add explicit proxy DNS policy, safe diagnostic events and native artifact verification examples.

* Updated the Android runtime dependency to `dev.tfox.fluttervless:xray-android:26.9.9-protect1`.
* Rebuilt Android `libxray.so` binaries for `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64` against Xray-core `v26.9.9`.
* Added bounded, cross-process Xray/tun2socks diagnostics through
  `getProviderDebugSnapshot`.

* Kept host-application traffic inside the VPN and protected only runtime
  transport/bootstrap sockets through the native descriptor bridge. Explicitly
  blocked applications retain their bypass behavior.
* Required socket protection failures reject runtime startup or socket use.

## 1.1.5

* Updated the Android runtime dependency to `dev.tfox.fluttervless:xray-android:26.7.11`.
* Rebuilt Android `libxray.so` binaries for `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64` against Xray-core `v26.7.11`.
* Fixed Android VPN app routing: all configured blocked apps are now applied to `VpnService.Builder` as disallowed applications and bypass the Xray VPN tunnel.

## 1.1.4

* Updated the Android runtime dependency to `dev.tfox.fluttervless:xray-android:26.6.27.1`.
* Rebuilt Android `libxray.so` binaries for `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64` against Xray-core `v26.6.27`.

## 1.1.3

* Updated the Android runtime dependency to `dev.tfox.fluttervless:xray-android:26.6.22`.
* Rebuilt Android `libxray.so` binaries for `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64` against Xray-core `v26.6.22`.

## 1.1.2

* Clarified that Android device and emulator runtime binaries are delivered through the main Maven `xray-android` AAR.
* Kept the Android runtime dependency on `dev.tfox.fluttervless:xray-android:26.6.1.1`.

## 1.1.1

* Updated the Android device runtime `libxray.so` binaries to Xray-core `v26.6.1`.
* Kept Android 15+ 16KB page-size linker alignment for the rebuilt ARM binaries.
* Moved Android runtime binaries and geodata into the Maven `dev.tfox.fluttervless:xray-android:26.6.1.1` AAR dependency.
* Included device and emulator ABIs (`armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`) in the main Maven runtime AAR.
* Removed raw device `jniLibs` and geodata files from the Pub.dev wrapper package; the wrapper now resolves the runtime from Maven Central.

## 1.1.0

* Replaced Android Dart boilerplate with the shared `VlessMethodChannelAdapter`.
* Removed template `getPlatformVersion` scaffold files.
* Moved `flutter_lints` to `dev_dependencies`.
* Removed publish-time dependency overrides from `pubspec.yaml`.

## 1.0.2

* XRay version up

## 1.0.1

*   XRay version up

## 1.0.0

*   Initial release of the Android implementation for `flutter_vless`.
*   Supports VLESS/VMESS protocols using Xray core.
*   Implements `VlessPlatform` interface.
