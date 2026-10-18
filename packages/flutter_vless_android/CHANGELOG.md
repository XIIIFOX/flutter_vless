## 1.1.7

* Shut down development-broker sockets before closing them so blocked accepts/reads drain. Strengthen rejection checks and add an opt-in, provenance-verified instrumentation APK for actual composed Core DNS/HTTP and bounded parent-EOF cleanup; ordinary runtime packaging is unchanged.
* Add an opt-in development socket broker requiring both VPN protection and binding of transferred descriptors to a captured physical Network. Revoke new acknowledgements on generation closure and refuse legacy/system DNS commands; ordinary VPN startup retains its existing path.
* Reserve standalone delay SOCKS/API listener ports together until Core launch; bound allocation retries, retain cleanup on interruption and add private stage/exit diagnostics without native output.
* Reserve caller API and metrics listener ports before allocating the private VPN adapter; preserve caller metrics settings and cover their listener alongside authenticated traffic. Full caller API passthrough remains separate work.
* Reserve imported port lists/ranges and environment references when allocating private listeners; preserve Unix listeners and their authentication. Add real TUN/imported-listener HTTP regression coverage.
* Add native Quick Settings Tile and Android 13+ add-tile dialog with encrypted no-backup quick profiles and independent automatic-restart authorization.
* Implement notification actions/icons/labels, capped retry policy, diagnostics controls and OS Always-on/lockdown capability checks. Preserve active capture when retries stop; reject library Stop while system-managed policy requires VPN.
* Test every option block and SystemUI tile stop/cold reconnect without a Flutter engine.

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
