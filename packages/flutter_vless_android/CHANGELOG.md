## 1.1.7

* Add a build-only CI preview that rebuilds all four ordinary Core ABIs and verifies their exact AAR bytes, source provenance, unchanged HEV/geodata and 16 KiB alignment. Qualify the development example APK, its exact three-architecture payloads and all three original full JSON profiles with real Android browser traffic, domain split routing in both directions and Stop recovery. Keep published runtime pins unchanged; physical HTTP/3 acceptance remains separate.

* Include XHTTP HTTP/3 dial cleanup in source-built Android runtimes and previews, with patch-input and copied-source checks. Published runtime artifacts remain unchanged.

* Preserve logical endpoint names behind caller proxy chains in explicit proxy DNS mode, including effective XHTTP download chains. Keep physical endpoint bootstrap and WireGuard peer lookup; add native regressions and an exact-output Core traffic gate.

* Add shared inactive TLS/Reality and XHTTP download regressions through native preparation and runtime normalization, preserving the existing Android admission behavior.

* Include Classic DNS UDP lifecycle cleanup in locally built Core artifacts, retaining caller DNS data and protecting late requests during shutdown.

* Give periodic watchdog probes one session-owned deadline and cancel their sockets on Stop. Recheck session and Core ownership between probes and before publishing a connected state.

* Return a request-owned report after final Core preflight and candidate admission. Collect actual typed preparation edits and closed failure stages without exposing configuration data.

* Add preparation regressions for preserved, unused XHTTP grandchild socket chains.

* Bind relative Realm/XDNS TLS certificate and key files to the explicit certificate assets directory without traversing unrelated mask data.

* Bind queued physical-network callbacks to their VPN session generation, preventing an earlier session's event from restarting its replacement. Cover availability, loss, current recovery and stopped-session behavior through the registered service callback.

* Preserve unknown profile data instead of recursively editing every object. Scope stream/TLS cleanup and protected-feature checks to Core schema fields, retaining XHTTP precedence and real UDP XICMP/local-QUIC DNS refusals. Add shared preparation and controlled device regressions.

* Match Core environment alias casing and whitespace for ports and addresses, and pass the captured environment into private port reservation. Cover the shared corpus through the actual runtime builder with fake availability callbacks.

* Preserve root routing-rule attribute dictionaries during normalization and protected-feature checks, including literal values that resemble DNS or transport settings.

* Preserve the remaining typed transport header maps, including XHTTP `extra`/download streams and TCP HTTP header lists, through runtime normalization and protected-feature admission. Keep inherited XHTTP download socket options unchanged in proxy-DNS mode and validate its active transport before bootstrap.

* Treat root DNS hosts and inbound/outbound WebSocket headers as caller data during normalization and protected-feature checks. Preserve literal values while retaining rejection of actual unsupported XICMP and local QUIC DNS paths.

* Preserve caller DNS hosts keys and values through runtime normalization, including names matching legacy stream settings. Retain TLS cleanup and add shared preparation and TUN DNS controls.

* Preserve compatible FakeDNS engines and caller DNS in VPN preparation, restore domains only on the managed input, and move private DNS outside the default fake pool. Reject native-address pool overlaps before bootstrap; add shared and device regression coverage.
* Select traffic counters from the actual session inbound instead of a fixed outbound name. Preserve disabled caller policy, handle zero and unavailable directions independently, and clear speed baselines across gaps/restarts. Add consumer and controlled TUN regressions.
* Consume per-session VPN routing selections with final config/metadata checks before replacement and through recovery. Add an instrumentation-only routing preview; published runtime pins remain unchanged.
* Add per-start/profile-delay `certificateAssetsDirectory`. Freeze relative Core TLS certificate/key paths before preflight and recovery, keeping caller-owned files, inline material and certificate reload settings intact.
* Add bounded HTTP fixture connection/relay stages and response-length diagnostics for protected DNS acceptance. Preserve failures without retries or response changes; cover failure paths with fake sockets.
* Extend the shared protocol corpus with penetrating XHTTP download settings. Verify parent/child socket options remain independent in JSON until Core applies its runtime inheritance, preserving caller DNS in config mode.
* Cover missing, null and empty localhost DNS server tags in the shared preparation corpus, retaining the caller's DNS and default protected resolution path.
* Cover named DoH with exact `full:` hosts in the shared full-profile corpus, preserving caller hosts, URLs, tags and query strategy through native DNS preparation.
* Allocate private service tags outside known nonempty balancer/observatory prefixes without rewriting selectors. Cover shared allocation cases and a round-robin TUN traffic regression; retain the empty-wildcard boundary explicitly.
* Follow Core's legacy `servers`/`vnext` fallback when a flat address is null, retaining strict malformed-value rejection and the original settings. Cover Shadowsocks 2022 in the shared preparation corpus.
* Cover the shared direct-only profiles in preparation and TUN runtime regressions: source default order, HTTP, domain blocking and caller TCP DNS through virtual UDP/TCP DNS.
* Await the same Core process's local listener within a shared five-second startup/authentication/packet deadline. Retry only a pre-handshake native ECONNREFUSED; keep periodic checks, strict recovery and credential/permission failures immediate. Record bounded numeric stage/errno diagnostics.
* Capture IPv6 in the VPN and send private AAAA queries through Core without overriding caller query strategy. Preserve the existing protected socket/DNS paths; add a controlled IPv6 TCP/UDP TUN regression through an IPv4 proxy.
* Apply `geoAssetsDirectory` during preflight, startup, recovery and standalone delay. Retain it in saved profiles, override both data-root aliases without copying bundled files into explicit roots, and add a custom GeoSite TUN traffic regression.
* Resolve imported `listen` environment references once before port and authentication selection. Keep Unix listeners out of TCP allocation, preserve source JSON and test the shared address corpus.
* Preserve caller API/services, stats and policy without enabling disabled counters or polling an imported API. Keep private statistics only for profiles without an API; accept null download socket options consistently with Core.
* Recognize MASQUE in explicit proxy DNS; follow Core's active XHTTP/alias/null branches and distinguish ignored primary stream addresses from independent download endpoints. Add shared protocol preparation fixtures.
* Connect the default config DNS policy to Core's caller DNS through the private VPN adapter. Preserve root hosts/server/tag policy and protected physical-Network localhost resolution; retain explicit proxy overrides and separate proxy-only behavior.
* Bound statistics collection while reading, rather than waiting for EOF before applying its timeout. Cap captured bytes, reject unsuccessful commands and terminate/reap owned children on timeout or cancellation.
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
