# Xray 26.10.21 validation and remaining work

This update publishes native runtimes only. The Flutter source packages and
example remain 1.1.7; no pub.dev publication or plugin 1.1.7 GitHub release is
part of this update.

## Published runtimes

| Platform | Published artifact | SHA-256 of the main payload |
| --- | --- | --- |
| Android | [26.10.21-protect1](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-android-v26.10.21-protect1), also Maven Central | `d719bad4a15d99af8aa13f37295b9b86f7e58dd962338075151a4530d4b54810` |
| iOS | [26.10.21](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-ios-v26.10.21) | `66915e945357f1649eeeef131e31dc25ff486698a53d27b80e3a60d87e6d6d6e` |
| macOS | [26.10.21](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-macos-v26.10.21) | `afdf766ed6fc962bb0dc9e413cda21f19e812630896a337adfaec0e979618765` |

All public payloads were independently checked against their producer receipts.
The Android release contains the same signed files published to Central. The
tracked Apple SDK trees contain the exact published SDK bytes; changing only a
download URL would leave those local SDK consumers on the old runtime.

## Validation scope

- [Apple producer](https://github.com/XIIIFOX/flutter_vless/actions/runs/40216827708):
  both SDK builds, strong exports, architectures, routing capability 1, Darwin
  binding capability 1 and controlled routing/close tests passed.
- [Windows validation](https://github.com/XIIIFOX/flutter_vless/actions/runs/40215983786):
  all six jobs passed, including Windows 2022/2025 tunnel, DNS, routing,
  protection and recovery checks.
- [Shared Core tests](https://github.com/XIIIFOX/flutter_vless/actions/runs/40217789558):
  all three OS jobs passed. The experimental native DNS context patch now makes
  repeated UDP shutdown idempotent with the upstream constructor timer. This
  experimental gate is separate from the published SDK/AAR producer inputs.
- [Consumer CI](https://github.com/XIIIFOX/flutter_vless/actions/runs/40220738981):
  Dart, Android JVM/strict Central resolution, Apple build/native tests, Windows
  build/native tests and shared Core jobs passed. Android device tests exposed
  two obsolete expectations: the old version string and capability 0 for the
  public runtime. Their assertions were corrected without changing runtime code;
  the [targeted device rerun](https://github.com/XIIIFOX/flutter_vless/actions/runs/40222596849)
  passed all 41 native instrumentation tests, including both routing tests, and
  the separate-UID gate. The overall job remains **failed**: the independent
  Flutter smoke app installed but never reached its test-entry marker within
  600 seconds. Its process was alive and no crash was recorded; the saved logs
  cannot distinguish engine startup from VM-service discovery/attachment. No
  Core/version assertion was reached. Preserve verbose launch/attach output and
  PID-focused device logs in a later diagnostic run; do not call this a green
  Flutter smoke result or infer a Core defect from the timeout.
- Signed physical iPhone 13 Pro Max, iOS 27.0.1: the example used the published
  SDK and reported Core 26.10.21. Three original VLESS/REALITY JSON profiles
  produced Japanese, Polish and Swedish public IPs in Safari. Both opposite
  domain splits passed with explicit native default selection: tfox.dev through
  the server with 2ip.ru/2ip.io direct, then tfox.dev direct with 2ip through the
  server. The Polish original passed both sites; the original Japanese/Swedish
  2ip pages were still loading when sampled, so those two original-profile
  second-site checks are not claimed. Each qualified session ended with the
  real Disconnect action, native Stop acknowledgement and ordinary-internet
  recovery. On Demand, reconnect, quick access and diagnostics stayed disabled;
  the full Options matrix was not repeated for this runtime-only change.
- Local Android API 35 arm64 emulator: the app resolved the published Central
  AAR with strict verification; the running Core executable matched its exact
  packaged native bytes. All three original profiles produced the expected
  country on tfox.dev; Poland and Sweden passed both sites. Both opposite domain
  splits also passed, with the direct path retaining the host VPN's baseline IP.
  Chrome initially reported `ERR_NETWORK_CHANGED` for the Japanese proxy path;
  the second split passed after a brief stable-network wait before cold browser
  navigation. Earlier failed/timeout observations remain unqualified, including
  the Japanese original's second-site check. No runtime source change was made
  in response to that browser error. Qualified sessions ended with Disconnect,
  native Stop acknowledgement, Core/service shutdown and ordinary-IP recovery.

The Mac's active VPN and network settings were not changed. Native Go/Core/SDK
compilation and runtime qualification ran in Actions. Local work built only the
example apps against the verified published runtimes. A live macOS VPN session
remains deferred until the owner is ready.

## Changes still requiring separate qualification

1. **Certificate trust:** Go 1.27.3 and the refreshed fallback CA dependency are
   already in the producers. This is the urgent change in the
   [official upstream release](https://github.com/XTLS/Xray-core/releases/tag/v26.10.21).
2. **XDRIVE and HTTP/3:** qualify transport admission, request templates, hrefPath,
   XMUX and storage/cleanup behavior across the native adapters before claiming
   wider transport support. Apple/Windows XDRIVE admission remains restricted.
3. **Inbound finalmask filtering:** add focused preservation/admission and traffic
   cases before claiming the newly added filter semantics on every platform.
4. **GeoIP packaging:** upstream archives now ship a lite GeoIP database. The
   project retains its existing full GeoDAT files; changing database coverage
   requires an explicit choice and routing regression checks.

The eight broader DNS, IPv6, import, full-configuration and recovery requirements
in [Compatibility](../compatibility.md) retain their individual partial statuses.
The three supplied profiles do not replace a protocol/transport matrix.

## Plugin publication remains blocked separately

Android, macOS and Windows implementation package versions 1.1.7 already exist
on pub.dev with older sources and cannot be overwritten. The new interface API
is not in the currently published interface package. Follow the
[registry publication order](README.md#registry-blockers-before-publishing-the-plugin)
with free implementation versions and matching root minimum constraints before
publishing the root plugin. No package versions are changed by this update.
The unresolved CI Flutter launch/attach gate and the deferred live macOS VPN
check are additional acceptance items before declaring the plugin release ready.
