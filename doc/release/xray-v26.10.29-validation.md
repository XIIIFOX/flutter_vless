# Xray 26.10.29 validation and remaining work

This update publishes native runtimes only. Flutter source packages and the
example remain 1.1.7. No pub.dev package or plugin 1.1.7 GitHub release is
published. The producer and consumer CI checks below pass against this runtime;
live mobile acceptance is recorded separately. Earlier-version results are not
carried forward as proof for this runtime.

## Published artifacts

All three native assets use producer revision
`c381b13dd694ba415ef7d55302abdd0e43b86e2b`, Xray-core
[v26.10.29](https://github.com/XTLS/Xray-core/releases/tag/v26.10.29), commit
`0afec66085a85191e9dd2a4a6646c7c9a94688d1`. The pinned module is
`v1.260327.1-0.20261029083850-0afec66085a8`, sum
`h1:EZzaOZYkWkLLEdwYKzCOck7s15y1sspw/b98ChzCA0I=`.

| Platform | Public native asset | Payload SHA-256 |
| --- | --- | --- |
| Android | [26.10.29-protect1](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-android-v26.10.29-protect1); Maven `dev.tfox.fluttervless:xray-android:26.10.29-protect1` | `ac498513218e640c6524e59eb5bba5431ff51c396f114931ada1837f79561ecb` |
| iOS | [26.10.29](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-ios-v26.10.29) | `c6b2070b24e7f150fea5460fd2c42beef3dda92ad94439069e6b933e2cfeee55` |
| macOS | [26.10.29](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-macos-v26.10.29) | `9c451bd1e8db3ece6afbcb03ffdd4326035ea339a253b388ee83e2691cd5a1b1` |

The Android [candidate build](https://github.com/XIIIFOX/flutter_vless/actions/runs/40956105136)
compiled four ABIs with Go 1.27.3, protected sockets, routing capability 1 and
16 KiB ELF LOAD alignment. Its [same Central deployment](https://github.com/XIIIFOX/flutter_vless/actions/runs/40957965701)
reached PUBLISHED without a second build/upload. All eight public signed payload
bodies return HTTP 200 from Maven Central and independently match the candidate
bytes/hashes. The GitHub AAR and all eight asset digests match that same candidate.

The [canonical Apple build](https://github.com/XIIIFOX/flutter_vless/actions/runs/40956099275)
passes both jobs, twelve controlled privacy/DNS/routing modes per platform,
preflight, routing and mandatory Darwin-interface capability gates, and clean
probe shutdown. Independent static audits verify every framework member, all
five architecture observations and thirty strong-export observations. Both
public archive bodies match their source-bound producer receipts. Local SDK
trees are replaced from those public archives; previous trees are retained.

The selected full project GeoDAT and existing HEV bytes remain unchanged.
Apple retains the 128 KiB HTTP/2 upload scratch cap. The standalone arm64 macOS
example tool also matches the official archive and all four upstream digests;
it was inspected as data without execution on the owner's Mac.

## Source compatibility and regression checks

The Darwin interface-binding patch is rebased onto upstream's corrected TCP
keepalive idle/interval values. A regression first reproduces the obsolete
anchor, then passes with mandatory interface binding and the upstream fix intact.
Six exact-source file-only ordinary/routing/full-DNS compositions, with and
without Android protection, pass without changing the pristine source.

The initial Android/Windows producer runs stop before compilation because the
mobile module retained Protobuf 1.36.12 while the new Core selects 1.36.11.
The Apple producer is cancelled before publication to keep the dependency graph
consistent. Aligning the mobile pin to 1.36.11 fixes exact tagged readonly graph
checks on Windows, Linux and Android; strict readonly builders remain unchanged.
A hash-bound upstream module fixture and mismatch regression guard this case.
The successful producer runs above use the corrected revision.

There are 214 local producer/supervisor cases and 86 import/adapter cases.
The latter use the actual example importer and four Dart adapters with mocked
native channels. They preserve all four fresh owner-supplied links, including
REALITY identity, the third profile's nonempty short ID, spiderX, Unicode names,
start/delay serialization and both domain split directions. User profiles stay
in private ignored local files and are never uploaded to Actions or Git.

The [scoped Core CI](https://github.com/XIIIFOX/flutter_vless/actions/runs/40956588683)
passes on Linux, macOS and Windows with 81 selected checks per OS, no FAIL/SKIP,
exact Core/module pins, immutable source/copy checks and drained child cleanup.
Its Linux forwarder and CLI evidence do not establish a Linux Flutter plugin.

The [Windows runtime CI](https://github.com/XIIIFOX/flutter_vless/actions/runs/40956111345)
passes all six jobs on Server 2022/2025. Each system passes 21 proxy, 21 Unicode
portable and 189 VPN rows, actual WFP/Wintun routing, DNS/FakeDNS, recovery and
numeric IPv6 qualification. All four numeric IPv6 proofs clean up services,
filters, routes, adapters and helpers. Full proxy/VPN corpus uses the unpublished
source-built routing companion; official Core separately passes numeric IPv6
TCP and scoped denial checks. The owner endpoints are not sent to CI.

The consumer-version preflight also detects a stale explicit Gradle whitelist,
both actual Core smoke expectations and the Windows example guide. Four
file-only failures are reproduced before correction; eight train-consistency
cases and twelve existing gate cases pass after the fix. Unit-test mock version
strings are fixtures and are not rewritten as live-runtime requirements.

The [combined Android consumer corridor](https://github.com/XIIIFOX/flutter_vless/actions/runs/40961754608)
at `822dde0` passes native → Flutter → separate UID in order: 41 native tests
without skips, three Flutter tests in one 112.109-second attempt with actual
Core 26.10.29, and the OS denial/UID gate. Child, pipe, app and emulator cleanup
pass. UID denial occurs before connection, not inside the native peer-credential
branch. The superseded 814e02e Android run is retained as cancelled and does not
qualify a runtime pass.

The [released Apple SDK checks](https://github.com/XIIIFOX/flutter_vless/actions/runs/40960590589)
at `814e02e` pass iOS/macOS FakeDNS and DNS data maps against the exact published
26.10.29 ZIP pins. The shipped macOS HEV bridge also passes bidirectional 8 MiB
IPv4 traffic and IPv6 TCP/UDP packet probes with clean shutdown. The compiled
Apple consumers, SDK manifests and producer sources are unchanged by 822dde0's
Android guard and uncompiled test/documentation corrections.

The [Apple and Windows consumer checks](https://github.com/XIIIFOX/flutter_vless/actions/runs/40960596669)
at `814e02e` pass all five active jobs, including Windows example/native-control
builds, Apple example builds and twelve SDK preview modes per Apple platform.
Each of three timing jobs completes eighteen cases. iOS runs 252 XCTest cases
and macOS runs 266, with zero failures and one intentional opt-in skip per
platform. Recording WFP controls and Darwin fake-OS/typecheck checks retain
their scope: they do not replace the real Windows runtime corridor or a live
owner-Mac Network Extension session. The iOS HEV build/link checks also do not
replace physical-device packet traffic.

## Consumer and device acceptance

The published consumer URL/checksum and Maven strict-verification pins are
committed before device starts. The new example products bind their compiled
source closures and native payloads to the verified public artifacts.

- Android emulator: **PASS** all four fresh URI profiles imported through the
  example UI, both real browser pages per profile, and both native domain-split
  directions. Each of the six sessions has one Connect, explicit Stop
  acknowledgement, Core/service/VPN OFF and fresh ordinary-network recovery.
- Physical iPhone: **PARTIAL** all four profiles have strict ON-state browser
  proofs with the fresh signed example and published iOS SDK. The proxy-default
  split with 2ip direct passes. A direct-default proxy exception for tfox also
  passes, but the complete direct-default two-site scenario remains unqualified:
  2ip displays Loading in the recorded frames, whether selected proxy or direct.
- Consumer Actions: **PASS** combined Android corridor, released Apple SDK
  checks and Apple/Windows example builds after committing the public pins.
- Owner Mac live VPN: **DEFERRED** until the owner is ready. Its active VPN,
  DNS, proxy and routes are not modified by this update.

The Android product binds application revision `822dde0` to the public AAR
above: APK SHA-256
`0d6a4fe3752c7485948a02d1003eee2f9c23f9e80c5081c8df670cabea733081`.
Independent static replay checks 117 app inputs, 72 runtime producer/packager
inputs, six packaged native members and both full GeoDAT files. The arm64 API 35
emulator runs actual Core 26.10.29. The foreground notification and action are
present. Direct traffic uses the ordinary emulator path through the owner's
existing Mac VPN; it does not mean an unprotected ISP path on the Mac.

The first Android ordinary-network readiness attempt expires before any
Connect while resolving observer metadata and Chrome onboarding. A distinct
bounded readiness attempt passes after correcting those observers. One
third-profile page observer also misses a heading's trailing whitespace; the already-recorded page/XML
proves the expected result, so an offline correction retains the original
failure without another VPN start. Its extra second-page Core PID sample is
absent; the contemporaneous VPN interface remains validated. That page displays
proxy IPv6 egress while the ordinary physical interface has no IPv6 route;
this is not a full packet-level IPv6 qualification. Site geolocation databases
disagree for some identical egress IPs, which is separate from routing behavior.
The owned emulator, exclusive ADB server, forwarding and build/control helpers
are stopped. End-of-test source checks match all 117 application inputs, and
the four Mac DNS/proxy/default-route/VPN snapshots match their baselines.

The physical iPhone 13 Pro Max runs iOS 27.0.1. Its signed product binds
application revision `f4b7a2c` and the published iOS SDK above; all 74 product
files, 162 Git-bound application inputs and 15 SDK members are rechecked.
Normalized full JSON from the common example importer is entered through the
real example UI. This does not qualify physical-iPhone URI clipboard import;
the Android URI UI and common importer checks are separate evidence.

This installed iPhone product is an acceptance-only preview with automatic
controls disabled, an independent 75-second host Stop guard and a compiled
110-second provider stop request. The presence of the provider timer is not
proof that it independently guarantees OS VPN shutdown. Normal builds omit
both acceptance flags; this preview is not suitable for unrestricted manual
sessions or testing automatic-reconnect/On Demand/quick-control combinations.

Retained iPhone exceptions are not promoted into passes: the initial first
profile does not reach CONNECTED within its admission bound, but a later targeted
attempt passes both sites without a runtime or connection-profile fix. The
initial second profile's second page is captured after the host guard, and a later complete
attempt supplies strict ON-state proof. The third profile has valid ON-state
pages but its Stop acknowledgement arrives after the host guard has also fired.
An initial direct-default split has only two ON-state Loading frames; later
post-Stop frames cannot prove routing or continuous failure up to the deadline.

Ten iPhone Start attempts are retained, including separately authorized causal
observations. The repeated 2ip-proxy split has a Loading frame at +23.451 seconds
and a valid tfox-direct result at +33.144 seconds; Stop is acknowledged
39.791 seconds after Start. A final conformance case changes only the proxy exception to
tfox, keeping the direct default and server fields. Its tfox result is the VPN
egress at +34.085 seconds, with Stop at +40.802 seconds; 2ip is still Loading
at its +24.335-second frame. These are positive direct/proxy-exception proofs,
not complete two-site passes. The normal all-proxy comparison loads both sites
and stops at +41.611 seconds. No additional domain rules, masks or runtime fixes
are introduced to make the missing result appear successful.

Independent static requests to [2ip](https://2ip.io/ru/) receive an HTTP 503
cookie/reload challenge visually matching the Loading frames. That document has
no external script/API origins, so a missing third-party routing rule is not
established. The phone's response status, cookies and individual requests are
not captured; its cause remains unclassified. Controlled SDK tests with
domain-bearing SOCKS requests do not reproduce this browser observation.

Bounded Diagnostics is enabled through the real UI for the later observations,
and the supported diagnostics dialog reads the native startup, protected-route
and DNS events. A direct app-group export attempt is rejected by CoreDevice's
allowed-directory policy, not proven to be a missing log. The bounded log does
not contain per-request routing traces. Full live Options and packet-level
IPv6 matrices remain outside this acceptance result.

The native Device Hub screenshot-export path supplies fresh physical-device
frames after the computer-use connection becomes unavailable. Existing
Accessibility access is used; Screen Recording permissions are not changed.
An offline audit also finds 68 rejected VM-file copy requests with a CLI timeout
below the tool's five-second minimum. Those requests never read the device and
do not establish a native VM-publication failure. Correcting the observer
retrieves a fresh PID-bound receipt without changing the app or VPN deadlines.

Final iPhone closure verifies native Stop acknowledgement, DISCONNECTED state,
routing OFF, the original fourth profile inactive, and ordinary Internet
recovery. Diagnostics, reconnect, quick controls and On Demand match the initial
safe baseline. The owned app and tunnel extension are absent from the device
process inventory; the USB forward, host listener, guards, log readers, Dart and
AX helpers are closed. Source/product/SDK rechecks remain unchanged. The signed
acceptance-only preview stays installed; no other phone, Mac VPN/network
setting, or macOS permission is changed.

## Upstream features and limits

| Change | Follow-up / current limit |
| --- | --- |
| [XDRIVE S3 and Google Drive ring slots](https://github.com/XTLS/Xray-core/commit/b4123b57483bf27aad4a88373f341b0567c990d2) | **XDRIVE remains unsupported by the Android, Apple and Windows VPN preparers.** Qualify its storage/fronting endpoints, DNS, socket protection and cleanup before widening admission. Runtime inclusion does not establish VPN support. |
| [Freedom fragment/noises deprecation](https://github.com/XTLS/Xray-core/commit/613d8147bb2b3bcfb0600a525c33260a9a2ca5f6) | Add migration examples for a `fragment` entry under `streamSettings.finalmask.tcp` and a `noise` entry under `streamSettings.finalmask.udp`; upstream still accepts the older fields. |
| [Generalized private IP ranges](https://github.com/XTLS/Xray-core/commit/43c29f8eb1f7ebeba1958e5f2f2ba65807f81d58) and stricter outbound transport security | Check special-purpose/NAT64 routing expectations. Unencrypted VLESS/Trojan to special-purpose IPs cannot rely on the old generalized-private exemption. Preserve upstream security checks; supplied REALITY profiles already use transport security. |
| [Geodata updater limits](https://github.com/XTLS/Xray-core/commit/48f62b801a6130776ad39e14e180166ab528c83d) | Scheduled updates require `.dat` assets, at most 100 assets, downloads at most 256 MiB and intervals at least one minute. Keep custom asset roots and referenced-file validation. |
| Windows single-family/DNS binding and Darwin TUN IPv6 binding fixes | Exercise the applicable Core paths in remote platform CI. The plugin uses its own Network Extension/HEV bridge on Apple; upstream TUN changes do not automatically qualify that bridge. Live Mac VPN testing remains deferred. |
| DNS oversized A/AAAA replies, WebSocket normal-close EOF, Freedom `blockDelay`, and inbound initialization ordering | Inherit upstream fixes and qualify DNS, lifecycle and routing regressions with the new runtime. |

Even successful tests of four live profiles and two domain splits cannot
establish support for every Xray configuration, transport or Options combination.
The broader DNS, IPv6,
import, file and recovery requirements retain their individual statuses in
[Compatibility](../compatibility.md). Full Options/protocol matrices and a new
Linux plugin implementation are outside this runtime update.

## Plugin release is a separate decision

Runtime publication does not publish or qualify the Flutter plugin. Before a
future package release, review the registry/version constraints and publication
order in [Package Release Preparation](README.md#registry-blockers-before-publishing-the-plugin),
complete the deferred live macOS check, close the unqualified iPhone 2ip
direct-default case, and review remaining compatibility coverage.
Full Options/protocol matrices and long-duration/NAT64 handover
acceptance are not established by this runtime update.
