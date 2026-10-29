# Xray 26.10.29 validation and remaining work

This update publishes native runtimes only. Flutter source packages and the
example remain 1.1.7. No pub.dev package or plugin 1.1.7 GitHub release is
published. Device acceptance and the current consumer CI are still pending;
earlier-version results are not carried forward as proof for this runtime.

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

## Consumer and device acceptance

The published consumer URL/checksum and Maven strict-verification pins are
prepared before device starts. New signed example products must bind their
compiled source closure and native payload to the verified public artifacts.

- Android emulator: **PENDING** four fresh profiles, real browser traffic,
  tfox.dev versus 2ip.ru/2ip.io split routing, Stop and recovery.
- Physical iPhone: **PENDING** fresh signed example using the public iOS SDK,
  four profiles, both native routing defaults, Stop and ordinary recovery.
- Consumer Actions: **PENDING** combined Android corridor and Apple released-SDK
  plus example build checks after the new public pins are committed.
- Owner Mac live VPN: **DEFERRED** until the owner is ready. Its active VPN,
  DNS, proxy and routes are not modified by this update.

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
complete the deferred live macOS check, and review remaining compatibility
coverage. Full Options/protocol matrices and long-duration/NAT64 handover
acceptance are not established by this runtime update.
