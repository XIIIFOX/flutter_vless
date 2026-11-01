# Xray 26.10.29 compatibility work

The Flutter packages stay at 1.1.7. This work does not publish the plugin or run
a VPN on the owner's Mac. Native runtime revisions and live-device evidence
have separate qualification requirements.

## Transport security and special-purpose addresses

Core has two different policies. Its generalized private-address matcher is
used by Freedom's default private-destination protection. The plaintext
VLESS/Trojan exception uses the narrower standard private, loopback and
link-local checks, plus Core's private-domain matcher. A match in the first
policy does not grant an exception in the second.

The configuration-only pinned-Core tests cover both policies independently.
They include RFC 1918 and IPv6 ULA, loopback/link-local, CGNAT, benchmarking and
documentation addresses, multicast, and both NAT64 prefixes `64:ff9b::/96` and
`64:ff9b:1::/48`. NAT64 addresses remain IPv6 even if their embedded IPv4 address
looks private. VLESS/Trojan without TLS cannot use the generalized classifier
to bypass the transport-security requirement; the same endpoints with TLS
still compile. The plugin preserves Core's decision instead of maintaining a
second, potentially different trust list.

The [Core CI](https://github.com/XIIIFOX/flutter_vless/actions/runs/41027939264)
at `3119fe9` passes on Linux, Windows and macOS. The exact selected
`TestAcceptanceCoreCompatibility` pass is checked in all three artifacts, with
child exit, output drainage, source-copy and module-cache invariants.

Apple endpoint tests separately check that a numeric NAT64 endpoint is not
resolved or synthesized again, and that a system AAAA answer retains its
interface, expiry and honest source. A familiar prefix does not prove DNS64
synthesis or reachability. These are source-only resolver checks; they do not
qualify a live IPv6-only/NAT64 network or handover.

Sources: [address classifier](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common/geodata/consts.go),
[transport-security checks](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go).

## Freedom masks

The [example pair](../example/configs/finalmask/README.md) demonstrates legacy
Freedom `fragment/noises` and the new TCP `fragment` / UDP `noise` final masks.
It maps the legacy fragment `interval` to the new `delay`, and compares the
actual compiled packet, length, random-size and delay ranges in pinned Core.
It does not claim a universal conversion for family-specific `applyTo`, mask
ordering or scripts.

Eight shared tests also check that both JSON examples reach Android, iOS,
macOS and Windows start/delay adapters without an automatic rewrite. Native
Core schema validation is separate from these mocked-channel checks.

## Managed services

[S3 and Google Drive examples](../example/xdrive/README.md) use full JSON
configuration. Native preparation uses the active cloud service endpoints,
including S3 virtual bucket hosts and Google OAuth/API hosts. Optional fronting
is prepared separately; HTTP/TLS identity, signing inputs, remote object names
and secrets remain caller-owned. Dormant protocol addresses are not resolved
as if they were the physical cloud endpoints.

Each Core owns its cloud resources and cache. Closing that owner cancels a
separate service context; it must not cancel the parent or the Core feature
context. The existing routing construction-failure ordering is retained.
S3/Google HTTP fixtures exercise signing, fronting, CRUD, fresh owners and
cancellation without real accounts. They do not qualify a live cloud account,
a complete relay deployment, HTTP/3 or ECH.

[GeoDAT examples and limits](../example/geodata/README.md) describe writable
existing targets, HTTPS, at most 100 assets, constant intervals of at least one
minute and Core's 256 MiB response limit. Core retains its download transaction
and rollback behavior. The native patch cancels its downloader before waiting
for scheduled work; Android creates bundled defaults only when missing and
never overwrites a downloaded dataset during recovery.

Both features require explicit lifetime capabilities. Apple SDK bridges must
return `1` for GeoDAT and `2` for XDRIVE. Android/Windows query the selected
image's `native-services capabilities` command: bit 0 is GeoDAT, bit 1 is
XDRIVE storage ownership, and bit 2 is XDRIVE idle worker ownership. XDRIVE
requires both of its bits (`6`); `7` enables both managed features. An older
SDK or a stock external Core with the same version is insufficient. Ordinary
configurations remain usable with those runtimes.

The extra worker requirement follows an actual Core shutdown regression:
an idle WAL reader remained asleep after its storage owner closed. The
[original test failed](https://github.com/XIIIFOX/flutter_vless/actions/runs/41047188984)
and the [same test passes after the worker fix](https://github.com/XIIIFOX/flutter_vless/actions/runs/41049190758).
Worker contexts now retain the caller's metadata/cancellation while also
following the separate service owner; releasing a connection or listener
does not cancel sibling services or the Core context.

Native revisions are published separately from Flutter packages:
Android `26.10.29-protect3`, Apple `26.10.29-r3`, and the Windows
`26.10.29-r3` companion. The [release notes](release/README.md) link their
exact producers and archive checksums. Public CDN/Maven bytes match the
qualified artifacts; earlier assets are unchanged. The
[full Core regression](https://github.com/XIIIFOX/flutter_vless/actions/runs/41050075901)
passes on all three runners, and the
[Windows native/example/VPN acceptance](https://github.com/XIIIFOX/flutter_vless/actions/runs/41050075535)
passes on Windows 2022 and 2025. Physical-device evidence is recorded separately.

## IP-check browser diagnostics

The example's opted-in browser diagnostics now open the exact public URLs
`https://2ip.ru/` and `https://tfox.dev/ip/`. Navigation/session identifiers
remain local metadata; the diagnostic no longer adds query parameters to the
website URL. The embedded view retains its explicit cache-reload policy.

The Android control kept the profile, SDK, options and routing JSON identical:
with a diagnostic query, the 2ip page remained in Loading; removing only that
query allowed the redirect to `2ip.io` and displayed the expected proxy address.
The other site displayed the ordinary address. Reverse routing also passed,
and stopping restored the ordinary address on both sites. Expanding an exact
domain rule to include subdomains alone had not fixed the observed Loading.
On iPhone, the query/plain contrast was reproduced twice in Safari while the
test VPN was off. This evidence calls for correcting the browser observer's
URL, without changing the meaning of routing rules.

Android's four supplied profile checks produced two traffic passes and two
timeouts. Those timeouts remain unresolved: successful import or `CONNECTED`
alone does not prove a remote handshake, and a timeout alone does not identify
an expired server or a plugin defect. All eight Android connection cases ended
with a native Stop acknowledgement, an inactive service/VPN and ordinary
browser connectivity; the emulator and its owned helpers were then stopped.

On the physical iPhone, the final signed example uses the exact public iOS r3
SDK and reports GeoDAT/XDRIVE/routing/Darwin capabilities `1/2/1/1`. All-proxy
Safari traffic and the split with 2ip direct and tfox proxied displayed the
expected primary addresses. The inverse split remains **unqualified**: tfox
displayed its ordinary address, but 2ip remained on its own Loading page,
including a direct canonical `https://2ip.io/ru/` observation after 20 seconds.
Every connection attempt received a Stop acknowledgement and ordinary tfox
connectivity recovered. Owned example, forwarding, compiler and guard processes
were closed; Safari was left with working ordinary connectivity.

A separate cold Safari control reproduced canonical 2ip Loading while the VPN
was off, before any new example session or connection. An independent public
HTTP request from the unchanged Mac network also received HTTP 503 with title
`2ip loading...`; that document contains an inline cookie challenge and no
external dependencies. This does not establish the iPhone's exact response or
identify a routing defect. The passing Android and current iPhone inverse-split
input JSONs are equivalent apart from a diagnostic rule tag; both adapters
enable `routeOnly` on the managed SOCKS input. No routing/DNS behaviour is changed
on the basis of these incomplete browser observations.

## Remaining acceptance outside this change

* Finish the iPhone inverse split with a healthy browser/site baseline; if it
  repeats, capture the failing request/status/protocol and the final prepared
  extension configuration. Resolve the two unsuccessful supplied Android
  profiles with a known working reference or peer-side evidence.
* Add a controlled literal-IP SOCKS destination plus TLS ClientHello/SNI routing
  case before extending coverage to QUIC/ECH; existing domain-SOCKS tests do not
  establish those paths.
* Live S3 and Google Drive accounts with a complete relay deployment, including
  HTTP/3/ECH where configured. Controlled endpoint fixtures establish the
  ownership and cancellation contract, not account availability.
* A physical IPv6-only/DNS64/NAT64 network and Wi-Fi/mobile handover. Address
  classification and resolver tests do not establish that network's reachability.
* A broader server-backed protocol/transport matrix and additional external
  configuration/file/import combinations as suitable fixtures become available.
* A live macOS VPN session, only when the owner can interrupt the existing VPN.
* Free implementation package versions and matching root constraints before
  pub.dev publication; the current Android/macOS/Windows `1.1.7` versions are
  already occupied. No package version is changed by this work.
