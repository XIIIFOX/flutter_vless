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

Native revisions are built and qualified separately from Flutter packages:
Android `26.10.29-protect3`, Apple `26.10.29-r3`, and the managed Windows
companion. Earlier public runtime assets must not be relabelled. Final native
publication and device evidence remain pending until their exact artifacts
pass the current acceptance runs.
