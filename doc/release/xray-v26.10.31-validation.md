# Native Core 26.10.31 qualification

Flutter package sources remain **1.1.7**. This stage publishes only native
artifacts: no Flutter package or plugin `v1.1.7` release is published by this
stage. Previously published implementation versions are a separate registry
constraint. The owner's Mac VPN stays on; live macOS VPN acceptance is excluded.

## Published native bytes

All four native releases use upstream commit
`a4a3dff5b20c2faae567b742c172c7b95e75c083` and producer
`13c47ed2caabd70b082449ed4917ce65574df91e`.

| Runtime | Public identity | Canonical archive SHA-256 |
| --- | --- | --- |
| Android | [Maven/GitHub 26.10.31-protect1](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-android-v26.10.31-protect1) | AAR `4c7080a48106e1b0369d7aba68a4969382de22a21ecf7c89f3e86685adb8d704` |
| iOS | [26.10.31-r1](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-ios-v26.10.31-r1) | `22813f46cd978341a2f6aa61f8d346fb57393c53a9f271d5f42b6b1a3371b9cc` |
| macOS | [26.10.31-r1](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-macos-v26.10.31-r1) | `15de3fed0dc69604ba0a76172ff0d1550f2d64ebc1c173109e2308ef657cb07c` |
| Windows AMD64 | [26.10.31-r1](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-windows-v26.10.31-r1) | `19268b7f9f5ddedbcf9c3cb294175f28f1c6a4d495327e790f8e519e8073aa48` |

Public payloads match their qualified producer artifacts. Android was published
from the same USER_MANAGED Central deployment after review, without rebuilding
or uploading another bundle; all public Maven payloads and signatures match.
Apple consumers include exact public vendored SDK trees as well as updated
SwiftPM/CocoaPods pins. Merely changing URLs would leave existing vendored
frameworks selected, so both trees were replaced and checked member by member.

The shared MPTCP default-off method is identical to official Core in all five
protected/ordinary/routing source compositions. It belongs to the shared
listener reached by the in-process SDK, not just a CLI initializer. Explicit
caller socket policy is retained. Go 1.27.3, Root CA filtering and Apple H2BUF
128 KiB remain qualified.

## Completed checks

* [Core31 CI on Linux/macOS/Windows](https://github.com/XIIIFOX/flutter_vless/actions/runs/41350987225)
  at `d9316e9356b27720d13b081d06d7fc931ebcdb03`: 340 supervised phases, 790
  exact source bindings, numeric SOCKS/TLS-SNI routing in both directions,
  IPv6/DNS/NAT64 address carriage, S3 encrypted relay and Google OAuth/API
  contracts, nine typed ECH cases and 21 strict H3 certificate rejection cases.
  Thirteen S3 HTTP/thread controls per OS pass with no hidden thread exceptions.
  The producer and validation heads have identical native-producing sources.
* [Apple native producer](https://github.com/XIIIFOX/flutter_vless/actions/runs/41349615824):
  both SDKs execute version/capability/custom-root checks in Actions; all five
  architecture slices pass 16 strong C-export checks each. Source/tree/ZIP
  receipts and fresh anonymous public downloads agree.
* [Windows producer](https://github.com/XIIIFOX/flutter_vless/actions/runs/41349615668):
  all six Windows 2022/2025 jobs pass. Each OS verifies 189 VPN, 21 proxy and
  21 portable cases plus numeric IPv6/WFP controls. The two Core executables
  are byte-identical and match the compiled 1.1.7.117 example bundles.
* Fourteen consumer-pin contracts pass: all platform defaults, Apple tags and
  checksum agreement, Android strict Maven checksums/preview commit, and all
  unchanged Flutter package versions. The legacy stock17 Android test-input
  fixture remains explicitly historical; its old bodies are not relabelled.

## Post-publication acceptance

The public-byte Windows workflow mode installs the fixed released ZIP and
manifest, checks hashes and executes version/capabilities before the full
existing native/example/VPN matrix; it skips rebuilding and packaging Core.
[Windows post-publication run 41355175815](https://github.com/XIIIFOX/flutter_vless/actions/runs/41355175815)
at `d0ea97552858ed8234b69d050c142b9ce0283837` passes all six Windows 2022/2025
jobs using the fixed public PE, with all Core build/package steps skipped.
Both compiled examples retain the exact public executable. Each OS passes
189 VPN, 21 proxy and 21 portable checks; numeric IPv6 uses actual kernel
sockets with wrong-address/image controls and zero final filters/routes/helpers.
Source bindings and all six downloaded artifact ZIP digests were verified.

[Apple post-publication run 41358204284](https://github.com/XIIIFOX/flutter_vless/actions/runs/41358204284)
at `14360cc` installs the checksum-pinned public iOS/macOS SDKs and skips both
preview rebuilds. The full runtime/bridge/example checks and final exact-tree
check pass: actual iOS simulator SDK, both example builds, macOS protection and
runtime/HEV checks all succeed. The earlier cancelled build-mode run is not
counted as public-byte acceptance.

The downloaded final evidence ZIP matches GitHub's artifact digest. Each SDK
passes 12 runtime modes, two-generation domain routing/owned drain and three
DNS-over-HTTP/SOCKS owner generations; runtime skips and hidden thread exceptions
are zero. Both public framework trees remain unchanged (15 iOS, 8 macOS files),
with 64 producer/current source bindings per platform. The 255 iOS and 269 macOS
Swift tests pass apart from one pre-existing opt-in encrypted-bootstrap endpoint
skip per platform. The macOS HEV test exchanges 8 MiB duplex data and IPv6 TCP/UDP
with clean shutdown. iOS HEV coverage in this workflow is compile/link only;
physical iPhone VPN acceptance is recorded separately below.

The preceding [setup failure 41356744495](https://github.com/XIIIFOX/flutter_vless/actions/runs/41356744495)
verified the fixed public ZIP and manifest, then could not read the historical
producer source from a shallow checkout. No runtime test had run. The fix
fetches that single immutable producer commit before the existing complete
source checks. A real shallow local Git fixture reproduces failure before the
fetch and source-binding success afterwards; nine SDK-selection tests pass.
The iPhone development-only safety observer also has a monotonic two-second
bound, single-owner/reference checks and read-only output. Its late-callback
failure was reproduced before correction and independently reviewed.

The [next setup run 41357218312](https://github.com/XIIIFOX/flutter_vless/actions/runs/41357218312)
passes public installation and source checks, then rejects synthetic qualifier
logs because a job-wide runtime capability requirement leaked into those
fixtures. The corrected workflow scopes that requirement to the two real SDK
runtime steps. Nine workflow/selection guards and forty original qualifier
mock tests pass; actual public runtime capability checks remain strict. Neither
setup failure is claimed as a Core runtime defect or a successful runtime test.

The VPN-compatible local Android emulator runs the fresh example with the
public `26.10.31-protect1` AAR. Installed native version/capabilities and APK/Core
hashes match the public consumer, and ordinary Chrome IP APIs have a matching
healthy baseline. Each of the four owner profiles failed a single independent
unmodified official Core31 control on the same guest network: TLS timed out
without origin bytes. Their real-public two-direction routing is therefore
**unqualified**; no expiry, MPTCP or plugin-defect cause is asserted. Actual
example URI import succeeds, and its profile-delay failure completes in
5,167 ms with its child drained. Public peer work stops before the iPhone starts.

Two fresh actual example/Core31 S3 sessions pass: each forces SOCKS through a
sole encrypted VLESS/XDRIVE outbound, sends 43,008 nonce-bound binary bytes and
receives the exact 43,021-byte response. The independent origin records both
requests. Signature, request and handler failures remain zero; objects and
active connections are zero after server close. Notifications, UI Stop,
fullStop acknowledgement and ordinary recovery pass. All owned Android
processes, emulator, ADB, forwards, servers and guards are stopped; the four
Mac network snapshots remain byte-identical.

An independent audit reproduces the normal NDK r28c packaging transformation:
the public AAR's ARM64 Core hash `192026d9…` becomes APK/installed/live
`69024103…` under the pinned `llvm-strip --strip-unneeded` tool. The APK is
`5c41ae21…`; exact public AAR, transformed member, installed bytes, live
`/proc/PID/exe`, both payload hashes and origin observations agree. Raw AAR and
packaged ELF hashes are not falsely required to be identical. No Core code is
built or executed on the Mac. The first private S3 observer attempt correctly
rejected its stale 26.10.29 expected hash before payload; its strict predicate
was retained and the expected identity bound to the qualified current product.

The physical iPhone uses a fresh signed `af9387b` example with the exact public
iOS SDK31. The UIKit/NetworkExtension observer compiles in the full app. A
fresh read-only two-read observation confirms exactly one owned disabled
profile, a consistent nonempty reference, no On Demand and disconnected status.
The required in-session forwarding protection remains enabled; it is not
misreported as disabled. The test-only 110-second device backup deadline is
compiled in with its actual branch prerequisites checked; its expiry is not
exercised. Every live case explicitly stops before 42 seconds, with a separately
armed 75-second host guard normally cancelled and reaped. The fresh
own-WKWebView OFF baseline loads tfox and ipify completely with the same ordinary address. Canonical 2ip
first reports 503, then 200 and a visible IP with no Loading text; its six-second
snapshot is still `interactive`, so this is partial page evidence rather than
a complete load. Canonical 2ip over VPN is not qualified by these observations.
No fresh Safari result is inferred from an open-URL callback or a stale mirror. The current P1 all-proxy reference loads both services
completely with the same proxy address, distinct from the fresh ordinary address. Both split directions
also pass within separate guarded sessions:

* Default PROXY, ipify DIRECT: the explicit caller per-domain DIRECT numeric
  DoH recipe and retained UDP/443 block produce ordinary ipify and proxy tfox.
* Default DIRECT, ipify PROXY: caller DNS is absent; ipify uses the qualified
  proxy address while tfox retains the ordinary address.

Both pages return HTTP 200 with complete DOM in each case. FullStop is
acknowledged at about 41 seconds, the host guard is reaped, and the profile is
disabled/disconnected with a consistent reference after each case. A fourth
all-proxy case on P3 with a nonempty Reality Short ID also passes.
Every post-Stop recovery pair returns complete HTTP 200 documents with the same
ordinary address. Final inspection confirms exactly one owned disabled profile,
consistent reference, On Demand/reconnect/quick access off, no authorized quick
reference and no owned provider process. App/control extension, USB forward,
guards and build groups are stopped. An independent root audit checks 42
referenced files, all eight native PNG bindings, both IP splits, source/product
identity and final disabled status. These are fresh31 results; earlier
26.10.29 passes are not inherited.

Device acceptance, teardown and final Apple Actions results are recorded above.
The bounded goal closes with named external limits, rather than a claim of
universal configuration or plugin-publication readiness. [Remaining plugin and new-Core work](xray-v26.10.31-plugin-followups.md)
separates publication review from wider feature coverage. Real cloud accounts,
physical IPv6-only/NAT64 and handover conditions remain separate from controlled
fixtures. No native Core/SDK is executed on the owner's Mac for this stage.
