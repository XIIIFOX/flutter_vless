# Compatibility

This page lists the expected platform shape for `flutter_vless`.

## Package Scope

`flutter_vless` is a federated Flutter plugin for Xray/V2Ray-compatible client
flows:

- VLESS
- VMESS
- Trojan
- Shadowsocks
- SOCKS
- WireGuard import from Clash YAML and sing-box JSON
- Hysteria2 import from share links, Clash YAML, and sing-box JSON
- raw Xray JSON
- supported Clash YAML and sing-box import paths

Runtime support for newer protocols still depends on the packaged or supplied
Xray artifact on each platform. Validate generated configs against the target
artifact before release.

## Platform Matrix

| Platform | Supported modes | Minimum / validated version | Native requirement | Main limitations |
| --- | --- | --- | --- | --- |
| Android | VPN, proxy-only | `minSdk` 23, target SDK 35 in the Android package (example: 24/36) | Xray runtime AAR from Maven Central; Gradle `packaging.jniLibs.useLegacyPackaging = true` when extracted native executables are required | Main AAR includes device and emulator ABIs. |
| iOS | VPN, proxy-only | iOS 15.0+ | Network Extension, Packet Tunnel target, App Group, signed real device for tunnel validation | Simulator is not a reliable VPN/tunnel test target. |
| macOS | VPN, proxy-only | macOS 13.0+ for the validated setup | Packet Tunnel extension, App Group, Swift Package products, setup command | Packet Tunnel routing and DNS changes must follow the architecture note. |
| Windows | VPN/tunnel, proxy-only | Recent Flutter Windows toolchain | Local `xray.exe` available to the app | Tunnel/system routing may require elevated permissions; the plugin does not download Xray for you. |
| Web | Not supported | N/A | N/A | No web implementation is registered. |

Linux runners below test Xray Core and shared native preparation. The Flutter
plugin does not include a Linux implementation.

## Android

The Android implementation includes 16KB page size support for modern Android
builds and bundles native Xray libraries for device ABIs.

The Android runtime AAR includes `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`.

Use the Android Gradle plugin packaging DSL when your app needs extracted native
executables:

```kotlin
android {
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}
```

## Apple Platforms

iOS and macOS use Apple's Network Extension model for tunnel mode.

Required for tunnel mode:

- Packet Tunnel extension target
- Network Extension capability
- App Group shared between the app and extension
- matching signing team/profile setup

Pass the base app bundle id to Dart:

```dart
await flutterVless.initializeVless(
  providerBundleIdentifier: 'com.example.myapp',
  groupIdentifier: 'group.com.example.myapp',
);
```

The plugin appends the Packet Tunnel extension suffix internally.

## Windows Xray Lookup

Windows needs a local `xray.exe`. Common lookup locations include:

```text
windows/xray/xray.exe
xray/xray.exe
xray.exe
data/flutter_assets/xray/xray.exe
data/flutter_assets/windows/xray/xray.exe
```

The plugin does not search PATH, AppData or the current working directory.
Paths are resolved relative to the application directory. The bundled example expects:

```text
example/windows/xray/xray.exe
```

## Known Product Boundaries

- No web implementation.
- No automatic Windows Xray download.
- No guarantee that every imported server config works on every platform.
- No automatic conversion for protocols that Xray cannot run.
- VPN/tunnel mode depends on operating-system permissions and native project
  setup, not only Dart code.

## Full Xray profiles in 1.1.7

Android, iOS, macOS and Windows add a separate authenticated loopback SOCKS
adapter for the VPN. Imported listeners, accounts, tags and sniffing remain in
the runtime profile, including the common `socks-in` + `socks-direct` arrangement.
Service ports and tags avoid profile collisions; adapters use HTTP/TLS/QUIC
sniffing for VPN domain routing. Apple preparation also preserves an explicitly
selected `routing.domainStrategy`. Isolated Apple delay probes remove imported
inbound, API and metrics listeners and open their own temporary authenticated
listener. This measurement exception leaves normal VPN/proxy API settings intact.

This fixes the extra-listener rejection. It does not establish compatibility
with every feature or protocol accepted by the Xray command-line runtime.

## Remaining compatibility work

These are implementation and acceptance tasks, not supported-feature claims.

### Incremental delivery order (2026-10-19)

Deliver one useful cross-platform increment at a time: failing regression,
production adaptation, then targeted runtime acceptance. The full protocol and
transport matrix is deferred; a missing server configuration does not block the
first DNS increment. The eight requirements below remain the long-term list.

1. DNS: preserve explicit caller `hosts`, remote `servers`, domain selection,
   tags and query strategy. Send the managed VPN resolver's A/AAAA queries to
   Core's own DNS client, retaining caller `UseIPv4` AAAA NODATA behavior. Keep
   transport bootstrap outside the caller's hosts map.
2. Protocols and transports: remove avoidable adapter restrictions using focused
   synthetic cases and the configurations available for live checks.
3. Full configuration passthrough, then ports/addresses and files/imports.
4. Remaining IPv6, diagnostics, recovery and device acceptance from the eight
   requirements, expanding the corpus when a concrete gap is found.

Track the small delivery gates separately from the eight full requirements:

| Minimum increment | Status | Acceptance boundary |
| --- | --- | --- |
| Preserve caller DNS and private A/AAAA path | Qualified controlled baseline on all four native platforms | Caller DNS and controlled FakeDNS Core/Android TUN/Windows TUN/both released Apple SDK gates pass. Combined Apple HEV/FakeDNS, physical devices and wider DNS semantics remain open. |
| DNS dictionary data, remote URL data and system-hosts flag | Qualified controlled increment | Shared five-profile preparation, all four public message adapters and Android JVM controls pass. Expanded Core traffic passes all three OS jobs at f5e0a88; both released Apple SDKs and Android's augmented CallerRoot DNS tests pass at e2acc10. Physical/system-VPN and wider DNS acceptance remain separate. |
| IPv6 caller DNS server addresses | Preparation qualified; UDP/TCP runtime pending | Both Apple preparers and Windows preserve numeric IPv6 servers and static resolver mappings, including mixed address families. The 33 inert preparation cases pass; exact IPv6 destinations carried through an IPv4 proxy still require the new remote Core traffic gate. Android already admits these address families. |
| Classic UDP DNS shutdown | Qualified controlled Core increment; physical IPv6 DNS unresolved | The shared lifetime patch closes the channel and cleanup timer, fences late normal/EDNS sends and retains caller policy. The exact UDP/TCP IPv6 and paired UDP IPv4 gates pass on all three Core systems at 4a52394. The bounded iPhone candidate below stops and restores safely, but its A query times out. |
| Protocol/transport preparation and controlled XHTTP | Qualified | Shared pinned-Core corpus and controlled payloads; the exhaustive external-server matrix is deferred. |
| Typed transport headers and XHTTP download policy | Qualified controlled increment | The ten-profile transport dictionary corpus checks 18 raw maps and effective pinned-Core headers through both native preparers, public import/start/delay on all four message adapters and Android's actual prepare/build path. This covers data preservation, not a full transport handshake matrix. |
| Routing attribute dictionary data | Preparation qualified | Shared literal regex corpus, all four public import/start/delay adapters, Android producer and actual pinned-Core attribute matching pass. Both native preparers retain the exact compiled rule; this is separate from system-VPN traffic. |
| Public Core schema fields and effective transport admission | Preparation qualified | The shared five-case corpus retains Go-folded fields and method precedence through all four public adapters, Android preparation and both native exporters. Core rejects the active-empty and non-string controls; ambiguous aliases remain refused. |
| Opaque full-JSON fields | Qualified controlled increment | Six shared profiles retain 18 unknown subtrees through all four public adapters, actual Android preparation and both native exporters. Pinned Core comparisons and existing traffic gates pass Actions on all three Core systems at e49c1e0. Android's five live CallerRoot DNS tests also pass locally with the host VPN enabled, including six exact runtime metadata subtrees and retained DNS/HTTP/API controls. Physical iOS and broader configuration acceptance remain separate. |
| Imported API/services/stats/policy | Qualified | Shared preparation and API/traffic gates, including Windows service acceptance. |
| Safe per-start preparation reports | Qualified controlled increment; device scope remains limited | Closed operation codes follow each invocation's checked candidate. Apple VPN and Windows proxy reports cover host preparation; Android reports admission before asynchronous readiness. The source-bound 80d3caf/53fafe8/28dc44b CI lineage below qualifies the closed summaries and retained runtime gates. Physical iPhone preview observations cover host preparation only; final Apple provider reports, broader device acceptance and later-startup rollback remain open. |
| Port/address syntax and explicit data/certificate roots | Qualified baseline | Shared Core/native controls and the targeted runtime cases below; OS allocation/reload and managed import lifetime remain open. |
| Environment aliases in ports and addresses | Qualified controlled increment | Shared eight-case Core/native corpus, four public adapters, actual Android builder and both Apple port binders pass. Generated Unicode casing matches pinned Go. Actual Windows UTF-16 environment reads and existing Core traffic pass Actions at 038615d. Apple byte-exact snapshots additionally pass synthetic native-reader, host-admission, allocation and startup-retry checks; physical acceptance remains separate. |
| Source inbound and explicit VPN default | Qualified controlled baseline | Shared Core, Android TUN, Windows 2022/2025 and both enabled Apple SDK runtimes pass controlled source/default selection. Physical/system-VPN acceptance remains separately tracked. |
| Occupied private TCP listeners | Qualified controlled baseline | Bounded selection, held-port traffic and Android/Windows probe exclusions pass the targeted runtime gates below. Atomic ownership transfer and reload remain separate. |
| Session-owned traffic counters | Qualified controlled baseline | At f5acbbc, Windows passes 460 rows and Android passes 41 native tests plus three Flutter tests with no skips, including enabled/disabled counter generations. At 02136f1, both enabled Apple SDKs pass counters, all twelve ordinary modes, routing and cleanup. Apple VPN keeps HEV accounting; physical-device acceptance remains separate. |

Each qualified row refers to the specific checks recorded below. It does not
mark an entire long-term requirement complete.

The DNS MVP uses an address-only virtual resolver at `10.0.85.53:53`, scoped to
the private VPN adapter. A and AAAA now use Core's preserved root DNS; an explicit
caller `UseIPv4` still produces successful AAAA NODATA. Other record types return REFUSED.
Imported listeners do not acquire this private path. Proxy-only and measurement
preparation retain their separate behavior.

Apple transport endpoint lookup happens before installing VPN routes and stays
separate from caller DNS. Both Apple platforms use cancellable, bounded system
IPv4 lookup, then HTTPS bootstrap to `1.1.1.1` for public hostnames
only. The fallback retains normal TLS validation and refuses redirects. The
physical iPhone check at `78a68c7` used system lookup successfully; it does not
qualify the encrypted fallback branch or IPv6-only endpoint bootstrap.

Caller DNS admission now accepts numeric IPv6 addresses as well as IPv4 and
mapped addresses. It preserves the DNS object, query strategy and caller route;
allowed TCP/HTTPS/h2c URLs and named resolvers with static IP mappings use the
same address-family check. Preparation acceptance also includes explicit direct
DNS. This does not establish physical IPv6 reachability or change Windows
physical IPv6 protection or Apple transport endpoint bootstrap. The new runtime
gate targets UDP and TCP logical IPv6 DNS destinations through an IPv4 SOCKS
carrier; broader DNS transports, direct IPv6 and IPv6-only VPN endpoints remain
separate acceptance work.

The first IPv6 DNS wire run at `b4d0277` receives the exact A/AAAA responses and
retains `UseIPv4` NODATA, with zero OS resolver calls. Its TCP modes pass, but UDP
channels remain active beyond the three-second post-Close observation on all
three Core systems. Pinned Core detaches the Classic DNS channel from the query
context and keeps a one-minute inactivity timer; its DNS feature does not close
that channel. This is family-independent retention, not proof of a permanent
leak. The subsequent guarded lifetime patch also covers IPv4 controls. Runtime
preparation tests that use this patch report a checked disposable Core copy and
alternate module file explicitly; their pure default baseline remains upstream
Core. No module-cache source or published runtime pin is changed.

The [corrected runtime run at `4a52394`](https://github.com/XIIIFOX/flutter_vless/actions/runs/39369095981)
passes all three Core systems. Each actual native preparer passes four IPv6 DNS
modes (UDP/TCP with `UseIP`/`UseIPv4`) and two IPv4 UDP controls, with exact target
address/port, query/answer counts, zero OS resolver calls and post-Close channel
and callback drain before generic fixture cleanup. macOS checks both Apple and
Windows preparation; the other systems each check Windows preparation. All six
Classic memory-only controls pass per system, retaining existing XHTTP traffic
and independent-download checks. The preceding fixture repairs change tests
only. Latest Ubuntu text-artifact collection returned zero bytes; its complete
canonical log and the preceding production-equivalent source artifact are
retained, without claiming verification of the missing latest artifact.
The source-build paths for Android, Apple and the desktop routing CLI consume
the same narrow lifetime patch. Published binary pins remain unchanged.

The fresh signed physical iPhone product at `c72bd03` includes that same Classic
lifetime implementation. One derivative of the first supplied profile selects
a single public numeric IPv6 UDP resolver through its original proxy, with
`UseIPv4`, no hosts shortcut and no alternate resolver. The actual app connects,
but its managed A query times out after four seconds; AAAA returns successful
NODATA. The candidate is therefore **inconclusive**, and its VPN browser phase
is not entered. This does not establish proxy IPv6/UDP reachability or identify
a wrapper defect. No retry or second Start is used. Exact full Stop ACK,
independent provider absence, prior options/profile restoration and a fresh
OFF Safari page showing the original direct address are checked. The owned app,
USB forwarder and helpers are then stopped. This is a safe restoration result,
not physical IPv6 DNS qualification.

The physical iPhone preview at `ae68d75` also checks A and AAAA requests from
an actual app UDP socket to this virtual resolver with caller `UseIPv4` and no
explicit DNS servers. The A reply contains the expected public address; AAAA
returns successful NODATA. A cold Safari page then displays the proxy exit.
The [development-only probe](../example/test_driver/acceptance_dns_probe.dart)
changes no resolver configuration. Diagnostics enabled before startup return
organic provider stages within the requested bounds; disabling them is confirmed
through the native API and persisted options. The project retains its released
SDK; this device product uses a separately built, unpublished preview. These
checks do not establish the cause of earlier intermittent blank pages or a
startup timeout, or qualify combined FakeDNS, broader IPv6 or recovery behavior.

The same physical-device sequence checks all three supplied VLESS/Reality
profiles in cold Safari sessions. Two domain-rule variants send `tfox.dev`
direct and `2ip.io` through the proxy, then reverse those choices; the pages
display the corresponding distinct direct/proxy addresses. The first reverse
variant attempt times out before browser acceptance, while the later diagnostic
run passes. That timeout remains unexplained. The third profile's displayed
IP geolocation differs from its imported country label; profile labels are not
used as evidence of exit location.

An earlier bounded recovery attempt stops before worker-loss injection because its
test-harness confirmation deadline expires. Native Stop succeeds and prior
options are restored. Across these physical sessions, cross-process clock
readings do not establish elapsed time from guard activation or qualify the
driver's arm-relative deadlines. The independent guard retains its own local
clock; page captures, native Stop acknowledgements, provider exit and option
restoration are separate evidence. No fault is injected in that recovery attempt,
so it provides no new physical-device qualification for recovery, retry limits
or kill-switch behavior.

The [parent-local acceptance clock](../tool/live_acceptance_clock.py) now models
guard activation as an interval between launch and acknowledgement in one
process. Delayed acknowledgements do not extend launch-relative cutoffs, and
reported durations remain bounds. Pure controls cover different process origins,
late/stale/repeated acknowledgements and invalid clock observations. This host
tool does not retroactively qualify earlier timings or prove native Stop.

Apple recovery now counts an attempt at the final admitted Core call, after old
workers drain. Cancelled queued work retains its initial or finite retry budget;
an actual failed call still consumes it. Both providers' extracted methods pass
the same sleep, drain, admission-boundary and exhaustion controls against inert
workers. The explicit recovery pause is retained when drain cannot finish.
Physical sleep/wake and retry-exhaustion acceptance remain separate.

The signed iPhone example rebuilt from `28b8412` also passes one acknowledged
Core-worker-loss case. The natural watchdog restarts Core and HEV inside the
same concrete NetworkExtension process, with ordered failure, restart, healthy
and forwarding-restored stages and no new tunnel start. A separate cold Safari
session then loads `tfox.dev/ip/` through the same expected proxy exit. Native
Stop is acknowledged, and provider exit is confirmed separately; the whole prior
options are restored, diagnostics and On Demand are off, and ordinary Safari
Internet access is confirmed. An earlier, shorter observation window saw only the worker restart
before Stop; it remains inconclusive for full recovery. Neither result qualifies
physical sleep/wake, retry exhaustion or universal kill-switch behavior.

[The exact `28b8412` Actions run](https://github.com/XIIIFOX/flutter_vless/actions/runs/39350945905)
passes all four selected jobs. Both extracted Apple providers pass 13 admission
controls each; the parent-clock controls pass 18 tests on each of Linux, macOS
and Windows. Apple SwiftPM suites pass 176 iOS and 190 macOS tests, with one
optional public encrypted-bootstrap check skipped per platform. Both unpublished
SDK runtime gates and the shipped macOS HEV packet gate pass remotely, alongside
the example and standalone plugin builds. iOS HEV simulator coverage remains
compile/link only; these remote fixtures do not qualify the local Mac system VPN.

Apple watchdog probes share a 15-second monotonic budget. Local authentication,
CONNECT and HTTP phases may shorten it to 2, 5 and 8 seconds respectively;
partial reads and interrupted calls retain the same deadline. Budgeted I/O uses
nonblocking operations with waits of at most 100 milliseconds. Stop and sleep
revoke probe admission, and cancelled samples cannot start later phases or
publish health/failure state. Existing HTTP/TLS delay callers retain their
previous socket behavior.

Android periodic health checks share the existing five-second readiness budget
across private authentication and the packet challenge, with captured session
and Core ownership. Stop cancels the phase's adopted sockets before queued
worker cleanup; the old phase cannot clear a replacement phase or publish its
connected state. Death of the same checked Core retains ordinary recovery.
Startup's existing refusal retry policy remains separate.

Windows packet checks use one 2,250-millisecond exchange budget, and accepted
challenge exchanges use 1,500 milliseconds, with cancellation checks and waits
of at most 50 milliseconds. The idle listener retains its 100-millisecond poll.
The worker passes its stop request into startup and periodic packet checks;
socket cleanup retains join-before-close ownership. SOCKS-listener readiness now
uses nonblocking I/O with one three-second invocation budget, capped by a shared
six-second VPN or five-second proxy startup budget. Authentication fragments and
retries keep that deadline; cancellation and expiry are checked after socket
cleanup and before admitting the listener to the next setup operation. The 52
inert actual-method controls cover these boundaries. The
[Windows run at `23bb13d`](https://github.com/XIIIFOX/flutter_vless/actions/runs/39365877362)
passes all six jobs: those 52 controls and the existing 20 packet controls per
system, both example builds and 460 VPN/proxy/portable traffic rows across Windows
2022/2025. Its two follow-up test-only repairs address MSVC warnings; production
runtime code is identical to `b4d0277`. These budgets do not bound the entire Stop call,
subsequent WinInet operations or OS scheduling latency.

Focused controls exercise actual probe methods with in-memory I/O and clocks.
Four additional real Apple loopback cases are wired into CI for authenticated
payloads, fractional socket timeouts, fragmented replies, cancellation and
refused authentication downgrade. The results below qualify this increment
separately from the `28b8412` results above.

The signed iPhone preview rebuilt from `7dedb8f` passes a new, single Core-worker
loss after these health changes. The same NetworkExtension process records
failure, Core/HEV restart and restored forwarding; separate cold Safari sessions
before and after show the expected Japanese exit. Native Stop and provider exit
are confirmed, the whole prior options are restored, and ordinary Safari access
works with the test VPN off. This is a recovery regression check; it does not
exercise a stalled socket, physical sleep, retry exhaustion or enabled On Demand.

The [Android/Apple run at `7dedb8f`](https://github.com/XIIIFOX/flutter_vless/actions/runs/39358509456)
passes both selected jobs. Apple checks 30 extracted provider controls, 52 inert
client controls and all four real Darwin loopback cases. The iOS/macOS SwiftPM
suites retain 176/190 passes and one optional public-bootstrap skip each. Both
unpublished SDK runtime gates retain their twelve modes, DNS, routing, occupied
ports, FakeDNS and counters; the remote macOS HEV gate retains 8 MiB payloads,
IPv6 TCP/UDP and cleanup. iOS HEV coverage remains compile/link only. The Android
job passes all 342 native tests, including the eight real loopback tests.
The isolated local ARM64 emulator also passes the controlled caller-root DNS and
domain-routing/recovery tests with the Mac VPN enabled: actual DNS, HTTP, caller
API, counters and Stop acknowledgements remain checked. The routing preview is
present only in the instrumentation APK. Live Android Stop during a stalled
readiness probe remains a separate, unqualified acceptance gate.
The [Windows run at `b2f93e3`](https://github.com/XIIIFOX/flutter_vless/actions/runs/39359055408)
passes all six jobs, including 20 inert packet-budget controls per system, both example
builds and 460 proxy, portable and VPN rows across Windows 2022/2025. Its only
change from `7dedb8f` corrects the generated test's port type to match production;
the native runtime sources are identical. Those results precede the separate
SOCKS-listener readiness follow-up above and do not qualify an overall Stop
deadline.

Full JSON import, startup and delay normalization retain explicit `null`, empty
objects/arrays and null array elements. In particular, an explicit `fakedns: []`
must reach Core as an empty engine rather than becoming an absent engine with
implicit pools. Share-link generation keeps its separate cleanup behavior.
Existing legacy stream-setting aliases and removal of `allowInsecure` still
apply; preservation concerns JSON structure rather than its original whitespace.
The public API regression checks all four concrete platform adapters through
their mocked message channels. Together with the root and example import/routing
tests, this verifies the shared JSON handoff without claiming a new native
runtime result.

The [five-profile schema-field corpus](../tool/fixtures/compatibility/schema-fields.json)
checks full JSON discovery and structural validation with Go-folded names such
as `OUTBOUNDS`, `PROTOCOL`, long-s and Kelvin-sign schema spellings. Lookup is
read-only and limited to inspected fields; keys and dictionary values keep their
original spelling. Conflicting aliases refuse before the native handoff. JSON,
subscription arrays, public start/delay and the first-outbound accessor use the
same schema interpretation. Sing-box discovery keeps its own field rules.

The [opaque-field corpus](../tool/fixtures/compatibility/opaque-fields.json)
places configuration-looking names and strings in unknown fields at the root,
DNS, handlers, protocol settings, routing, transport, TLS and XHTTP download
levels. Full JSON copies these subtrees intact before applying compatibility
edits to typed stream/TLS fields. Preferred XHTTP aliases and `extra`, including
explicit null, determine which download stream is visited. Genuine Realm and
XDNS mask TLS fields retain the same TLS cleanup; unrelated `tlsConfig` keys
remain data. Typed share-link generation keeps its separate legacy cleanup.

Android checks actual root DNS server addresses and UDP finalmask entries for
its unsupported local-QUIC DNS and XICMP paths. Metadata containing those strings
does not activate either feature. The negative controls still exercise the real
schema locations, including Core's address parsing and Go-folded field names.
Raw and native-prepared Core protobuf comparisons prove that the opaque fields
do not change compiled behavior. The [Core regression run at e49c1e0](https://github.com/XIIIFOX/flutter_vless/actions/runs/39310757774)
passes on Ubuntu, Windows and macOS with the existing traffic controls retained.
The local Android TUN regression then checks six exact metadata subtrees in the
running configuration while retaining its DNS, HTTP, API and cleanup assertions;
all five CallerRoot tests pass on the ARM64 emulator with the host VPN enabled.
The earlier Android Actions attempt stopped during the routing-preview build,
before an emulator started; it supplies no device qualification. Physical iOS
acceptance and the three supplied external profiles are tracked separately.

Transport string semantics belong to native Core preflight. `method: "tcp"`
can make `network: ""` inactive and valid; an active empty network still fails
Core Build, and a numeric network fails decoding. Structural Dart validation
retains the type check and passes the string through without choosing its
transport. Three positive profiles preserve Core-compiled semantics through
both native exporters; the two negative controls retain their Core refusals.
All four public adapters, actual Android preparation and example imports have
focused regressions. This is preparation evidence, not new protocol traffic.

The [five-profile DNS data corpus](../tool/fixtures/compatibility/dns-data-maps.json)
checks that host names matching legacy settings (`allowInsecure`, `network` and
transport aliases) remain dictionary data, including mixed-case alias targets
and Go-folded DNS/hosts field names. Shared Dart and Android runtime normalization
exempt that DNS dictionary from compatibility cleanup. Actual TLS cleanup
remains active. Windows accepts `+local` inside a remote resolver's path/query;
local-mode admission still follows the URL scheme. Apple preserves
`useSystemHosts`: pinned Core reads a hosts file during Build, without making a
system DNS lookup. Named resolver admission still requires an explicit caller
IPv4 hosts mapping. Pure preparation compares the exact caller DNS and compiled
Core DNS semantics. At [f5e0a88](https://github.com/XIIIFOX/flutter_vless/actions/runs/39286161954),
all three ordinary Core jobs also pass the expanded encrypted-DoH URI, static
A-over-TCP/UDP and system-hosts cases while retaining the TLS rejection and
zero-OS-resolver controls. This includes both production preparers on macOS.
The first [Android follow-up](https://github.com/XIIIFOX/flutter_vless/actions/runs/39286168518)
timed out before entering Flutter tests; its native tests were never reached.
The first [Apple follow-up](https://github.com/XIIIFOX/flutter_vless/actions/runs/39286174758)
exhausted its outer job budget during simulator preparation/compilation, before
SDK runtime began. These are not runtime acceptance for the new platform cases.
Android CI now runs native, Flutter and separate-UID gates independently and
retains every ordinary failure in the overall result. Apple SDKs run in separate
matrix jobs with fail-fast disabled; iOS preparation has a 30-minute outer
budget and the existing ten-minute runtime deadline remains unchanged.
Both [released Apple SDK jobs at e2acc10](https://github.com/XIIIFOX/flutter_vless/actions/runs/39290641058)
pass the new DNS data-map marker, 24 static A queries per SDK and the previous
two-generation opaque TCP/UDP FakeDNS controls. The separate macOS HEV IPv6 and
8 MiB packet controls also pass; this does not qualify combined HEV/FakeDNS or
physical-device traffic.
The [Android e2acc10 follow-up](https://github.com/XIIIFOX/flutter_vless/actions/runs/39290634195)
passes all three independent mandatory gates: native, Flutter and separate UID.
Native instrumentation selects 41 methods: 40 pass, including all five CallerRoot
DNS methods with the augmented opaque-host/system-hosts checks; the cellular
handover method skips because a cellular network is unavailable. This run does
not qualify cellular handover. Flutter passes all three tests on its first
attempt, and the separate-UID check passes. These runtime results bind e2acc10;
the subsequent WebSocket/header-guard change has the preparation proof below.

The bounded WebSocket data increment preserves
`inbounds/outbounds[*].streamSettings.wsSettings.headers`, including Go-folded
schema field names. Header names such as `allowInsecure` and `network`, and
literal values such as `xicmp` or `quic+local://...`, remain caller data.
Android uses the same schema dictionary boundary for normalization and protected
feature checks; root DNS hosts aliases such as `type -> xicmp -> 192.0.2.9`
are accepted too. Actual TLS cleanup, XICMP masks and local QUIC DNS restrictions
remain active. The shared WebSocket profile verifies source and native-prepared
Core Build/header/static-host semantics, with public start/delay/import and
example import regressions. The subsequent
[ten-profile transport dictionary corpus](../tool/fixtures/compatibility/transport-data-maps.json)
extends this boundary to HTTPUpgrade, XHTTP/SplitHTTP headers and `extra`,
immediate or nested download stream dictionaries, MASQUE, TCP/RAW HTTP
request/response string lists and Hysteria masquerade headers. The path scanner
recognizes schema fields without using the selected network as a dictionary
filter: Core can build configured transport settings independently of that
selection. Arbitrary `headers` objects and repeated `extra` objects do not gain
an exemption. Source maps, compiled effective header values and inactive
outer/alias data are checked separately. Other caller dictionaries and broader
schema-scoped admission remain open.

In explicit proxy-DNS mode, a penetrating XHTTP parent replaces its immediate
download's complete socket policy in Core's dialer. Android now preserves the
original child socket options, including dormant SRV strategy and null/absence,
while retaining the active download address and TLS handling. Active parent or
non-inherited child SRV strategies remain restricted. The immediate download
transport must match Core's XHTTP/SplitHTTP runtime cast, with `method` taking
precedence over `network`; inactive outer/alias downloads remain untouched.
Core constructs the immediate download's HTTP client directly, so that child's
own `downloadSettings` is unused even without parent socket inheritance. Proxy
bootstrap stops at that client after preparing its active address/socket policy;
unused grandchildren stay intact. A numeric TCP grandchild regression guards
against applying the new transport check to this inactive data. Broader dormant
chain-graph discovery remains open. This increment passes 186 root Flutter tests,
44 example tests, 293 Android JVM tests and 48 DNS-policy tests for each Apple
package. C++ sanitizer checks, Windows cross-compilation and the eleven-phase
file-only Core/native aggregate also pass. The expanded [controlled XHTTP traffic gate at 025ff2f](https://github.com/XIIIFOX/flutter_vless/actions/runs/39298834353)
passes on Linux, Windows and macOS, with both production preparers on macOS.
Each preparer transfers fresh payloads in both inherited modes and through an
independent download retaining its own socket policy and unused TCP grandchild.
Controlled upload/download fronts verify all five literal header values; exact
per-mode markers, joined cleanup and the existing DNS/TLS/privacy controls remain
mandatory. This qualifies those XHTTP paths, with broader transport handshakes
and device/system-VPN acceptance separate.

The [routing-attribute profile](../tool/fixtures/compatibility/routing-attrs.json)
checks root `routing.rules[*].attrs` as caller data, including Go-folded schema
field names. Legacy cleanup must retain literal keys such as `allowInsecure`
and `xHTTPSettings`, and must not lowercase `network` expressions. These values
are case-sensitive regular expressions in Core. Android also keeps this exact
dictionary outside protected-feature discovery, while real unsupported DNS and
mask paths remain refused. Public import/start/delay checks cover all four
platform adapters; actual Core matcher and native preparation checks qualify
semantics without opening network listeners. Nine public semantic failures and
three Android failures were reproduced first; the resulting 196 root Flutter,
45 example and 299 Android JVM tests pass. The final file-only native/Core
aggregate passes all eleven phases with both preparers and unchanged inputs.
Other caller dictionaries and system-VPN traffic remain separately tracked.

The FakeDNS increment moves owned DNS to `10.0.85.53`, the Windows probe
to `10.0.85.54`, and Apple interface IPv4 to `10.0.85.2/24`, outside Core's
implicit `198.18.0.0/15` pool. Native preparation preserves caller engine/pools
and DNS selection, and enables FakeDNS restoration only on its managed input.
Custom pools overlapping the shared reserved networks `10.0.85.0/24`,
`26.26.26.0/30`, `fd26:26:26::/126` or `fd00:198:18::/64` refuse before bootstrap;
malformed pools and ambiguous fields also refuse. This is an explicit native
namespace reservation. It does not implement dynamic relocation for every
possible caller pool. Direct-name lookups need real DNS or caller static hosts:
Core's ordinary lookups skip FakeDNS; a fake-only root may return NODATA.
The shared five-profile corpus and focused native regressions test preparation.
At `f5acbbc`, the [controlled Core run](https://github.com/XIIIFOX/flutter_vless/actions/runs/39270289950)
passes on Linux, macOS and Windows: two fresh engines carry opaque TCP/UDP bytes
to the recovered domain, return the exact fake IPv4 to the client, retain mixed
real DNS and caller `UseIPv4`, and close their associations before restarting.
This tests an explicit `198.19.0.0/16` pool through native-prepared configurations;
it does not by itself qualify the implicit pool through an OS tunnel.
The implicit pool subsequently passes the [Android TUN run](https://github.com/XIIIFOX/flutter_vless/actions/runs/39271561994)
(41 native tests and three Flutter tests, no skips) and [Windows 2022/2025 TUN run](https://github.com/XIIIFOX/flutter_vless/actions/runs/39271568100)
(all six jobs, 460 passing result rows). Both new gates transfer opaque TCP/UDP
through two fresh sessions and require cleanup before restart. Android runs
without physical capture, so this is not universal physical leak qualification.
The [iOS preview SDK gate at 2ef989f](https://github.com/XIIIFOX/flutter_vless/actions/runs/39275604631)
then passes two fresh FakeDNS TCP/UDP sessions, all twelve ordinary modes,
three counter cases, routing, occupied-port and preflight controls. Its exact
committed log qualifier and forty source hashes are verified independently.
The full job was intentionally cancelled later during the macOS app build;
its macOS runtime was skipped. This qualifies the iOS SDK path, with simulator
and device HEV still link-only. The subsequent [released-SDK gate at 0c11271](https://github.com/XIIIFOX/flutter_vless/actions/runs/39280870346)
confirms both checksum-pinned 26.10.17 SDKs through two fresh FakeDNS TCP/UDP
sessions each, including exact recovered domains, original fake-IP replies and
joined shutdown. The separate shipped macOS HEV fixture also transfers 8 MiB
in each direction, IPv6 TCP/UDP and drains before shutdown. These are verified
canonical runtime outputs; combined Apple HEV/FakeDNS and physical iOS packets
remain open. The earlier `db2ac65` CI run acquired no hosted ARM64 runner and
executed no SDK tests.


The default Android CI job runs the production adapter and five focused
caller-DNS TUN methods in parallel with desktop Core checks: caller DNS,
missing/localhost defaults, direct/selector routing, IPv6 payloads and FakeDNS.
It uses the existing
`--no-capture` mode: functional Wi-Fi DNS/system-policy tests remain mandatory,
while the report explicitly marks physical packet capture unverified. Cellular
capture/handover qualification remains separate because the emulator may not
provide a cellular Network. Strict capture and its verifier remain available in
the default standalone harness. Development-only Core/forwarder composition
also remains an explicit harness option, outside this minimum delivery's gate.

The controlled Android HTTP fixture records bounded connection/relay stages,
error classes and byte counts. Its device test records the HTTP status and
header/body lengths before parsing the event array. These diagnostics retain
the original I/O and parse failures without retries or raw response logging;
they help investigate an empty response without treating it as a DNS success.

On Android the default `config` policy preserves the caller root DNS, including
missing/localhost resolution through the existing protected physical-Network
resolver. The explicit `proxy` policy intentionally selects proxied system DNS.
On Apple and Windows missing/empty/localhost DNS uses a documented native
default, `tcp://1.1.1.1` through the selected proxy. This is an adaptation, not
identical OS-localhost behavior. Other fields on a localhost server entry remain.

The shared [three-case DNS tag corpus](../tool/fixtures/compatibility/dns-default-tags.json)
covers missing, null and empty tags on a localhost server. Core decodes all three
as the same default. Native Apple/Windows preparation must produce identical
effective configurations for them, retaining the root tag, hosts, per-domain
selection and other server settings. Android preserves the source DNS through
its existing protected physical-Network path. Boolean, numeric, array and object
tags remain invalid; Apple rejects them before modifying the profile instead of
silently replacing them with a private tag. File-only preparation is tested
against the pinned Core; the added Apple runtime generation checks the null-tag
form alongside the existing missing-server/restart cases. Its runtime acceptance
is pending CI.

Apple/Windows initially admit numeric UDP/TCP and remote HTTPS/h2c resolvers;
named resolvers need an exact caller-owned IPv4 static hosts mapping. Bootstrap
pins live in private closed routing branches, preserving logical endpoints and
TLS/HTTP names. Unqualified local/QUIC resolver paths, system-family strategies and scripts
fail preparation rather than silently using OS fallback.
The pinned Core has no `tls://` DoT implementation. These limitations, arbitrary
DNS record types and full dual-stack/FakeDNS support remain open; this MVP does not
complete item 1. Test compilation and runtime results are recorded separately.

The numeric IPv4 check also accepts Core's exact IPv4-mapped IPv6 spelling
(`::ffff:1.1.1.1`, including Core's bracket/whitespace parsing), both as a
resolver address, inside TCP/HTTPS/h2c URLs and in its caller-owned static hosts
values. It leaves raw
caller DNS untouched and does not admit genuine IPv6, IPv4-compatible `::x`
addresses or NAT64 prefixes through this IPv4 policy. Three shared positive
cases compare compiled DNS against dotted IPv4 controls; two genuine IPv6
controls retain the desktop admission boundary. Android retains caller DNS for
both families. Controlled DoH uses a mapped static host with the same TLS,
wire-answer, environment-handoff and zero-OS-resolver checks. All three ordinary
Core jobs at [3ab20f2](https://github.com/XIIIFOX/flutter_vless/actions/runs/39205340041)
pass that mapped-host traffic check and the existing DNS/routing/IPv6 controls.
This is controlled Core qualification; physical iOS and full system VPN
acceptance remain separate.

[CI on 6c19e2d](https://github.com/XIIIFOX/flutter_vless/actions/runs/39172041164)
qualifies the production C++ preparer on Linux/macOS/Windows and the Apple preparer on
macOS against ordinary pinned Core: TCP/UDP virtual DNS, numeric TCP/UDP and
named h2c upstreams, per-domain tags, static hosts, endpoint pinning and HTTP
bytes pass with no OS-resolver attempt. Source hashes match that commit.
[Android on c40f4b6](https://github.com/XIIIFOX/flutter_vless/actions/runs/39174414486)
passes all 35 native emulator checks without skips, including both new production
TUN DNS cases: source hosts, root/per-server tags, per-domain selection, TCP/UDP,
OS resolution, HTTP, missing/localhost defaults and clean Stop. The controlled
fixture also proves an unrelated refused query does not kill its worker.
Physical packet capture was explicitly disabled and remains unverified in this
run. The iOS simulator and remote macOS runtime on 6c19e2d pass both HTTP/SOCKS
DNS proxy variants, two generations, non-IP refusal and failure without direct
fallback. This qualifies the minimum DNS increment, not full advanced DNS,
physical Apple VPN routing or encrypted DoH/TLS.

The encrypted DNS runtime gate uses a synthetic HTTPS/HTTP2 resolver with a private
test CA. It requires A/AAAA wire answers over the managed TCP/UDP resolver,
preserved SNI/HTTP authority/path, caller service/tag policy, an independent
transport pin and zero OS-resolver attempts. Fresh bounded child processes
test valid trust, an unrelated CA and a certificate for the wrong name against
the same source/effective configuration. Each child must also retain static
hosts, working proxy traffic and disabled caller counters after TLS rejection.
The trust file is selected only in those disposable Go 1.27 test children;
host trust stores, production DNS policy and public runtime artifacts are
unchanged. Crypto/material, bounded-output and Core Build checks pass locally.
Ordinary Core acceptance passes on all three desktop systems at
[9361270](https://github.com/XIIIFOX/flutter_vless/actions/runs/39184191040).
This does not qualify device-wide encrypted DNS, DoQ, ECH
background lookups or additional production certificate/import APIs.

### Environment names in imported ports and addresses

The [eight-case environment corpus](../tool/fixtures/compatibility/port-env.json)
compares Core port decoding with native reservation and Address lookup. Go uses
simple uppercase one Unicode scalar at a time: `ß` stays `ß`, `ü` becomes `Ü`,
and Greek and supplementary characters retain their upstream alias semantics.
Full Unicode uppercase and ASCII-only conversion can select another variable.
The native adapters use a generated Unicode 17 mapping from the pinned Go
reference, checked against every code point. A read-only generator gate checks
all four emitted regions, including CRLF checkouts, before native compilation.
Port tokens and alias names also use Core's explicit whitespace set.

An existing exact variable, including an empty value, keeps precedence over its
alias. Empty or missing port values remain invalid; missing Address values keep
Core's empty-address behavior. Nested Address `env:` values remain refused to
prevent a second expansion after materialization. Android forwards the same
captured environment into imported port reservation before choosing its private
listener. Apple validation and frozen port binding share one lookup. Windows
reads process variables through UTF-16 APIs instead of the CRT codepage.

The combined environment/schema regression set passes 227 root Flutter,
47 example and 305 Android JVM tests. Both Apple packages pass 15 targeted
port methods; C++ sanitizer checks and MinGW compile/link checks also pass.
The file-only Core/native aggregate passes thirteen phases, including the
eight-case upstream oracle, schema-field controls and generator checks.

At [038615d](https://github.com/XIIIFOX/flutter_vless/actions/runs/39306084830),
all three ordinary Core OS jobs pass the expanded preparation and existing
traffic gates, with both production preparers on macOS. Windows executes the
actual UTF-16 process-environment checks for Unicode, present-empty and missing
values while retaining caller last-error state. Its original endpoint
roundtrip/pinning assertions and all eight port/address/allocation rows pass.
The reader now handles a successful zero-length second read as present-empty;
an exact empty value cannot accidentally fall through to its alias.
Physical-device and service-name/race/recovery acceptance remain separate.
Apple now captures raw native environment entries into immutable byte-keyed
snapshots before Swift dictionary bridging. A causal regression reproduced a
composed key hiding an absent decomposed exact key and its valid alias. Both
platforms now retain distinct spellings, the first byte-identical entry and
present-empty precedence. Host validation, port allocation, address/DNS binding
and provider startup retries share the captured values; only expanded profile
data crosses the persistence boundary. Existing dictionary and closure injection
APIs remain available. Isolated child processes check the actual C reader using
only synthetic environment entries, and host-admission tests mutate the injected
source after capture without changing queued profile bytes. The privacy module
also typechecks against the physical iPhoneOS SDK. These checks qualify native
preparation, rather than a new physical-device VPN session.
This does not complete the full port/address requirement.

### Minimum protocol and transport adaptation

Protected native preparation now recognizes MASQUE's address/port shape and
Core's `direct`/`block` role aliases, retaining the caller's protocol text.
Source DNS/loopback handlers stay in place and no longer hide the selected
proxy's transport. Windows applies its physical binding to a source DNS raw
dialer; loopback remains dispatch-only. XHTTP uses Core's effective method,
preferred alias and extra/download branch, including explicit null values.
An unused primary stream address must not trigger bootstrap; an independent
download address still does.

The shared [nine-config corpus](../tool/fixtures/compatibility/protocols.json)
covers MASQUE/TLS, VLESS with WS/gRPC/HTTPUpgrade, two XHTTP precedence cases
and HTTP alongside internal handlers/role aliases, plus Shadowsocks 2022 with
an explicit null flat address and a valid legacy server. The ninth case adds
XHTTP with parent `sockopt.penetrate` and a separate download port, including an
inactive child socket chain. Android checks this same
corpus in JVM tests. Production C++/Apple export plus pinned Core decode/build
passes locally without a Core instance or listeners. This proves preparation,
not MASQUE/WS/gRPC/HTTPUpgrade/Shadowsocks 2022 server handshakes.
The null-address case first reproduced an Android/Windows rejection: Core
selects the legacy server when its flat address pointer is nil. Both adapters
now follow that choice; malformed non-null values still fail and caller
encryption settings remain unchanged. Apple already followed Core's choice.
[Ordinary Core acceptance at dacfd59](https://github.com/XIIIFOX/flutter_vless/actions/runs/39176129350)
passes on Linux/macOS/Windows: imported loopback HTTP routing and a source DNS
raw relay both carry controlled traffic, with final upstream counts checked
after cleanup. The macOS job exercises both production C++ and Apple preparers.

The pinned Core keeps download socket settings independent unless the parent's
`sockopt.penetrate` is true; only then does it replace the download's settings
with the parent object. Apple/Windows now prepare an explicit XHTTP/SplitHTTP
download in one parent context containing exact upload and download host/port
pins followed by unconditional denial. A caller parent chain carries both
logical destinations instead; only that carrier's physical endpoint is pinned.
The child JSON remains intact and its overwritten socket chain is inactive.
Socket dependency admission also stops at the active immediate download: Core
creates that HTTP client directly and does not recursively dial its nested
download settings. Apple/Windows preserve an unused grandchild's `dialerProxy`
without requiring its tag to exist. Active upload/download dependencies and
cycles still receive their existing checks; Android already stops at this
boundary. This runtime dependency boundary is separate from Core's recursive
configuration Build, which still reads typed TLS certificate references in
nested streams. The controlled independent-download XHTTP case retains the
unused missing-chain settings while carrying its ordinary HTTP payload.
Active download TLS/ECH admission still applies. Dynamic uploads without a
finite endpoint set and non-XHTTP downloads retain the existing refusal.
Missing/null download socket settings on a nonpenetrating parent remain
independent. Controlled CI acceptance adds actual XHTTP/VLESS payloads through
separate HTTP fronts, including a parent SOCKS carrier, with distinct HTTP
authority/path checks and zero OS-resolver attempts. At `cdc5b94`, ordinary
pinned Core passes this packet-up HTTP/1.1 gate on Ubuntu, Windows and macOS,
including both production preparers on macOS. Each variant echoes 57,344 bytes
in both directions. This does not qualify additional XHTTP TLS/HTTP3/QUIC
server handshakes, TUN traffic or physical iOS packets.
Each controlled client runs in its own bounded process: Core's system dialer
uses process-global DNS/handler state, and XHTTP detaches some request lifetimes
from session cancellation. This keeps backend resolution and later tests
independent. Failed clients retain bounded front response/status, packet sequence,
consumed body length, origin entry and backend log evidence. The controlled
server's explicit final rule allows only TCP to the allocated origin IP and
port, since Core blocks private targets after VLESS by default. All other Core
defaults and client restrictions remain in force. An origin success event
requires the complete body. The existing deadline and DNS counts stay strict.
WG/XDRIVE and the exhaustive protocol matrix remain unqualified.
Pinned Core requires one receiver/user in the relevant `servers`/`vnext` arrays;
multiple independent outbounds with a balancer are a different supported shape.

### Minimum full configuration preservation

Caller `api` (tag, listener and services), `stats` and `policy` subtrees remain
intact during VPN preparation, including explicit null, disabled flags,
levels-only policy and nested field spelling. Library statistics defaults are
added only when the respective root section is absent. Normal sessions retain
caller services; the standalone delay probe still omits API/metrics listeners
to avoid rebinding a live session's ports.

Android/Windows create and query a private statistics endpoint only when the
source has no API section. They do not query an imported API, even if it has
StatsService and a loopback listener. An explicit API/null or caller policy
may therefore leave the example's counters at zero; this does not prevent VPN
startup. The session-owned counter increment below replaces broad accounting;
a public availability signal remains separate work. Apple uses its existing
in-process reader.

The shared [six-case full-config corpus](../tool/fixtures/compatibility/full-config.json)
checks these source sections after native preparation and against pinned Core
decode/build. Runtime acceptance additionally requires a caller StatsService
to remain available while HTTP/DNS traffic flows and disabled counters to stay
disabled. [Ordinary Core acceptance on 8ed2b7e](https://github.com/XIIIFOX/flutter_vless/actions/runs/39178340305)
passes this check on Linux/macOS/Windows, including both native preparers on
macOS. [Windows service acceptance on 1c2c490](https://github.com/XIIIFOX/flutter_vless/actions/runs/39177932558)
also passes proxy/portable and VPN tests on Windows 2022/2025 with working
traffic after rejected replacement and disabled caller counters unchanged.
This baseline did not qualify source-inbound context selection or an explicit
VPN default. Their subsequent implementation and acceptance are described below,
alongside nonempty prefix isolation.

The next increment reads Android and Windows VPN/proxy counters by the exact
inbound selected for that session, rather than a literal outbound name or a
sum of all caller inputs. Apple proxy-only uses the same identity rule through
its in-process reader; Apple VPN continues to report HEV packet counters.
Untagged or ambiguous proxy inputs remain unchanged and have unavailable
statistics. Apple text-format counters also reject a CR/LF-bearing tag as
unavailable because its line representation is ambiguous.

Uplink and downlink availability are independent internally. A present Core
JSON counter with an omitted `value` is zero; a missing record is unavailable.
Invalid, duplicate, negative or overflowing values invalidate only their
direction. Baselines clear on Start, Stop, unavailable samples and counter
resets, so the first speed sample after a gap is zero. The six-field public
status remains compatible and represents unavailable totals numerically as
zero. Adapter stream bytes can include SOCKS framing and are not promised to
equal application or TUN payload bytes.

Caller API/stats/policy sections, including explicit null, false and levels-only
policy, remain intact. Only an absent policy root receives inbound counter
defaults alongside the existing outbound defaults. Android/Windows query only
their own API; Apple queries Core directly. No caller counters are enabled to
fill a display.

The [shared eleven-case wire corpus](../tool/fixtures/compatibility/traffic-counters.json)
matches the pinned Core CLI encoder without starting a Core instance. Local
actual-consumer checks pass 15 Android tests, 92 checks per Apple platform and
Windows source/wire/consumer gates of 4/11/12, plus 47 Windows fixture tests.
These are inert checks and compile/link evidence. New remote runtime gates
require Android enabled/disabled TUN payload sessions, three proxy payload
cases on each Apple SDK and Windows counter samples after the existing proxy, portable
and VPN HTTP requests. Windows enabled cases require an available snapshot
before the requests and a fresh increase in both directions afterwards; the
observation window can also include managed health probes, so it does not
claim exact HTTP-only byte attribution.
[Windows acceptance at 2775207](https://github.com/XIIIFOX/flutter_vless/actions/runs/39256146812)
passes all six jobs and 442 result rows on Windows 2022/2025, including the
new 4/11/12 native consumer markers and 2/2/4 proxy/portable/VPN counter gates
per system. The new iOS three-case counter gate and joined origin counts pass
at [7bf540e](https://github.com/XIIIFOX/flutter_vless/actions/runs/39258113463),
but that job later stops in `delay/none` with only 11 of 12 ordinary modes
recorded; the console process's zero status does not identify the app's exit.
The earlier 6dfb96f Apple job passes all steps, including the macOS counter
qualifier, with the same production sources.

Android's first attempt stops after successful APK installation but before
Flutter test entry and qualifies none of the 40 native runtime cases. At
[b7d2126](https://github.com/XIIIFOX/flutter_vless/actions/runs/39259088156),
Flutter passes all three tests, 27 native cases pass the strict harness and
the new counter method itself passes JUnit: both totals grow with enabled
policy and remain zero for two fresh disabled-policy samples. The harness
then rejects extra completion-status messages used for diagnostics, leaving
12 later native cases unexecuted. Diagnostic values now use separate result
bundle keys; the strict completion count remains unchanged.
[The complete Android follow-up at 02136f1](https://github.com/XIIIFOX/flutter_vless/actions/runs/39262231663)
passes three Flutter tests and 39 native cases, including the counter method,
all later DNS/system-policy cases and both routing cases. One cellular-handover
case is skipped because the emulator has no cellular Network; Wi-Fi restoration
and cleanup assertions still run.
[The Apple follow-up on the same production sources](https://github.com/XIIIFOX/flutter_vless/actions/runs/39262254253)
passes all twelve ordinary modes and all three counter cases per SDK, both
routing/held-port gates, unsigned apps and the macOS HEV packet/cleanup checks.
The optional iOS phase receipt is unavailable in that run; strict stdout remains
the acceptance authority. Neither earlier failed run is reclassified, and their
unproven interruption causes remain unproven.

The inert pinned-Core Router regressions explain why those two options need a
runtime seam: an appended default rule prevents `IPIfNonMatch` from reaching its
DNS/IP matching pass, and Core's loopback changes `SkipDNSResolve`. Neither is
an equivalent transfer of the original inbound context. The tests exercise the
actual Router and a test-only context/default model, including live API rule
changes. They do not enable a public routing option or claim packet acceptance.

The separate [optional source overlay](../third_party/xray-vpn-routing/README.md)
now binds the exact private handler to its Core instance and preserves that
binding across authentication, sniffing and asynchronous mux lifetimes. Native
private guards precede forced detours; the unchanged live caller router receives
only an inbound-tag view, with an explicit default after its complete miss.
Pure regressions cover the actual DNS/IP router pass, API additions/removals,
foreign-instance rejection, revocation and actual inert mux-session cleanup.
The isolated TCP/UDP/DNS byte fixture passes all four scenarios on Linux and
macOS at [78ade5c](https://github.com/XIIIFOX/flutter_vless/actions/runs/39214337019),
with exact committed sources, drained workers and zero OS-resolver attempts.
Windows closure assertions now recognize typed `WSAECONNRESET` and
`WSAECONNABORTED` only on Windows, with pure controls retaining timeout and
unknown-error rejection. All three Core runners pass the routing and constructor
fixtures at [ada26d6](https://github.com/XIIIFOX/flutter_vless/actions/runs/39218706245),
using identical copied Core source bytes and drained resources.
At that stage, native launcher/capability integration and device acceptance
remained open; the seam alone did not enable a public routing option.

The optional constructor also revokes its owner and closes partially created
Core features when `NewWithContext` fails, preserving the original error.
Unseeded constructors retain upstream behavior. Inert cleanup tests pass;
the actual early-construction failure fixture passes on all three Core runners
at [9bfe38b](https://github.com/XIIIFOX/flutter_vless/actions/runs/39216266631).
The subsequent ada26d6 run also passes the routing traffic and cleanup scenarios
on all three systems, including the Windows closure assertions above.

The shared mobile factory now validates a strict launcher-owned spec against
the digest of the final JSON and retains the exact compiled private inbound.
It clones selected private guards, derives the source alias from the selected
compiled inbound, and validates the optional explicit default outbound.
The optional factory seals before Start and publishes only after success;
Stop revokes the owner before Core.Close. Both ordinary and optional artifacts
pass pure lifecycle/spec/preflight checks. Default artifacts report capability
zero; the optional tagged artifact reports one. A disposable iOS preview also
compiles device/simulator bridge headers. The actual factory traffic,
active-candidate rejection, bounded Stop and fresh restart fixture passes all
four cases on Linux, macOS and Windows at ada26d6. Each run uses the committed
source (including Windows checkout line-ending conversion), completes cleanup
and records zero OS-resolver attempts. That factory run preceded native
Android/Apple/Windows adoption of the new check/start ABI, described below.

The additive CLI now shares that factory's config/spec validation and lifecycle.
Ordinary/capable builds pass registration, stock-version, capability and real
decode/build Check controls, plus fake-backend cancellation/Stop tests. These
safe CLI checks construct no Core; all three Core runners pass them at
[8cf9ef8](https://github.com/XIIIFOX/flutter_vless/actions/runs/39222171801).
Foreground CLI traffic and native launcher adoption remain separate. The Apple
static archive fixtures pass locally on arm64/x86_64. CI exposed a same-address
weak-entry alias being rebound with the strong runtime symbol. The fallback
anchors now use distinct alternate-entry offsets. At
[5c41b3e](https://github.com/XIIIFOX/flutter_vless/actions/runs/39226845029),
the remote Xcode 26.6 linker passes all 16 arm64/x86_64 link-and-run cases and
both object-shape checks, including partial and unknown-capability refusals.
Capability probing does not trial Start or Check, and unsupported Start returns
a fixed error.

Disposable Android and desktop builders can now compose the same optional
routing factory and CLI. Android requires `XRAY_NATIVE_ROUTING=1` and an explicit
`TARGET_DIR`; the ordinary build remains unchanged. The desktop builder writes
to a new directory and supports Linux, macOS and Windows targets. Both use
verified copies of the pinned Core/mobile sources and retain source/cache
integrity receipts. Android x86_64, Darwin arm64 and Windows amd64 artifacts
compile locally without executing them. These are unpublished build paths;
these build results alone did not qualify native launcher adoption.

Apple preparation can also freeze a native-only routing intent after all
adapter and DNS transformations. Its metadata hashes those exact final bytes,
maps the original inbound index explicitly, and records only rules inserted by
the preparer. A caller rule with a matching service name does not become a
private guard. Mirrored pure tests cover this metadata, ordinary preparation
and DNS. Both actual iOS and macOS preparation modules export synthetic pairs
which pass the shared Go Check on the remote macOS runner without constructing
Core. Native consumer runtime and device traffic acceptance are tracked below.

Matching native-only Kotlin and C++ encoders retain that same byte/digest and
selection contract. Focused JVM and portable C++ tests exercise their ordinary
path, immutable inputs, explicit source mapping and guard/default refusals;
both synthetic exported pairs also pass Go Check without constructing Core.
The C++ Windows hash implementation uses BCrypt; all 42 checks pass under real
Windows/MSVC, and its exported pair passes Go Check. Android passes 202 JVM
checks, including the 11 encoder cases, and its exported pair also passes Go
Check. CI pairs each platform's metadata producer with the shared Go validator.
Those codec results alone did not qualify native consumers.

The subsequent implementation adds per-session `VpnRoutingOptions` to Dart and
all native launchers. A strict selection-only channel map identifies the
original inbound and exact default tag; it cannot supply private metadata.
Native preparation records only its own DNS/probe guard indices, freezes the
final bytes and digest, and uses that same pair for Check and Start. Requested
routing requires capability one before profile/state publication or old-session
replacement, without a legacy fallback. Recovery rebuilds and checks a fresh
pair; quick profiles retain the user selection. Ordinary omitted-option paths
retain their existing runtime. The example exposes both choices and keeps
stale selections visible. Local causal/fake admission, codec and compile/link
checks pass; enabled-runtime results are recorded below.
Published runtime artifacts remain unchanged, so this does not yet qualify the
option for a released application or complete long-term requirement 4.

The enabled Windows consumer at
[`64e8cff`](https://github.com/XIIIFOX/flutter_vless/actions/runs/39240980181)
passes on Windows 2022 and 2025: 213 proxy/portable/VPN result rows per system,
including all eight routing rows, native adoption, final preflight, owned parent
stdin and strict IPv6 cleanup. Its selected-source, selected-default, rejected
replacement and restart checks use the unpublished capable CLI. The separate
Core jobs at the same commit pass on Linux, macOS and Windows. Enabled iOS
simulator routing also passes both source variants, TCP/UDP DNS, rejected final
bytes, restart and joined origin counts of 3/9 with zero DNS-trap connections.
The Apple job still fails later: the ordinary `delay/none` case does not report
completion after its entry marker. Eleven other ordinary modes pass; subsequent
macOS checks do not run. The Android ordinary 37 native and three Flutter cases
pass, but both new routing methods time out before their first HTTP response.
Origin request completion was not recorded, so the connection's cause remains
unknown. The next fixture restricts caller traffic to controlled port 18083;
private DNS/probe guards must still precede the caller's blocking rule. These
results do not replace physical-device checks.

The subsequent [Apple job at e5f9fc6](https://github.com/XIIIFOX/flutter_vless/actions/runs/39244500636/job/118033023701)
passes both enabled SDK runtimes, unsigned example builds and all 12 ordinary
modes on each platform. Tagged and untagged original-source selection, a
nonfirst default, TCP/UDP DNS guards, rejected final bytes and exact-pair restart
pass on iOS simulator and native macOS. Joined controlled origins record 3/9
requests and connections with zero DNS-trap connections. Both variants keep an
owned TCP listener on 10808 while Core uses another private port. The shipped
macOS HEV also transfers 8 MiB in each direction and IPv6 TCP/UDP, then shuts
down cleanly. The 20 Apple source inputs are unchanged in 2f74f13. These SDK
checks do not substitute for physical iOS or full Apple system-VPN acceptance.

At [2f74f13](https://github.com/XIIIFOX/flutter_vless/actions/runs/39247496850),
Android passes all 246 JVM tests, 37 ordinary and two enabled-routing native
tests, and three example Flutter tests, without skips. Both routing tests retain
owned listeners on preferred ports 10807/10809 and require actual alias/default
traffic, private guards, rejection without replacing the live PID, a fresh
recovery pair, exact accepted-request counts and Stop cleanup. The ordinary
domain-routing test also passes. Its statistics fixture derives the endpoint
from the owned final config instead of assuming port 10809; the numeric chosen
port is not retained in the successful artifact. Separate-UID authentication
controls and emulator cleanup pass. The same run passes all three desktop Core
jobs and the Windows plugin build. These are unpublished capable runtime checks.

The final-config preflight baseline at `4f887ae` passes the three Core jobs,
Dart, Android JVM, unsigned Apple builds/runtime and Windows plugin checks.
Its Android tile fixture did not establish active listening after registration;
the focused `a7bc584` follow-up corrects that setup and passes all 37 native
cases plus three Flutter cases, without skips. Windows 2022/2025 also pass the
410 ordinary proxy/portable/VPN result rows and exact final preflight checks.
These baseline results do not substitute for the new enabled-routing gates.

The Android emulator at 5c41b3e passes 36 native cases and three Flutter cases,
including the four protected system-DNS scenarios. One native case skips because
the emulator has no cellular network. Its finally block completes the Wi-Fi
restoration and controlled HTTP assertions before that skip is reported;
cellular traffic remains unverified. This does not identify the earlier
intermittent empty HTTP ready response.

The earlier ada26d6 Apple privacy app stopped reporting after ten of twelve
modes. The fresh 5c41b3e run passes all twelve modes on both ordinary iOS and
macOS SDKs, plus the DNS generations, direct/proxy and custom-asset markers.
The fixture guards its owned client sockets against SIGPIPE and records each
mode's entry; the successful rerun does not establish the cause of the earlier
termination. A failure-only collector retains bounded metadata for the exact
test bundle/process/PID while preserving the original failure and uninstall.

All eight CI jobs pass at 5c41b3e, including actual shared factory traffic on
Linux/macOS/Windows, unsigned iOS/example builds and remote macOS HEV traffic.
The Apple SDK runtime acceptance uses ordinary capability-zero artifacts;
factory-capable SDKs are not yet qualified through native consumers. iOS HEV
is compile-only here, not physical-device packet acceptance. No local Mac VPN,
OS network settings, emulator or device were used for this run.

The fifth case adds an explicit null tag on the default direct outbound. Core
decodes this as untagged; Windows previously rejected it before preflight.
Windows now skips null tags during named-chain validation and treats a null
remote tag like an absent tag for its existing private-name allocation. Invalid
non-null types and broken chains still fail. Shared native preparation and
Android checks retain the untagged direct default, outbound order and caller DNS.
This is a focused compatibility increment, not new remote-protocol handshake
qualification.

The sixth case adds a named DoH resolver with an exact `full:` static hosts key.
Windows previously rejected this Core-supported form. Apple already admitted
it but also accepted an uppercase prefix which Core treats as part of a literal
domain name. Native checks now recognize only the literal lowercase `full:`
prefix, then apply DNS domain lowercasing independently of JSON schema folding.
The original hosts map, URL, server tags and query strategy remain unchanged.
Pure checks use the pinned Core's actual inert static-host matcher, including
wrong prefix/FQDN and Unicode controls; the existing HTTPS fixture adds a full-key
positive child alongside its bare-key trust/name controls.
[Core acceptance on 3188183](https://github.com/XIIIFOX/flutter_vless/actions/runs/39192554787)
passes the full-key HTTPS case on Linux, macOS and Windows, including both native
preparers on macOS. This does not qualify device-wide encrypted DNS.
Named resolvers without a qualifying static map
and broader DNS bootstrap routing remain separate work.

Listener address increment: native preparation now expands only imported
`inbound.listen` environment references before deciding whether a listener
occupies TCP ports. Apple also freezes that value before saving a profile for
its separate extension process. The caller's source stays unchanged; the
effective listener retains its other fields. Exact-name lookup precedes the
normalized alias, an explicitly empty value wins, and missing values become
Core's empty/AnyIP address. Unix listeners no longer consume or remap an ignored
TCP PortList. Outer brackets and whitespace are interpreted for classification
as Core does, without changing the stored resolved text.

The [six-case address corpus](../tool/fixtures/compatibility/listen-addresses.json)
is checked with pinned Core decode/build and native preparation. Recursive
environment listener references are rejected: Core interprets the first result
as an address, while freezing and reparsing it could otherwise expand it again.
ASCII normalized aliases are qualified; Apple/Windows explicitly reject a
non-ASCII alias when the exact key is absent. Wider Unicode alias parity remains
separate work. Ordinary Core acceptance on 8ed2b7e also carries actual HTTP bytes
through an environment-based Unix listener on all three desktop test systems,
alongside the existing HTTP/DNS/API checks. Other address fields and environment
references are outside this increment.

Core decode/build acceptance alone does not establish a listening protocol:
the pinned SOCKS handler advertises TCP, while its HTTP handler advertises TCP
and Unix. The pure address corpus checks Core's port semantics; the runtime
Unix fixture deliberately uses HTTP.

### Minimum external data adaptation

The existing `geoAssetsDirectory` argument now reaches Android and Windows
preflight, startup and recovery/quick-profile paths as well as Apple. An explicit
root must be an existing absolute directory. Both Core data-root aliases select
that directory in owned child processes; inherited settings cannot override the
argument. Bundled data is copied only for Android's legacy default path, never
into an explicit caller directory. Android/Apple standalone delay uses the same
selection; Windows standalone delay remains unsupported.

Apple no longer requires unrelated `geoip.dat` and `geosite.dat` files when
selecting a directory. Core validates the data actually referenced by the
configuration, including custom `ext:` GeoSite files. An empty directory is
valid for an asset-free profile. Apple VPN providers still require an
extension-readable App Group path; callers must retain data until Stop completes.
Certificate/key lookup uses Core's independent certificate root. Managed
asset-import/copy lifecycle remains open.
Custom-only Apple roots require the rebuilt unpublished Core preview; published
framework URLs and checksums remain unchanged during this acceptance phase.

`certificateAssetsDirectory` is a separate optional per-start/per-profile-delay
resolution base for TLS `certificateFile` and `keyFile`. Every backend binds
relative references before native preflight and preserves the resulting paths
for runtime/recovery/quick access. It follows Core's effective TLS and recursive
XHTTP download Build branches, including alias and `extra: null` precedence.
Absolute paths, inline material, file-over-inline precedence and reload flags
remain intact; an omitted option retains existing lookup. Native capability
negotiation prevents an older backend from ignoring the option.

The directory must already exist and be absolute. It is not a sandbox: relative
`..` retains Core's normal path semantics. Files stay caller-owned and must
remain readable through Stop, including background reload; Apple VPN needs App
Group access. Core preflight checks referenced files before replacing a session.
No global certificate root, trust store or file-copy lifecycle is changed. This
increment covers StreamConfig TLS file fields and the TLS configurations owned
by `finalmask.udp` Realm and XDNS resolvers. Other masks, TCP mask lookalikes and
arbitrary metadata remain untouched, including unknown mask type values that
resemble known schema names.

The [eight-case shared certificate corpus](../tool/fixtures/compatibility/certificate-paths.json)
checks complete JSON preservation and pinned Core protobuf equivalence, with
missing-root/file controls and source immutability. Realm/XDNS relative-file
cases reproduce the old native preparation failure; literal absolute controls
and missing-file Core Build checks distinguish path binding from protocol
handshake acceptance. Native regressions retain folded keys, effective XHTTP
downloads, nulls and opaque lookalikes. Realm/XDNS handshake, physical file
access and background reload remain separate acceptance work.

The controlled DoH runtime
also uses a TLS-wrapped caller proxy whose explicit CA file is bound through the
native helper; DoH trust/name rejection remains independent. In the
[ca96891 CI run](https://github.com/XIIIFOX/flutter_vless/actions/runs/39211822084),
ordinary pinned Core passes all four trust/name variants for each preparer:
C++ on Ubuntu, Windows and macOS, plus Swift on macOS. All 16
`TLS_CERTIFICATE_ASSET_BYTES_PASS` markers are verified against the exact
committed sources. This qualifies controlled CA-file loading and TLS traffic;
physical Apple certificate access and background reload remain unqualified.

The shared [synthetic custom GeoSite fixture](../tool/fixtures/compatibility/asset-files.json)
contains one full domain and no standard GeoDAT files. File-only native
preparation and pinned Core build require a missing-root failure followed by
success with the selected custom-only root. Android TUN, Apple proxy and Windows
runtime fixtures require actual HTTP traffic whose route depends on that custom
file. [Android on cecac3a](https://github.com/XIIIFOX/flutter_vless/actions/runs/39179227305)
passes both caller-root TUN cases within 35 native checks. [Windows on cecac3a](https://github.com/XIIIFOX/flutter_vless/actions/runs/39179235345)
passes 366 proxy/portable and VPN rows on Windows 2022/2025, including the custom
root and rejection without replacing a working session. [Apple on bea89db](https://github.com/XIIIFOX/flutter_vless/actions/runs/39180284967)
passes the custom-root traffic marker on iOS simulator and remote macOS with the
rebuilt unpublished Core. Windows explicit-root recovery/quick-profile paths
have source/compile coverage, not a separate explicit-root runtime qualification.

### Minimum IPv6 payload adaptation

Private address DNS delegates A and AAAA to the unchanged caller DNS root. An
explicit `UseIPv4` remains authoritative. Android captures IPv6 with a tunnel
ULA and default route. Apple keeps its existing IPv6 capture; Apple/Windows
remove the managed blanket IPv6 block before caller routing. Windows adds an
owned ULA and split default routes, and permits IPv6 only on the exact tunnel
LUID while retaining its physical IPv6 block. Failed address deletion retains
cleanup ownership and prevents a replacement from claiming the old address.

Android keeps its existing descriptor protection and protected OS DNS; Apple
keeps Network Extension capture and Core's existing provider egress. Intentional
caller-selected Core direct IPv6 is distinct from application bypass. Windows
physical IPv6, including direct Core IPv6, remains blocked in this slice. This
increment does not introduce a new family restriction for imported listeners
or already accepted transports on Android/Apple.

The shared [two-config corpus](../tool/fixtures/compatibility/ipv6-payload.json)
checks both DNS strategies against production preparation and pinned Core Build.
Regression tests first reproduced AAAA suppression and managed IPv6 blocks.
Local preparation passes for both C++ and Apple exporters without starting Core.
Android passes 139 JVM checks and a third caller-root device fixture in CI.
Apple pure policy checks and both shipped HEV fixture targets compile. Windows
policy, cleanup and runtime-fixture checks pass locally without running VPN.

New remote runtime gates require actual IPv6 TCP/UDP payloads through an IPv4
proxy, exact targets/nonces, and preserved caller AAAA policy. Separate HEV
binary checks exercise framed IPv6 TCP/UDP packets on macOS. The shared fixture
also compiles for physical iOS; the simulator slice only supports linking.
Windows also rechecks bytes after recovery and route cleanup; failed address
deletion ownership has separate production-helper unit coverage.
[Ordinary Core on aeae2c0](https://github.com/XIIIFOX/flutter_vless/actions/runs/39182393132)
passes IPv6 TCP/UDP over IPv4 VLESS on Linux/macOS/Windows, with both caller DNS
strategies and both production preparers on macOS. Source hashes match the
commit, caller counters remain disabled and no OS resolver is attempted.
[Windows service acceptance on aeae2c0](https://github.com/XIIIFOX/flutter_vless/actions/runs/39182405856)
passes all six jobs and 386 proxy/portable/VPN rows on Windows 2022/2025,
including 155 VPN rows per OS. IPv6 payload and AAAA, underlay rename, both
worker recoveries and physical-interface blocking pass.
[Android TUN on aeae2c0](https://github.com/XIIIFOX/flutter_vless/actions/runs/39182393132)
passes all 36 native checks without skips, including actual IPv6 TCP/UDP and
caller AAAA. Three Flutter checks and separate-UID authorization controls also
pass. Physical capture is explicitly unverified; cross-UID IPv6 bypass is a
separate qualification requirement.

The same run passes all iOS simulator Xray/privacy checks, then the new HEV
packet fixture fails before its first IPv4 packet. Inspection of the original
checksum-pinned Tun2SocksKit 5.15.0 archive proves its simulator slice is a
link-only stub: all main entrypoints return `-2`. The compiled device/macOS
slices are real implementations. CI therefore links the simulator packet
fixture without claiming runtime support; the script still fails if an actual
stub runtime is requested. A device compile-only target prepares that same
fixture for later physical acceptance without installing or launching it.
The physical iOS packet gate remains pending, and the first remote macOS HEV
gate was not reached after the simulator failure.
[The later ba25f85 run](https://github.com/XIIIFOX/flutter_vless/actions/runs/39185610755)
passes actual remote macOS HEV framing, IPv4 bulk in both directions and IPv6
TCP/UDP targets/nonces through IPv4 SOCKS, with clean shutdown. This is a shipped
packet-engine qualification, not a full macOS Network Extension VPN test.
Physical iOS packet acceptance, IPv6-only endpoints, NAT64, cross-family
handover and physical IPv6 bypass qualification remain open. The physical
iPhone and host Mac VPN are not used by this increment.

The preceding [bea89db Android run](https://github.com/XIIIFOX/flutter_vless/actions/runs/39180284967)
passes 34 native checks and three Flutter checks, including caller DNS/assets,
but fails one strict Always-on readiness check with `AUTH_PROBE_FAILED`. Its
bounded logs do not identify the underlying error. The later aeae2c0 strict
Always-on case passes; the earlier failure's cause remains unproven.

An independent test-first Android regression reproduces a local-listener race:
the FD-protection acknowledgement precedes Core listener startup. Startup now
uses one five-second budget for authenticated SOCKS and both private/packet
challenges, tied to the original session generation and exact live Core child.
Only a native `ECONNREFUSED` at the initial local connect can wait/retry that
same process. Permission failures, unknown causes, auth/protocol/token errors
and post-connect timeouts fail immediately; periodic checks remain one-shot.
An owned deadline task closes only readiness sockets and is drained on exit.
Strict disabled recovery still does not relaunch workers. All 164 JVM checks
and the test APK compile pass; the startup runtime gate passes on
[9361270](https://github.com/XIIIFOX/flutter_vless/actions/runs/39184191040).
Diagnostics retain fixed numeric stage/errno metadata without raw errors,
credentials or tokens. The specific H-before-listener gap does not apply to
Apple's synchronous Core Start; Windows already has a bounded startup check.

### Encrypted DNS and direct-only increment

[Ordinary Core acceptance on 9361270](https://github.com/XIIIFOX/flutter_vless/actions/runs/39184191040)
passes named HTTPS DoH on Linux, macOS and Windows, using production native
preparation and an owned TLS origin. It verifies SNI/Host/path, caller A/AAAA
policy, and refusal for untrusted and wrong-name certificates without an OS
resolver fallback. macOS checks both C++ and Apple preparers. This is Core
acceptance, not a device-wide DoH or additional protocol matrix qualification.

Apple and Windows now admit profiles with only `freedom`/`direct` and
`blackhole`/`block` handlers when caller DNS is explicit and supported. A
physical proxy endpoint is required only for the existing native default-DNS
replacement, so missing/empty/localhost DNS without a qualified proxy still
fails preparation. The caller's first outbound stays first; no default direct
or proxy handler is guessed. Existing physical IPv4 dialing adaptation remains.
Android already admitted these profiles and gains the same shared regression
cases. [The two-case corpus](../tool/fixtures/compatibility/direct-only.json)
covers a direct default and a blocked default with explicit domain/DNS routes.

Test-first checks reproduced the Apple/Windows rejection, then passed after
the minimal admission fix. File-only native preparation and pinned Core Build
pass with both exporters, alongside Apple pure suites, Android JVM/APK and
Windows sanitizer/crosscompile checks.
[The ba25f85 CI run](https://github.com/XIIIFOX/flutter_vless/actions/runs/39185610755)
passes ordinary Core on all three desktop systems, both native Apple runtime
fixtures and Android's 165 JVM, 37 native and three Flutter checks. Both new
direct-only profiles pass Android TUN traffic and native Apple HTTP/DNS/block
checks. [Windows runtime acceptance](https://github.com/XIIIFOX/flutter_vless/actions/runs/39185622126)
passes all six jobs and 406 proxy/portable/VPN result rows on Windows 2022/2025,
including both new direct-only TUN sessions and their explicit Stop cleanup.
Controlled origins and final drained counts make a timeout alone insufficient
blocking evidence. Physical device and full system-VPN qualifications remain
separate from these scoped gates.

### Nonempty selector prefix isolation

Android, iOS, macOS and Windows now allocate private service tags outside known
nonempty `routing.balancers[].selector`, `observatory.subjectSelector` and
`burstObservatory.subjectSelector` prefixes. Field matching follows Core's
schema aliases; tag prefixes remain case-sensitive UTF-8 values. Caller
selectors, source outbound order and settings are not rewritten. Existing
preferred private names remain when safe; a covered name or collision suffix
uses a deterministic unused leading scalar.

The [nine allocation cases](../tool/fixtures/compatibility/selector-prefixes.json)
reproduce the previous selection pollution and pass after the change. They
cover comma-list parsing, folded schema keys, unrelated user maps, suffix
collisions and Unicode. A file-only check exercises the pinned Core's actual
outbound manager with inert handlers: private handlers remain explicitly
addressable, selection is unchanged and later public additions still invalidate
the selection cache. It creates no Core instance or network workers.

The [controlled traffic profile](../tool/fixtures/compatibility/selector-traffic.json)
selects a caller direct handler through a `flutter-vless` round-robin prefix.
Core, Android, Apple and Windows runtime fixtures require actual HTTP and DNS
bytes, caller domain blocking and bounded cleanup for that profile. Ordinary
Core acceptance passes on all three desktop systems in
[3d6da94 CI](https://github.com/XIIIFOX/flutter_vless/actions/runs/39189818021).
[Successor a475374 CI](https://github.com/XIIIFOX/flutter_vless/actions/runs/39190514531)
passes Android's 168 JVM, 37 native and three Flutter checks, both Apple native
fixtures including the third balancer profile, and the existing remote macOS
HEV packet gates. [Windows runtime](https://github.com/XIIIFOX/flutter_vless/actions/runs/39190539040)
passes all six jobs and 410 proxy/portable/VPN rows on 2022/2025, including the
third balancer session and final drained origin counts. Physical iOS packet and
full macOS system-VPN acceptance remain separate.
An empty selector (`[""]`, including a null array element decoded as an empty
string) matches every tag. Naming cannot isolate it. Universal prefix coverage
also remains open; complete support needs construction-owned handler provenance
inside Core, including the Windows packaged runtime. Selectors are never frozen
to a static list, and valid profiles are not rejected for this limitation.

Port grammar progress (2026-10-18): the Dart, Kotlin, Swift and C++ paths now
share a 20-case corpus checked against the pinned Core decoder/build path.
It covers lists/ranges, numeric zero, native `env:` lookup and its normalized
alias, Unicode whitespace, empty lists and malformed values. Private allocation
does not reserve ignored TCP ports for Unix listeners. Apple binds environment
port references from the containing application's environment before encrypted
session persistence, so a separately launched provider does not need that
environment. The caller's source document is unchanged; missing references fail
with a redacted `inbounds[index].port` error before VPN startup.

A physical iPhone check used both a literal port list/range and an environment
range with a supplied VLESS profile and fresh Safari traffic. This is progress
on item 5, not completion of it: OS bind races, remaining service-listener ports,
tag namespaces and proxy-only selection still need acceptance. Parser/build
acceptance is distinct from a functioning listener: this Core's SOCKS inbound
advertises TCP, while its HTTP inbound also supports Unix sockets. See the
[pinned Core port parser](https://github.com/XTLS/Xray-core/blob/92ccc939aaf4f8965f369cf0b142e005aeaa11d5/infra/conf/common.go)
and [inbound implementations](https://github.com/XTLS/Xray-core/tree/92ccc939aaf4f8965f369cf0b142e005aeaa11d5/proxy).

Typed endpoint address progress (2026-10-19): Apple and Windows bind native
`env:` references in the selected protocol server address and active immediate
XHTTP download address before physical bootstrap. Apple also freezes these
values before saving a session for its provider process. Android applies the
same binding in explicit proxy DNS mode; default config mode already passes
the original Address to Core. Exact environment keys, including empty values,
take precedence over the normalized alias. Lookup happens once; a result that
would trigger another `env:` lookup on re-decoding is refused. The raw expanded
text stays in the effective JSON; endpoint checks use Core's bracket-before-
whitespace parsing order. Other caller policy, ignored stream addresses and arbitrary
strings such as Host, paths and WireGuard's plain endpoint are unchanged.
Three shared cases compare pinned Core protobufs and complete native prepared
profiles against literal controls. The controlled XHTTP chain also changes the
client process's environment after preparation and requires the original
upload, download and carrier destinations to carry the payload. File-only
equivalence and runtime acceptance remain distinct evidence.

Root DNS address progress: the selected typed fields also include string DNS
servers, object server `address`, root/per-server `clientIp`, and scalar or array
values in `hosts`. Apple and Windows freeze these fields before protected
preparation; Apple freezes them before profile persistence. Android binds them
in caller config mode before validating FakeDNS engine/pool compatibility. Its
explicit proxy DNS mode still replaces the caller root by request. Server options, host-map
keys, array order, tags and embedded `env:` substrings in URLs remain intact.
Core's first domain-valued hosts array entry retains alias precedence over all
IP entries. Guards inspect Core's parsed address while effective JSON keeps the
expanded raw value. No new DNS transport or physical fallback is enabled.

The three [shared DNS Address cases](../tool/fixtures/compatibility/dns-addresses.json)
compare pinned Core DNS protobufs and complete prepared profiles with literal
controls, then change the receiving environment and require identical compiled
DNS. The controlled HTTPS DoH fixture also freezes its server and `full:` host
mapping before starting the child with different environment values. On
[fdf936c](https://github.com/XIIIFOX/flutter_vless/actions/runs/39201573852),
all three ordinary Core jobs pass that handoff and the existing IPv6, routing
and XHTTP payload controls. Native platform and physical-device qualification
remain separate from this controlled Core proof.

Logical handler destination progress: DNS outbounds and imported
`dokodemo-door`/`tunnel` inputs now freeze their effective typed destination on
all native backends. A non-null `settings.address` takes precedence over
`rewriteAddress`; null or missing selects the latter. The dormant alias stays
unchanged, as do network/port aliases, rules, sniffing and input identity.
These are logical handler targets, so this pass adds no physical endpoint
lookup, pin or routing override. It does not apply Address expansion to
WireGuard endpoint strings, `portMap`, arbitrary user maps or other protocols.

The four [shared logical Address cases](../tool/fixtures/compatibility/logical-addresses.json)
check raw Core equivalence, complete native literal controls and a second Core
build under a different environment. A fifth file-only case builds the exact
runtime document. The CI-only runtime owns one HTTP and one DNS origin and starts
Core in a bounded child with changed environment values: both imported input
aliases must echo 32 KiB, and both DNS address aliases must deliver the expected
wire question and answer. Final origin counts are checked after callback drain.
At [fa882a2](https://github.com/XIIIFOX/flutter_vless/actions/runs/39202974762),
ordinary Core on Linux/macOS passes these payload checks; Android passes 181 JVM,
37 native emulator and three Flutter checks. The Windows Core run transfers all
four expected payloads but fails when the test DNS origin reads another frame
after its completed exchange. The fixture now serves exactly one framed query
per connection, retaining strict answers, request counts and post-drain errors;
new memory-only controls cover complete, malformed and truncated frames.
The corrected fixture passes all three ordinary Core jobs at 3ab20f2. A separate
Windows 2022 TUN run previously failed a required positive HTTP request after a
blocked request. Both Windows 2022/2025 suites now pass all 410 rows at
[3ab20f2](https://github.com/XIIIFOX/flutter_vless/actions/runs/39205346209),
with exact post-drain origin counts and no retries. The earlier failure's cause
remains unproven; bounded stage/process/origin diagnostics remain in the gate.
Other typed Address roles and XDRIVE fronting/lifecycle remain open;
there is no claim of universal environment expansion or a complete transport
matrix.

Apple's address binder now belongs to the existing privacy module shared by the
containing app and tunnel support. This fixes the unsigned example build failure
caused by referencing a helper unavailable in the app's module. The regression
links the actual app call against privacy alone and runs ten shared cases plus
a rejected recursive reference for each Apple namespace. Both unsigned example
builds pass locally without launching an app, Core or VPN; network acceptance
remains a separate gate. The 3ab20f2 Apple CI job also passes both containing app
builds, standalone SwiftPM, actual iOS preview and macOS component runtime gates.
The iOS HEV simulator/device path is compile/link qualification only.

Transport default-strategy progress: the native adapters now admit Core's
equivalent missing, null, empty and case-insensitive `none` forms of
`sockopt.addressPortStrategy`, retaining the exact caller spelling. Shared
WebSocket and XHTTP cases cover upload, active independent download and direct
socket contexts, including TLS/Host/path and keepalive retention. Active SRV/TXT
overrides still need their own protected bootstrap design; malformed non-null
values do not silently become defaults. The valid active SRV control targets
the primary remote socket only: pinned Core itself forbids that override on
freedom. File-only preparation/build checks and new-head payload acceptance are
recorded separately.

Core preflight is now wired into both Apple app entry points and into the final
provider configuration before route installation. The additive Go bridge decodes
and builds with pinned Core without opening listeners. Closed numeric results
identify privacy/decode/build failures and, where available, an inbound/outbound
index. A failed candidate cannot stop the app's active proxy-only singleton or
replace its saved VPN profile. `tool/build_apple_core_preview.sh ios|macos OUTPUT`
builds the extended runtime locally without publishing anything; CI requires
actual traffic through an existing session after valid and invalid checks.
Published runtime artifacts/checksums remain unchanged: legacy Apple binaries
explicitly report preflight unavailable and retain their previous startup path.
The released Apple SDKs and unpublished previews can report the same Core
version while exposing different additive Check/routing ABIs. The version string
does not establish preflight or routing capability; the loaded bridge must do so.
This feature requires the build-only preview until its runtime artifacts are
approved for release. Windows runs its bundled Core `run -test` against private
documents before session replacement; proxy-only checks normalize the source
and use current-user storage. VPN preparation now applies the underlay binding
and packet-path probe before checking. It retains the checked file and the same
administrator-owned executable for launch, without another serialization or
runtime copy. Failed candidates release only their own probe/file/runtime;
successful candidates retain the probe through worker shutdown. Recovery
prepares and checks a fresh candidate, and a changed underlay refuses admission.

Android likewise configures its candidate-owned readiness probe before native
preflight, profile persistence or active-worker replacement. The native check
and launch write the same immutable final bytes; the first startup adopts that
probe instead of generating another rule after checking. Recovery regenerates
and checks the final document before launching new workers. Apple VPN providers
already Check and Start the same final preparation data before route installation.
Both Apple proxy-only hosts now prepare once, Check that final data before
stopping a system VPN, and pass the prepared data unchanged to the runner.
Direct runner calls also reject an active singleton before changing its assets.
The admission and cleanup controls use inert native boundaries locally. The
source-bound preparation-report qualification spans three runs with identical
production bytes. [80d3caf](https://github.com/XIIIFOX/flutter_vless/actions/runs/39338662731)
passes Core on all three systems, Dart/API/example tests and all 326 Android JVM
tests, but remains an overall failure at Apple and Windows test compilation.
[53fafe8](https://github.com/XIIIFOX/flutter_vless/actions/runs/39339803270)
passes the Apple helper, SDK and app builds, both controlled Core runtimes and
shipped macOS HEV packets; iOS HEV remains compile/link-only. Each Swift suite
skips only its opt-in public-DNS smoke check. That run still fails at a
Windows-only consumer test fixture.
[28dc44b](https://github.com/XIIIFOX/flutter_vless/actions/runs/39340784664)
passes all six Windows 2022/2025 jobs, including actual MSVC report controls
(18 producer, 12 consumer and three extractor checks per system), release app
builds and all 460 proxy/portable/VPN result rows. The repairs change test support
and workflow selection only, not application/runtime source.

These closed summaries are not general effective-configuration diffs. Complete
asset diagnostics, bind-race handling, final Apple VPN provider report delivery
and rollback from later runtime failures remain open; item 7 is still Partial.

Apple's in-process preflight now refuses nonempty root `env` with the fixed
`environment-policy` stage and `feature: env` before Core Build. Pinned Core
otherwise calls `os.Setenv` even for null string values and before a later
configuration failure, which can modify the working process. Both Apple native
entry paths also reject canonical nonempty `env` before calling a cached older
checker. Absent, null and empty maps retain normal checking. The original profile
and `StartPrivate` are not rewritten; this is an explicit interim compatibility
refusal, not scoped support for root `env`. Existing inherited `env:` address and
port bindings are separate. Android and Windows check in separate child
processes and keep that behavior. Supporting candidate environment changes
inside Apple preflight still requires scoped Core building; changing and
restoring global environment variables would not isolate a running session.

Service identifier progress (2026-10-18): Android, both Apple packages and
Windows reserve definitions and exact references before allocating private
adapter, DNS, statistics and delay tags. This includes API/DNS tags, reverse
bridges/portals, balancers/fallback tags and nested dialer chains. A dormant
imported rule must not begin matching the adapter just because it uses a
library-preferred name. A shared 12-case corpus checks allocation and input
preservation. Apple and Android system DNS rules are scoped to their managed
inputs, as Windows DNS already was; Android/Windows packet-path probe rules
are now scoped too. Runtime fixtures require imported-input blocking rules to
retain their effect. Android shares its native DNS adapter identity during
startup and worker recovery, rejecting missing or mismatched preparation.
Android's isolated native authorization fixture transfers actual HTTP bytes
with a deliberately conflicting imported rule. The complete local Android
emulator suite passes all 27 tests, including the imported DNS blocking case,
worker recovery, handover and physical DNS capture (`.5UHS7XV2`). The nonempty
prefix increment above extends exact-name reservation; wildcard isolation and
the source-inbound routing context remain open. API passthrough acceptance is
recorded separately above.

Numeric `api.listen` and `metrics.listen` ports now participate in adapter
allocation on all native platforms, with shared 21-case API and 36-case service
fixtures for IPv4/IPv6, host addresses, aliases, Unix-looking addresses and port
zero and Go's optional leading plus on decimal TCP ports. Extraction does not
resolve hostnames or rewrite the source services.
The metrics listener uses Core's TCP-listen grammar; ignoring Unix-looking
addresses for reservation does not establish that metrics can bind Unix sockets.
Service-name ports remain accepted syntax for Core/OS handling
and are not yet resolved by this reservation helper. Apple runtime acceptance
requires the original API to return an HTTP/2 SETTINGS frame while the separate
authenticated SOCKS adapter transfers HTTP bytes. Android/Windows API
passthrough is still item 4; reserving a source API port does not implement it.
The physical iPhone example also retained a caller API on 10809 while its private
adapter used 10810: both Safari sites showed the Japan proxy exit, and explicit
Stop restored ordinary internet with disabled-profile readback. macOS now retains
the caller's API alongside in-process counters; its runtime acceptance requires
an HTTP/2 response. Isolated Apple/Android profile-delay documents omit caller
API/metrics listeners to avoid rebinding an active session's sockets. Ordinary
session OS bind races, service-name allocation, caller stats/policy preservation
and standalone Windows delay remain open.

[CI on 81ca7d0](https://github.com/XIIIFOX/flutter_vless/actions/runs/39141006566)
passes all five jobs. The iOS/macOS runtime artifacts contain both generations
of API HTTP/2, metrics HTTP and authenticated SOCKS acceptance, a working isolated
delay while the caller's service ports are occupied, and the macOS native-counter
check alongside retained API services, including signed decimal listener ports.
[Windows runtime on the same commit](https://github.com/XIIIFOX/flutter_vless/actions/runs/39141023789)
also passes both OS versions with real metrics JSON, routing and recovery.
Physical iPhone owner-authenticated
Control Center start/stop and subsequent ordinary internet also pass; this does
not complete the remaining compatibility items below.

The physical iPhone also recovered after a development-only, acknowledged stop
of its running Core worker. Ordinary watchdog recovery retained the same tunnel
provider; fresh Safari requests afterward reached both IP sites through the
proxy. Explicit Stop and normal internet were checked before restoring the
ordinary signed app. See the [device record](device_matrix.md#iphone-acceptance-2026-10-18-117--core-261017)
for the fault boundary, timestamps and limits of that observation.

Advanced DNS preparation now has an unpublished, pinned Core source capability
under [third_party/xray-native-dns](../third_party/xray-native-dns/README.md).
It separates immutable, instance-owned physical transport pins from caller DNS
lookups and preserves compiled caller root DNS. Shared Go preparation inspects
actual compiled outbound/transport types and uses Core's static-host matcher;
it does not copy endpoint addresses into caller `dns.hosts`. Root DNS analysis
classifies routed/local resolver modes, implicit system-DNS defaults, resolver
names, FakeDNS, system-family queries and scripts into explicit native
requirements. A transport scope alone cannot authorize these separate paths.

This source capability is not enabled in production native builders or published artifacts.
Its pure preparation checks do not establish protected socket behavior or full
DNS support. A separate CI-only real-Core fixture checks concurrent owners,
caller hosts, per-domain tagged TCP DNS, rejected candidates and owner shutdown;
actual runtime results must be recorded separately. Local checks compile this
fixture without executing Core. Root/local DNS, ECH/QUIC/cached transports,
protected bootstrap, API-created handlers and native integration still need
implementation and qualification before preserving arbitrary imported DNS is
safe to enable. Item 1 remains pending.

The next unpublished increment adds a scoped local/default resolver seam, without
editing caller `dns` configuration. Its first native policy is numeric TCP through
a sealed, exact source-index freedom handler, including untagged handlers; it is
not enabled by any production host. Independent per-query Core DNS clients avoid
sharing the first request's cancellation, and a query-scoped dispatcher restores
cancellation after Core's DNS context detachment. Pure tests cover these paths
using actual DNS framing over memory pipes. CI acceptance additionally requires
unchanged missing/empty/localhost and mixed roots, actual A/AAAA and HTTP bytes,
owner-only cancellation of a stalled exchange, and another owner's survival.
The [b315a65 CI run](https://github.com/XIIIFOX/flutter_vless/actions/runs/39150730894)
passed both actual DNS acceptance fixtures on Windows, macOS and Ubuntu with
unchanged compiled roots, complete output capture and matching source hashes.
This remains a preview qualification; production builders do not enable it.

The retained native-entry increment now keeps an immutable decoded/build
blueprint and creates a fresh scoped owner/delegate for each start. A separate
unpublished executable accepts explicit native policy, traps system resolution
during both preparation and runtime, and owns bounded Stop/parent-EOF cleanup.
Its first graph admits authenticated loopback SOCKS and simple IPv4 freedom
with a numeric TCP default resolver; unsupported capabilities remain rejected
in that development path. Ordinary plugin builders and official artifacts do
not enable it. The Android S/Q development broker additionally requires actual
descriptor protection and binding to a captured physical Network, with
permanent generation revocation. Neither an acknowledged descriptor nor a
`started` child status establishes VPN readiness, DNS bridge support, network
handover or retroactive closure of already acknowledged sockets. The host must
also close its runtime on network replacement. See the
[native-entry contract](../third_party/xray-native-dns/README.md#retained-native-entry-preview)
for the exact qualification boundary and runtime checks. Item 1 remains pending.
Protected proxy egress, OS DNS semantics, DoH/DoT, FakeDNS and physical native
socket protection remain separate work; this does not complete item 1.

The [0273c1a CI run](https://github.com/XIIIFOX/flutter_vless/actions/runs/39157185531)
passes the Runtime, LocalDefault and Launcher actual-Core fixtures on Windows,
macOS and Ubuntu. Apple native runtime and pure suites also pass. Its overall
result is failure: the four new Android broker tests fail before later device
suites run. The socket timeout was configured before connect, and listener close
did not wake a blocked accept. Both are corrected in the following increment;
negative tests now require explicit protocol refusal rather than accepting a
connection error. Local Android unit tests pass all 99 cases and the corrected
instrumentation APK compiles; a new device run is still required.

The next increment adds an optional in-process DNS wire-message handle tied to
that runtime's exact compiled config clone. Its restricted A path uses the
original caller root DNS; AAAA is explicit IPv4-policy NODATA and unsupported
records are refused. It creates no listener or OS/TUN consumer. A fourth actual
Core acceptance fixture covers two owners, DNS tags, UDP/TCP framing and shutdown.
Local validation passes 97 top-level pure Go tests and 162 subtests, compiles all
four runtime fixtures, and builds the separate Android executable and conditional
instrumentation APK. These are compile/pure results, not device runtime passes.
The optional Android fixture additionally requires real brokered Core HTTP/DNS
traffic and causal stalled-query cleanup. It still does not qualify system DNS,
proxy bootstrap, IPv6 or arbitrary imported graphs; item 1 remains pending.

The subsequent [c291989 CI run](https://github.com/XIIIFOX/flutter_vless/actions/runs/39159134068)
passes all eight jobs: all four actual DNS fixtures on three desktop systems,
Apple native runtime checks, 99 Android unit tests, 35 native emulator tests and
three example tests. The four broker and two composed-runtime device cases pass;
the observed stalled DNS socket closes about 0.53 seconds after entering its
stalled stage, before its four-second natural bound. This qualifies that preview
composition only. It still creates no system DNS consumer or production host
integration, and does not complete advanced DNS compatibility.

The following unpublished managed-input consumer appends an authenticated input
only to a private compiled clone and authenticates construction/connection
identity before consuming DNS. It checks each UDP packet rather than trusting a
cached ray's first destination, and owns complete source/managed SOCKS callbacks
through shutdown. Its four-connection/four-ray/one-lookup limits are explicit
preview restrictions. Ordinary managed UDP remains unavailable; production TUN
hosts do not enable this component. The unpublished CLI now accepts a separate,
permission-checked private policy bound to the source hash and session nonce.
Selected UDP associations require a concrete prebound peer and a grant retained
through the full callback finalizer. Local validation passes 126 pure tests and
191 subtests plus fixture/launcher compilation (34 phases); it executes no Core.
The [b030db9 CI run](https://github.com/XIIIFOX/flutter_vless/actions/runs/39164717739)
passes all five actual-Core fixtures, including private-policy/managed-UDP
controls, on Windows, macOS and Ubuntu. Its source snapshots match that commit;
Linux also passes the synthetic descriptor-ownership fixtures without opening a
TUN or starting the forwarder engine.
See the [consumer boundary](../third_party/xray-native-dns/README.md#managed-input-consumer-preview).
Items 1 and 2 remain pending.

An explicit Android development host now compiles with separate verified Core
and forwarder executables in the test APK. Five device scenarios cover the
planned TUN DNS/HTTP, rejected-candidate survival, child recovery, controlled
Wi-Fi/cellular replacement and fresh Chrome marker checks. They have not run
yet. Their optional harness path is prepared after the three-system Core and
Linux descriptor qualification gates. The harness checks actual APK payloads
against both fresh binary reports before installation. It keeps the development
service out of ordinary OS-policy tests because Android applies any service's
Always-on opt-out to the whole app, then installs the two-binary APK for the five
new cases. Owned browser/instrumentation cleanup precedes emulator Wi-Fi recovery
after failures. Ordinary builds omit the service and executables. Synthetic forwarder
tests prove password negotiation, prebound UDP tuple, exact relay-source filtering
and descriptor cleanup without starting an engine/TUN; these are not mobile
system-traffic acceptance. The eight statuses below remain unchanged.

The b030db9 Android job exhausted its 45-minute limit while the example smoke
wrapper was waiting for Flutter. No native security class ran and the wrapper
had not persisted its buffered child output, so the underlying Flutter/build/app
cause is unknown. The three scoped Core jobs, Apple job and Android's 105 native
unit tests pass. The bounded smoke wrapper now retains live private output,
enforces a 600-second attempt budget and requires entry, Core-version and exact
three-test completion evidence. Read-only context precedes cleanup for child
failures; cleanup failures remain failures. Synthetic controls cover timeouts,
signals, inherited pipes, short writes and scoped cleanup. The five TUN cases
run in the same job only after ordinary Android acceptance succeeds; the harness
enforces that gate before installing the development VPN service. New actual
Android results are still required.

Session teardown progress: Android now closes callback admission before its final
cleanup, so late network/worker events cannot enqueue into a stopped executor.
[Android CI on 9a6b595](https://github.com/XIIIFOX/flutter_vless/actions/runs/39147429528)
passes all 29 native device tests and three example smoke tests, including the
system Forget scenario. The previous CI crash lacked a primary crash log; the
pass does not prove its cause. Failure capture now runs before emulator cleanup.
Both Apple providers also use session epochs to reject stale recovery/wake and
startup callbacks after Stop; controlled pure tests cover Stop during drain and
between native stages. Follow-up controls also cover queued sleep/wake callbacks
in both orders and a recovery check firing while asleep: callback admission
follows the latest synchronous sleep/wake decision, and a sleeping check releases
its retry slot for wake. Both actual provider implementations pass eight pure
scenario groups; this is separate from physical sleep/wake acceptance.
Actual Apple runtime/device acceptance of these changes is recorded separately.

Android standalone delay probes now reserve their SOCKS/API listener pair while
preparing the temporary runtime, with at most 32 allocation attempts. Interrupted
cleanup retains a bounded child reap and always attempts private-file removal;
only allowlisted stage/exit events are recorded. These changes have deterministic
allocator/process tests and a compiled device fixture that requires real HTTP
bytes and successful cleanup. The preceding device-CI accept timeout did not
record the underlying Core outcome; its cause is still unproven. The handoff
between releasing a reservation and Core binding remains a separate bind-race
requirement. This standalone-probe work preceded the main VPN allocator change
below.

Generated VPN listeners now accept a native-only TCP availability predicate.
Normal file-only preparation omits it; actual Android service, Apple host/provider
and Windows service preparation supply a loopback bind-and-close check before
publishing or replacing a candidate. Caller listener ranges, API and metrics
ports are excluded before counting at most 32 OS candidates for each generated
SOCKS/API listener. Caller listeners and their configuration remain intact.
The fixed SOCKS listener uses TCP; an unrelated UDP listener does not consume
that TCP port. Focused fake-kernel and pure chooser regressions pass.
[Windows acceptance at e5f9fc6](https://github.com/XIIIFOX/flutter_vless/actions/runs/39244521230)
also passes real availability checks and VPN traffic while preferred TCP ports
10807/10086 remain occupied, on both Windows 2022 and 2025; all 426 ordinary and
routing result rows pass. Both enabled Apple SDK runtimes pass occupied TCP-port
traffic in the e5f9fc6 run above; Android TUN passes at 2f74f13. Releasing the test
socket is not an atomic transfer to Core.

Android and Windows readiness listeners additionally exclude ports declared in
the final Core configuration, including numeric API/metrics ports and imported
ranges. They close rejected port-zero allocations and try at most 32 times
before starting a worker, retaining the accepted socket for the probe lifetime.
Pure/fake regressions cover exclusion, exhaustion, cleanup and admission refusal;
Android runtime acceptance passes at 2f74f13. The earlier Windows 2022 run
fails an ordinary replacement check before the new routing cases,
without retaining the child exit status. Atomic command publication and bounded
exit diagnostics address a demonstrated fixture ordering gap; that gap is not
established as the cause of this CI failure. Apple VPN health checks connect to
the existing adapter and do not own an analogous TCP listener.
The 2025 Windows job reaches its 15-minute limit before retaining VPN-profile
logs. File-only regressions also ensure partial fixture setup closes every
constructed server and avoids shutdown before its worker starts. They fix a
demonstrated cleanup hang without identifying the cause of that earlier timeout.
[Subsequent Windows acceptance at fb2eb75](https://github.com/XIIIFOX/flutter_vless/actions/runs/39249923372)
passes all six jobs and all 426 proxy/portable/VPN result rows on Windows
2022/2025. Both systems also pass the four probe source guards, eight allocator
controls, held-port traffic and final IPv6 cleanup. This qualifies that
controlled baseline; it does not establish the earlier failures' causes or
qualify the new counter increment above.
Standalone delay allocation, Core handoff races, recovery relocation and broader
proxy-only allocation remain separate work under item 5.

Current implementation/acceptance status (1.1.7, unreleased):

| Item | Status | Evidence and remaining work |
| --- | --- | --- |
| 1. Advanced DNS | Partial; minimum increment qualified | Production adapters preserve explicit remote caller DNS and use Core for private address queries. Caller AAAA, bare/full resolver hosts and encrypted DoH trust/name controls pass ordinary Core on all three desktop systems. Missing/null/empty localhost server tags pass shared preparation and native Apple DNS generations. Direct-only traffic passes shared Core, Android TUN, native Apple and Windows TUN gates. Controlled FakeDNS TCP/UDP passes native-prepared ordinary Core on Linux/macOS/Windows and Android/Windows TUN at f5acbbc, plus both released Apple SDKs at 0c11271. Combined HEV/FakeDNS and additional DNS paths remain open; the subsequent DNS data/URL/system-hosts corrections pass the ordinary Core traffic gate, both released Apple SDKs and Android CallerRoot DNS at e2acc10. Broader DNS/device acceptance remains open. |
| 2. IPv6 | Partial; physical iOS packet gate pending | IPv6 TCP/UDP with preserved AAAA policy passes ordinary Core on all three desktop systems, actual Android TUN and Windows 2022/2025 TUN/recovery/physical-interface controls. Actual shipped macOS HEV packet controls pass remotely; iOS simulator HEV is a verified link-only stub and physical iOS remains pending. Full macOS system-VPN acceptance, IPv6-only endpoints, NAT64, cross-family handover and broader physical bypass qualification remain open. |
| 3. Protocol/transport matrix | Partial; controlled XHTTP increment qualified | Supplied VLESS TCP/Reality profiles work on devices. Minimum MASQUE/internal-handler/alias/XHTTP and null legacy-endpoint preparation fixes pass a nine-case pinned Core build corpus with native preparation, including shared XHTTP upload/download socket policy. At cdc5b94, ordinary Core on all three desktop systems carries actual XHTTP HTTP/1.1 packet-up payloads with and without a caller SOCKS chain; both Apple and Windows preparers pass on macOS. The additional ten-profile header corpus preserves 18 raw maps; at 025ff2f, all three ordinary Core OS gates pass literal-header traffic and the independent-download/inactive-grandchild case. Further protocol handshakes, XHTTP TLS/HTTP3/QUIC, physical iOS packets and the full matrix remain open. |
| 4. Passthrough and VPN routing context | Partial | Imported listeners/authentication remain intact; private DNS/probe rules are scoped to their adapters. API/services/stats/policy preservation passes shared preparation and ordinary Core traffic checks on all three desktop systems; Windows service acceptance passes on 2022/2025. Nonempty selector prefixes pass shared component, ordinary Core and native platform traffic gates at a475374. Per-session source/default selection passes Android TUN at 2f74f13, both enabled Apple SDK runtimes at e5f9fc6 and Windows 2022/2025 at fb2eb75. Session-owned counters pass Android/Windows again at f5acbbc and both complete enabled Apple controlled gates at 02136f1. Public full-JSON startup/delay/import now also preserves explicit nulls and empty containers through all four platform message adapters; DNS hosts, known typed transport header dictionaries and routing-rule attribute dictionaries are exempt from legacy cleanup, and Android protected-feature checks respect those exact data dictionaries. The ten-profile header corpus adds preparation coverage without qualifying every transport handshake. The six-profile opaque-field corpus retains 18 unknown subtrees through schema-owned normalization, with Core comparisons on all three systems and six exact Android runtime metadata assertions. Broader schema coverage, wildcard isolation and physical/system-VPN acceptance remain open. |
| 5. Ports/addresses | Partial | Shared port/service/tag fixtures and Android/iPhone list/range/env/Unix and collision cases pass; iPhone also avoids simultaneous API/metrics ports with fresh browser traffic. Bounded OS-aware generated TCP admission passes Android TUN at 2f74f13, both enabled Apple SDK held-port runtimes at e5f9fc6 and Windows 2022/2025 at fb2eb75. Android/Windows probe exclusion passes targeted runtime acceptance. The additional eight-case env corpus aligns simple Unicode casing and whitespace across native adapters; the actual Windows UTF-16 environment reader and Core regression traffic pass at 038615d. Apple byte-exact snapshots additionally pass synthetic reader, actual host-admission and startup-retry checks. Physical acceptance, recovery relocation, service-name resolution, wildcard isolation, bind races and broader proxy-only parity remain open. |
| 6. Assets/import syntax | Partial; data-root increment qualified | The shared 22-case syntax corpus covers comments/BOM with Core decoding. Explicit roots propagate across native backends; custom GeoSite traffic passes Android TUN, both Apple preview runtimes and Windows 2022/2025. Explicit TLS certificate/key directory binding passes shared native/Core regressions; controlled CA-file TLS traffic passes ordinary Core on all three desktop systems at ca96891 (four variants per preparer, 16 markers). Physical Apple access/reload, managed asset import/lifetime, specialized certificate features and explicit multi-document merging remain open. |
| 7. Preflight/errors | Partial | Preflight/storage checks retain working traffic after a rejected candidate. The source-bound 80d3caf/53fafe8/28dc44b lineage above qualifies per-invocation closed preparation reports and safe failure stages, with the stated host/final-candidate scopes. Apple bridge capability is distinct from its Core version. Arbitrary configuration diffs are outside this API contract; final Apple VPN provider reports, later-startup rollback, complete asset diagnostics and bind-race handling remain open. |
| 8. Runtime corpus | Partial | Shared port/syntax fixtures and platform/device HTTP, DNS, routing and recovery checks exist. The complete ECH/DoH/QUIC/protocol corpus and remaining physical options acceptance are not complete. |

Comment filtering follows the [pinned Core local-file reader](https://github.com/XTLS/Xray-core/blob/92ccc939aaf4f8965f369cf0b142e005aeaa11d5/infra/conf/json/reader.go),
including its LF handling. Quoted URLs/headers/comment markers are preserved.
The leading BOM is an SDK import extension; the core receives canonical JSON.
Single-document APIs reject trailing documents/data instead of silently ignoring
them. Subscription arrays use the existing explicit `parseMany`/first-profile
contracts; this does not implement Core multi-file override/merge semantics.

1. **Preserve advanced DNS semantics.** Separate the OS-facing protected resolver
   from imported `dns` hosts, servers, per-domain rules, query strategies, DoH/DoT
   and DNS tags. The minimum adaptation above preserves explicit remote roots;
   localhost behavior, FakeDNS and IPv6 remain constrained. Qualify advanced
   DNS loops, endpoint bootstrap and additional resolver modes. DoT needs a
   supporting Core implementation before it can be admitted.
2. **Complete IPv6 forwarding.** Carry TCP/UDP and DNS across both address
   families, including IPv6-only endpoints, NAT64 and network handover. The
   minimum payload increment passes Core/Android/Windows runtime acceptance;
   physical iOS and full macOS system-VPN gates remain pending, and Windows retains its physical IPv6 restriction.
3. **Broaden native protocol/transport acceptance.** Test every protocol and
   transport in the pinned core against each packaged artifact. Include XHTTP
   download settings, Reality/TLS variants, QUIC/UDP, chaining, mux, balancers,
   observatory and reverse routing; remove wrapper whitelists only after socket
   protection and bootstrap behavior are established for that path.
4. **Finish full-document passthrough.** Preserve imported API/services/stats
   alongside private statistics (the minimum preservation increment is implemented),
   and isolate all injected DNS/probe rules to their own adapter. Define which
   imported input backs VPN traffic and carry its `inboundTag` routing context
   into the private adapter; retaining the original rules alone does not make
   input-specific rules apply to that new adapter. Test profiles whose first
   outbound is not the intended VPN default. Preserve user fields outside the documented privacy
   overrides for logs and native protection. Qualify the new exact,
   session-owned adapter counter source on every backend, retaining unavailable
   directions internally instead of summing unrelated caller counters.
   Distinguish adapter stream
   bytes (which can include SOCKS framing) from TUN/application payload, and do
   not enable caller-disabled policy counters merely to fill plugin totals.
5. **Unify port/address handling.** Accept upstream string port lists, ranges,
   `env:` references, port zero and Unix sockets where supported. Align Dart and
   native validators. Private allocation must also check actual OS listeners,
   API listeners and every generated tag namespace, with bounded retries for
   bind races. Profile collision checks alone do not cover unrelated processes.
6. **Manage portable assets and imports.** Define per-platform mappings for
   certificates/keys, GeoIP/GeoSite and external rule files. Validate missing
   assets explicitly; a macOS absolute path cannot be assumed to exist on
   Android. Match JSON/JSONC/BOM/multiple-document support to the actual embedded
   core and preserve full JSON independently of share-link conversion.
   Pinned Core resolves relative TLS certificate/key paths from its certificate
   location or executable directory, separately from its GeoDAT asset location;
   changing the config directory or Apple's geo option does not cover both.
   Owned private asset copies must survive certificate reloads for the complete
   session and remain isolated between an accepted owner and a rejected candidate.
7. **Expose precise compatibility errors.** Run the pinned core's configuration
   check before replacing a working session. Report the failing feature/stage
   with redacted diagnostics and a safe original/effective-config comparison;
   avoid generic “invalid config” for an OS policy requirement or asset failure.
8. **Maintain a cross-platform runtime corpus.** Store synthetic, non-secret
   profiles for the cases above and run them on every core upgrade. Check real
   HTTP/TCP/UDP bytes, IP/country, direct/proxy routing in both directions,
   ECH/DoH/QUIC behavior, fresh browser connections, worker/process recovery,
   system controls and physical devices. A green parser test or CONNECTED icon
   alone is insufficient.

Always-on acceptance must include an initial authorized profile, cold system
starts with library reconnect disabled, and policy changes while the service is
inactive. Android's public state getter may return false until a VPN network
exists. Lockdown settings are read only for the current consented owner; the
plugin never changes OS Always-on policy itself.
