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
   tags and query strategy. Send the managed VPN resolver's A queries to Core's
   own DNS client. Keep transport bootstrap outside the caller's hosts map.
2. Protocols and transports: remove avoidable adapter restrictions using focused
   synthetic cases and the configurations available for live checks.
3. Full configuration passthrough, then ports/addresses and files/imports.
4. Remaining IPv6, diagnostics, recovery and device acceptance from the eight
   requirements, expanding the corpus when a concrete gap is found.

The DNS MVP uses an address-only virtual resolver at `198.18.0.2:53`, scoped to
the private VPN adapter. A uses Core's preserved root DNS; AAAA returns successful
NODATA while forwarding is IPv4-only; other record types return REFUSED.
Imported listeners do not acquire this private path. Proxy-only and measurement
preparation retain their separate behavior.

The default Android CI job now runs the production adapter and its two focused
caller-DNS TUN tests in parallel with desktop Core checks. It uses the existing
`--no-capture` mode: functional Wi-Fi DNS/system-policy tests remain mandatory,
while the report explicitly marks physical packet capture unverified. Cellular
capture/handover qualification remains separate because the emulator may not
provide a cellular Network. Strict capture and its verifier remain available in
the default standalone harness. Development-only Core/forwarder composition
also remains an explicit harness option, outside this minimum delivery's gate.

On Android the default `config` policy preserves the caller root DNS, including
missing/localhost resolution through the existing protected physical-Network
resolver. The explicit `proxy` policy intentionally selects proxied system DNS.
On Apple and Windows missing/empty/localhost DNS uses a documented native
default, `tcp://1.1.1.1` through the selected proxy. This is an adaptation, not
identical OS-localhost behavior. Other fields on a localhost server entry remain.

Apple/Windows initially admit numeric UDP/TCP and remote HTTPS/h2c resolvers;
named resolvers need an exact caller-owned IPv4 static hosts mapping. Bootstrap
pins live in private closed routing branches, preserving logical endpoints and
TLS/HTTP names. Unqualified local/QUIC resolver paths, system-family strategies,
scripts and FakeDNS fail preparation rather than silently using OS fallback.
The pinned Core has no `tls://` DoT implementation. These limitations, arbitrary
DNS record types and dual-stack/FakeDNS support remain open; this MVP does not
complete item 1. Test compilation and runtime results are recorded separately.

[CI on 7ec4636](https://github.com/XIIIFOX/flutter_vless/actions/runs/39171589801)
qualifies the production C++ preparer on Linux/macOS and the Apple preparer on
macOS against ordinary pinned Core: TCP/UDP virtual DNS, numeric TCP/UDP and
named h2c upstreams, per-domain tags, static hosts, endpoint pinning and HTTP
bytes pass with no OS-resolver attempt. Source hashes match that commit.
Windows stopped in a platform-dependent test mock before runtime; Android TUN
and iOS simulator acceptance are recorded separately. This is targeted DNS
acceptance, not a complete platform VPN or encrypted DoH/TLS qualification.

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
This feature requires the build-only preview until its runtime artifacts are
approved for release. Windows runs its bundled Core `run -test` against private,
privacy-normalized temporary documents before session replacement and against
the generated adapter config. VPN preflight uses the same administrator-owned
runtime directory as forwarding, denying filtered same-user access to its
configuration and Core image; proxy-only preflight uses current-user storage.
Both success and rejection must remove the temporary runtime. Android already
checks its final candidate with its bundled Core before the service transaction. Safe effective-config diffs,
complete asset diagnostics, bind-race handling and rollback from later runtime
failures are still pending; item 7 is not complete.

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
worker recovery, handover and physical DNS capture (`.5UHS7XV2`). Prefix
selectors in balancers/observatory, API passthrough and the source-inbound
routing context remain separate work.

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
requirement, and the main VPN listener allocator is unchanged.

Current implementation/acceptance status (1.1.7, unreleased):

| Item | Status | Evidence and remaining work |
| --- | --- | --- |
| 1. Advanced DNS | Partial; MVP runtime qualification pending | Production adapters now preserve explicit remote caller DNS and use Core for private A queries. Test-first native regressions pass; ordinary Core and Android TUN acceptance are wired into CI. Localhost adaptation, IPv4-only answers and unsupported paths are documented above. Full advanced/FakeDNS semantics remain open. |
| 2. IPv6 | Pending | Current tests prove blocking, not dual-stack forwarding, IPv6-only endpoint or NAT64 support. |
| 3. Protocol/transport matrix | Pending | Supplied VLESS TCP/Reality profiles work on devices. Full pinned-Core transport/socket-protection coverage is still required. |
| 4. Passthrough and VPN routing context | Partial | Imported listeners/authentication remain intact; private DNS/probe rules are scoped to their adapters. Apple retains caller API/services; Android/Windows API, caller stats/policy, source-inbound context and explicit VPN default selection remain open. |
| 5. Ports/addresses | Partial | Shared 20-case port, 12-case service-tag, 21-case numeric API and 36-case service-listener fixtures cover allocation. Real Android/iPhone list/range/env/Unix and tag-collision cases pass; iPhone also avoids simultaneous API/metrics ports with fresh browser traffic. OS port checks, service-name resolution, prefix-selector isolation, bind retries and broader proxy-only parity remain open. |
| 6. Assets/import syntax | Partial | A shared 22-case JSON syntax corpus is checked against actual Core decoding. SDK start/delay/import/subscriptions and the example routing editor accept Core-style comments and a leading BOM. Device browser/routing checks pass. Portable cert/key/geodata assets and explicit multi-document merging remain open. |
| 7. Preflight/errors | Partial | [All-platform CI](https://github.com/XIIIFOX/flutter_vless/actions/runs/39088987119) and [Windows native/runtime validation](https://github.com/XIIIFOX/flutter_vless/actions/runs/39089712376) pass for the preflight/storage changes, including working traffic after a rejected candidate. Apple preview/legacy distinctions above still apply; safe diffs and later-startup rollback remain open. |
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
   families, including IPv6-only endpoints, NAT64 and network handover. Current
   Apple/Windows forwarding blocks IPv6 instead of providing full dual stack.
3. **Broaden native protocol/transport acceptance.** Test every protocol and
   transport in the pinned core against each packaged artifact. Include XHTTP
   download settings, Reality/TLS variants, QUIC/UDP, chaining, mux, balancers,
   observatory and reverse routing; remove wrapper whitelists only after socket
   protection and bootstrap behavior are established for that path.
4. **Finish full-document passthrough.** Preserve imported API/services/stats
   alongside private statistics (Android/Windows currently replace API settings),
   and isolate all injected DNS/probe rules to their own adapter. Define which
   imported input backs VPN traffic and carry its `inboundTag` routing context
   into the private adapter; retaining the original rules alone does not make
   input-specific rules apply to that new adapter. Test profiles whose first
   outbound is not the intended VPN default. Preserve user fields outside the documented privacy
   overrides for logs and native protection. Private traffic counters need an
   exact, session-owned adapter source: the current Android literal `proxy`
   lookup misses other egress tags, and Windows aggregation can include caller
   inputs or count both inbound and outbound bytes. Distinguish adapter stream
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
