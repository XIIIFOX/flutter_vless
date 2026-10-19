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
the private VPN adapter. A and AAAA now use Core's preserved root DNS; an explicit
caller `UseIPv4` still produces successful AAAA NODATA. Other record types return REFUSED.
Imported listeners do not acquire this private path. Proxy-only and measurement
preparation retain their separate behavior.

The default Android CI job runs the production adapter and its two focused
caller-DNS TUN tests in parallel with desktop Core checks; a third IPv6 payload
case passes in the current increment. It uses the existing
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
TLS/HTTP names. Unqualified local/QUIC resolver paths, system-family strategies,
scripts and FakeDNS fail preparation rather than silently using OS fallback.
The pinned Core has no `tls://` DoT implementation. These limitations, arbitrary
DNS record types and full dual-stack/FakeDNS support remain open; this MVP does not
complete item 1. Test compilation and runtime results are recorded separately.

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
startup. Exact per-adapter accounting and a public availability signal remain
separate work. Apple uses its existing in-process reader.

The shared [six-case full-config corpus](../tool/fixtures/compatibility/full-config.json)
checks these source sections after native preparation and against pinned Core
decode/build. Runtime acceptance additionally requires a caller StatsService
to remain available while HTTP/DNS traffic flows and disabled counters to stay
disabled. [Ordinary Core acceptance on 8ed2b7e](https://github.com/XIIIFOX/flutter_vless/actions/runs/39178340305)
passes this check on Linux/macOS/Windows, including both native preparers on
macOS. [Windows service acceptance on 1c2c490](https://github.com/XIIIFOX/flutter_vless/actions/runs/39177932558)
also passes proxy/portable and VPN tests on Windows 2022/2025 with working
traffic after rejected replacement and disabled caller counters unchanged.
This increment does not implement source-inbound context selection, explicit
VPN default selection. Nonempty prefix isolation is described below.

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
Certificate/key lookup uses Core's independent certificate root. Relative
certificate portability and a managed asset-import/copy lifecycle remain open.
Custom-only Apple roots require the rebuilt unpublished Core preview; published
framework URLs and checksums remain unchanged during this acceptance phase.

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
in caller config mode before checking unavailable FakeDNS. Its explicit proxy
DNS mode still replaces the caller root by request. Server options, host-map
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
New-head traffic acceptance remains pending until its exact CI artifacts are
verified. Other typed Address roles and XDRIVE fronting/lifecycle remain open;
there is no claim of universal environment expansion or a complete transport
matrix.

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
requirement, and the main VPN listener allocator is unchanged.

Current implementation/acceptance status (1.1.7, unreleased):

| Item | Status | Evidence and remaining work |
| --- | --- | --- |
| 1. Advanced DNS | Partial; minimum increment qualified | Production adapters preserve explicit remote caller DNS and use Core for private address queries. Caller AAAA, bare/full resolver hosts and encrypted DoH trust/name controls pass ordinary Core on all three desktop systems. Missing/null/empty localhost server tags pass shared preparation and native Apple DNS generations. Direct-only traffic passes shared Core, Android TUN, native Apple and Windows TUN gates. Additional DNS paths and full FakeDNS semantics remain open. |
| 2. IPv6 | Partial; physical iOS packet gate pending | IPv6 TCP/UDP with preserved AAAA policy passes ordinary Core on all three desktop systems, actual Android TUN and Windows 2022/2025 TUN/recovery/physical-interface controls. Actual shipped macOS HEV packet controls pass remotely; iOS simulator HEV is a verified link-only stub and physical iOS remains pending. Full macOS system-VPN acceptance, IPv6-only endpoints, NAT64, cross-family handover and broader physical bypass qualification remain open. |
| 3. Protocol/transport matrix | Partial; controlled XHTTP increment qualified | Supplied VLESS TCP/Reality profiles work on devices. Minimum MASQUE/internal-handler/alias/XHTTP and null legacy-endpoint preparation fixes pass a nine-case pinned Core build corpus with native preparation, including shared XHTTP upload/download socket policy. At cdc5b94, ordinary Core on all three desktop systems carries actual XHTTP HTTP/1.1 packet-up payloads with and without a caller SOCKS chain; both Apple and Windows preparers pass on macOS. Further protocol handshakes, XHTTP TLS/HTTP3/QUIC, physical iOS packets and the full matrix remain open. |
| 4. Passthrough and VPN routing context | Partial | Imported listeners/authentication remain intact; private DNS/probe rules are scoped to their adapters. API/services/stats/policy preservation passes shared preparation and ordinary Core traffic checks on all three desktop systems; Windows service acceptance passes on 2022/2025. Nonempty selector prefixes pass shared component, ordinary Core and native platform traffic gates at a475374. Source-inbound context, explicit VPN default selection, wildcard isolation and exact adapter counters remain open. |
| 5. Ports/addresses | Partial | Shared 20-case port, 12-case exact service-tag, nine-case selector-prefix, 21-case numeric API and 36-case service-listener fixtures cover allocation. Real Android/iPhone list/range/env/Unix and tag-collision cases pass; iPhone also avoids simultaneous API/metrics ports with fresh browser traffic. OS port checks, service-name resolution, wildcard isolation, bind retries and broader proxy-only parity remain open. |
| 6. Assets/import syntax | Partial; data-root increment qualified | The shared 22-case syntax corpus covers comments/BOM with Core decoding. Explicit roots propagate across native backends; custom GeoSite traffic passes Android TUN, both Apple preview runtimes and Windows 2022/2025. Relative certificate portability, managed asset import/lifetime and explicit multi-document merging remain open. |
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
