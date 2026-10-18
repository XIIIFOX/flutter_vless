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
allocation on all native platforms, with shared 14-case API and 28-case service
fixtures for IPv4/IPv6, host addresses, aliases, Unix-looking addresses and port
zero. Extraction does not resolve hostnames or rewrite the source services.
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

[CI on a087241](https://github.com/XIIIFOX/flutter_vless/actions/runs/39135338877)
passes all five jobs. The iOS/macOS runtime artifacts contain both generations
of API HTTP/2, metrics HTTP and authenticated SOCKS acceptance, a working isolated
delay while the caller's service ports are occupied, and the macOS native-counter
check alongside retained API services. Physical iPhone owner-authenticated
Control Center start/stop and subsequent ordinary internet also pass; this does
not complete the remaining compatibility items below.

The physical iPhone also recovered after a development-only, acknowledged stop
of its running Core worker. Ordinary watchdog recovery retained the same tunnel
provider; fresh Safari requests afterward reached both IP sites through the
proxy. Explicit Stop and normal internet were checked before restoring the
ordinary signed app. See the [device record](device_matrix.md#iphone-acceptance-2026-10-18-117--core-261017)
for the fault boundary, timestamps and limits of that observation.

Current implementation/acceptance status (1.1.7, unreleased):

| Item | Status | Evidence and remaining work |
| --- | --- | --- |
| 1. Advanced DNS | Pending | Current protection tests cover resolver isolation/refusal. Protected DNS policies still replace imported DNS; full hosts/server/FakeDNS semantics are not accepted yet. |
| 2. IPv6 | Pending | Current tests prove blocking, not dual-stack forwarding, IPv6-only endpoint or NAT64 support. |
| 3. Protocol/transport matrix | Pending | Supplied VLESS TCP/Reality profiles work on devices. Full pinned-Core transport/socket-protection coverage is still required. |
| 4. Passthrough and VPN routing context | Partial | Imported listeners/authentication remain intact; private DNS/probe rules are scoped to their adapters. Apple retains caller API/services; Android/Windows API, caller stats/policy, source-inbound context and explicit VPN default selection remain open. |
| 5. Ports/addresses | Partial | Shared 20-case port, 12-case service-tag, 14-case numeric API and 28-case service-listener fixtures cover allocation. Real Android/iPhone list/range/env/Unix and tag-collision cases pass; iPhone also avoids simultaneous API/metrics ports with fresh browser traffic. OS port checks, service-name resolution, prefix-selector isolation, bind retries and broader proxy-only parity remain open. |
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
   and DNS tags. Apple/Windows currently replace DNS for VPN protection; FakeDNS
   and IPv6 remain constrained. Cover DNS loops and endpoint bootstrap without
   adding physical resolver fallbacks.
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
   overrides for logs and native protection.
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
