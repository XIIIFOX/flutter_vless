# Compatibility

Protocol support depends on the configuration, server and native Core capabilities;
accepting a profile does not guarantee that its remote server is reachable.

## Versions and platforms

The main package and platform interface use `1.1.7`. Android, macOS and Windows
implementations use `1.1.7+1`. The published packages shipped Xray-core
**26.10.31**. Builds from the repository, including the example with local
package overrides, use the **26.11.9** native previews below.

| Platform | Modes | Requirements | Runtime |
| --- | --- | --- | --- |
| Android | VPN, proxy-only | Android 6 / API 23+, VPN permission | Maven `26.11.9-protect1`; device and emulator ABIs |
| iOS | VPN, proxy-only | iOS 15+, signed Packet Tunnel extension and App Group | `26.11.9-r1` SDK |
| macOS | VPN, proxy-only | macOS 13+, signed Packet Tunnel extension and App Group | `26.11.9-r1` SDK |
| Windows | VPN, proxy-only | Supported Flutter Windows toolchain; administrator privileges for VPN; local runtime/helpers | Managed `26.11.9-r1` companion |

There is no Linux or web Flutter implementation. Linux CI validates shared Core
behavior; it does not add a Linux platform backend. See the
[platform guides](platform/README.md) for native setup and permissions.

Android includes `armeabi-v7a`, `arm64-v8a`, `x86` and `x86_64`, with 16 KiB page
alignment. Apps that require extracted native executables must retain
`packaging.jniLibs.useLegacyPackaging = true`. Apple tunnel testing requires
signed devices; an iOS simulator is not a substitute for a real VPN session.
Windows applications supply `xray.exe`, compatible `tun2socks.exe` and
`wintun.dll`; the plugin does not download missing binaries.

## Profiles and imports

- Share links: VLESS, VMess, Trojan, Shadowsocks, SOCKS and Hysteria2.
- Subscriptions: plain links, supported base64 lists and explicit multi-profile
  import with `parseMany()`.
- Full Xray JSON, including comments and a leading BOM.
- Supported Clash YAML and sing-box JSON profiles, including WireGuard and HTTP
  proxy outbounds in subscription/import context.

Use full JSON for Core features that do not have a share-link or typed-builder
representation. Unknown fields and caller data dictionaries are retained;
explicit nulls, empty containers and Core aliases are handled by the native
preparation path. Generated transport support is listed in
[protocols and transports](protocol_support_roadmap.md).

Single-document configuration APIs reject trailing documents or data. They do
not implement Core's multi-file override/merge semantics. A subscription's
first-profile import and `parseMany()` remain separate contracts. Arbitrary
browser `http://` URLs are not HTTP proxy share links, and `wireguard://` is not
a supported share-link format.

## Full configuration and VPN adapters

VPN mode adds a private authenticated loopback SOCKS adapter. Imported
listeners, accounts, tags, sniffing, API, metrics and services remain in the
runtime configuration. Multiple imported SOCKS inputs, such as `socks-in` and
`socks-direct`, do not have to be removed. Generated ports and tags avoid
profile collisions, with bounded OS port-allocation checks.

The private adapter is a distinct inbound. Rules tied to an imported
`inboundTag` do not automatically apply to it. Use `VpnRoutingOptions` to select
an imported source/default context when needed; ordinary starts remain valid
without that option. See [per-session routing](../example/README.md#per-session-vpn-routing)
and the [API contract](api.md#startvless).

Caller routing, DNS selection and an explicit `routing.domainStrategy` remain
authoritative. HTTP/TLS/QUIC sniffing supports domain routing for VPN traffic.
Imported log destinations are replaced by the documented private logging
policy; OS socket protection can also reject paths that cannot safely leave
the tunnel. See [security boundaries](security.md).

Isolated delay measurements intentionally omit imported inbound, API and
metrics listeners from the measured copy and allocate a separate authenticated
listener. This exception avoids listener conflicts and does not alter the
normal VPN/proxy configuration.

## DNS and IPv6

The managed VPN resolver delegates application A/AAAA queries to caller Core
DNS. It preserves explicit hosts, remote servers, domain selection, tags,
query strategies and supported encrypted DNS policy. `UseIPv4` retains its AAAA
NODATA behavior. A failed remote query does not silently fall back to a public
system resolver.

Apple VPN uses the protected virtual resolver `10.0.85.53`. Endpoint bootstrap
is prepared against the selected physical path independently of application
DNS policy. Ordinary routed `tcp://`, `https://` and `h2c://` resolvers retain
caller routing and HTTPS authority. Supported `tcp+local://`, `https+local://`
and `h2c+local://` resolvers require a usable physical path and finite numeric
or statically pinned destinations. Unpinned names and `quic+local` are not
covered by that local-DNS path. Read the [Apple DNS contract](apple-readiness-and-dns.md)
before using these modes.

IPv4 and IPv6 payloads and numeric endpoint addresses have dedicated native
preparation and forwarding checks. This does not establish every IPv6-only,
DNS64/NAT64 or cross-family handover environment. Those paths require testing
on the actual target network. Windows blocks physical IPv6 except for finite,
explicitly admitted proxy endpoint permissions; a direct IPv6 outbound is not a
general physical-IPv6 bypass. IPv6 bypass CIDRs are unsupported on Windows. Compatible FakeDNS profiles are admitted with
checks for private-address, pool, port and tag collisions; wider resolver
combinations still depend on Core and the platform's protected socket path.

## Readiness, statistics and diagnostics

`CONNECTED` reports native forwarding readiness. On Apple, the current session
must have a running packet worker and an authenticated managed listener; an OS
VPN icon alone is insufficient. A blocked default outbound or private-only
profile may be valid while general Internet access remains unavailable.

Measure a destination permitted by the active profile with
`getConnectedServerDelay(url: ...)`. That check is separate from readiness and
does not weaken protection or change caller routing. Invalid, cancelled,
stopped and replaced sessions cannot become ready through a late reply.

When the backend owns Core's statistics API, it enables missing private inbound
counter defaults without replacing caller policy levels or unknown fields.
Explicitly disabled statistics, null values and caller-owned API settings remain
authoritative; Core monitoring can be unavailable for those profiles. Apple VPN
counters come from its packet worker. Counter sources can include adapter
framing and must not be treated as an exact application-payload measurement.

`DiagnosticsOptions` bounds privacy-filtered native diagnostics. It does not
enable raw Core logs or expose configuration, credentials or arbitrary imported
log destinations. Preparation reports are optional API results and do not
prove network reachability. See [runtime diagnostics](runtime-diagnostics.md).

## Assets, ports and addresses

Supply datasets and certificates through paths available to the target app.
`geoAssetsDirectory` and `certificateAssetsDirectory` retain their separate
lookup rules; a desktop absolute path cannot be assumed to exist on a phone.
Relative certificate/key paths are frozen against the supplied certificate root,
without replacing system trust roots. Update data files while Core is stopped
unless using the managed update service.

Imported listener port lists/ranges, supported `env:` references and Unix-socket
addresses are handled according to Core and OS capabilities. Captured
port/address environment values are stable during one preparation attempt.
Generated listeners still need available OS ports; configuration checks do not
guarantee that an unrelated process cannot race a subsequent bind.

Managed XDRIVE S3/Google Drive and GeoDAT services require capabilities from the
actual loaded native artifact. A matching version string alone is insufficient.
The managed Windows companion supplies these capabilities; compatible external
stock Core builds remain usable for ordinary profiles that do not require them.
S3 and Google Drive XDRIVE profiles use the prepared cloud endpoint path;
`local` and `template` XDRIVE services are not admitted. See the [XDRIVE examples](../example/xdrive/README.md) and
[GeoDAT examples](../example/geodata/README.md).

## System controls and protection

Typed options cover notifications, quick access, reconnect, protection and
diagnostics. Android Quick Tile, macOS menu bar and Windows tray controls have
different OS lifetimes. Apple Control Center requires a separate signed host
extension. Unsupported surfaces and required protection guarantees fail
explicitly; they are not replaced with a weaker mode.

Android Always-on/lockdown is controlled by the user or device owner in Android
settings. Apple On Demand is not Apple's managed IKEv2 Always On, and this
custom Packet Tunnel cannot offer that managed guarantee. See
[options and system controls](options-and-system-controls.md) for the platform
capability matrix, configuration and persistence rules.

## Validation boundaries

Automated tests cover configuration preservation, controlled protocol exchanges,
DNS, routing, statistics, lifecycle and protection. System-VPN behavior must also
be tested on the target OS with real traffic. A compile, simulator run, localhost
Core test or connected icon does not establish the full network path.

The library does not claim every Core server composition, external cloud account,
transport handshake or network environment is qualified. Validate the protocols,
UDP behavior, DNS and routing used by your application. The
[VPN validation matrix](device_matrix.md) describes repeatable checks without
substituting historical test results for your deployment's acceptance.
