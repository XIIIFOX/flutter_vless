# macOS Packet Tunnel Architecture and Regression Notes

This note documents the working macOS VPN path for `flutter_vless`.
It is intentionally detailed because the macOS Network Extension path has many
places where a tunnel can report `connected` while real browser traffic is still
stalled. Keep this file close to the implementation when changing the packet
tunnel, Xray config normalization, DNS handling, route exclusions, or debug
health checks.

The current working model was validated with VLESS/XHTTP-style configs on macOS
using Xray core `26.7.28`, a Packet Tunnel Network Extension, and HEV
tun2socks. The important final evidence was:

- `Server TCP route health check: ok <server-ip>:443`
- `XRay started successfully`
- `SOCKS inbound health check: ok response=05 00`
- `SOCKS CONNECT health check: ok response=05 00 00 01 ...`
- `SOCKS HTTP health check: ok 1.1.1.1/cdn-cgi/trace HTTP/1.1 301 Moved Permanently`
- `SOCKS URLSession HTTPS health check: ok status=204`
- Default IPv4 route moves to `utun`.
- Packet Tunnel DNS is published as `1.1.1.1` / `8.8.8.8` with
  `matchDomains = [""]`.
- The proxy server IPv4 host route stays on the primary interface.
- App-side raw TCP probes through the selected `utun` route can connect.
- Upload and download counters both grow over time.

## Runtime Shape

The packet path is:

```text
macOS apps
  -> NetworkExtension Packet Tunnel utun
  -> HEV socks5 tunnel / tun2socks
  -> local Xray SOCKS inbound on 127.0.0.1
  -> Xray proxy outbound
  -> remote VLESS server
```

The control/debug path is separate:

```text
Flutter app
  -> NETunnelProviderSession.sendProviderMessage
  -> Packet Tunnel provider
  -> Xray stats / HEV stats / provider debug ring buffer
```

Proxy-only mode and VPN mode are different macOS paths. Proxy-only uses system
proxy settings and local Xray from the app process. Packet Tunnel mode uses the
Network Extension process, utun routing, HEV, and a local Xray inbound inside
the extension. Do not assume that a proxy-only delay probe proves the Packet
Tunnel path is healthy.

## Startup Order

The stable startup sequence is:

1. The app saves or reloads the `NETunnelProviderManager`.
2. The app writes the Xray config bytes into `providerConfiguration`.
3. `startVPNTunnel` asks macOS to start the extension.
4. The provider prepares the Xray JSON for the packet-tunnel constraints.
5. The provider applies `NEPacketTunnelNetworkSettings`.
6. The provider checks the remote server TCP route before starting Xray.
7. The provider starts Xray.
8. The provider starts HEV tun2socks against the local Xray SOCKS inbound.
9. The app polls provider messages for stats and debug snapshots.

The app may optimistically start its UI/traffic timer after `startVPNTunnel`
returns, but the trustworthy readiness markers are the provider health checks.
`NEVPNStatus` values seen in logs:

- `1`: disconnected
- `2`: connecting
- `3`: connected
- `5`: disconnecting

Seeing several repeated `status=2` or `status=3` callbacks is normal. The
Network Extension framework emits repeated status/configuration notifications
during profile reload and tunnel startup.

## Network Settings Invariants

These settings are deliberate and should not be changed casually.

| Area | Current value | Why it exists | What breaks if changed |
| --- | --- | --- | --- |
| Tunnel MTU | `1280` | Conservative MTU for nested tunnel/proxy transport. It avoids fragmentation-sensitive stalls across XHTTP/TLS paths. | Pages can partially load, large downloads may hang, or HEV may show traffic without useful browser progress. |
| Tunnel remote label | `127.0.0.1` | Matches the current sing-box Apple pattern: this value identifies the Network Extension endpoint and is not the VLESS server or TUN gateway. | Treating this as the gateway can leave macOS with an unusable self-peer route. |
| Tunnel IPv4 address | `198.18.0.1/24` | Uses benchmarking/test-net space for the local utun address and avoids colliding with normal LAN ranges. The default route gateway is the same local TUN address. | The previous `/30` setup still produced `198.18.0.2 --> 198.18.0.2` self-peer routes and app sockets failed with `No route to host`. |
| Included route | IPv4 default route through utun with gateway `198.18.0.1` | Makes Packet Tunnel mode route app traffic through HEV/Xray. | Without it, only selected traffic enters the tunnel and the VPN appears connected but does not carry browser traffic. |
| DNS host exclusions | disabled | The working macOS path publishes explicit Packet Tunnel DNS and lets resolver traffic follow the validated utun path. | Reintroducing DNS host exclusions can create stale/cloned resolver routes and make behavior depend on the pre-VPN network. |
| Server host exclusion | resolved proxy server IPv4 outside utun | Prevents the Xray outbound connection to the VPN server from being routed back into the same Packet Tunnel. | Routing loop: Xray tries to reach the server through the tunnel that depends on Xray reaching the server. |
| IPv6 | disabled in Packet Tunnel | The current validated path is IPv4-only. macOS can create IPv4-mapped IPv6 routes that bypass the explicit IPv4 server exclusion. | Server traffic may be sent through another utun route, starving the Xray outbound connection. |
| DNS settings | explicit `NEDNSSettings` with `matchDomains = [""]` | macOS needs a real default resolver while the Packet Tunnel is active. | With `dnsSettings = nil`, `scutil --dns` can show an empty unreachable resolver and browsers stall at DNS. |
| Profile route flags | `includeAllNetworks=false`, `excludeLocalNetworks=false`, `enforceRoutes=false` | Keeps the `NETunnelProviderProtocol` flags close to current sing-box Apple defaults; actual capture is defined by the provider's routes. | `enforceRoutes=true` can force macOS into stale utun-scoped route behavior after startup or teardown. |
| Xray DNS | `queryStrategy = UseIPv4`, optional host mapping for server domain | Keeps Xray's own resolution aligned with the IPv4-only packet path while preserving server domain semantics. | Xray may prefer IPv6 or resolve differently than the route exclusion, creating mismatched routing. |

## DNS And Route Model

The final working configuration is intentionally simple:

1. Publish DNS servers through Network Extension:

   ```swift
   let dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
   dnsSettings.matchDomains = [""]
   settings.dnsSettings = dnsSettings
   ```

2. Do not add DNS host-route exclusions.

This is the working compromise on macOS:

- `NEDNSSettings` gives the system resolver real nameservers while the tunnel is
  active.
- Resolver traffic follows the same validated Packet Tunnel path as normal app
  traffic.
- Only the remote proxy server IPs are excluded from the tunnel to prevent Xray
  self-routing.

Do not judge readiness only by `NEVPNStatus.connected`. The useful proof is an
app-side raw TCP probe through the selected utun route plus growing download
counters. If `raw-http-ip-literal-bound-utun*` fails with `No route to host`,
the Packet Tunnel route is still broken even when Xray's internal SOCKS health
checks pass.

### DNS States We Tried And Rejected

`settings.dnsSettings = nil`:

- Symptom: `scutil --dns` may show `resolver #1` with no nameserver and
  `reach = Not Reachable`.
- Result: Xray/HEV may still pass literal-IP health checks, but browsers can
  stall before opening useful TCP sessions.

DNS through the Packet Tunnel with the old self-peer route:

- Symptom: `route get 1.1.1.1` selects utun, but raw app sockets fail with
  `No route to host`.
- Result: It is easy to get upload counters and a connected status with little
  or no downloaded page data.

Removing Xray DNS entirely:

- Symptom: Xray may resolve the proxy server differently from the Network
  Extension route exclusion, especially with dual-stack DNS.
- Result: The provider can exclude one IPv4 while Xray attempts another address
  family or another address.

The current approach keeps system DNS explicit, keeps DNS packets reachable,
and keeps Xray's own DNS on IPv4.

## Xray Config Normalization

Imported configs are app/user/server owned. The Packet Tunnel provider adjusts
only the pieces needed to run that config inside the macOS extension.

### Preserve The Proxy Server Domain

The provider resolves the proxy server domain to IPv4 for route exclusion and
for Xray DNS host mapping, but it does not replace the outbound server domain
inside the Xray outbound.

Why:

- TLS, Reality, XHTTP, and server-side routing can depend on the original
  domain, SNI, host, or authority fields.
- Replacing the server with a raw IPv4 can make a transport pass TCP connect but
  fail at TLS/Xray protocol level.
- Keeping the domain in Xray while mapping it to IPv4 through Xray DNS preserves
  protocol semantics and still aligns the connection with the provider's IPv4
  route exclusion.

Good log:

```text
Resolved proxy server domain <domain> to IPv4 <ip> for packet tunnel routing
Using local Xray inbound port 10807, server=<domain>
Excluded IPv4 server route(s): <ip>
Server TCP route health check: ok <ip>:443
```

### Force Local Inbounds To The Proxy Outbound

Packet Tunnel traffic enters Xray through a local SOCKS/HTTP inbound. Imported
configs can contain routing rules intended for normal Xray clients, not for a
Network Extension feeding all system traffic through one local inbound.

The provider tags local SOCKS/HTTP inbounds and inserts a high-priority routing
rule:

```json
{
  "type": "field",
  "inboundTag": ["in_proxy"],
  "outboundTag": "proxy"
}
```

Why:

- Prevents local tunnel traffic from falling through to `freedom` or another
  default outbound.
- Makes the Packet Tunnel data path deterministic.
- Keeps imported route rules from accidentally bypassing the VLESS outbound.

Good log:

```text
Forced local tunnel inbound(s) in_proxy to proxy outbound proxy
```

### Use Sniffing With `routeOnly = true`

The provider enables sniffing on local SOCKS/HTTP inbounds, but uses
`routeOnly = true`.

Why:

- Xray can still use sniffed metadata for routing decisions.
- Xray should not rewrite the outbound destination in a way that breaks literal
  IP health checks, domain-sensitive transports, or the HEV -> SOCKS flow.

Earlier `routeOnly = false` behavior could make handshake-level checks pass
while the actual HTTP byte path stayed fragile.

### Ensure A Local SOCKS Inbound

HEV speaks SOCKS to local Xray. The provider therefore needs a usable local
SOCKS inbound:

- `listen = 127.0.0.1`
- `auth = noauth`
- `udp = true`
- stable local port, usually `10807`

If a config has only HTTP or a malformed local inbound set, the provider injects
or normalizes a SOCKS inbound. This is not an optional convenience; it is the
bridge between utun packets and Xray.

### Block UDP/443

The provider adds a UDP/443 blackhole rule.

Why:

- Browsers prefer QUIC/HTTP3 over UDP/443 when possible.
- The current Packet Tunnel validation is focused on the TCP path through HEV
  and Xray.
- If QUIC is allowed to dominate early traffic, browsers can look stuck even
  though TCP fallback would work.

The rule forces browser traffic toward TCP/TLS, which is the path proven by the
SOCKS HTTP and URLSession HTTPS health checks.

Good log:

```text
Added UDP/443 block rule to force browser TCP fallback
```

### Disable Xray File Logs In The Extension

The provider clears Xray file log outputs.

Why:

- The Network Extension sandbox has a smaller and different filesystem view
  than the app process.
- Imported desktop/mobile configs often contain log paths that do not exist or
  are not writable in the extension container.
- A bad file log path can make Xray startup fail before networking is tested.

Runtime diagnostics instead use:

- `TunnelDebugStore` in memory.
- Optional App Group debug file.
- HEV log tail under the extension temp directory.
- Provider messages such as `xray_debug` and `xray_traffic`.

## HEV tun2socks Settings

The provider starts HEV with a local SOCKS target:

```yaml
tunnel:
  mtu: 1280
socks5:
  address: 127.0.0.1
  port: <local-xray-socks-port>
  udp: 'udp'
misc:
  task-stack-size: 20480
  tcp-buffer-size: 4096
  connect-timeout: 5000
  read-write-timeout: 60000
```

Why these matter:

- `mtu: 1280` matches the Network Extension MTU and avoids fragmentation issues.
- `tcp-buffer-size: 4096` keeps memory use modest in the extension and worked
  reliably with the tested XHTTP path.
- `udp: 'udp'` allows UDP packet handling inside HEV, even though UDP/443 is
  intentionally blackholed at Xray routing to force browser TCP fallback.
- The HEV log tail is included in provider debug snapshots because it shows
  whether HEV is creating TCP sessions or only seeing UDP churn.

Good HEV evidence:

```text
socks5 client tcp -> [203.0.113.10]:443
socks5 client tcp -> [192.168.1.1]:443
socks5 session tcp splice
```

Those lines mean real app TCP sessions are entering HEV and being spliced to
local Xray.

## Health Checks And What They Prove

The provider now emits several separate health checks because no single check
proves the full path.

### Proxy-only Delay Probe

Example:

```text
Started XRay delay probe on HTTP proxy port ...
Server delay probe response=204 delay=412ms
```

This proves the imported config can work in local proxy-only mode. It does not
prove Packet Tunnel routing, DNS, HEV, or extension sandbox behavior.

### Server TCP Route Health Check

Example:

```text
Server TCP route health check: ok 203.0.113.10:443 delay=74ms
```

This proves the resolved proxy server IP is reachable from the extension after
network settings are applied. Most importantly, it proves the server host route
is not trapped inside the utun default route.

If this fails after `setTunnelNetworkSettings`, suspect:

- missing server host exclusion,
- wrong resolved server IP,
- IPv6 path stealing traffic,
- network/firewall issue,
- server port mismatch.

### SOCKS Inbound Health Check

Example:

```text
SOCKS inbound health check: ok response=05 00
```

This proves local Xray is listening and accepting SOCKS no-auth negotiation.
It does not prove outbound proxy traffic works.

### SOCKS CONNECT Health Check

Example:

```text
SOCKS CONNECT health check: ok response=05 00 00 01 ...
```

This proves Xray accepts a SOCKS CONNECT request and can return a successful
SOCKS response. It still does not prove HTTP bytes come back through the remote
proxy.

### SOCKS HTTP Literal-IP Health Check

Example:

```text
SOCKS HTTP health check: ok 1.1.1.1/cdn-cgi/trace HTTP/1.1 301 Moved Permanently
```

This is one of the key checks. It sends an HTTP request to a literal IP through
the local SOCKS inbound. It deliberately avoids system DNS so it tests:

```text
provider -> local Xray SOCKS -> Xray proxy outbound -> remote server -> response bytes
```

Earlier failures here looked like `recv http failed errno=35` or a closed read.
That meant the SOCKS handshake was not enough: the byte path through the proxy
was still broken.

### Xray Internal Delay Health Check

Example:

```text
XRay internal delay health check: ok delay=0ms
```

This proves Xray's internal delay API can run. It is useful but not sufficient:
it can pass while system DNS or HEV/browser traffic is still broken.

### URLSession HTTPS Through SOCKS

Example:

```text
SOCKS URLSession HTTPS health check: ok status=204 delay=5129ms
```

This is a high-value real-client check. It uses `URLSession` with a SOCKS proxy
configuration, so it is closer to how system clients behave than a raw socket
probe. A passing status `204` proves HTTPS over the local SOCKS/Xray path works.

### Traffic Counters

Good counters grow in both directions:

```text
Traffic stats up=1618969 down=19672426 upSpeed=7749 downSpeed=218769 vpnStatus=3
```

Bad counters often show only upload growth or tiny download values. That means
traffic entered the tunnel but useful responses did not return.

## Reading Route Snapshots

The first snapshot can be too early. During `status=2`, default route may still
show the physical interface:

```text
route-default -> gateway 10.0.0.1, interface en0
```

The delayed snapshot after `status=3` is the important one:

```text
route-default -> interface utun19, mtu 1280
route-dns-1.1.1.1 -> gateway 10.0.0.1, interface en0
route-dns-8.8.8.8 -> gateway 10.0.0.1, interface en0
203.0.113.10 -> 192.168.1.1, interface en0
```

`netstat` may show duplicate host entries, for example both:

```text
1.1.1.1 10.0.0.1 en0
1.1.1.1 link#43 utun19
```

That is not automatically bad. Use `route get <ip>` snapshots to confirm the
selected route. The working final logs showed `route get 1.1.1.1` and
`route get 8.8.8.8` selecting `en0` even while `netstat` had extra cloned utun
entries.

## Golden Log Checklist

A healthy macOS Packet Tunnel run should contain these stages:

```text
requestPermission result=true
startVless VPN ... configBytes=...
VPN preferences saved and reloaded status=1 enabled=true
startVPNTunnel returned currentStatus=1
NEVPNStatusDidChange status=2
NEVPNStatusDidChange status=3
```

Provider preparation:

```text
Legacy startTunnel entrypoint called
Starting Xray packet tunnel
Disabled XRay file log outputs for packet tunnel
Added Xray DNS queryStrategy=UseIPv4 for packet tunnel
Resolved proxy server domain <domain> to IPv4 <ip> for packet tunnel routing
Forced local tunnel inbound(s) in_proxy to proxy outbound proxy
Added UDP/443 block rule to force browser TCP fallback
Using local Xray inbound port 10807, server=<domain>
Configured packet tunnel MTU=1280
DNS route exclusions disabled; using Packet Tunnel DNS settings
Excluded IPv4 server route(s): <ip>
IPv4 settings local=198.18.0.1/24 gateway=198.18.0.1 remoteLabel=127.0.0.1 subnetMask=255.255.255.0 includedRoutes=default excludedRoutes=<n>
IPv6 tunnel routing disabled; using IPv4-only packet tunnel
Packet tunnel DNS servers=1.1.1.1,8.8.8.8 matchDomains=default
```

Provider health:

```text
Server TCP route health check: ok <ip>:443
XRay started successfully
SOCKS inbound health check: ok response=05 00
SOCKS CONNECT health check: ok response=05 00 00 01 ...
SOCKS HTTP health check: ok 1.1.1.1/cdn-cgi/trace HTTP/1.1 301 Moved Permanently
SOCKS URLSession HTTPS health check: ok status=204
```

System routes:

```text
route-default -> interface utun*
route-dns-1.1.1.1 -> interface utun*
route-dns-8.8.8.8 -> interface utun*
<proxy-server-ip> -> interface en0
scutil --dns -> nameserver[0] : 1.1.1.1, nameserver[1] : 8.8.8.8
```

Traffic:

```text
Traffic stats up=<growing> down=<growing> vpnStatus=3
HEV log tail includes socks5 client tcp -> [real-ip]:443
```

Shutdown:

```text
Method call: stopVless
System proxy cleared for ...
Calling stopVPNTunnel currentStatus=3
NEVPNStatusDidChange status=5
NEVPNStatusDidChange status=1
```

## Known Bad Patterns

### Connected But No Pages Load

Likely causes:

- System DNS resolver is empty or unreachable.
- DNS routes are trapped in utun.
- Server route is trapped in utun.
- Xray local inbound accepts SOCKS but outbound bytes do not return.
- Browser is trying QUIC/HTTP3 over UDP/443 instead of TCP fallback.

Look for:

```text
scutil --dns
resolver #1
  flags : Request A records
  reach : Not Reachable
```

or:

```text
SOCKS HTTP health check: recv http failed errno=35
```

### Upload Grows, Download Does Not

Likely causes:

- Packets enter HEV but do not return from Xray/remote server.
- Routing loop for server connection.
- DNS/QUIC traffic dominates but TCP page flow is not established.

Traffic counters with `up` growing and `down=0` are not success.

### Proxy Delay Works, VPN Fails

This means the config is viable in the app process local-proxy mode, but the
Network Extension path is broken. Continue debugging Packet Tunnel network
settings, HEV, provider sandbox, route exclusions, and DNS.

### `scutil --dns` Shows utun For DNS

This is acceptable only if `route get 1.1.1.1` and `route get 8.8.8.8` select
the physical interface. Resolver ownership and packet route are not identical
concepts on macOS.

### Repeated Status Events

Repeated `NEVPNStatusDidChange status=2`, `status=3`, or `status=1` callbacks
are noisy but expected. Do not treat repetition as failure unless the tunnel
never reaches `status=3` or health checks fail.

## Why Not Use These Simpler Alternatives

### Why not pin the Xray outbound server to IPv4?

Because VLESS/XHTTP/TLS/Reality configurations can depend on the original
domain. Pinning the outbound server field to an IP can break SNI, host headers,
certificate validation, or server-side routing. The provider should resolve the
domain for route exclusion and Xray DNS host mapping, while preserving the
domain in the outbound config.

### Why not leave DNS entirely outside Network Extension?

Because macOS can create an empty unreachable default resolver when a Packet
Tunnel is active with no `NEDNSSettings`. That makes browsers stall before they
open TCP sessions, even if literal-IP Xray checks pass.

### Why not exclude DNS host routes?

The validated macOS fix publishes Packet Tunnel DNS and routes resolver traffic
through the same utun path as normal app traffic. Excluding DNS host routes was
part of an earlier workaround, but it made behavior depend on the pre-VPN
network and did not fix the real failure: macOS had created an unusable utun
self-peer route.

### Why not enable IPv6 now?

The validated path is IPv4-only. Enabling IPv6 before adding explicit IPv6
server exclusions and health checks can create `::ffff:<server>` or other IPv6
routes through utun that bypass the IPv4 route safety net.

### Why not rely on Xray's delay API?

Xray delay only proves Xray can perform its own probe. It does not prove macOS
DNS, HEV packet forwarding, browser TCP fallback, or Network Extension routing.

### Why not keep UDP/443 open?

Browser QUIC/HTTP3 can obscure whether TCP/TLS page loads work. Blocking UDP/443
forces TCP fallback and matches the currently validated HEV/Xray flow.

### Why not use system proxy settings inside Packet Tunnel mode?

Packet Tunnel mode should not depend on system proxy settings. The app clears
macOS system proxy settings before VPN startup and on shutdown to avoid mixing
proxy-only and VPN behavior. Packet Tunnel traffic should be carried by utun,
HEV, and local Xray inside the extension.

## Files To Check Before Changing Behavior

- `packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_tunnel_support/FlutterVlessPacketTunnelProvider.swift`
  - Network settings
  - DNS settings
  - route exclusions
  - HEV startup
  - provider health checks
  - provider debug messages
- `packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos_tunnel_support/TunnelXrayConfigPreparer.swift`
  - Xray DNS normalization
  - local inbound normalization
  - forced inbound-to-proxy routing
  - UDP/443 blackhole rule
  - server domain/IP handling
- `packages/flutter_vless_macos/macos/flutter_vless_macos/Sources/flutter_vless_macos/FlutterVlessPlugin.swift`
  - `NETunnelProviderManager` lifecycle
  - system proxy cleanup
  - status stream/timer behavior
  - system network snapshots
  - provider message polling
- `bin/setup_macos_vpn.dart`
  - generated Xcode target setup
  - entitlements
  - App Group and Network Extension configuration

## Regression Test Procedure

Use a real macOS run of the example app, not only a build.

1. Start from a clean disabled VPN profile or delete the old profile.
2. Run `requestPermission`.
3. Start a VLESS config that uses the macOS Packet Tunnel path.
4. Wait for `NEVPNStatusDidChange status=3`.
5. Confirm the provider debug snapshot contains all golden health checks.
6. Open a real browser page or perform a real HTTPS request.
7. Confirm traffic stats grow in both directions.
8. Stop the VPN.
9. Confirm status returns to `1` and system proxy settings are cleared.

Build checks:

```bash
cd example
flutter build macos --debug
```

Signature checks are useful but can fail with `CSSMERR_TP_NOT_TRUSTED` when the
local Apple signing certificate is not trusted. That is a signing environment
problem, not a Packet Tunnel routing regression by itself.

## Quick Diagnosis Matrix

| Symptom | Most likely layer | First log to inspect |
| --- | --- | --- |
| `requestPermission` false | Apple entitlement/provisioning/profile | setup output, Xcode signing, App Group |
| VPN never reaches status `3` | Network Extension startup/profile | `NEVPNStatusDidChange`, provider startup logs |
| Server TCP check fails | route exclusion or network reachability | `Excluded IPv4 server route(s)`, `route get <server-ip>` |
| SOCKS inbound fails | Xray did not start or wrong inbound | `XRay started successfully`, inbound port |
| SOCKS CONNECT ok but HTTP fails | Xray outbound/routing/transport | `Forced local tunnel inbound`, `SOCKS HTTP health check` |
| Literal-IP HTTP ok but browser stuck | system DNS, QUIC, or app route behavior | `scutil --dns`, `raw-http-ip-literal-bound-utun*`, UDP/443 rule |
| Only upload grows | no response path | traffic stats, HEV tail, server route |
| `scutil --dns` empty resolver | DNS settings missing | `Packet tunnel DNS servers=... matchDomains=default` |
| Server route points to utun | routing loop risk | `route-default`, `route get <server-ip>` |

## Maintenance Rules

When changing the macOS Packet Tunnel path:

- Keep a literal-IP HTTP health check.
- Keep a real `URLSession` HTTPS health check.
- Keep route snapshots for default, DNS servers, and server IP.
- Keep explicit Packet Tunnel DNS publication enabled.
- Keep DNS host-route exclusions disabled unless a real macOS smoke test proves
  the alternative route model.
- Keep server route exclusion based on the same IPv4 address family Xray will
  use.
- Keep Xray outbound domain semantics intact.
- Keep IPv6 disabled until IPv6 routing, exclusions, and health checks are
  designed together.
- Keep UDP/443 blocked until QUIC over this path is deliberately tested.
- Do not use proxy-only success as proof of Packet Tunnel success.
