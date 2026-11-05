# Apple VPN readiness and local DNS

The Apple adapters distinguish native forwarding readiness from the
reachability of a remote destination. `CONNECTED` requires the current session
and endpoint plan, a running HEV worker, and successful authentication to its
managed SOCKS listener within one cancellable two-second deadline. Startup
validation, packet-worker failure, authentication failure and cancelled or stale
sessions still prevent readiness. The watchdog does not open arbitrary external
connections or modify caller routing to make a connectivity check succeed.

To measure the network path, use a URL permitted by the profile:

```dart
final delayMs = await vless.getConnectedServerDelay(
  url: 'https://your-allowed-domain.example/health',
);
```

This separate measurement can fail while the protected runtime remains active.
A blocked default outbound or a private-only configuration is a valid policy;
`CONNECTED` alone does not prove remote-server or general Internet availability.

Existing iOS hosts must update their copied `PacketTunnelProvider.swift` from
`example/ios/XrayTunnel` together with the Swift package. The provider belongs
to the host extension; changing the package dependency alone cannot replace a
previously copied provider. The macOS provider is part of its package.

## DNS policy

Ordinary routed `tcp://`, `https://` and `h2c://` resolvers retain caller DNS
selection fields, static hosts, TLS authority and caller routing. For example,
named DoH endpoints pinned in `dns.hosts` can use different outbounds according
to the caller's IP/port rules. Preparing transport endpoints does not replace
those rules with a universal direct or proxy DNS rule.

Core's `tcp+local://`, `https+local://` and `h2c+local://` clients normally bypass
the routing dispatcher. The Apple tunnel prepares these modes as equivalent
routed clients with a private per-server tag and a dedicated physical outbound.
This preserves their direct-underlay intent while applying the SDK's scoped
socket protections. The private branch accepts only the resolver's finite
numeric or statically pinned addresses and exact TCP port, followed by a block
rule. It does not install system DNS changes or global route exclusions.

The effective runtime URL loses the `+local` suffix and uses an internal tag;
the imported source profile remains unchanged. Resolver selection fields and
HTTPS authority/path/query remain intact. Admission requires a usable selected
underlay and a numeric resolver or a finite static `dns.hosts` mapping. Unsafe
or unsupported forms fail preparation rather than falling back to the system
resolver. Other DNS schemes, OS-resolver modes and IPv6-only/NAT64 environments
require testing on the deployment network; the supported local-DNS forms do
not establish those paths.

Upstream behavior is pinned to [Xray-core 26.10.31 TCP DNS](https://github.com/XTLS/Xray-core/blob/v26.10.31/app/dns/nameserver_tcp.go)
and [DoH DNS](https://github.com/XTLS/Xray-core/blob/v26.10.31/app/dns/nameserver_doh.go).
