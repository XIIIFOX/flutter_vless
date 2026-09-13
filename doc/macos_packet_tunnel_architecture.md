# macOS Packet Tunnel Architecture

The macOS VPN uses a Network Extension containing Xray and HEV tun2socks.
Proxy-only mode runs Xray in the application process and installs system proxy
preferences. These modes have separate lifecycles and guarantees.

## Packet and control paths

```text
macOS application traffic
  -> Network Extension packetFlow readPackets/writePackets
  -> owned datagram socket pair (Darwin packet framing)
  -> HEV tun2socks
  -> authenticated loopback SOCKS inbound
  -> Xray routing
  -> selected proxy or configured direct outbound
```

The application sends bounded provider messages for readiness, counters and
private diagnostics. A successful proxy-only delay measurement does not prove
that Network Extension packet forwarding works.

## Startup and persistence

1. The application validates the profile and IPv4 bypass CIDRs.
2. It stores configuration bytes in a scoped shared Keychain item. Saved
   provider preferences contain a persistent reference, not the JSON profile.
3. It saves the mandatory routing and on-demand policy, then starts the provider.
4. The provider reads the secret, supplies fresh local SOCKS credentials and
   prepares transport endpoint addresses before installing virtual DNS.
5. It installs capture routes and starts its recovery watchdog.
6. Xray and HEV start using the prepared configuration. An owned socket pair
   connects HEV to the public `NEPacketTunnelFlow` packet API.
7. The application reports `CONNECTED` only when Network Extension is connected
   and the provider reports forwarding readiness.

Preparation failures reject startup. The provider never runs the original JSON
as a fallback. An identical active configuration is an idempotent start; a
changed profile requires an explicit stop before replacement.

Endpoint bootstrap gives the system resolver two seconds per lookup. If it does
not return an address, the provider resolves public transport names using HTTPS
to `https://1.1.1.1/dns-query` with normal certificate validation, a five-second
request/resource timeout, and no redirects, cookies or persistent cache. This
uses the same upstream as tunnel DNS, without depending on mDNSResponder while
the protected tunnel is starting. Single-label names and reserved local suffixes
do not use the public fallback. Only transport endpoint names are queried, never
routing domains, sniffed destinations or TLS/Reality server names. Responses must
match the question and its CNAME chain. Cancellation stops outstanding lookups;
bootstrap retries are bounded. No bootstrap lookup runs after virtual DNS is
installed or during worker recovery.

## Network and configuration invariants

| Area | Behavior |
| --- | --- |
| Profile protection | `includeAllNetworks = true`, local network exclusions disabled, sleep disconnect disabled; APNs/cellular service exclusions disabled where available |
| IPv4 | Default capture plus an explicit route to virtual DNS `198.18.0.2` |
| IPv6 | Default capture and an Xray `::/0` block rule; application forwarding remains IPv4-only |
| Endpoint bootstrap | Resolve before installing virtual DNS and retain prepared endpoint mappings during worker recovery; endpoint route exclusions prevent transport loops |
| System DNS | Publish `198.18.0.2` with `matchDomains = [""]`; relay TCP/UDP DNS through Xray as TCP DNS to `1.1.1.1` via the selected proxy |
| DNS fallback | No physical DNS host-route exclusions or system-resolver fallback after setup |
| Managed listener | Exactly one loopback SOCKS inbound with native session authentication; reject extra listeners |
| Imported management API | Remove it before running Xray |
| Domain routing | Preserve user rules and remote credentials; use sniffing with `routeOnly = true` so domain rules cannot bypass the literal IPv6 block |
| Subnet bypass | Translate IPv4 CIDRs into Xray direct rules below mandatory DNS/IPv6 rules, rather than adding system route exclusions |
| Unsupported configuration | Reject ambiguous fields, incompatible FakeDNS and unsupported endpoint resolution forms |

Server domains remain intact for TLS SNI, Reality and XHTTP. Prepared DNS host
mappings align endpoint resolution with routing without rewriting remote
credentials or the transport's domain fields.

## Readiness, recovery and stop

The packet bridge keeps one outstanding `readPackets` call across worker
recovery. Old-generation callbacks and buffered packets are discarded on restart.
Both socket descriptors belong to this provider's bridge; there is no private
KVC lookup, descriptor enumeration or selection of another tunnel. Datagrams
preserve packet boundaries and HEV's four-byte Darwin address-family header.
Invalid/oversized frames are dropped. Each socket requests 512 KiB send and
receive buffers, falling back to 256/128/64 KiB if the OS rejects a larger size.
When the worker's socket is full, the bridge retains the current batch and retries
without issuing another `readPackets` call. The pending batch is capped at 4 MiB
and 4096 packets; exceeding either limit stops forwarding and requests recovery.
Pause, recovery and stop clear queued packets and cancel retries. Diagnostics
include packet counts, backpressure waits and buffer usage without packet data.
Descriptors close only after the native worker exits.
The adapter uses Apple's [public packet API](https://developer.apple.com/documentation/networkextension/nepackettunnelflow)
and the framing used by [HEV 2.15.0](https://github.com/heiher/hev-socks5-tunnel/blob/2.15.0/src/hev-tunnel-macos.h).

The provider checks the HEV worker state and authenticated SOCKS forwarding.
Network Extension's connected status alone means that the system accepted the
tunnel setup. It does not establish that the local workers can forward traffic.

Worker failures clear forwarding readiness and retain capture routes and virtual
DNS while recovery retries. Network changes and wake events schedule health
checks. Recovery reports `CONNECTING`; the saved on-demand policy requests
provider restart after process termination, subject to macOS scheduling.

Explicit stop first disables on-demand recovery in preferences. If that save
fails, the application does not silently stop the protected tunnel. Operations
are serialized, provider replies have deadlines, and worker teardown is bounded.

## Profiles, runtime and diagnostics

The host and extension must share the App Group or dedicated Keychain access
group used for profile references. Legacy plaintext profile migration is
transactional. Dynamic geo assets must be readable by the extension.

The private startup and asset-location APIs require macOS runtime revision
`xray-macos-v26.7.28-r1`. SwiftPM/CocoaPods use the bundled XCFramework when
available, otherwise the pinned release archive. Publish that archive before
distributing packages that depend on the hosted fallback.

Native diagnostics are bounded and omit imported log destinations, credentials
and raw runtime output. Use `getProviderDebugSnapshot()` to inspect readiness and
recovery state. The plugin does not use physical-interface reachability probes.

Proxy-only stop restores system proxy dictionaries only while their current
values still match the settings installed by this session. Changes made by
another application are preserved.
