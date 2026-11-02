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
3. It saves mandatory routing with On Demand staged disabled, then starts the provider.
4. The provider reads the secret, supplies fresh local SOCKS credentials and
   prepares transport endpoint addresses before installing virtual DNS.
5. After Core/capability preflight, it installs capture routes and arms only the
   configured recovery policy after network setup is confirmed.
6. Xray and HEV start using the prepared configuration. An owned socket pair
   connects HEV to the public `NEPacketTunnelFlow` packet API.
7. The application reports `CONNECTED` only when Network Extension is connected
   and the provider reports forwarding readiness.

Preparation failures reject startup. The provider never runs the original JSON
as a fallback. An identical active configuration is an idempotent start; a
changed profile requires an explicit stop before replacement.

Endpoint preparation captures a physical-path generation and bounded IPv4/IPv6
candidates with freshness/provenance. Encrypted bootstrap for public transport
names uses certificate-validated HTTPS at `https://1.1.1.1/dns-query`, without
redirects, cookies or persistent cache; reserved local names do not use that
public fallback. Only physical transport endpoint names are queried, never
caller routing domains or TLS/Reality identity names. Responses must match the
question/CNAME chain. Cancellation and newer paths revoke stale answers. Path,
wake, expiry and recovery can prepare a new plan from the original profile,
using the selected physical interface and serialized network-setting commits.
Caller DNS hosts and logical destinations retain their own meaning.

## Network and configuration invariants

| Area | Behavior |
| --- | --- |
| Profile protection | `includeAllNetworks = true`, local network exclusions disabled, sleep disconnect disabled; APNs/cellular service exclusions disabled where available |
| IPv4 | Default capture plus an explicit route to virtual DNS `10.0.85.53` |
| IPv6 | Default capture with caller IPv6 routing/query policy; real IPv6-only/NAT64/handover remains separate acceptance work |
| Endpoint bootstrap | Use a current physical-path plan, private finite endpoint dialing branches and mandatory interface binding; renew stale/path-changed plans without a protection gap |
| System DNS | Publish `10.0.85.53` with `matchDomains = [""]`; send private A/AAAA queries through caller Core DNS, with the selected-proxy TCP default for missing/localhost servers |
| DNS fallback | No physical DNS host-route exclusions or system-resolver fallback after setup |
| Managed listener | Separate authenticated loopback SOCKS adapter; preserve imported listeners, credentials and tags |
| Imported management API | Preserve caller API/services/statistics, including explicit null/disabled values; reserve its listener ports when allocating private adapters |
| Domain routing | Preserve caller rules and remote credentials; managed sniffing restores the routing context without changing imported listeners |
| Subnet bypass | Translate IPv4 CIDRs into Xray direct rules below managed DNS rules rather than adding system route exclusions |
| Unsupported configuration | Reject ambiguous fields, incompatible FakeDNS and unsupported endpoint resolution forms |

Server domains remain intact for TLS SNI, Reality and XHTTP. Private finite
socket branches align physical dialing with the endpoint plan without inserting
transport pins into caller DNS hosts or rewriting remote credentials. Explicit
local DNS modes use separate closed, bound branches; see
[Apple readiness and local DNS](apple-readiness-and-dns.md).

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

The provider checks the current HEV worker and authenticated managed SOCKS
listener under one cancellable deadline. It does not require a fixed public
site; use a caller-allowed connected delay URL for remote reachability.
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

The private startup and asset-location APIs use the pinned macOS runtime revision
`xray-macos-v26.10.31-r2`, which also closes listeners after invalid server
`h2Params`. SwiftPM/CocoaPods use the bundled XCFramework when
available, otherwise the same checksum-pinned published release archive.

Native diagnostics are bounded and omit imported log destinations, credentials
and raw runtime output. Use `getProviderDebugSnapshot()` to inspect readiness and
recovery state. The plugin does not use physical-interface reachability probes.

Proxy-only stop restores system proxy dictionaries only while their current
values still match the settings installed by this session. Changes made by
another application are preserved.
