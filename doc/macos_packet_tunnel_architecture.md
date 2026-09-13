# macOS Packet Tunnel Architecture

The macOS VPN uses a Network Extension containing Xray and HEV tun2socks.
Proxy-only mode runs Xray in the application process and installs system proxy
preferences. These modes have separate lifecycles and guarantees.

## Packet and control paths

```text
macOS application traffic
  -> Network Extension packetFlow / owned utun
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
6. Xray and HEV start using the prepared configuration and the provider's own
   validated packet-flow descriptor.
7. The application reports `CONNECTED` only when Network Extension is connected
   and the provider reports forwarding readiness.

Preparation failures reject startup. The provider never runs the original JSON
as a fallback. An identical active configuration is an idempotent start; a
changed profile requires an explicit stop before replacement.

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
