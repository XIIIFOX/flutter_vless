// The nativeinstance preview is retained preparation plus an owned runtime, not
// a general Xray/native API and not production host integration.
//
// V1 admits zero or authenticated single-port TCP SOCKS inbounds on 127.0.0.1;
// caller freedom UseIPv4, a separate selected plain freedom egress, and optional
// blackhole outbounds. It denies other inbound/outbound protocols, mux/chaining,
// headers/security/finalmask/socket policies, independent apps, router scripts,
// balancers and webhook rules. It deliberately does not implement proxy endpoint
// bootstrap, DoH/DoT/DoQ, FakeDNS, system families, IPv6, service records or ECH.
//
// Caller root DNS is retained: hosts, per-domain rules, tags, query strategy,
// cache and fallback settings are not replaced. Missing/empty/localhost DNS uses
// an EXPLICIT trusted numeric IPv4 TCP native default resolver; that is a native
// policy override, not exact OS split-DNS/mDNS/search-domain/Private-DNS behavior.
// Explicit caller numeric IPv4 remote TCP DNS is also admitted. At most four
// servers and at most 4000 ms per configured server are accepted; implicit/default
// zero timeout retains Core's existing 4000 ms default. General dual-stack DNS is
// not qualified even when source UseIP is retained.
//
// Prepare performs no Core.New/Start, resolution, sockets, environment writes or
// asset download. Build may read installed geodata assets. Source bytes and
// digest are separate from the privately normalized document. Every Start clones
// the compiled blueprint and binds the clone's exact pointers/source indices.
// A failed candidate closes only itself. Close revokes immediately and retains
// eventual cleanup ownership even when its bounded wait returns ErrDrain.
//
// LookupIPv4 calls the caller's own root DNS, whose pinned interface has no
// per-request context. Caller cancellation bounds waiting and rejects late
// results, but does NOT immediately cancel an already running remote root query.
// A one-worker limit rejects further lookups until that worker has returned;
// Close cannot report success while the worker remains. Native local/default
// delegate exchanges do have owner cancellation and close their own rays.
//
// Core logging, controllers, environment settings and config registries include
// process-global state. Prepare installs a discard common/log handler before
// decoding; private app log outputs are disabled. This API does not make those
// registries instance-scoped or authorize unrelated in-process code to mutate
// them. The intended v1 host is the separate opt-in nativepreview executable,
// with independently qualified socket protection. No host routes/DNS/proxy/VPN
// settings are touched and no Stats API or production capability is provided.
package nativeinstance
