# Unpublished native DNS context capability

Status: **preview source only; not enabled by production builders or releases**.
Pinned Core commit: `92ccc939aaf4f8965f369cf0b142e005aeaa11d5`.
This internal capability is not a public upstream API or full advanced DNS support.

`overlay/` contains a strict instance/handler transport-bootstrap implementation
and its pure tests. Existing source changes are SHA-guarded in the manifest;
the additive local/default resolver patch also covers `features/dns/localdns`,
`app/dns` and Core construction. Other overlay files are new. Shared Go preparation
in `common/nativeconfig` sits above protocol/transport packages and must not be
imported back into `transport/internet` or `app/dns`.

`apply.py` verifies the pinned affected-source SHA256 values, creates a **new
copy** outside the source/module cache, and changes only that copy. It refuses
existing destinations, module-cache locations and symlink source trees. It never
patches an existing shared checkout or Go module-cache source. The acceptance
runner also verifies the exact module version and module checksum before copying.
The manifest records `published: false`; normal Apple/Android/Windows builders
have no dependency on this directory yet. A separate development-only Android
builder is described below; it does not replace the packaged executable.

## Implemented boundary

`NativeDNSOwner` owns immutable copies of endpoint metadata, a unique Core
instance identity, and a lifetime cancellation context. Every outbound binding
uses the exact compiled `*core.OutboundHandlerConfig` pointer and source index,
with expected protobuf type/tag as assertions. Empty or duplicate tags do not
serve as identities. No new tags, `sockopt.interface` values, marks, or global
hostname maps are introduced.

`Handler.Dispatch` restores the captured instance's DNS/outbound features with a
caller-purpose scope. `Handler.Dial` restores an endpoint-purpose scope even
when mux/proxy code supplies a detached context, while retaining the current
operation's cancellation/deadline. It never copies a first request's mutable
Outbounds/session state into a cached transport. Freedom caller lookups use the
captured instance DNS client; they never consult endpoint pins or the last
process-global `InitSystemDialer` features.

`DialSystem` may replace only a **local socket destination copy**, for an exact
owner + handler + network + hostname + port. The protocol's destination remains
unchanged for TLS/Reality SNI and HTTP Host. Literal IP endpoints cannot be
rewritten. Unknown endpoints, missing/foreign/closed scopes, SRV/TXT address
strategies, and unresolved physical names fail before OS resolution/dial.

An explicit `dialerProxy` target stays logical and is never pinned at that
boundary. Its existing explicit caller domain strategy can still resolve it
through the instance DNS client before redirect, as in Core. Only the eventual
leaf handler can bootstrap its own physical endpoint. Chain selection uses that
owner's outbound manager, including when another instance has the same tag.

Pin selection filters families against transport `DomainStrategy` and an
explicit outbound source Gateway; contradictory forced/source families fail.
Without an explicit source, the configured fallback family can be selected.
The prototype chooses one pin deterministically; it does not reproduce Core's
random endpoint selection, retry rotation or Happy Eyeballs over pinned IPs.

Existing controller-aware `effectiveSystemDialer` remains responsible for the
final numeric socket. The overlay does not replace or bind a bypass interface.
Interface protection/bypass routing still belongs to each native host and must
be verified for IPv4/IPv6 and bootstrap traffic. Process-global alternative
dialers/controllers remain shared Core state and are not made instance-owned
by this overlay.

## Scoped local/default DNS preview

An additive `features/dns.NativeLocalResolver` context seam now captures the
local/default lookup implementation without changing caller DNS protobufs.
Missing DNS, empty servers and explicit `localhost` can use an explicitly
installed native delegate. A present nil/not-ready/closed delegate never falls
back to the OS. Construction performs no query. The implicit scoped client has
a four-second bound; the legacy zero-timeout/local implementation is unchanged.
Current query cancellation and missing construction/Core context are combined
without retaining the first request. Close cancels active local-client contexts;
late answers are discarded and mutable IP slices copied.

`common/nativednsruntime.TCPResolver` is the first managed default policy, not a
replacement enabled by production native hosts. It accepts a numeric TCP
resolver and an exact compiled source index whose complete runtime handler has
registered with the owner. After Core construction the concrete manager validates
all expected handler pointers and seals Add/Remove under its admission lock.
Existing empty tags are supported without renaming or changing ordinary routes.
Hot handler mutation is explicitly unavailable for that sealed instance;
read-only API/statistics services do not require that mutation capability.

This first policy accepts only a simple freedom TCP egress: mux/chaining,
rewrites, custom TCP headers, socket options and other transports are refused.
That intentionally narrow qualification does not establish a protected default
through a proxy, DoH/DoT, or every freedom option. Native socket protection still
belongs to the host; numeric loopback acceptance cannot establish underlay bypass.
Ordinary plugin launchers do not install this delegate; the separate development
entry below owns its first restricted native integration.

Each lookup creates its own cache-disabled Core TCP name server and query-scoped
dispatcher. Even a cache-disabled upstream server otherwise coalesces same-name
requests using the first caller's context. Core's `toDnsContext` also detaches
cancellation. The per-query wrapper restores only that lookup's fixed operation
after detachment; no cached transport captures a first request. Native exchanges
allocate fresh bounded pipes and routing metadata without caller user/session
objects. Owner cancellation, the query deadline and delegate Close interrupt
owned pipes; Close also waits a bounded interval for handlers and reports a
drain failure. The enclosing host must still close Core.

The source-only tests exercise actual Core TCP DNS framing over in-memory pipes,
including independent same-name cancellation, plus source identity and late
result refusal. The CI-only local-default fixture adds missing/empty/explicit
localhost roots, independent owners, A/AAAA, mixed per-domain TCP, unchanged
hosts/aliases/rcode/family filtering, real HTTP bytes and a stalled TCP exchange
canceled by owner Close alone. Local runs compile that fixture without executing
Core; actual remote runtime results must be checked separately.

The source document is preserved, while an explicit native resolver policy
changes how `localhost` is resolved. This is not OS search-domain, mDNS,
split-DNS or `/etc/hosts` passthrough. Root `UseSystem` route probes, `+local`,
FakeDNS, ECH and other independent resolver paths remain gated. Opt-in Core
construction failure closes partial features and unadded handlers; legacy
construction behavior is unchanged. The native caller closes its owner/delegate
separately before Core.

## Retained native entry preview

`common/nativeinstance` now supplies a private retained preparation and runtime
API. `PrepareJSON` normalizes private log/security sinks, decodes/builds once,
and admits an explicitly limited graph before any Core construction. Source
bytes and their digest remain separate from the normalized compiled blueprint.
Every `Prepared.Start` clones that blueprint, binds the clone's exact outbound
pointers to a fresh owner/delegate, seals the manager and starts its own Core.
There is no process-global Core singleton or legacy bridge fallback.

This first development graph permits authenticated TCP SOCKS on IPv4 loopback,
simple caller freedom with explicit UseIPv4, a separate plain freedom selected
by source index for numeric TCP DNS, and blackhole. Root hosts and implicit,
empty, explicit localhost or numeric IPv4 TCP servers remain caller-owned.
Unsupported transports, endpoints, independent apps, scripts, socket options,
server callbacks and DNS capabilities are refused in this preview. Environment
mutation is refused before Core's configuration builder applies it. These gates
are qualification boundaries for the unpublished entry, not changes to ordinary
plugin configuration support or completion of the full compatibility plan.

`Runtime.Close` revokes admission synchronously, then owns delegate/Core cleanup
and outstanding lookup work. Its wait is bounded and reports incomplete cleanup;
a timed-out wait does not relinquish cleanup ownership. `LookupIPv4` uses the
caller root DNS, including hosts/per-domain rules. That pinned root API is
context-free: cancellation bounds the caller's wait, while at most one tracked
worker remains outstanding until the actual lookup ends. It does not promise
immediate cancellation of a remote caller DNS request. There is no Stats API in
this preview.

`main/nativepreview` is a separate executable with `capabilities`, `check` and
`run` commands. Check/run require the exact `native-instance-preview-1`
capability, an absolute private `--config` path, numeric IPv4 `--resolver`,
`--egress-index` and an optional bounded `--timeout-ms` (at most 4000). It emits
closed JSON statuses and an exact source digest, never decoder/Core text. Both
preparation and runtime trap unintended system resolver attempts. `run` accepts
one private stdin `stop\n` command; parent EOF also stops and drains the runtime.
The `started` status establishes native startup only. Every response explicitly
reports `host_qualified: false`; it is not tunnel/packet-path readiness.

The separate Android command requires a development-only S/Q FD broker. A
legacy H/P broker cannot acknowledge that capability. The strict contract
requires protect and binding to the captured physical Network, permanently
revocable admission, and no D/system-resolver delegation. Generation revocation
does not retroactively close an already acknowledged Core socket: its native
host must also close the owner/runtime on network replacement or Stop. Ordinary
Android launchers continue to use the existing legacy path.

`python3 tool/build_android_dns_preview.py --ndk NDK --output NEW_DIRECTORY`
composes both pinned overlays in a disposable copy and builds only
`libxray_dns_preview.so` for the selected ABI (`--arch`, default x86_64). It never
installs, runs, publishes or replaces an official artifact. The build report
records source and output hashes, verifies unchanged inputs/cache, and keeps
production/host qualification false. Go 1.27+ can be selected with `--go`.

The CI-only launcher fixture checks the actual child entry, separate resolver
observations, authenticated HTTP bytes, static-host precedence, rejected
candidate preparation, bounded stalled-socket Stop, independent runtime
survival, parent EOF, output EOF and process reaping. Compiling that fixture
locally is distinct from a remote runtime PASS. Native mobile host wiring and
the OS-facing DNS bridge remain pending; none of this establishes browser DNS
compatibility, DoH/DoT/FakeDNS or full dual stack.

## Required native host integration contract (partial)

1. Freeze a candidate's compiled config once, then enumerate **that exact
   config's** `Outbound[i]` pointers. Construct one binding for every outbound,
   including nontransport freedom/DNS/block roles; otherwise their construction
   is rejected. Do not tag/rename/reorder caller outbounds. Hot API-created
   handlers need an explicit owner binding lifecycle and are currently rejected.
2. The shared Go endpoint extractor must identify only physical endpoints
   for the allowlisted VLESS/VMess/Trojan/SOCKS/HTTP/Shadowsocks roles. Its native
   metadata carries source index, expected type/tag, network/host/port and IPs.
   It is privileged side data, never an accepted caller JSON policy key. The companion common/nativeconfig preparation helper is unpublished too;
   ordinary platform bridges do not enable it. Additional proxy protocols remain unsupported.
3. Prepare endpoint IPs through a protected pre-tunnel bootstrap resolver. The
   imported `dns.hosts` must remain unchanged and retain its Core semantics;
   endpoint static-host/alias precedence must be explicitly defined and tested
   before this resolver is implemented. Blindly substituting a physical
   bootstrap answer can contradict caller hosts or per-domain DNS intent. The
   transport overlay accepts already prepared IPs. The shared preparation helper
   uses Core's actual static-host matcher for pure host/alias planning, but no
   protected dynamic bootstrap resolver or native host integration is enabled.
4. **Before preserving caller root DNS, run a root DNS/native capability gate.**
   Transport validation is insufficient: root DoQ/QUIC, `localhost`, `+local`
   DoH/DoT, ECH record lookup, FakeDNS, WireGuard/browser/Realm resolver paths can
   bypass this `DialSystem` hook. Missing/empty DNS also defaults to local DNS.
   Such paths must be rejected explicitly in the strict candidate until their
   resolver/socket seams are implemented; they must not silently fall back to
   physical DNS. `common/nativeconfig.AnalyzeRootDNS` classifies these compiled
   requirements and `ValidateRootDNSCapabilities` rejects an unqualified set.
   The development entry gates its restricted graph; ordinary plugin launchers
   do not enable it. No production host installs the scoped localhost implementation, and no QUIC
   capability is qualified. Preserving arbitrary root
   DNS is **not safe to enable** from this patch alone.
5. Construct using owner context + `core.NewWithContext`. `NewHandler` now uses
   checked feature assertions and returns a fixed scope error on missing
   features. `core/xray.go:218-251` installs essential defaults before initial
   inbound/outbound creation, so the initial feature capture ordering is
   supported by source and the remote-TCP CI factory fixture. It does not require
   `RequireFeatures` just for that order. Alternate construction and native host
   integration remain separate gates; pure Handler tests alone cannot establish
   them. For a scoped default delegate, seal runtime identities and bind the
   delegate after the same Core.New succeeds and before Core.Start.
6. On failure or shutdown call `owner.Close()` **before** `Core.Close()`; never
   reuse an owner/config pointer set for another instance. Profile-delay Core,
   VPN provider and macOS proxy instances each need distinct owner/generation
   lifecycles. Candidate failure must not change the active owner's metadata.
7. Ship the same capability contract in Apple/Android bridges and the Windows
   packaged executable. The current unmodified CLI entry point cannot create
   metadata/owner context, and the patched strict CLI rejects unscoped handlers.
   A Windows wrapper/launcher and pinned patched binary pipeline are necessary;
   compiling a Windows executable does not establish that integration.

## Lifetime and semantic limits

Owner Close cancels contexts for the full duration of `Handler.Dial`, including
cooperative TLS/upgrade work until it returns, and the nested physical Dial.
A synthetic blocked transport test verifies cancellation delivery, not a real
TLS implementation's response. A context-free `dns.Client.LookupIP` cannot be
interrupted mid-call; late results are discarded. Post-Dial work, established
connections and resources are not forcibly closed by the owner; the native host
must close Core. Cached/independent transports are rejected rather than assumed
safe. A transport that discards its dial context can still evade cancellation;
real runtime lifecycle coverage remains mandatory.

Freedom's UDP writer retains immutable handler ownership, refuses sends/lookups
after owner Close (including a cached IP), and refuses missing scope. Its old
implicit OS resolver fallback is replaced by Core `LookupForIPContext(USE_IP)`.
**That is a protection/semantic override for AsIs, not exact passthrough.** A
production design must choose a protected OS-resolver seam or reject unsupported
AsIs names. It must not advertise this behavior as unchanged caller DNS.

Freedom's **domain final-rule precheck with AsIs** is refused before any lookup,
retry or socket. The upstream separate `net.DefaultResolver.LookupIPAddr` branch
is removed by a SHA-guarded exact source replacement; it is not redirected to
caller DNS. `RequireFinalRuleDNS` marks configured AsIs final rules on a possible
domain target, excluding ignored rules behind dialerProxy and literal redirects.
An inbound can also supply a default private-IP final rule (for example VLESS),
so an outbound-only plan cannot enumerate every affected request. The same
runtime guard rejects that case too. This is an explicit unsupported combination,
not qualified protected system-resolver support or a complete final-rule policy
claim. Pure Process tests cover configured and inbound-default rules without
Core/sockets; CI also checks a real configured allow-rule request fails with no
system-resolver or fixture socket activity while the other owner still works.
The refused name matches an observed caller DNS fixture, so redirecting the
lookup to caller DNS would fail this check too. Numeric AsIs and named UseIP
requests with allow rules are successful controls in the same runtime fixture.

The name parser intentionally accepts only IP literals or ASCII DNS labels.
Underscore/IDNA and exact Core address acceptance parity are pending; it is not
a general-purpose Xray name validator. Each original literal must match its pin.

Pending paths include production protected localhost, `+local`/FakeDNS, root DoQ, ECH/HTTPS records,
QUIC/H3, gRPC, mKCP, XHTTP/SplitHTTP download/cached clients, Hysteria/MASQUE/FinalMask,
Realm, WireGuard, Browser Dialer, imported Reality server-side callbacks,
SRV/TXT address-port strategies, alias/static-host bootstrap semantics, endpoint
rotation, full concurrent shutdown, hot handlers, and actual socket protection.
The narrow transport allowlist itself still needs runtime qualification.
Both caller aliases `kcp` and `mkcp` compile to canonical `mkcp` in pinned Core;
the pure decoder/build test verifies that normalization and deliberate rejection
until mKCP UDP endpoint roles/lifetime are qualified. There is no unreachable
`kcp` allowlist spelling.

## Build and CI acceptance

From the repository root, `python3 tool/test_native_dns_context_runtime.py`
creates `build/native_dns_context_runtime/Core`, compiles/runs only the pure
policy tests, and **compiles without running** the actual Core acceptance test.
The retained native API and launcher policy tests are pure too; the separate
launcher and actual fixture are compiled without starting Core locally.
Go 1.27+ is required; `--go /path/to/go` selects an existing toolchain. It never
changes the selected toolchain. A rerun refuses to overwrite the earlier Core
copy; use a fresh CI checkout or explicitly preserve/remove the owned build
artifacts first.

The actual runtime command is:

```text
python3 tool/test_native_dns_context_runtime.py --run-runtime
```

It requires `CI=true`; Darwin additionally requires `GITHUB_ACTIONS=true` in
both the runner and Go test. Do not run real Core on the developer Mac. Root
workflow wiring owns the Linux/macOS/Windows matrix. Output streams to the job
and to `build/native_dns_context_runtime/*.log`; `result.json` preserves each
phase's status and timeout. Runtime has a 75-second Go timeout and a 90-second
outer owned-child bound. The runner creates/terminates only its own child process
group; the fixture creates no external workers. All loopback listeners and
accepted connections have deadlines and owned cleanup.
The Unix guard also removes an owned group whose leader exited while a compiler
grandchild retained stdout; a harmless regression verifies a separate process
group survives. Windows uses the still-owned leader's process tree and never
guesses descendant PIDs after that leader exits. An unexpected inherited pipe
is a failure (status 125), not accepted runtime evidence; the runtime fixture
deliberately has no external worker processes.
Exit zero alone cannot pass runtime acceptance: the runner requires both exact
selected tests' `--- PASS` events, so an empty/mismatched test filter fails.

The CI-only `tool/fixtures/native_dns_context_runtime/runtime_test.go` constructs
real Core instances with exact compiled-config-pointer bindings. Two simultaneous
owners use identical SOCKS endpoint hostname/port, pinned respectively to `::1`
and `127.0.0.1` same-port fixture servers. Actual HTTP owner markers and unchanged
SOCKS logical hostname prove physical endpoint isolation. A plain HTTP request
through freedom uses **the same endpoint hostname and port**, resolving via
unchanged caller `dns.hosts`, not the transport pin. A's caller hosts answer is
`127.0.0.1` and B's is `::1`, opposite to each one's transport pin. Their outbound
sources are byte-equal while caller DNS source differs, so a global/cross-owner
DNS client cannot pass both expected markers. TCP DNS fixtures select
IPv4/IPv6 marker servers per domain and observe exact A/AAAA questions; only their
caller DNS tags route those numeric resolver destinations to freedom. It also
checks rejected candidate preflight, stale-owner A rejection while Core A is
still alive, B survival before/after Core A close, and root DNS/tag source
preservation. A fail-closed process resolver trap counts forbidden system-DNS
dials and is restored after fixture cleanup. The no-DNS case tests **raw factory
feature ordering only**, without name resolution; its implicit local-DNS plan
must still fail the remote-TCP capability gate. It does not qualify protected
usable default DNS.
The fixtures never relay or resolve any requested hostname outside loopback.
`TestAcceptanceNativeDNSLocalDefault` covers the additive scoped default policy
described above; the existing unscoped no-DNS factory case still does not grant
permission to use legacy OS DNS.

These are bounded acceptance cases. They do not validate DoH/DoT,
OS localhost/+local semantics, FakeDNS, ECH/QUIC/gRPC, native socket protection, routing/bypass
interfaces or an arbitrary imported root DNS graph. Those remain gated above.
Local compile and pure test evidence does not establish a successful runtime;
only the actual CI result does.

Pure copier/runner guard checks are:

```text
python3 third_party/xray-native-dns/test_apply.py
python3 tool/test_native_dns_context_runner.py
```

## Composition and next integration

The existing Android socket protection overlay is
`packages/flutter_vless_android/android/xray-protect/apply.py`. It modifies
`transport/internet/system_listener.go`, `features/dns/localdns/client.go`,
`transport/internet/reality/config.go`, `proxy/vless/inbound/inbound.go` and
`proxy/trojan/server.go`, plus new controller/protection files. It checks existing
system-dialer error propagation. The local/default preview also changes
`features/dns/localdns/client.go`, preserving its legacy protected dial block.
Compose them only in one disposable pinned Core copy:
apply this guarded source copy first, then the Android protection overlay to
that copy, preserving both sets of SHA guards. Do not patch the shared module
cache or select a different Core fork for Windows. The protection overlay does
not supply instance owner metadata, root DNS gates or bootstrap resolution.
The localdns legacy protected dial block remains byte-identical; structural
composition and its pure localdns tests pass. Composition still needs the same
actual fixture plus Android-specific FD/UID tests
before shipping; no production composition is enabled here.

Prefer one shared Go preparation/extractor against built Core proxy settings
and MemoryStreamConfig, including exact XHTTP/download aliases. Native side
metadata should carry config-index/owner identity. Root DNS resolver endpoints
and ECH requests require separate purpose identities, not transport pins. No
native whitelist or blanket DNS replacement should be added to bypass these
capability gates.
