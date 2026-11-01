# Bounded compatibility acceptance, 2026-11-01

Work stays on `main`, with Flutter packages at `1.1.7`. No pub.dev/plugin
publication or live macOS VPN session is part of this stage. The owner's Mac
VPN and unrelated working files/processes must remain untouched.

| Item | Completion boundary | Evidence still required at the start |
| --- | --- | --- |
| 2ip Loading and supplied-profile timeouts | Reproduce with independent OFF/reference controls; correct confirmed plugin defects with a failing test first; report external site/peer failures separately | Healthy iPhone OFF baseline, both split directions, independent Core/endpoint comparison for Android profiles 2/3 |
| S3 / Google Drive | Verify endpoint/auth identity, data round trip, cancellation and fresh-owner isolation with actual managed Core fixtures | Requalify controlled fixtures on current CI; live account/relay acceptance only if authorized test settings are available |
| IPv6 / DNS64 / NAT64 / handover | Runtime tests distinguish literal IPv6, synthesized destinations and address-family changes; include actual device/emulator checks where the network supports them | Explicit inventory of available network families; controlled CI coverage must not be called a physical IPv6-only network test |
| Config/import/protocol/transport matrix | A finite representative matrix covers full JSON/JSONC, file bytes and URI/subscription imports, preserving opaque fields and producing explicit failures; fix discovered defects before rerunning | Cross-platform adapter tests, literal-IP SOCKS with real TLS/SNI and wrong-route controls; QUIC/ECH support stated precisely |
| Windows and macOS Actions | Actual pinned Core routing/compatibility tests pass on both OSes at an identified source commit, with bounded teardown | Fresh Actions evidence for new runtime tests; live Windows VPN tests if the affected code needs them |
| Review and cleanup | Independent review of changed contracts; record results and external limitations, push main; stop owned VPN sessions/processes/emulators and verify ordinary internet | Final source/test review, receipt links and process ownership audit |

An import pass, `CONNECTED`, source-level test, controlled runtime test and
live network pass are different results. None substitutes for another.
Unavailable accounts, protocols or physical network conditions remain named
external acceptance limits; they are never marked as successful live tests.

The earlier baseline is recorded in
[Xray 26.10.29 compatibility](xray-26.10.29-compatibility.md). Results below are
updated as each boundary is reached.

## Corrections and their regression checks

* `23c6cdf` fixes VMess SNI loss, optional display names, encoded Trojan/VLESS
  credentials and scheme-only case normalization. Seven failures were reproduced
  first; independent review added an empty-SNI regression before the final fix.
  Explicit SNI wins; absent/empty SNI retains the transport-Host fallback.
* `9b92af4` bounds iOS/macOS delay sockets across proxy negotiation, TLS and
  HTTP with one monotonic budget. The original trickled CONNECT reply exceeded
  the 12.5-second parent limit. Eight real slow-peer cases now retire within
  their 8/10-second budgets; elapsed-time floors reject an immediate-error false
  pass. Existing HTTP success, bad-auth and untrusted-TLS controls still pass.
* `c21116c` gives Android delay work one five-second budget, retries only local
  listener refusals and bounds child/socket/reader/file cleanup. The native
  suite passes 393 tests in 53 classes; a subsequent interrupted-HTTP regression
  passes in its focused suite. Cancellation can wait for the armed deadline;
  immediate interruption is not promised. A valid slow handshake can exceed
  this diagnostic budget, so `-1` is not proof that a profile is unusable.
* `441b379` corrects both XDRIVE templates: the pinned Core requires VLESS
  Encryption and client Mux. Actual Core build tests cover the valid examples
  and eight invalid encryption/Mux/flow contracts. No user credentials are in
  these templates or in CI.

## Controlled cross-platform acceptance

[Compatibility CI 41337803683](https://github.com/XIIIFOX/flutter_vless/actions/runs/41337803683)
at `441b37967703c0e0bec206c9260fbc5c23c7f31d` passes on Linux, macOS and
Windows. Its 340 supervised runtime phases cover:

* Numeric SOCKS CONNECT destinations with real TLS 1.3 SNI, both routing
  directions, wrong/missing SNI and disabled-sniffing controls; actual IPv4 and
  IPv6 loopback traffic. `routeOnly` preserves the numeric destination.
* Scoped AAAA/TTL, resolver ownership and fresh generations, both NAT64 prefix
  address-carriage cases, IPv6 TCP/UDP and existing HTTP/3 traffic/lifetime
  regressions. Address carriage is not a DNS64 translator or physical handover.
* An encrypted S3 relay with two actual Core peers and two fresh owner
  generations, nonce-bound 42 KiB binary application payloads in both directions, and an
  independent Python SigV4/API service. The service's object-traffic totals
  include protocol overhead and are not application payload sizes.
* Google OAuth form/Bearer identity, data round trips and cancellation of real
  blocked OAuth/API sockets on controlled endpoints. This is not a Google
  account or full Google relay deployment.
* Config/file/opaque-field, native-routing factory/CLI and shutdown contracts.
  New runtime cases pass without skips. The two older opt-in public encrypted
  bootstrap checks remain skipped, one in each Apple preparation suite.

The same run passes 526 Dart/Flutter tests with six clean analyses, 255 iOS and
269 macOS preparation tests, and the actual Apple deadline/auth controls.
Windows source provenance records only two exact LF-to-CRLF checkout
projections for the XDRIVE JSON examples; other source bindings are byte exact.
Artifact downloads were checked against GitHub's digests and their source,
exit/drain and owner-lifetime records. No native Core or SDK was run on the Mac.

The earlier [RED run 41336113548](https://github.com/XIIIFOX/flutter_vless/actions/runs/41336113548)
is retained: it exposed the invalid XDRIVE examples and a Windows fixture's
typed connection-abort handling. A separate no-DNS trap exposed the Python
HTTP server's unnecessary numeric-loopback reverse lookup, now removed. That
change is not claimed as the proven cause of the old macOS timeout.

## Physical iPhone and Android emulator

The physical iPhone uses the public Apple `26.10.29-r3` SDK in a signed
`1.1.7+117` example. A fresh OFF baseline and all-proxy reference were followed
by two fixed-domain splits in the same guarded sessions:

* Default DIRECT, `api.ipify.org` PROXY: both HTTP 200, complete DOM and the
  expected ordinary/proxy primary addresses.
* Default PROXY, `api.ipify.org` DIRECT: passes with the explicit scoped DIRECT
  DNS server/rule in the [split-DNS recipe](../example/configs/split-dns/README.md).
  The original implicit-DNS case and a UDP/443-block-only control failed to
  complete the DIRECT API request. The passing DNS variant retained that UDP
  rule; DNS alone without it was not tested. Resolver answer addresses were
  not captured, so a GeoDNS cause is not established. Caller DNS is not silently
  rewritten by the plugin.

Every session received Stop acknowledgement and a healthy ordinary-browser
recovery check. Own browser frames/native screenshots corroborate the IP text;
a cached Device Hub image is not treated as a new observation. The new recipe
also passes six Dart forwarding checks and stock Core `run -test` in Android;
neither check is a cross-platform live DNS claim.

Canonical 2ip remained intermittent even before VPN Start: the iPhone embedded
view observed 503, 503 and 200 while the page still showed Loading; Safari also
reproduced Loading with VPN off. The independent 503 document contains a cookie
challenge. The challenge was not bypassed. These results do not prove a plugin
routing defect or establish a reliable public-site acceptance baseline.

Android's current public-profile comparison remains **unqualified**. Two
profiles produced earlier real traffic; later paired controls on stock
26.10.31 and the original, unmodified pinned 26.10.29 also timed out under the
same current network conditions. The original Core was built in the
[stock reference workflow](https://github.com/XIIIFOX/flutter_vless/actions/runs/41338608598)
without plugin patches. An earlier stock reference obtained tfox HTML; HTML
alone does not prove its separately fetched IP API succeeded. Neither an
expired account nor an SDK/MPTCP defect has been established. No current
two-direction public Android routing pass is inferred from the older pass.

Registration-free local Android S3 acceptance **passes** with the published
`26.10.29-protect3` binary, an unmodified stock 26.10.31 peer in the guest and a
Mac Python-only S3 API. Two actual example proxy-only sessions each forced a
SOCKS request of 43,008 nonce-bound binary bytes and received the exact 43,021-byte response;
the origin independently observed both requests. Fresh native client/server
owners, authenticated S3 reads/writes and zero signature failures were checked.
Both sessions stopped normally; final S3 objects, active sockets and server
workers were zero. This qualifies the local cloud relay, not public VPN routing.

The iPhone's passive network inventory had no global IPv6 prefix. The emulator
provides ordinary IPv4 connectivity behind the unchanged Mac VPN. Neither was
presented as a physical IPv6-only, DNS64/NAT64 or Wi-Fi/mobile handover test.

## Release boundary and remaining external acceptance

This bounded stage does not establish universal compatibility or publication
readiness. The remaining work is explicit:

* Upgrade native artifacts from the withdrawn 26.10.29 to the official
  [26.10.31 security release](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31),
  then requalify consumers. Upstream disables MPTCP by default. No silent
  repin or new native publication is included in these current-version results.
* Repeat fresh public Android split routing with an independently healthy
  peer/reference; retest the original implicit-DNS iPhone case if its policy
  is required. A passing explicit-DNS recipe does not erase that limitation.
* Actual S3/Google accounts, cloud quotas and a complete Google relay; real
  IPv6-only/DNS64/NAT64 and physical handover; active QUIC-SNI routing and a
  broader server-backed protocol matrix. Controlled tests do not replace them.
* Live macOS VPN acceptance only when the owner schedules interruption of the
  existing VPN. Windows/macOS Actions are controlled runner acceptance.
* Resolve occupied Android/macOS/Windows implementation-package versions and
  matching constraints before pub.dev publication. Versions stay at `1.1.7`
  during this stage; neither plugin nor package publication was performed.

Device teardown records show test VPNs OFF, ordinary internet restored, owned
examples/Core peers/servers/forwards/guards/emulators/ADB drained and all four
Mac network snapshots unchanged. Unrelated project/MCP processes and the two
pre-existing YAML edits are preserved. Final repository/process audit follows
the final test and documentation commit.

The VMess field mapping follows the
[v2rayN share-link specification](https://github.com/2dust/v2rayN/wiki/Description-of-VMess-share-link).
S3's independent signature verifier uses the public
[AWS SigV4 reference](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html).
