# Five bounded Core31 follow-ups

The five feature criteria are qualified on producer commit
`2505694c4001e7d52f06d6a63f29780da8dc7d49`, upstream Core
`a4a3dff5b20c2faae567b742c172c7b95e75c083` (26.10.31).
Flutter packages remain 1.1.7 and example remains 1.1.7+117. No Flutter package
or plugin release is part of this work. Physical-device acceptance is reported
separately below; a successful source test is not a public-binary device result.

## Completed source-runtime criteria

[Four-runner acceptance](https://github.com/XIIIFOX/flutter_vless/actions/runs/41446768463)
passes all applicable groups on Linux, macOS, Windows 2022 and Windows 2025.
The runner requires exact selected test/subtest results, control markers,
finite process/EOF deadlines, immutable input bindings and resource cleanup.

| Item | Actual acceptance |
| --- | --- |
| GeoDAT gzip | Content-sniffed decoding independently of filename; raw input with a gzip filename; corrupt/truncated headers, payload, CRC/trailer and second member; empty input; actual 256 MiB decoded boundary and one byte over; active H2 download cancellation; atomic replacement and preservation of previous files. |
| XHTTP | Actual TLS/H2 POST and OPTIONS exchanges in packet-up, stream-up and stream-one; exact 4,096-byte payloads; OPTIONS upload distinguished from genuine CORS preflight; observed server H2 SETTINGS, including 7 streams and a 32,768-byte maximum frame; wrong-path and invalid-parameter controls. |
| QUIC SNI | Eleven decoder controls and 44 actual UDP routing cases, including authenticated encrypted Initial CRYPTO fragments, out-of-order/coalesced/separate packets, repaired and unrepaired gaps, empty/wrong SNI, truncation and authentication corruption; both routing defaults, sniffing on/off, independent destination and unchanged packet evidence. |
| Windows Core TUN | Actual Core WFP installer on both Windows runners; TCP/UDP 853 and explicit protocol/port rules, unaffected controls, permitted interface and application cases; independent copied probe executable; exact installed filter conditions and restoration of the original filter inventory. UDP timeout alone cannot pass. No TUN adapter or route changes are needed for this isolated WFP criterion. |
| HTTP inbound | Actual Core HTTP proxy with short and fragmented `100 Continue`, exact 65,536-byte uploads; 417 rejection without upload, truncated interim response and cancellation controls, bounded shutdown. |

All seven example JSON files in `example/configs/core31/` are decoded and built
by the actual pinned Core with assertions on their resulting configuration.
The QUIC criterion covers finite Initial sniffing/routing; it does not claim a
complete HTTP/3 handshake, real-device UDP reachability or NAT64 qualification.
The WFP criterion covers Core `autoSystemWfpBlockLeak`, separately from the
plugin's ProtectionOptions and existing Windows VPN architecture.

## Correction and native distribution

The first runtime run reproduced a listener leak after malformed `h2Params`
on every OS. The correction closes the newly opened listener on that existing
error branch. A positive sibling configuration first proves the live server
and its SETTINGS; the negative control then requires rejection and immediate
same-port reuse. Thirteen file-only patch guards bind the exact change and
reject drift, duplication and symlink substitution.

All four corrected native releases are public and their anonymous downloads
match the qualified producer artifacts. Consumers at
`e9cf73568e4873dfd5dadf32036f937eb71531e3` select these releases:

| Platform | Native release | Canonical payload SHA-256 |
| --- | --- | --- |
| Android | [26.10.31-protect2](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-android-v26.10.31-protect2), GitHub and Maven | AAR `3280118949aa5fa05fa58d233642af5ebd3b7eb484bb3d30fffa29271cddcc12` |
| iOS | [26.10.31-r2](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-ios-v26.10.31-r2) | ZIP `8d693bc767b8f292f0ec0459850287f752c40499fa6542caef5b749c8bdc5f00` |
| macOS | [26.10.31-r2](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-macos-v26.10.31-r2) | ZIP `59f41c9f8d6bafce3b15741adb0aefe37634737ff1b22075fa4ec9b56fdc2687` |
| Windows AMD64 | [26.10.31-r2](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-windows-v26.10.31-r2) | ZIP `dfdf80c45268719d047cb14560fca11b6815b98961916c9b5dc68ad2a547f824` |

Android publication reused the same single reviewed Central deployment;
40 public Maven payload/signature/checksum files match it. Apple consumers
include the exact downloaded vendored framework trees as well as updated
SwiftPM/CocoaPods pins. Windows selects the exact public PE; the separately
pinned official stock Core remains distinct. Native release notes carry the
corresponding immutable build, provenance and verification details.

## Published-binary and device acceptance

[Apple public-mode acceptance](https://github.com/XIIIFOX/flutter_vless/actions/runs/41454266581)
and [Windows public-mode acceptance](https://github.com/XIIIFOX/flutter_vless/actions/runs/41454268132)
at the consumer commit pass their applicable jobs. Both install released,
checksum-pinned managed runtimes and skip rebuilding those native runtimes.
Detailed artifact qualification and final live-client outcomes are added only
after their independent evidence review. All seven evidence ZIPs were
downloaded and their GitHub digests verified. Apple runtime logs bind the
public manifest and SDK, actual capabilities, both routing directions and owned restart/drain;
the post-test framework trees retain exactly 15 iOS and 8 macOS files.
Both Windows versions retain the same public PE in their runtime and compiled
example and pass 21 proxy, 21 portable and 189 VPN controls each, including
both routing directions and managed/official numeric IPv6 controls with zero
remaining owned filters, routes or helpers.

The fresh Android example is built from the exact protect2 Maven payload;
the packaged/installed ARM64 ELF equals the normal pinned NDK stripping
transformation, rather than being incorrectly compared with the unstripped AAR
member. Ordinary Chrome IP checks pass with the Mac VPN connected.

The first controlled live XHTTP/HTTP composition is **not a pass**: example
Connect succeeds, the independent TLS front observes actual Core GET/POST and
SETTINGS 7/32,768, but the client times out before interim 100. The imported
HTTP accounts, ports, tags, CA, peer and routing rules survive preparation.
OPTIONS is not attempted after that failure. The app is force-stopped, native
VPN/service/Core absence and ordinary Chrome recovery are verified, and the
owned emulator/ADB/relay/guard are closed before their original deadline.
This timeout remains separate from the successful isolated runtime criteria.

A second no-VPN reference reproduces the failure even for ordinary GET.
Actual server DEBUG output identifies the cause: Freedom's default private-IP
protection for the VLESS inbound blackholes the owned loopback origin. This
does not establish a plugin import, VPN or HTTP-continue defect. The revised
test server requires an explicit `finalRules` allow limited to TCP,
`127.0.0.1/32` and its single owned origin port. The plugin does not insert
that permission or relax the caller's/private-network protection.

With that explicit server rule, the no-VPN exact-public-ELF reference passes
ordinary GET, POST/short-100 and OPTIONS/fragmented-100, including both exact
65,536-byte uploads. The actual Android example then passes the same three
requests after one real UI Connect, in 6.41 seconds for the whole session.
UI Stop, native fullStop acknowledgement, managed Core/service/VPN absence,
the disarmed/reaped 110-second guard, and all six reaped host clients pass.
The independent server sees three new APP-labelled origin connections and
records, separately from the closed no-VPN reference, with all 23 observed H2
statuses 200 and exact forwarding hashes in both directions. Fresh ordinary
Chrome IPify/AWS checks recover the same baseline IP after Stop; the four Mac
network snapshots remain unchanged within that Android phase.
This path is Mac raw client -> owned ADB forward -> actual app HTTP inbound
-> strict TLS/H2 XHTTP -> actual guest Core -> owned origin. It proves the
installed public Core's imported inbound and transport exchange; it does not
claim public ON browsing or TUN/domain routing from those requests.

The physical iPhone has the exact public r2 SDK in its newly installed example.
Native version/capability, own-manager OFF and ordinary in-app browser
HTTP-200 checks pass. The first timing-invalid attempt queried its HTTP port
after the 75-second safety Stop; that reset is not an XHTTP result. The bounded
replacement samples UI/native state before Stop and never sends a raw request
unless both report CONNECTED.

The first bounded attempt remains REASSERTING: the controlled profile and
origin-only server block the provider's fixed DNS/Internet health checks.
That is not evidence of an XHTTP failure. The final client fixture retains
blackhole as its default and the caller-HTTP-to-XHTTP rule first. Separate
exact TCP health routes allow only `1.1.1.1:80`,
`www.gstatic.com:80` and tagged TCP DNS at `1.1.1.1:53` through a dedicated
health Freedom outbound. All other destinations retain the default block;
the imported caller HTTP inbound has no direct fallback. Sixteen fixture
contracts reject wider routes, DNS-tag loss and precedence changes. The
server remains limited to the single owned loopback origin, with no public
egress permission.

With that explicit fixture policy, physical POST passes strict UI/native
CONNECTED, actual interim 100 before the exact 65,536-byte body, final 200 and
the exact response hash. The raw exchange completes in 0.627 seconds. Normal
UI Stop, fullStop, two native OFF readings and ordinary HTTP-200 recovery pass;
the guard is disarmed after OFF and never fires. The independent server
records the phone source address, exact forwarding hashes and the matching
origin upload. OPTIONS is not inferred from this result: its first batch
refuses preparation after the remaining server budget drops below the bound.
A separate, OPTIONS-only case on a fresh backend then passes the same strict
UI/native CONNECTED, fragmented interim 100, exact 65,536-byte upload,
final 200 and response hash in 0.336 seconds. The independent server observes
the actual phone source, three OPTIONS uplinks with no CORS-preflight header,
all H2 statuses 200, exact forwarding hashes and the matching origin upload.
Normal UI Stop, fullStop, two OFF readings and ordinary recovery pass again;
the guard never fires and all phone/app/VM/HTTP workers are reaped.

These physical cases use Mac -> owned USB forward -> actual phone HTTP inbound
-> strict TLS/H2 XHTTP -> actual guest Core -> owned nonce origin. They prove
the published phone Core's selected inbound/transport bytes. The raw client
executes on the Mac; this is not a phone-executed browser or TUN/domain-routing
result. Health-only direct permissions do not qualify general ON Internet
access. The source/public-SDK routing checks remain separately identified.
Live TLS terminates at the owned transparent fixture front, which forwards
HTTP/2 bytes to actual Core over h2c. Core server-side TLS is exercised by the
separate source-runtime acceptance.

The assigned Wi-Fi IPv4 is obtained through a separately built private QA
addition to the development-only interface inventory. It exposes only `en0`
IPv4, has two focused Flutter tests, and uses the same public SDK and signed
safety guards. Main/plugin/native sources remain unchanged by that QA delta.
The final phone orchestrator has fault controls for refused CONNECTED, partial
guard arming, normal-Stop failure, missing OFF, failed cleanup and a fired
guard. A failure cannot become a passing case through fallback Stop alone.
Only the original diagnostics-disabled state is retained; no automatic
reconnect, On Demand or quick-access reference is left active. The phone's
own app and current-install extension processes are absent after final cleanup.

No native SDK/Core was compiled or executed on the owner's Mac. App-only
builds use prebuilt public libraries. Live macOS VPN acceptance and plugin
publication remain excluded. Source, published-runtime, Android and physical
iPhone results were reviewed independently, with their evidence boundaries
kept separate. Backend06 closes with no faults: its Core/timer/watcher,
host children, ports and exact forwards/reverses are all gone. Final host
cleanup verifies the emulator, private ADB, relay, watchdog and their exact
netsimd/crashpad helpers absent, all owned foreground children reaped and
ports closed. A final task-path process audit is empty; pre-existing
MCP/application processes and the two foreign YAML edits are preserved.

The final root audit matches the initial DNS, proxy and connected Happ service
inventory/status byte for byte. The default route still uses a VPN interface,
but its identifier is `utun16` instead of the initial `utun14`; this is the
only textual route difference and its cause is not inferred. No task action
changed Mac VPN, DNS, default-route or system-proxy settings. Per-phase network
snapshots are kept distinct from that full-run comparison.
