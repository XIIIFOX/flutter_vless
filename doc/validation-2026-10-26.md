# Fresh-profile validation, 26 October 2026

This follow-up uses three fresh owner-supplied VLESS/REALITY JSON profiles
(Czechia, Cyprus and Israel) and the Israeli share link. Credentials, server
addresses, original files and device evidence stay in ignored private local
directories. They are not test fixtures committed to Git or uploaded to Actions.
The plugin and its implementation packages remain at 1.1.7 and are not published.

## Shared import and public API checks

The actual example importer, public facade and four Dart platform adapters pass
28 private serialization cases. These retain both caller listeners, accounts,
sniffing, DNS strategy, policy, routing and transport maps at start/delay
boundaries. They also cover source inputs 0/1, explicit default outbounds, both
domain split directions and the Czech profile's nonempty short ID. The supplied
share link retains its critical VLESS/REALITY parameters, empty short ID,
spiderX and Unicode title; a share link cannot represent the original JSON's
extra listener and routing rule. Another 58 existing targeted root/example
tests pass. Native channels are mocked in these 86 tests; they do not establish
server connectivity or native VPN behavior.

## Android example

A dedicated API 35 arm64 emulator runs the already verified example APK against
the published 26.10.21-protect1 AAR. The running Core executable matches the
packaged native bytes. No Core, SDK or AAR is compiled on the owner's Mac.

All six authorized live sessions pass both fresh browser pages:

1. Original Czech JSON, including its nonempty short ID.
2. Original Cyprus JSON.
3. Original Israel JSON.
4. Israeli share link, imported using the real Import (clipboard) button and
   the emulator's text-selection Copy action.
5. Czech proxy default with tfox.dev routed directly.
6. Czech proxy default with both 2ip.ru and its redirect target 2ip.io routed
   directly instead.

The routes are verified using different observed proxy/direct IPs; a CONNECTED
label alone is insufficient. The direct emulator path retains the Mac VPN's
baseline IP. Each session has one Connect, real Disconnect, native Stop
acknowledgement, Core/service shutdown and ordinary-internet recovery. The
longest active session is 35.12 seconds. No live runtime hang, crash or Chrome
network-change error occurs in these six sessions. Earlier clipboard control
failures occurred before Start and remain separately recorded.

The Cyprus profile produces the same IP on both sites, while their location
databases disagree: tfox.dev reports Sweden and 2ip reports Cyprus/Nicosia.
This is recorded as a database discrepancy, not a plugin routing failure.

The emulator, app, browser, port forward and owned test processes are stopped.
The shared ADB process is preserved. Before/after Mac VPN, DNS, proxy and route
snapshots are byte-identical.

## Physical iPhone

The signed acceptance example on iPhone 13 Pro Max uses the published SDK and
reports Core 26.10.21. The final qualified original-profile sessions verify
both 2ip and tfox.dev with each of the three fresh JSON profiles while the VPN
is still connected. The Cyprus and Israel trials load 2ip first; the final
original Czech trial also uses that order and explicitly disables the native
routing override. All three retain their exact stored original JSON.

Both explicit native routing variants pass both pages before their test Stop:

- Czech proxy default for tfox.dev, direct rules for 2ip.ru and 2ip.io.
- Direct default for tfox.dev, proxy rules for 2ip.ru and 2ip.io.

The actual routing UI selects these native defaults. Proxy/direct IP differences
are observed in fresh native screenshots before the 75-second host deadline;
the CONNECTED label is not used as an internet or routing result.

Earlier controller failures remain unqualified: a Czech response captured after
a possible automatic Stop, an over-budget Cyprus second-site check, an Israeli
ordinary-IP screenshot after Stop, and a reverse-route page still loading when
sampled. They are not rewritten as successes, proxy results or leaks. The Mac
also locks during the run; testing pauses with the phone VPN OFF until the owner
manually unlocks it. No unlock bypass is attempted. The subsequent fresh owned
session completes the remaining checks.

The acceptance build has test-only automatic Stop guards. They are distinct
from production connection behavior and do not qualify long-duration stability
or the full Options matrix. Some guards complete native Stop before a manual
Disconnect tap; those cases retain a native Stop acknowledgement without claiming
that the tap happened. Qualified sessions include ordinary-internet recovery.
Final recovery is captured again, original profile 3 is restored without Start,
and routing is disabled. Native options match their initial values: reconnect,
On Demand, quick access and diagnostics disabled; required protection retained.
The owned app, USB forward, Dart clients, guards and capture watchers are stopped.

Live macOS VPN testing remains deferred until the owner is ready; remote checks
do not modify the owner's Mac VPN. The share-link device import is qualified on
Android; the iPhone live sessions use full JSON profiles. Remote Apple/Windows
terminal results are recorded separately below.

Linux is a controlled Core/shared-preparation test platform in Actions, not an
implemented Flutter plugin platform. No local Linux VM is started: no ready
engine is available, and host-VPN-safe guest networking has not been qualified. The unrelated stopped Colima profile is preserved.

## Flutter smoke diagnostics

The previous combined CI installed the app but hung before its test-entry marker.
The new bounded supervisor retains verbose host launch/attach output, one extra
launch-window snapshot and PID-focused device logs. These use the existing
absolute attempt deadline and log limits. The optional retry remains limited
to a classified DDS startup failure; a timeout does not gain a retry.

The [fresh standalone smoke run](https://github.com/XIIIFOX/flutter_vless/actions/runs/40232767506)
passes all three tests in one attempt against the actual published runtime
(Xray 26.10.21, Go 1.27.3, Android amd64), including real test entry and child/app
cleanup. It does not prove the cause of the earlier combined-workload hang.
Its trace also exposed a diagnostic parser bug: Flutter's verbose
`VM Service URL on device:` message was not recognized. A regression reproduces
that false observation; the narrow fix changes only the diagnostic boolean and
retains the version, test-entry, exact three-test summary and successful-exit
requirements. All 45 supervisor tests pass. One earlier unrelated synthetic
one-second timing failure is retained; its focused check and full rerun pass.

The [combined Android corridor](https://github.com/XIIIFOX/flutter_vless/actions/runs/40234333712)
also passes at 7c441e0 in the mandatory native → Flutter → separate-UID order:
41 native instrumentation tests, both routing tests and three Flutter tests
pass without skips. Flutter takes 93.068 seconds in one attempt with the exact
26.10.21/Go 1.27.3 runtime, and child/app/emulator cleanup completes. Separate UID
is denied by Android access control; this run does not exercise the native peer
credential denial branch. The former 600-second pre-entry hang does not recur
in this combined run; its historical cause remains unproven.

The [Apple/Windows checks](https://github.com/XIIIFOX/flutter_vless/actions/runs/40234802035)
pass all five active jobs at the same 7c441e0 source; six jobs are outside this
manual scope. They run without private owner profiles or release steps. The Windows job builds the
example EXE and passes options, status/cancellation, tray callbacks, config/DNS/
IPv6/domain-routing boundaries and cleanup tests. Its WFP test uses a recording
backend, so it adds no real Windows TUN traffic claim.

Apple passes unsigned iOS/macOS example builds, the SwiftPM build, and all twelve
controlled Core 26.10.21 privacy/DNS/FakeDNS/native-routing runtime modes on both
iOS simulator and macOS. The iOS HEV simulator slice is link-only. The macOS HEV
packet probe passes real IPv4 bidirectional bulk transfer and IPv6 TCP/UDP, with
clean shutdown. Fifteen Darwin semantic tests use a fake OS and virtual API
checks establish type compatibility only. The Apple XCTest suites report 252
and 266 tests respectively with zero failures and one intentional opt-in public
encrypted-bootstrap smoke skip per platform. These remote preview SDK results
do not replace live VPN acceptance on the owner's Mac or prove liveness of the
private owner endpoints on Windows/macOS.

The wider compatibility requirements and separate package version/publication
constraints remain documented in [Compatibility](compatibility.md) and the
[release preparation guide](release/README.md).
