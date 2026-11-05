# Apple readiness and DNS follow-up

Scope: working plugin version 1.1.7, published Core 26.10.31-r2, iOS and macOS
adapter corrections. No plugin publication, native SDK rebuild or live macOS
VPN test. The owner's Mac VPN, system DNS, default route and proxy are not
changed by this work.

Implementation commit: `0f16a94620f4769e17b2773a59cd7029b85fcc66`.

## Behavior

* Native readiness uses the current session/plan, live HEV and authenticated
  managed SOCKS listener within one cancellable two-second deadline. It no
  longer requires CONNECT to 1.1.1.1:80 or HTTP from gstatic. An optional
  `getConnectedServerDelay(url)` checks a destination permitted by the caller.
* `tcp+local`, `https+local` and `h2c+local` are prepared as closed physical DNS
  branches with finite address/port permissions and interface binding. Source
  JSON, ordinary routed DoH, static hosts and per-domain selection remain
  caller-owned. Missing physical context and unsafe/unsupported local forms
  fail preparation.
* DNS-only profiles also require the SDK's interface-binding capability even
  when they have no proxy endpoint selection. Failure occurs before Core
  admission, routes or On Demand are armed.

See [the public behavior contract](../apple-readiness-and-dns.md), including
limits for preparation paths without a physical-interface snapshot.

## Local tests

Tests first reproduced the previous false readiness failure for a valid
private/default-blocked profile and the missing DNS-only capability check.

* Full Swift helper suites: 263 iOS and 277 macOS tests, zero failures. Each
  has one pre-existing, opt-in public bootstrap test skipped. After the final
  capability-helper amendment, all nine local DNS tests ran again on each
  platform with zero failures.
* Actual provider-method harnesses: 32 iOS and 33 macOS controls, including
  cancellation, stale owners, worker exit/Stop during authentication, listener
  failure, late authentication and private-profile readiness.
* Actual SOCKS helper tests: 26 controls per platform, including incorrect
  authentication, fragmented replies, deadlines and socket closure.
* Actual cold-start ordering: 24 controls per platform; capability values 0/2
  refuse DNS-only startup, while 1 admits preflight. Nine mutations per platform
  confirm the admission assertions detect a removed gate.
* Example DNS probe and live-control tests: 31 tests passed. The QA-only probe
  now checks both fixed public domains, tfox.dev and 1cfresh.com, with strict
  question/type/class and CNAME ownership checks and bounded socket cleanup.
* Runtime version contracts: 14 tests passed; plugin versions and public
  native artifact pins remain unchanged.

These local Swift harnesses use inert native boundaries; they do not run Core
or a macOS VPN on the owner's computer.

## Published-SDK Actions and physical iPhone

The app-only signed example was built from the implementation commit against
the exact public iOS SDK archive
`8d693bc767b8f292f0ec0459850287f752c40499fa6542caef5b749c8bdc5f00`.
Product receipt SHA-256:
`5c400f4f9db9e0ccc441ccf83b9e903de8767615da8309276a8380877f5c6bea`.
No local Core/Go/SDK compilation or execution occurred. The build restored its
metadata and reaped its compiler group before installation.

Four bounded cases passed on the physical iPhone 13 Pro Max, iOS 27.0.1:

| Profile | Actual observation |
| --- | --- |
| Private-only/default blackhole, no old health permissions | UI and native CONNECTED; the optional fixed URL probe reports unavailable, followed by a second UI/native CONNECTED observation. |
| Original fresh VLESS/WebSocket/TLS JSON with named DoH | tfox.dev A: one address, 335 ms; 1cfresh.com A: two addresses, 543 ms. Both AAAA queries return NOERROR/NODATA under UseIPv4. |
| Same source with only DNS servers changed to numeric tcp+local | tfox.dev A: one address, 221 ms; AAAA NOERROR/NODATA. |
| Same source with only DNS servers changed to named https+local | Cloudflare authority/path and caller static host retained; tfox.dev A: one address, 201 ms; AAAA NOERROR/NODATA. |

Each case includes normal UI Stop, a native full-Stop acknowledgement, two fresh
OFF observations, a disarmed/non-intervening host guard and ordinary IPify
recovery with a current native frame. The 110-second provider guard is verified
as compiled inclusion; its physical expiry was not exercised. Exact records
are under ignored `build/apple-readiness-dns-20261102/phone-01` and `phone-02`.
DNS answers prove actual resolution; they alone do not identify which upstream
handled each query. Unit tests separately establish exact caller policy
preservation.

The post-install site observations distinguish an actual visible IP from a
fully finished document. Ordinary 2ip returns HTTP 200 with one IP and no
Loading text, but remains interactive within the bounded observation window;
tfox has no HTTP response in its current ordinary baseline. Neither is labelled
as a fully loaded ordinary page.

The original fresh WebSocket/TLS profile also transfers actual browser traffic
to IPify with a VPN exit distinct from the ordinary exit. The fresh France
Reality share link was imported by the plugin's actual parser; both IPify and
2ip return the same VPN exit, distinct from the ordinary exit.

Both opposite domain-routing cases passed against those fresh references:

| Direction | api.ipify.org | 2ip.ru, redirect to 2ip.io |
| --- | --- | --- |
| A | VPN exit | Ordinary direct exit |
| B | Ordinary direct exit | VPN exit |

Both ON documents reach HTTP 200, complete DOM and finished navigation in the
all-proxy and both routing cases, with current native frames. The narrow
two-frame visible-IP observer is needed only for the ordinary baseline; it does
not relabel an interactive document as fully loaded. Every routing case also
includes the same strict CONNECTED/normal Stop/two-OFF/guard/recovery checks.
The France import and its routing variants have no explicit `dns` section;
these cases also qualify the protected default DNS path for this finite setup.
Exact source/target/response/navigation/epoch and native-image bindings are
retained under ignored `phone-03` and `phone-04` evidence. No physical claim is
made for the currently unresponsive ordinary tfox baseline.

The fresh Singapore Reality share link also passes an actual IPify HTTP 200
request with complete DOM and a VPN exit distinct from the ordinary exit.
All nine bounded physical cases pass. Their safety sequence finishes with
ordinary Internet recovery; no additional VPN starts are planned.

All five finite phone leases are closed. The final physical audit finds the
owned app/current extension and all recorded VM-forward/guard supervisors
absent; all 348 recorded host clients are reaped and absent, and their two USB
forward ports are closed. No emulator or Java worker was started in this task.
Mac DNS/proxy/default-route/VPN snapshots are byte-identical to the genuine
task baseline. Unrelated app-managed MCP and other project processes are
preserved.

Aggregate physical receipt SHA-256:
`6be771061311255ed2206de63f01e1c1ab690a43f3160c3006b42517e85accca`;
file: ignored `build/apple-readiness-dns-20261102/physical-nine-cases-qualified.json`.
Cleanup evidence is in `physical-final-cleanup-audit.json` and
`physical-final-owned-client-audit.json` in the same directory.

## Actions result

[Run 41524178148](https://github.com/XIIIFOX/flutter_vless/actions/runs/41524178148)
succeeds on its first attempt at the exact implementation commit. All four
applicable jobs are green. Current-source full Swift suites pass 264 iOS and
278 macOS tests, zero failures, with one expected opt-in public bootstrap skip
per platform. All nine new local DNS tests and the readiness/capability
regressions run on both platforms.

The iOS and macOS app/SwiftPM builds pass. Both actual public SDK runtimes
confirm mandatory capabilities, DNS/refusal, both routing directions and
session draining, with no optional SDK-runtime skip. The public archive and
manifest pins match, and all 15 iOS/eight macOS SDK files remain unchanged after
tests. SDK rebuild, packaging and preview publication steps are skipped.

Artifact `13180613435` ZIP SHA-256:
`dd6245556e9ffa59b75d10204c6c75c09f40ef4d97c5be8363e16980b5b24a7a`.
The root review independently checks its digest/CRC and both runtime log hashes,
requiring each mandatory runtime marker exactly once and no SDK skip. Detailed
qualification: ignored
`build/apple-readiness-dns-20261102/ci-41524178148/qualified.json`.

These are distinct evidence layers: new local-DNS graph/provider unit tests,
public-SDK runtime DNS/routing tests and physical iPhone VPN cases. The iOS
simulator HEV artifact is link-only; the physical iPhone cases qualify its real
packet worker. Live VPN acceptance on the owner's macOS remains deferred.
The checks use flutter_vless 1.1.7.
