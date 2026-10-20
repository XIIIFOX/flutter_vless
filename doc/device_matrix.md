# Real-Device VPN Matrix

Run this matrix only on physical iOS and Android devices. Simulator traffic uses
the host Mac network path, so it can hide failures when the Mac is running a
system proxy.

## Cases

- `tcp-reality`: known-good VLESS TCP/Reality control profile.
- `xhttp-reality`: VLESS XHTTP/Reality profile.
- `xhttp-none-json`: VLESS XHTTP/none as raw Xray JSON with
  `users[].encryption = mlkem768x25519plus...`.
- `shadowsocks`: Shadowsocks profile from an SS subscription issue.
- `trojan`: Trojan TLS or gRPC profile.
- `vmess`: VMess WebSocket/TLS or comparable production profile.

## Command

```sh
cd path/to/flutter_vless
export DEVICE_ID="YOUR_DEVICE_ID"
export VPN_MATRIX_TCP_REALITY_URL="vless://..."
export VPN_MATRIX_XHTTP_REALITY_URL="vless://..."
export VPN_MATRIX_XHTTP_NONE_JSON='{"remarks":"xhttp none","outbounds":[...]}'
export VPN_MATRIX_SHADOWSOCKS_URL="ss://..."
export VPN_MATRIX_TROJAN_URL="trojan://..."
export VPN_MATRIX_VMESS_URL="vmess://..."
export VPN_MATRIX_PROXY_ONLY_URL="vless://..."
tool/run_real_device_matrix.sh
```

Set `VPN_MATRIX_REQUIRE_BROWSER_TRAFFIC=true` when the tester can manually open
Safari or Chrome during each browser window. The integration test always checks
local SOCKS, SOCKS CONNECT, and HTTP 204 through the tunnel on iOS; the browser
traffic gate adds a stronger end-user proof.

The script resets the example back to normal app launch mode at the end by
running `tool/reset_example_app_mode.sh`. Set
`VPN_MATRIX_RESET_EXAMPLE_APP_MODE=false` only when you intentionally want to
leave Flutter's generated iOS config pointing at the integration-test listener.

## Pass Criteria

- iOS debug snapshot confirms protected routes, a successful authenticated watchdog check, and restored forwarding.
- The connected-delay check returns an actual HTTP response through Xray.
- With `VPN_TEST_ROUTING=true` and `VPN_ORIGINAL_CONFIG`, the direct domain matches its physical baseline and the proxy domain exits through a different address, including after session replacement. Proxy exits may rotate between requests.
- `VPN_TEST_RECOVERY_WINDOW_SECONDS` leaves time for an external process fault; the test checks both routes afterward. The host driver must separately record that the fault actually occurred.
- Android status counters show meaningful download traffic during the browser
  window when `VPN_MATRIX_REQUIRE_BROWSER_TRAFFIC=true`.
- No case should pass based only on VPN connected state or upload-only counters.
- Proxy-only case should start without a VPN permission prompt and return a
  non-negative connected delay through local Xray.

## Security regression observations

For each HTTP/SOCKS/VLESS control, observe the **physical interface** and a
controlled server on initial connection and again **after transport recovery**.
Count proxy-endpoint bootstrap DNS separately from user queries. In protected DNS
mode, control system queries must not appear as direct UDP/TCP 53 to a public
resolver; fail DNS at the proxy and verify that no direct fallback appears.

Use a second application/UID to attempt SOCKS without credentials, with a wrong
password, with an old-session password, and HTTP on the SOCKS port. Verify correct
credentials inside the maintained worker path, UDP, IPv4/IPv6 behavior, and no
canary credentials in logcat/provider snapshots or persisted profiles.

Crash each worker, force FD-transfer failure, change networks, sleep/lock, and
start/stop rapidly. Check that a live provider/service retains capture and reports
CONNECTING until real transfer returns. Test explicit stop separately from entire
process termination. On Android test system restart with Always-on + Block
connections without VPN, missing/corrupt encrypted profile and lost Keystore key.
On iOS test shared Keychain access and first unlock after reboot on signed targets.

The local test suite uses controlled simulator/emulator peers and keeps the
development computer's VPN enabled. Those tests do not establish the
physical-device/OS guarantees above; record them separately rather than inferring
success from an icon, CONNECTED, or upload counters.

## Local desktop acceptance boundaries

Keep the development Mac's existing VPN enabled. Local macOS VPN acceptance
must wait until the owner explicitly confirms readiness, after the main iPhone
checks and planned implementation work. Until then, macOS network-runtime
checks run in GitHub Actions; local compilation does not authorize a local VPN
start or changes to host DNS, routes or proxy settings.

CrossOver may be used for the Windows example's interface, options, imports,
errors and available desktop controls. Keep all VPN and network-changing actions
disabled there. CrossOver observations do not establish Windows Wintun/WFP,
system routing, DNS protection or recovery behavior; verify those separately in
the real Windows runtime workflow or on a Windows device.

A subsequent process-only native regression ran successfully in CrossOver on
2026-10-18. The `FLUTTER_VLESS_PROCESS_CAPTURE_ONLY` build returns before private
file, listener, Core, ACL or packet-path tests, regardless of command arguments.
Actual self-children prove bounded stalled-command termination, the output cap
and nonzero-exit refusal. The task's existing test bottle was shut down afterward;
no CrossOver/Wine/test processes remained and the Mac VPN stayed connected.
This checks process management only; it does not add example UI or VPN acceptance.
The ignored evidence is `build/ios-live-2026-10-18/bounded-command-windows/`.

## iPhone acceptance, 2026-10-18 (1.1.7 / Core 26.10.17)

Physical iPhone 13 Pro Max over USB, iOS 27.0.1, signed Profile build of the
ordinary example with Flutter Driver enabled. The development Mac VPN stayed
enabled throughout. Supplied profiles and device screenshots remain outside Git.

* All three original full JSON profiles imported through the example. Both
  original SOCKS inputs and their routing rules were retained. Fresh Safari
  requests to `tfox.dev/ip/` and `2ip.ru` (redirecting to `2ip.io`) showed proxy
  exits distinct from the ordinary phone connection.
* The first two exits were reported as Japan and Poland. The third profile's
  Sweden remark disagreed with the site's United States geolocation. Both sites
  showed the same third exit; this discrepancy remains an observation to review,
  not proof of its physical location or a successful Sweden-country check.
* Domain routing was checked in both directions: tfox direct / 2ip proxy, then
  tfox proxy / both 2ip domains direct, with fresh browser requests each time.
* The added Control Center control opened the app, started a working tunnel,
  and stopped it through its native toggle. Its custom shield symbol was visible.
  The label persisted in options; its display on the compact native control was
  not established.
* Diagnostics disabled returned an empty snapshot; the example disabled Copy.
  A physical test exposed an extra metadata line exceeding a three-line budget.
  After correction the copied complete response contained three lines / 224
  bytes with a 3-line / 4096-byte setting. Zero lines was rejected in the example.
* With a deliberately unreachable endpoint and On Demand disabled, Safari failed
  to reach a fresh page while the protected tunnel remained active. App Stop
  completed and ordinary Safari internet returned. This tests blocked forwarding
  and explicit recovery, not a native worker crash or its retry schedule.
* With On Demand enabled, real Safari traffic worked and system Settings reported
  connection on demand. Explicitly switching VPN off in Settings disabled that
  automatic connection; fresh Safari traffic used the ordinary connection.
  Reconnecting and stopping from the app also completed. On Demand cannot promise
  to override an explicit system disconnect.
* Reconnect disabled / On Demand disabled was exercised with working traffic.
  A synthetic unsupported outbound then forced native Core startup to fail:
  100/200 ms and two retries produced three startup failures before exhaustion.
  A 1000/2000 ms, three-retry case produced four failures at elapsed 0/1/3/6
  seconds (second-resolution provider timestamps include scheduling overhead).
  With reconnect disabled the same profile produced only the initial failure.
  After exhaustion the UI remained CONNECTING with Disconnect available,
  fresh Safari failed, and Stop restored ordinary connectivity. This establishes
  startup retry counts/exhaustion, not successful recovery from a running
  native worker crash or subsecond timing accuracy.
* Unlock-before-action displayed Apple's authentication UI. Failed recognition
  followed by Cancel left VPN disconnected and no provider running. Successful
  device-owner authentication was subsequently completed as recorded below.
* Forgetting the quick-access profile during an active connection left fresh
  Safari traffic working. After Stop and a cold app start, the native toggle
  could no longer start that forgotten profile. Disabling quick access also
  prevented native startup; the containing app still opened normally.

Before each development reinstall, app Stop is awaited, disabled recovery/profile
preferences are read back, provider termination is checked, and a fresh Safari
page must show ordinary connectivity. Never reinstall while the test VPN remains
active. The initial reinstall incident required the owner to reboot the phone;
subsequent stop/reinstall gates and normal-network checks passed.

This is a partial acceptance record. The broader compatibility corpus is not
implied by the successful cases above; a later running-worker loss check is
recorded below.

The build-only Apple preflight preview was also installed on the physical iPhone.
A synthetic unknown outbound was rejected as `outbounds[0]` at Core build before
any tunnel process started. Fresh Safari requests retained the ordinary IP.
All three original documents were then connected again: both websites reported
103.75.118.225, 82.40.63.24 and 87.232.225.232 respectively, with the same country
observations above. Each explicit Stop completed, preferences read back disabled,
the provider exited, and a fresh ordinary-IP page loaded. Provider diagnostics
confirmed that its final generated document passed Core checking before routes
were installed. These previews are local test artifacts, not a published runtime
or package release; the upstream Core revision remains unchanged.

The JSONC/BOM SDK path was exercised through the actual example editor on the
Android emulator and iPhone, retaining the full first supplied profile. Both
websites loaded through Xray. iPhone retained the earlier Japan exit; the Android
session used a different Japan IPv4 also returned by its original SOCKS input.
Runtime inspection confirmed the same server/credential/flow/transport and zero
traffic on the direct outbound in that initial all-proxy session. The example
routing editor then applied direct tfox/proxy 2ip and the reverse policy on both
devices; fresh browser pages showed the respective underlay/proxy addresses.
All test sessions were explicitly stopped, saved Apple recovery read back disabled,
and fresh ordinary-network pages loaded. The task-owned Android emulator was
stopped, and the added iPhone Control Center test control was removed. Successful
owner authentication and running-worker loss were subsequently checked below.

Private service identifiers were then tested with a supplied-profile derivative:
an imported rule blocks `flutter-vless-tun`, and four additional blackhole
outbounds occupy the library's DNS/IPv6 preferred tags. The actual iPhone
example connected with private tags allocated separately; fresh Safari tfox
and 2ip pages both reported 103.75.118.225 (Japan on tfox). The example routing
editor then applied direct tfox/proxy 2ip and the reverse policy. Browser pages
showed 95.139.123.8 on the direct path and 103.75.118.225 on the proxy path in
both directions. Editor readback retained the imported blocking rule, DNS and
all outbound credentials/settings. Provider diagnostics confirmed Core preflight
before routes and `On-demand recovery policy applied: enabled=false`.
Each Stop completed with disabled-profile readback; final provider absence and
a fresh Safari page with 95.139.123.8 (Russia) were verified. Quick access,
automatic reconnect and On Demand were disabled during this acceptance.

The Android native suite passed all 27 cases without skips after DNS/probe
scoping, including blocked DNS through an imported input, working VPN DNS,
worker recovery, routing, handover and physical DNS capture. Artifacts are in
the ignored local `build/android-security-emulator.5UHS7XV2` directory; its
task-owned emulator was stopped. Pure configuration suites passed 57 Android
unit tests, 63 iOS support tests and 84 macOS support tests (one additional
encrypted-bootstrap test requires an opt-in environment). Windows native,
proxy-only, VPN routing/recovery and example builds passed on Windows 2022 and
2025 in [run 39090838143](https://github.com/XIIIFOX/flutter_vless/actions/runs/39090838143).
Full advanced-DNS preservation, IPv6 forwarding, prefix-selector isolation and
the remaining items in the compatibility table are still open.

Numeric API allocation was exercised in the physical example with the first
supplied profile plus `api.listen=127.0.0.1:10809`. Its original inputs retained
10808/10820; provider diagnostics reported a separate authenticated adapter on
10810 and Core preflight before routes. Fresh Safari tfox/2ip pages both showed
103.75.118.225 (Japan on tfox). Explicit Stop completed, the provider exited,
a cold app readback reported `enabled=false status=1`, and fresh Safari returned
95.139.123.8 (Russia). Quick access, reconnect and On Demand were disabled.
The task-owned app console/USB forwarder were stopped; unrelated phone apps
were left running. This proves allocation/traffic, not all API RPC services or
metrics listener allocation. Windows 2022/2025 native, proxy, VPN/recovery and
example builds passed for the same allocator revision in
[run 39091995713](https://github.com/XIIIFOX/flutter_vless/actions/runs/39091995713).

The subsequent physical build added an independent `Profile delay` action.
With the supplied profile running, caller API port 10809 used the same `proxy`
tag as the VLESS outbound, and caller metrics listened on 10830. An isolated
profile measurement returned 7051 ms; fresh Safari tfox/2ip requests afterward both used
103.75.118.225, proving that stopping the measurement did not stop the provider.
Explicit app Stop then restored 95.139.123.8 in Safari. This is a connectivity
check, not a representative latency benchmark; API/metrics socket/RPC acceptance
is separately required in the Apple runtime fixtures.

Owner authentication was then accepted on the physical iPhone for both Control
Center actions with `requireUnlock=true`. The owner added the shield control,
pressed it and confirmed on the phone. The example showed CONNECTED with a real
provider process; fresh Safari tfox and 2ip requests both showed 103.75.118.225
(Japan on tfox). The owner pressed it again and confirmed the Stop action.
The provider exited and a fresh Safari page showed ordinary 95.139.123.8 (Russia).
After disabling quick access, a cold app launch read the VPN profile as
`enabled=false status=1`; options showed quick access and reconnect off, On Demand
disabled. The task-owned example process and USB forwarder were stopped.
This proves device-owner acceptance; the record does not distinguish Face ID
from the permitted passcode fallback. Worker loss was tested separately below.

The subsequent Android emulator suite passed all 29 tests without skips
(`build/android-security-emulator.VSBoaWAZ`). It includes an actual SystemUI
single-click Stop while a killed worker is in backoff with TUN still captured,
and verifies authorization removal, worker exit and the tile's final inactive
presentation. Earlier failures exposed unavailable recovery controls and stale
states after re-add/Stop; native listening lifecycle refresh now covers both.
A separate real-Core case transfers authenticated HTTP bytes while caller API
and metrics ports remain occupied, with service tags equal to the proxy tag.
The full DNS/routing/handover/OS-policy corpus also passes. Android pure tests
pass 63 cases; shared Apple control tests explicitly cover authenticated Stop
and cancelled authentication during `.reasserting` without touching a real VPN.

Running Core worker loss was then exercised on the same physical iPhone with
the first original supplied profile. Auto Reconnect used 1000/2000 ms and three
attempts; On Demand and quick access were disabled. A development-only build
flag enabled a once-per-provider message which stops only Core, leaving HEV,
TUN, routes and ordinary watchdog/retry state untouched. It acknowledged the
stop; a fresh Safari request failed with a lost-network error during the outage.
This browser observation is not a packet-capture proof of every possible leak.
Provider diagnostics recorded Core loss at 14:59:17 UTC, ordinary watchdog
failures, native worker restart at 14:59:58, and healthy forwarding at 15:00:00.
The provider PID stayed 2040 throughout. Fresh Safari tfox and 2ip pages then
both showed 103.75.118.225 (Japan on tfox). This proves successful worker-loss
recovery inside a surviving provider, not continuous protection after complete
provider termination or subsecond retry timing.

Explicit Stop completed afterward; the provider exited, cold preferences read
`enabled=false status=1`, and fresh Safari returned 95.139.123.8 (Russia).
Reconnect, On Demand and quick access were disabled before restoring the signed
ordinary build without the fault hook. The restored build's cold readback and
ordinary internet were checked again. Only task-owned app/USB forwarding
processes were stopped. Evidence stays under the ignored
`build/ios-live-2026-10-18/worker-recovery-*` paths. The test hook is compiled out
unless `FLUTTER_VLESS_ACCEPTANCE_TESTING` is explicitly supplied to both native
example targets; no production plugin method or release setting enables it.

To repeat that fault check, build the example using
`FLUTTER_TARGET=test_driver/live_main.dart` and the explicit Swift compilation
condition above. The driver `request_data` message `acceptance-stop-core` must
return `acceptance-core-stopped` before counting an induced loss. The host
requires its uniquely identified, connected profile with On Demand disabled;
the provider also requires a healthy running session with reconnect enabled.
Rejections, stale callbacks or timeouts do not prove a worker was stopped.
The boundary's pure regression runs in `tool/test_apple_options.sh`, covering
normal-build exclusion and refusing unhealthy, stopping or stale sessions.

The next normal signed physical build checked a metrics collision using the
first supplied profile plus API on 10809 and `Metricſ.Liſten` on 10810 (Core's
case-folded field aliases). Provider diagnostics reported its private adapter
on 10811 and preflight before routes. Fresh Safari pages at both IP sites
showed 103.75.118.225 (Japan on tfox). Stop completed, the provider exited,
fresh Safari returned 95.139.123.8 (Russia), and a cold app launch read
`enabled=false status=1`. Reconnect, On Demand and quick access remained off;
the task-owned app, controls process and USB forwarder were stopped. This is
physical allocation/traffic acceptance; service HTTP responses are separately
checked by the synthetic native runtime fixtures. The private screenshots and
diagnostics use `build/ios-live-2026-10-18/metrics-*` paths.

The same physical check was repeated after recognizing Go's optional leading
plus in TCP listener ports. Source API `127.0.0.1:+10809` and metrics
`127.0.0.1:+10810` retained their spelling; the private adapter used 10811.
Fresh Safari tfox/2ip pages showed the Japan exit, and Safari's direct request
to local metrics port 10810 rendered the actual provider's Go metrics JSON.
Explicit Stop restored the ordinary IP, the provider exited, and cold readback
again reported `enabled=false status=1`. The normal signed build has no native
fault hook; task-owned app, controls and forwarding processes were stopped.
Android's corresponding three-test real-Core authorization class also passed
with positive-sign metrics, actual HTTP JSON and authenticated SOCKS bytes;
its task-owned emulator was stopped. These checks are recorded in ignored
`signed-port-*` and `android-positive-metrics-*` artifacts.

The normal signed example was tested again after the Apple session-admission
and sleep/wake fixes in `89d3059`. The three original JSON documents produced
fresh Safari tfox results of Japan `103.75.118.225`, Poland `82.40.63.24`, and
United States `87.232.225.232`; the third profile's Sweden remark still differs
from the observed exit country. The example routing editor was exercised in
both directions: tfox direct / 2ip proxy, then 2ip direct / tfox proxy. The 2ip
direct rule includes both `2ip.ru` and its redirect target `2ip.io`.

Device Hub's video stream stopped updating during these VPN sessions. Fresh,
uniquely addressed Safari pages were loaded while connected and read back after
explicit Stop without reloading them; frozen or black frames were not accepted.
All seven accepted browser results and the final ordinary Russian connection
are retained in ignored `apple-sleep-wake-*` evidence.

With bounded Auto Reconnect enabled and On Demand disabled, a rapid Start/Stop
cancelled a connection before `CONNECTED` (native states 2, 5, 1). More than
116 seconds later it remained disconnected; a cold launch read back a disabled
manager. A stopped extension process remained resident until that cold launch;
process presence alone was not treated as an active VPN. No physical provider
sleep/wake callbacks were observed, so the rare queue orderings remain qualified
by the causal pure tests, separately from this device regression. Quick access,
reconnect and On Demand were left disabled; all task-owned app/control/forwarding
processes were stopped. A fresh Safari request after cleanup showed the ordinary
Russian IP, and the Mac's VPN remained connected.

## iPhone diagnostics options, 2026-10-20

The installed signed example `1.1.7+117` (app source `1fbece9`, existing Core
SDK `4690312`) passed a separate check with VPN disconnected. The actual options
page rejects `4095` bytes and `0` lines, stays open and leaves the complete
native options unchanged. Enabling diagnostics with `4096` bytes / `3` lines
updates only those three diagnostic fields in native preferences. The displayed
snapshot contains 52 UTF-8 bytes on one nonempty line; it may contain persisted
metadata and does not establish saturation, truncation or a new provider start.

Restoring the prior options returns the disabled diagnostics placeholder and
exact prior native settings (`OFF`, `8192` bytes / `32` lines). The fresh case's
profile bytes and routing state are restored. No VPN Start occurs; native Stop
acknowledges completion, the provider is absent and Safari loads the ordinary
internet afterward. Automatic controls remain off, required protection is
preserved and task-owned app/USB helpers are reaped. Mac VPN settings are
unchanged. This check does not install or qualify the later H3 source patch.
The private evidence is under ignored `iphone-off-diagnostics-02` artifacts.

## Unpublished iOS SDK regression, 2026-10-20

The signed example `1.1.7+117` and its Core SDK were rebuilt from `ce65b6a`.
The SDK came from the successful, build-only
[iOS preview run](https://github.com/XIIIFOX/flutter_vless/actions/runs/39401007662).
The app and tunnel extension linked the checked device SDK; stock repository
SDK and generated build files were restored before installation.

All three supplied original JSON documents were imported byte for byte and
connected separately on the physical iPhone 13 Pro Max. For each profile,
Safari loaded tfox.dev/ip and 2ip.ru (redirected to 2ip.io), and both pages
showed the same proxy exit. Tfox displayed Japan, Poland and
United States; the third profile's Sweden remark does not establish its exit
location. Each single connection stopped with native completion and provider
absence, restored each case's captured prior UI/profile/routing/options, and returned to the
ordinary internet afterward. Task-owned app, USB and guardian processes were
stopped and temporary VM inputs removed. Safari and unrelated apps were
preserved; the Mac VPN remained enabled.

These cases keep the routing panel and automatic options off, with required
protection unchanged. They qualify the new SDK's ordinary VLESS/Reality
regression and Stop recovery. They do not establish fresh TCP connections,
new split-routing/options coverage, physical HTTP/3 negotiation or its
same-process resource lifetime. Private evidence remains in ignored
`h3-lifetime/iphone-original-new-sdk-01`, `-02` and `-03` artifacts.
