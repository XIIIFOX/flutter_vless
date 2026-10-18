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

This is a partial acceptance record. Recovery from a running worker crash
and the broader compatibility corpus are not implied
by the successful cases above.

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
owner authentication was subsequently completed below; recovery from a running
worker crash remains outstanding.

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
from the permitted passcode fallback or establish worker-crash recovery.

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
