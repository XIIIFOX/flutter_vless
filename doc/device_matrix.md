# VPN validation matrix

Use signed physical Apple targets and real Windows for system-VPN acceptance.
Android emulators are useful for repeatable checks, but physical-device tests
remain necessary for OS-specific controls and network transitions. Run disruptive
VPN tests on a host or device reserved for the test.

## Profiles

Choose working endpoints for the features used by your application:

| Profile | Checks |
| --- | --- |
| VLESS TCP/Reality | Basic proxy and VPN connection, DNS, statistics and Stop |
| VLESS XHTTP | Upload/download, TLS/Reality policy and transport cleanup |
| VMess, Trojan, Shadowsocks | Import and the applicable transport/security path |
| Hysteria2 or WireGuard import | UDP and the exact native artifact's support |
| Full Xray JSON | Multiple listeners, API/services, caller DNS/routing and assets |
| Invalid or unreachable profile | Bounded failure, safe error and ordinary-network recovery |

Test share links, a subscription with several profiles and raw JSON separately.
Keep credentials and profile files outside source control and public artifacts.

## Connection and data

1. Record an ordinary-network baseline with the test VPN off. Confirm both
   chosen IP-check domains load and record the observed addresses.
2. Import the profile through the ordinary example. Start VPN mode, then confirm
   a successful request through the tunnel; an icon or `CONNECTED` is not enough.
3. Generate upload and download traffic. Verify totals, speed and duration update
   through the normal status callback and that diagnostics remain bounded.
4. Put one domain on the direct route and the other on the proxy route. Compare
   each response with the baseline and all-proxy reference. Repeat with the two
   domains exchanged, using fresh requests rather than cached pages.
5. Stop and await cleanup. Confirm ordinary Internet access returns and no worker,
   listener or session protection is accidentally retained.

Record monotonic timings for the Start request, provider start, native readiness
and first successful request. Keep permission/authentication prompts and UI
scheduling separate from tunnel startup. Compare several cold and warm sessions;
report the median, spread and failed attempts, not just the fastest sample.

## DNS and IPv6

Test caller hosts, per-domain DNS selection, permitted encrypted DNS and
`UseIPv4`/AAAA behavior. Observe a controlled server and the physical interface
when checking DNS protection. Count endpoint bootstrap separately from
application queries. A failed protected query must not produce an unexpected
direct public-resolver fallback.

Verify IPv4 and IPv6 TCP/UDP payloads when the network supports them. Test
IPv6-only, DNS64/NAT64 and Wi-Fi/mobile handover as separate environments;
IPv6 literals or localhost fixtures alone do not establish those paths.

## Lifecycle and controls

Test pending-Start cancellation, repeated Start/Stop, a rejected replacement
profile, sleep/wake, lock/unlock and worker failure. Verify that stale replies
cannot mark a stopped or replaced session ready. Reconnect and On Demand checks
must preserve the user's explicit Stop behavior and configured protection.

Exercise the actual Android tile/notification, Apple control/menu bar and Windows
tray surfaces. Check cold app launch, unlock/authentication, labels and the action
selected in Options. Test unsupported or incomplete setup with
`getCapabilities()` rather than assuming every OS exposes the same surface.

## Security regression observations

Use a second application/UID to attempt local SOCKS without credentials, with
wrong credentials and with credentials from an old session. Check the supported
TCP/UDP paths, private files and bounded diagnostics for secret leakage.

Crash a worker or force an initialization failure and confirm that protected
capture remains in place until an explicit Stop or authorized recovery. Android
Always-on/lockdown requires its own system-policy tests. Apple Keychain/App Group
checks require matching signing and first-unlock conditions on the real target.

## Mobile automation

The repository's mobile matrix accepts private profiles through environment
variables:

```sh
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

Set `VPN_MATRIX_REQUIRE_BROWSER_TRAFFIC=true` when the tester can open Safari or
Chrome during each browser window. The script restores normal example launch
mode through `tool/reset_example_app_mode.sh`; retain that cleanup unless a
separate test intentionally owns the generated integration-test configuration.

## Pass criteria

A system-VPN result requires actual OS capture, successful bidirectional traffic,
DNS/routing observations, meaningful counters and verified cleanup. Keep fixture,
emulator, physical-device and OS-VPN results distinct. A macOS application build
or localhost Core exchange does not prove a NetworkExtension VPN session; a
CrossOver UI run does not prove Windows Wintun/WFP behavior.
