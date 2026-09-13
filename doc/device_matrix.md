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
