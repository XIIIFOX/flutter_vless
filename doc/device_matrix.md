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

- iOS debug snapshot contains `SOCKS inbound health check: ok`.
- iOS debug snapshot contains `SOCKS CONNECT health check: ok`.
- iOS debug snapshot contains `SOCKS HTTP health check: ok`.
- Android status counters show meaningful download traffic during the browser
  window when `VPN_MATRIX_REQUIRE_BROWSER_TRAFFIC=true`.
- No case should pass based only on VPN connected state or upload-only counters.
- Proxy-only case should start without a VPN permission prompt and return a
  non-negative connected delay through local Xray.
