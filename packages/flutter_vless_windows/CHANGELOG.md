## Unreleased

* Captured IPv4 with two session-owned `/1` routes so physical interface metrics
  cannot silently bypass the VPN; removed these routes on stop or setup failure.

* Exposed the VPN Diagnostics button in the Windows example.

* Bound Windows `direct` transports to the pre-tunnel network interface to prevent
  domain bypass connections from looping back into the VPN.

* Preserved Xray domain rules, DNS settings, and server ports during proxy/VPN
  configuration. Selected SOCKS listeners structurally regardless of key order.
* Added a dedicated API listener without duplicate routing blocks.
* Joined failed workers on stop and reflected native service failures in status.
* Removed config fragments from endpoint extraction diagnostics.

## 1.1.1

* Added thread-safe, bounded Xray/tun2socks diagnostics through
  `getProviderDebugSnapshot`.

## 1.1.0

* Added the Windows implementation package for `flutter_vless`.
* Added support for Xray-backed proxy-only and tunnel flows.
* Added shared platform-channel integration through `flutter_vless_platform_interface`.
