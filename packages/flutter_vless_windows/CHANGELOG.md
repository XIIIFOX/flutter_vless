## 1.1.6

* Chain protected DNS with `streamSettings.sockopt.dialerProxy`, replacing the `proxySettings` field removed in Xray-core v26.9.9.

* Update the verified Windows workflow runtime to Xray-core `v26.9.9`.

* Install mandatory Windows Filtering Platform protection before VPN setup. Keep it during native worker failure, recovery and application crashes; remove only this application's filters on explicit stop. A retained policy can be cleared by restarting the application as administrator and stopping VPN.
* Block physical IPv4/DNS fallback and IPv6 outside the tunnel, including newly attached adapters. Route virtual DNS through the selected proxy and bootstrap transport endpoints before protection starts.
* Authenticate the internal SOCKS proxy, bind outbound sockets to the available underlay, retry failed workers and require a private challenge-response through TUN, tun2socks and Xray before reporting `CONNECTED`.
* Preserve domain routing and support IPv4 `bypassSubnets` as direct rules inside Xray, below mandatory DNS and IPv6 rules. Reject extra VPN proxy listeners, ambiguous configuration fields and unsupported IPv6 endpoints.
* Launch bundled executables by absolute application-relative paths with explicit arguments, bounded output and owned child jobs. Remove CWD, PATH and AppData executable discovery and shell command construction.
* Keep the VPN's Xray executable and configuration files in an unpredictable Administrators/System-owned directory. Require an elevated Xray token for its WFP exception and restrict DHCP permission to the Windows DHCP service. Keep proxy-only temporary files owner/System-only; remove configuration files after startup. Suppress raw worker output, imported log destinations and runtime debug environment overrides.
* Serialize native operations, join outstanding work before plugin destruction, and restore the proxy preferences captured before the session.
* Add policy, private-process/file, failure-transaction and local routing regression tests. Keep the VPN Diagnostics button available in the Windows example.

## 1.1.1

* Added thread-safe, bounded Xray/tun2socks diagnostics through
  `getProviderDebugSnapshot`.

## 1.1.0

* Added the Windows implementation package for `flutter_vless`.
* Added support for Xray-backed proxy-only and tunnel flows.
* Added shared platform-channel integration through `flutter_vless_platform_interface`.
