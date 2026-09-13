# Windows

The Windows backend supports a system proxy mode and an IPv4 VPN using Xray,
tun2socks and Wintun. VPN mode requires administrator privileges.

## Runtime files

Ship these files next to the application executable, or in its `xray` directory:

```text
app.exe
xray/
  xray.exe
  tun2socks.exe
  wintun.dll
  geoip.dat
  geosite.dat
```

The two data files are needed when the profile uses GeoIP/GeoSite rules. The
example bundles files from `example/windows/xray`. The plugin also supports
`data/flutter_assets/xray` and `data/flutter_assets/windows/xray` below the
application directory. It does not search the current working directory,
PATH or AppData for runtime executables. Keep `wintun.dll` beside tun2socks.

## VPN behavior

Use one loopback SOCKS inbound in the VPN profile. The plugin supplies private
session authentication, virtual DNS and traffic protection. Extra listeners,
ambiguous configuration fields and unsupported IPv6 endpoints are rejected.

IPv6 is blocked while VPN forwarding is IPv4-only. DNS travels through the
selected proxy without a physical resolver fallback. Xray domain rules remain
available; IPv4 `bypassSubnets` become direct rules inside Xray, below mandatory
DNS and IPv6 protection. IPv6 bypass CIDRs are unsupported.

`CONNECTED` requires the local TUN → tun2socks → authenticated SOCKS → Xray
packet path. It does not guarantee that a remote server or every Internet site
is reachable. A failed native path reports `CONNECTING` while recovery retains
traffic protection.

Call `stopVless()` for an explicit disconnect. Closing the application or
losing its native workers preserves the WFP traffic barrier. After an
application crash, reopen the app as administrator and explicitly stop VPN to
release its retained policy. A fresh hostname bootstrap may require this step
because the previous session's endpoint cache existed only in memory.

## Proxy-only behavior

`proxyOnly: true` starts local proxy service without Wintun or machine-wide
traffic protection. Applications that ignore system proxy settings can still
connect directly. The backend restores the proxy settings it captured when
that session is explicitly stopped.

## Run the example

```bash
cd example
flutter pub get
flutter run -d windows
```

Run the example from an elevated Windows terminal when testing VPN mode.
The plugin does not download missing native binaries automatically.
