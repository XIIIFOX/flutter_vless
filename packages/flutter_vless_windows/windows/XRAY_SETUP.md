# Xray integration setup for Windows

This guide describes the working 1.1.7 source. Native runtime publication is
separate from Flutter package publication.

Use the [current Windows platform guide](https://github.com/XIIIFOX/flutter_vless/blob/main/doc/platform/windows.md)
for runtime layout, administrator requirements, DNS/routing behavior and cleanup.

## Runtime selection

The repository's managed runtime is
[`xray-windows-v26.10.31-r2`](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-windows-v26.10.31-r2).
It supplies native routing and XDRIVE/GeoDAT service capabilities. The plugin
checks the actual selected executable; a version string alone does not prove
those capabilities. Compatible external stock Core builds remain usable for
ordinary profiles that do not require them.

Ship `xray.exe`, compatible `tun2socks.exe` and `wintun.dll` in the built app's
`xray/` directory. Add datasets referenced by the profile, or pass an explicit
`geoAssetsDirectory`. The plugin does not download missing binaries.

The executable search order, relative to the running application, is:

1. `xray.exe`
2. `xray/xray.exe`
3. `data/flutter_assets/xray/xray.exe`
4. `data/flutter_assets/windows/xray/xray.exe`

CWD, PATH, AppData, parent directories and reparse-point files are not discovery
locations. Keep `wintun.dll` beside the tunnel helper. VPN mode requires an
elevated application; `requestPermission()` checks elevation rather than granting it.

## Configuration and counters

Pass a full Xray JSON object through `startVless`. The backend performs Core
preflight before replacing an accepted session, adds its own authenticated VPN
adapter and retains caller listeners, DNS/routing, API/services and statistics
policy. There is no required fixed API port or mandatory caller StatsService
configuration. Private counters are used only when the backend owns that service;
caller APIs and disabled counters remain authoritative.

Use `getProviderDebugSnapshot()` for bounded safe lifecycle diagnostics and
`getConnectedServerDelay(url: ...)` for an allowed active-session destination.
Windows standalone profile delay is unsupported and returns `-1`.

The backend owns Wintun routes, WFP filters and process/configuration cleanup.
Do not add blanket physical DNS bypass routes to implement this setup. Use
caller Xray routing for intentional direct destinations. Call and await
`stopVless()` to release the session's protection; after a crash, reopen the
application as administrator and stop the retained policy explicitly.
