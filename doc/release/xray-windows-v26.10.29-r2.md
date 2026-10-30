# Xray Windows 26.10.29, managed native revision r2

This AMD64 companion retains upstream Core v26.10.29 and adds the native
routing CLI plus explicit XDRIVE/GeoDAT lifetime capabilities. It owns cloud
HTTP/token/pool resources and cancels scheduled GeoDAT downloads before Stop
waits for them. Cloud cancellation preserves the Core/parent feature context.

Producer: `ed3932ff69da47c6f0cdc4ad871da6ba7d032e5e`.
[Windows 2022/2025 native, example and real VPN acceptance](https://github.com/XIIIFOX/flutter_vless/actions/runs/41041997107).
[Core tests on Linux/macOS/Windows](https://github.com/XIIIFOX/flutter_vless/actions/runs/41041992418).
Both Windows runners produced the same executable bytes and passed reverse
routing, traffic, private-file, cleanup and numeric IPv6 checks.

`Xray-windows-managed-64.zip` SHA-256:
`58835712f5a36faf8db78eb7e765841a40b731dac7ef4d3c8a976d744801d4be`.
The ZIP contains `xray.exe`, the project's unchanged full `geoip.dat` and
`geosite.dat`, and the Xray license. The release includes its exact producer
manifest and checksum file.

Place these files in the application's existing `xray` directory. Retain the
compatible `tun2socks.exe` and `wintun.dll` beside them for VPN mode. The image
answers `native-services capabilities` with the bitmap `3`. An ordinary
external Core remains usable for profiles without managed services, but the
same Core version alone does not provide these lifetime capabilities.

Cloud tests use controlled endpoints and synthetic credentials; a live cloud
account, complete relay deployment and HTTP/3/ECH remain separate acceptance.
Flutter packages remain 1.1.7 and are not published by this native release.
