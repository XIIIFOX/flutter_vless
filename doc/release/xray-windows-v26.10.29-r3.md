# Xray Windows 26.10.29, managed native revision r3

This AMD64 companion retains upstream Core **v26.10.29** and fixes idle
XDRIVE connection/listener workers surviving Core shutdown. Worker
cancellation preserves caller metadata and parent/Core feature contexts.
The native routing CLI and bounded GeoDAT teardown remain available.

Producer: `3fffc1d1700889f216f8f02d51a809ec670b21ba`.
[Windows 2022/2025 native, example and real VPN acceptance](https://github.com/XIIIFOX/flutter_vless/actions/runs/41050075535).
[Core tests on Linux/macOS/Windows](https://github.com/XIIIFOX/flutter_vless/actions/runs/41050075901).
All six Windows jobs passed. Both runners produced identical executable
bytes and passed reverse routing, traffic, private-file and cleanup checks.
Numeric IPv6 endpoint tests are separate from IPv4 payload routing.

`Xray-windows-managed-64.zip` SHA-256:
`a518fc405f9da4ef6ad3cd9a6c2ebdd7ff9c6fd03a38e344be952107f159db54`.
The ZIP contains `xray.exe`, the project's unchanged full `geoip.dat` and
`geosite.dat`, and the Xray license. The release includes its exact producer
manifest and checksum file. Earlier native releases remain unchanged.

Place these files in the application's existing `xray` directory. Retain the
compatible `tun2socks.exe` and `wintun.dll` for VPN mode. The executable answers
`native-services capabilities` with **7**: GeoDAT plus XDRIVE storage and idle
worker ownership. Ordinary external Core images remain usable for profiles
without these managed services.

Cloud fixtures use controlled endpoints and synthetic credentials. Live cloud
accounts, complete relay deployment, HTTP/3/ECH and physical NAT64 remain
separate acceptance. Flutter packages remain **1.1.7**; the plugin is not
published by this native release.
