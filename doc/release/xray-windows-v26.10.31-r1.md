# Xray Windows 26.10.31, managed native revision r1

This AMD64 companion uses upstream Core **v26.10.31**, commit
`a4a3dff5b20c2faae567b742c172c7b95e75c083`, with the shared MPTCP default-off
security change. The native routing CLI and owned Classic DNS, XHTTP/H3,
XDRIVE and GeoDAT shutdown behavior are retained.

Producer: `13c47ed2caabd70b082449ed4917ce65574df91e`.
[Windows 2022/2025 native, example and real VPN acceptance](https://github.com/XIIIFOX/flutter_vless/actions/runs/41349615668).
[Core tests on Linux, macOS and Windows](https://github.com/XIIIFOX/flutter_vless/actions/runs/41350987225).
All six Windows jobs passed. Both runners produced identical Core executable
bytes and passed 189 VPN, 21 proxy and 21 portable checks each, including reverse
domain routing, FakeDNS, numeric IPv6/WFP controls and cleanup. The compiled
example version is 1.1.7.117 and contains that same Core.

`Xray-windows-managed-64.zip` SHA-256:
`19268b7f9f5ddedbcf9c3cb294175f28f1c6a4d495327e790f8e519e8073aa48`.
The Windows 2025 archive is canonical. It contains `xray.exe`, the unchanged
full project GeoDAT and the Core license; its manifest and checksum file are
included. Earlier native release assets remain unchanged.

Place these files in the application's `xray` directory and retain compatible
`tun2socks.exe` and `wintun.dll` files for VPN mode. The executed native service
capability is **7**: GeoDAT plus XDRIVE storage/idle-worker ownership. Physical
IPv6-only/NAT64 and live cloud accounts remain separate acceptance conditions.
