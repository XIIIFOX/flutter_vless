# Xray Windows 26.11.9-r1

Native Windows AMD64 pre-release for `flutter_vless` 1.1.7. It uses
[Xray-core 26.11.9](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9),
commit `676eaf66f8f05d4d558ee7a74b4736623d3feeb9`, built with Go 1.27.3.

The managed companion includes the native routing factory, XDRIVE and GeoDAT
lifetime management, and XHTTP listener cleanup. The
`native-services capabilities` command returns the managed-lifetime bitmap `7`.
Windows VPN uses the plugin's Wintun and WFP integration. Core's expanded TUN
leak rules apply to standalone Core TUN profiles.

The producer is `a56429a73d0229ffd5ac5223bfabdcd6a7c19724`. The
[Windows workflow](https://github.com/XIIIFOX/flutter_vless/actions/runs/43068599292)
built identical `xray.exe` payloads on Windows Server 2022 and 2025. Both
build-and-proxy jobs passed native ACL and WFP controls, reverse domain routing,
traffic counters, and portable paths containing Unicode. The same payload passed
both Wintun VPN jobs, including protected DNS, numeric IPv6 scope and route and
filter cleanup. The Flutter example built with MSVC on both runners.

| Release file | SHA-256 |
| --- | --- |
| `Xray-windows-managed-64.zip` | `81df36b77068fa7cf49f07311879a02d23e5d6bde9606c7d6cd024a5a01b6264` |
| `xray.exe` in the archive | `8385a665b77fbe2c0ce31972668e520f36cd453d895f98689ba3435ecca1699e` |
| `manifest.json` | `3dd40bdef1383d9accb60c2082f53d5e82a48f337e9b63598e6d95830b356c30` |

Use the archive and companion receipts from the Windows Server 2022 job. The
archive includes the executable, full project GeoDAT and the Xray license.
