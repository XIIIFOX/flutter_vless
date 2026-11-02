# Xray Windows 26.10.31-r2

Native AMD64 runtime only. Flutter plugin/packages remain **1.1.7**.

Closes the allocated XHTTP TCP listener on malformed server `h2Params` without changing valid-config behavior or the public capability contract. Upstream Core remains `26.10.31` (`a4a3dff5b20c2faae567b742c172c7b95e75c083`).

Producer `2505694c4001e7d52f06d6a63f29780da8dc7d49`; [Windows build/acceptance](https://github.com/XIIIFOX/flutter_vless/actions/runs/41446772424) passes all six Windows2022/2025 jobs. Each OS passes 189 VPN, 21 proxy and 21 portable cases, compiled example `1.1.7.117`, and kernel WFP/numeric-IPv6 cleanup checks. Both producer PE payloads are byte-identical.

[Focused feature acceptance](https://github.com/XIIIFOX/flutter_vless/actions/runs/41446768463) additionally verifies the five feature groups, including actual Core TUN port filters with independent-client, unaffected-port, interface, application-exemption and cleanup controls. This does not enable Core TUN in the plugin or replace its existing protection path.

Canonical Windows2022 `Xray-windows-managed-64.zip` SHA-256: `dfdf80c45268719d047cb14560fca11b6815b98961916c9b5dc68ad2a547f824`. The paired manifest and SHA256SUMS are unchanged producer assets.
