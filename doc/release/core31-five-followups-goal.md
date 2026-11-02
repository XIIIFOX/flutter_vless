# Bounded Core31 follow-ups — 2026-11-02

The active goal covers exactly the following five additions to the existing
Core 26.10.31 acceptance. Work stays on `main`, packages remain `1.1.7`, and
example remains `1.1.7+117`. No plugin/package publication is included.

| Item | Completion boundary |
| --- | --- |
| GeoDAT gzip | Runnable example; actual content-sniffed gzip decoding, corrupt/truncated input, decoded-size boundary, active cancellation and atomic replacement controls; exact data and owned-resource cleanup. |
| XHTTP | Client `OPTIONS` upload and actual CORS-preflight distinction; server `h2Params` observable on a real HTTP/2 exchange; exact bytes and bounded negative controls. |
| QUIC SNI | Active fragmented/gapped CRYPTO, empty/unmatched SNI and incomplete-input controls; observed destination in both domain-routing directions. No full QUIC/NAT64 matrix. |
| Windows Core TUN | Explicit `autoSystemWfpBlockLeak` TCP/UDP port and 853 checks, allowed/blocked controls and filter removal on Windows Actions. Remains separate from the plugin's ProtectionOptions and existing VPN path. |
| HTTP inbound | Actual `Expect: 100-continue` upload with interim response and exact body; bounded truncated/stalled/cancel controls. |

Tests and fault controls precede any necessary implementation correction.
Positive adjacent tests do not qualify an untested new feature. Each result
must identify source/runtime, selected tests, evidence and limitations.

Native Core/SDK compilation and execution on the owner's Mac are excluded.
Native runtime checks run in Actions on Windows/macOS/Linux. Applicable client
cases additionally use the VPN-compatible Android emulator and the connected
physical iPhone when available. Live macOS VPN testing, global network changes,
real cloud accounts and a broader protocol/device matrix are outside scope.

The Mac VPN stays connected. Preserve the two pre-existing analysis YAML edits.
After device tests, explicitly stop the test VPN, verify ordinary browsing,
and stop only owned emulators, servers, forwards, clients and build workers.
Independent review, scoped checks, documented results and push to `main` are
required before marking this goal complete. External limitations remain explicit.

## Progress

- [x] GeoDAT gzip
- [x] XHTTP OPTIONS and h2Params
- [x] QUIC fragmented SNI and routing
- [x] Windows Core TUN leak rules
- [x] HTTP inbound 100-continue
- [x] Relevant live client checks, independent review and cleanup

The progress checklist is updated from actual completed evidence, not from
fixture implementation alone.

All bounded criteria are complete. Published protect2/r2 consumers, Android
GET/POST/OPTIONS, physical iPhone POST/OPTIONS, independent backend witnesses
and final owned-process cleanup are recorded in the
[validation report](core31-five-followups-validation.md). Broader compatibility
and publication work stays in the separate
[follow-up list](xray-v26.10.31-plugin-followups.md).

All five source-runtime criteria pass on the immutable producer head
`2505694c4001e7d52f06d6a63f29780da8dc7d49` in
[four-runner acceptance](https://github.com/XIIIFOX/flutter_vless/actions/runs/41446768463).
The Windows-specific group runs on both Windows 2022 and 2025; the other
groups also run on Linux and macOS. This source-runtime result is distinct
from the subsequent acceptance of published binaries and physical devices.

## First runtime result

[Initial four-runner acceptance](https://github.com/XIIIFOX/flutter_vless/actions/runs/41441800609)
at `75dfe57` passes the gzip, XHTTP data/wire, HTTP inbound and QUIC groups.
The separate malformed-`h2Params` admission test reproduces an owned-listener
leak on every OS. Its minimal correction closes that listener on the existing
parse-error branch. Corrected native artifacts must carry this correction on
every platform; changing only test-source copies is not release readiness.
Native revision `26.10.31-protect2` / `26.10.31-r2` is limited to delivering
this reproduced correction with verified provenance. The upstream Core pin
and Flutter plugin/package versions remain unchanged. Active consumer pins
move only after the corresponding native assets have actually been published.

Windows' first UDP observer expected `WSAEACCES`, while the kernel silently
discarded the datagram. The stronger observer requires actual installed
protocol/port filters, zero nonce receipts for blocked endpoints, working
unselected endpoints, permitted interface/application controls, exact filter
removal and payload recovery. A timeout alone is never a passing observation.
