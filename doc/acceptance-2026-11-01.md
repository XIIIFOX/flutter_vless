# Bounded compatibility acceptance, 2026-11-01

Work stays on `main`, with Flutter packages at `1.1.7`. No pub.dev/plugin
publication or live macOS VPN session is part of this stage. The owner's Mac
VPN and unrelated working files/processes must remain untouched.

| Item | Completion boundary | Evidence still required at the start |
| --- | --- | --- |
| 2ip Loading and supplied-profile timeouts | Reproduce with independent OFF/reference controls; correct confirmed plugin defects with a failing test first; report external site/peer failures separately | Healthy iPhone OFF baseline, both split directions, independent Core/endpoint comparison for Android profiles 2/3 |
| S3 / Google Drive | Verify endpoint/auth identity, data round trip, cancellation and fresh-owner isolation with actual managed Core fixtures | Requalify controlled fixtures on current CI; live account/relay acceptance only if authorized test settings are available |
| IPv6 / DNS64 / NAT64 / handover | Runtime tests distinguish literal IPv6, synthesized destinations and address-family changes; include actual device/emulator checks where the network supports them | Explicit inventory of available network families; controlled CI coverage must not be called a physical IPv6-only network test |
| Config/import/protocol/transport matrix | A finite representative matrix covers full JSON/JSONC, file bytes and URI/subscription imports, preserving opaque fields and producing explicit failures; fix discovered defects before rerunning | Cross-platform adapter tests, literal-IP SOCKS with real TLS/SNI and wrong-route controls; QUIC/ECH support stated precisely |
| Windows and macOS Actions | Actual pinned Core routing/compatibility tests pass on both OSes at an identified source commit, with bounded teardown | Fresh Actions evidence for new runtime tests; live Windows VPN tests if the affected code needs them |
| Review and cleanup | Independent review of changed contracts; record results and external limitations, push main; stop owned VPN sessions/processes/emulators and verify ordinary internet | Final source/test review, receipt links and process ownership audit |

An import pass, `CONNECTED`, source-level test, controlled runtime test and
live network pass are different results. None substitutes for another.
Unavailable accounts, protocols or physical network conditions remain named
external acceptance limits; they are never marked as successful live tests.

The earlier baseline is recorded in
[Xray 26.10.29 compatibility](xray-26.10.29-compatibility.md). Results below are
updated as each boundary is reached.
