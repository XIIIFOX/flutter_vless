# Work after the bounded Core 26.10.31 acceptance

Native Core publication is separate from Flutter package publication. Packages
stay at 1.1.7 during the present goal. This is a follow-up list, not a claim that
all configurations or real networks have been qualified.

## New Core behavior needing additional examples or runtime coverage

* **GeoDAT gzip:** cover compressed, corrupt, truncated and oversized decoded
  input, cancellation and atomic replacement. The 256 MiB decoded limit stays
  in force; gzip detection is based on file contents.
  [Upstream change](https://github.com/XTLS/Xray-core/commit/0c3402d77874f400640214055ac76d2eff70ee36).
* **QUIC sniffing:** add active fragmented/gapped CRYPTO and empty-SNI controls
  with both routing directions. Existing TCP-SNI and H3 checks do not qualify
  QUIC-SNI routing.
  [Upstream change](https://github.com/XTLS/Xray-core/commit/9b8190f52c970861c938dcd8c8c6eb696a77a900).
* **XHTTP:** preserve and demonstrate ordinary `OPTIONS` uplink versus real
  CORS preflight, and server `h2Params`; verify actual OPTIONS/H2 round trips.
  `h2Params` is a server setting; the client uplink method is configurable.
  These changes do not automatically require new Flutter options.
  [OPTIONS](https://github.com/XTLS/Xray-core/commit/e7a69fa85a18146e83e008b6ec0a72e996dc6cf9),
  [h2Params](https://github.com/XTLS/Xray-core/commit/316e07a53822aa23661cb3f8b30e1132911c5b36).
* **Windows Core TUN leak rules:** separately evaluate `tcp/port`, `udp/port`
  and TCP/UDP 853 in `autoSystemWfpBlockLeak`. The plugin has its own VPN/WFP
  path; do not silently map this distinct Core setting into ProtectionOptions.
  [Upstream change](https://github.com/XTLS/Xray-core/commit/6cdd323ad82fe21bb9c1d06e6a5c5f909de2ffaf).
* **HTTP inbound:** add `Expect: 100-continue` upload regression coverage.
  [Upstream change](https://github.com/XTLS/Xray-core/commit/bc7c895278a895a87881953e1ec522fcdb0f885b).

The shared MPTCP default-off fix is already included in the protected SDK and
CLI source compositions. Explicit caller socket settings remain authoritative;
no system-wide network setting was changed. Balancer CLI corrections and
protobuf regeneration do not require a new public Flutter option.
[Security release](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31).

## Before plugin publication review

* Run live macOS VPN acceptance only when the owner can interrupt the existing
  VPN. Actions acceptance cannot establish behavior on that particular Mac.
* Android public routing was subsequently qualified on 2026-11-02 in both
  directions after configuring the emulator transport and responsive system
  DNS; see [the live setup/result](../android-emulator-host-vpn.md).
  The iPhone DIRECT-domain pass uses explicit caller
  DNS; investigate the original implicit-DNS policy with captured resolver
  answers if that unmodified behavior is required. Do not silently rewrite
  caller DNS or infer that a failed public reference proves expired credentials
  or a plugin defect.
* Choose available implementation-package versions, align root dependency
  constraints and rehearse publication order. A read-only registry check on
  2026-11-02 confirms Android/macOS/Windows already have 1.1.7, while root
  1.1.7 and platform-interface 1.1.7 are absent. Do not publish the current
  work under conflicting versions or automatically bump them in this goal.
  [Android](https://pub.dev/packages/flutter_vless_android/versions),
  [macOS](https://pub.dev/packages/flutter_vless_macos/versions),
  [Windows](https://pub.dev/packages/flutter_vless_windows/versions).

## Wider compatibility acceptance

These checks are needed before claiming the corresponding real-world coverage;
they are separate from the finite controlled acceptance completed in this goal.

* Repeat canonical 2ip over VPN when its ordinary baseline is stable and fully
  loaded. Its current OFF IP observation and historical Loading/503 evidence
  do not establish a complete ON result; tfox/ipify qualify the current splits.
* Qualify real IPv6-only/DNS64/NAT64 and Wi-Fi/mobile handover. Address carriage
  and controlled resolver/kernel tests are narrower evidence.
* With authorized test accounts, qualify real S3/Google service limits and a
  complete Google Drive relay. Registration-free controlled fixtures remain
  useful, but do not establish real account/API acceptance.
* Expand server-backed protocol/transport coverage and protected remote ECH /
  scoped Apple root environment support when those are required.
