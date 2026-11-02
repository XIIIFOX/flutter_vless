# Work after the bounded Core 26.10.31 acceptance

Native Core publication is separate from Flutter package publication. Packages
stay at 1.1.7 during the present goal. This is a follow-up list, not a claim that
all configurations or real networks have been qualified.

## Five Core31 follow-ups

The five items below now have examples and successful bounded native-runtime
acceptance on Linux/macOS/Windows. The
[results and precise limits](core31-five-followups-validation.md) distinguish
those completed criteria from remaining live-client investigation. They should
not be listed again as unimplemented features.

* **GeoDAT gzip:** covered compressed, corrupt, truncated and oversized decoded
  input, cancellation and atomic replacement. The 256 MiB decoded limit stays
  in force; gzip detection is based on file contents.
  [Upstream change](https://github.com/XTLS/Xray-core/commit/0c3402d77874f400640214055ac76d2eff70ee36).
* **QUIC sniffing:** added active fragmented/gapped CRYPTO and empty-SNI controls
  with both routing directions. Existing TCP-SNI and H3 checks do not qualify
  QUIC-SNI routing.
  [Upstream change](https://github.com/XTLS/Xray-core/commit/9b8190f52c970861c938dcd8c8c6eb696a77a900).
* **XHTTP:** preserved and demonstrated ordinary `OPTIONS` uplink versus real
  CORS preflight, and server `h2Params`; verified actual OPTIONS/H2 round trips.
  `h2Params` is a server setting; the client uplink method is configurable.
  These changes do not automatically require new Flutter options.
  [OPTIONS](https://github.com/XTLS/Xray-core/commit/e7a69fa85a18146e83e008b6ec0a72e996dc6cf9),
  [h2Params](https://github.com/XTLS/Xray-core/commit/316e07a53822aa23661cb3f8b30e1132911c5b36).
* **Windows Core TUN leak rules:** separately evaluated `tcp/port`, `udp/port`
  and TCP/UDP 853 in `autoSystemWfpBlockLeak`. The plugin has its own VPN/WFP
  path; do not silently map this distinct Core setting into ProtectionOptions.
  [Upstream change](https://github.com/XTLS/Xray-core/commit/6cdd323ad82fe21bb9c1d06e6a5c5f909de2ffaf).
* **HTTP inbound:** added `Expect: 100-continue` upload regression coverage.
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
  The subsequent fresh France iPhone import and both opposite domain-routing
  cases pass without an explicit `dns` section, using the protected default
  DNS policy; see [the Apple follow-up](apple-readiness-dns-validation.md).
  This finite result does not qualify every resolver/network combination or
  establish that an older failed public reference had expired credentials.
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

The Apple VPN readiness and bounded local-DNS follow-up is implemented in
`0f16a94`: readiness checks the current native worker and authenticated listener,
while an optional caller-selected URL checks network reachability. Protected
`tcp+local`, `https+local` and `h2c+local` preparation requires a physical path
and finite numeric/static resolver destinations. Physical iPhone regressions
cover private/default-blocked readiness, original named DoH and actual TCP/HTTPS
local DNS. See [the follow-up validation](apple-readiness-dns-validation.md).

* Extend DNS modes only with their own protected resolver/socket proof. The
  bounded Apple VPN change does not qualify `+local` preparation/delay paths
  without a physical-interface snapshot, unpinned resolver names, or
  `quic+local`. These forms continue to fail preparation explicitly.

* Track external 2ip page completion separately from VPN readiness. The new
  France all-proxy iPhone case reaches HTTP 200 and a complete document; the
  ordinary baseline shows its current IP without Loading while the document
  remains interactive. Other network paths and challenge behavior still need
  their own observations.
* Qualify real IPv6-only/DNS64/NAT64 and Wi-Fi/mobile handover. Address carriage
  and controlled resolver/kernel tests are narrower evidence.
* With authorized test accounts, qualify real S3/Google service limits and a
  complete Google Drive relay. Registration-free controlled fixtures remain
  useful, but do not establish real account/API acceptance.
* Expand server-backed protocol/transport coverage and protected remote ECH /
  scoped Apple root environment support when those are required.
