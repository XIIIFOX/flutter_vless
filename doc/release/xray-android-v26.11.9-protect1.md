# Xray Android 26.11.9-protect1

Android native runtime preview for flutter_vless, built from
[Xray-core v26.11.9](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9)
at commit `676eaf66f8f05d4d558ee7a74b4736623d3feeb9`.

The signed AAR uses Maven coordinate
`dev.tfox.fluttervless:xray-android:26.11.9-protect1`.
The [candidate build](https://github.com/XIIIFOX/flutter_vless/actions/runs/43068600201)
at `a56429a73d0229ffd5ac5223bfabdcd6a7c19724` built fresh
`arm64-v8a`, `armeabi-v7a`, `x86` and `x86_64` Core binaries and verified
16 KiB ELF load alignment. The AAR retains the pinned HEV and GeoDAT inputs.

The AAR SHA-256 is
`bd3aaa2015e4afe4b7e8b4ac0f03cd71a0d6cce2091ef95fee35fac7a5ec6a1d`.
The release includes the signed Maven files, their checksums and the
source-bound build manifest.
The [Central publication](https://github.com/XIIIFOX/flutter_vless/actions/runs/43070613697)
used the reviewed deployment. The four Maven files and their signatures
match the signed candidate by SHA-256.

The Android socket-protection and native-routing overlays carry forward to
26.11.9. The managed XDRIVE overlay cancels the new session and OAuth paths
with their Core. Drive slot pre-warming is disabled for managed sessions.
A local arm64 emulator build verified the Core version,
managed-service capability bits, routing capability, the minimum-version
guard and Freedom block-rule fields. Startup failed as expected when the
configured socket protection broker was absent.

The arm64 binary from the signed AAR also proxied an HTTP request on an
Android 35 emulator. A second request hit the configured Freedom block rule
and closed immediately with `delay: 0`.
