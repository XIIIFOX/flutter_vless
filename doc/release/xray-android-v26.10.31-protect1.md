# Xray Android v26.10.31-protect1

Native runtime only. Flutter packages stay **1.1.7**; this release does not
publish a pub.dev package or a plugin GitHub release.

Update to [Xray-core v26.10.31](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31),
commit `a4a3dff5b20c2faae567b742c172c7b95e75c083`, built with Go 1.27.3.
Keep upstream's explicit MPTCP default and caller opt-in, protected Android
sockets, native routing and the reviewed Classic DNS, XHTTP, XDRIVE and
GeoDAT lifetime fixes. The four freshly compiled Core ABIs use 16 KiB ELF
alignment; existing HEV libraries and full project GeoDAT bytes are preserved.

Maven: `dev.tfox.fluttervless:xray-android:26.10.31-protect1`.
Producer: `13c47ed2caabd70b082449ed4917ce65574df91e`.
[The signed four-ABI candidate](https://github.com/XIIIFOX/flutter_vless/actions/runs/41349647031)
was qualified before [publishing the same Central deployment](https://github.com/XIIIFOX/flutter_vless/actions/runs/41352381737),
without rebuilding or uploading another bundle.
[Core regressions pass on Ubuntu, macOS and Windows](https://github.com/XIIIFOX/flutter_vless/actions/runs/41350987225).

AAR SHA-256:
`4c7080a48106e1b0369d7aba68a4969382de22a21ecf7c89f3e86685adb8d704`.

The attached AAR, POM, sources, javadoc and four detached signatures are the
exact signed candidate. Their signatures were verified with fingerprint
`8703036B80C2E9E6F1E8BF582A9743122C267573`. The public runtime manifest binds
the files, Core source and producer; verify all nine payloads against
`SHA256SUMS`. Full producer archives remain attached to the candidate workflow.

Earlier native releases remain unchanged. Execution of these published bytes
on Android devices/emulators, live two-domain routing and physical network
changes are subsequent acceptance checks. This publication does not claim
that those device checks or the plugin release are complete.
