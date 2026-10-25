# XRay macOS v26.10.21

Runtime-only native artifact for the unreleased flutter_vless 1.1.7 work.

- Xray-core [v26.10.21](https://github.com/XTLS/Xray-core/releases/tag/v26.10.21), commit `1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`.
- Canonical builds require Go 1.27.3 or newer for root CA filtering.
- Retains private preflight/startup bridges, routing capability 1 and mandatory Darwin interface binding.
- Retains Classic DNS shutdown, XHTTP HTTP/3 failed-handshake cleanup and the 128 KiB HTTP/2 upload scratch cap.
- Architecture, strong exports, exact source/copy provenance and archive SHA-256 are verified by the manual Apple runtime build workflow before publication.

This releases only `XRay.xcframework.zip`; it does not release the Flutter plugin or change its 1.1.7 unreleased status. Consumer manifests must use the exact verified public archive checksum.

Archive SHA-256: `afdf766ed6fc962bb0dc9e413cda21f19e812630896a337adfaec0e979618765`.

Built from `e0274a62366f15f5119fdbdf8822154746875d41`; canonical runtime, architecture and ABI gates passed in [GitHub Actions](https://github.com/XIIIFOX/flutter_vless/actions/runs/40216827708/job/121239660614). The root independently rechecked the archive, every framework member and source binding, both architectures and all six strong exports.
