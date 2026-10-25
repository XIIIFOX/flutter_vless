# XRay iOS v26.10.21

Runtime-only native artifact for the unreleased flutter_vless 1.1.7 work.

- Xray-core [v26.10.21](https://github.com/XTLS/Xray-core/releases/tag/v26.10.21), commit `1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`.
- Canonical builds require Go 1.27.3 or newer for root CA filtering.
- Retains private preflight/startup bridges, routing capability 1 and mandatory Darwin interface binding.
- Retains Classic DNS shutdown, XHTTP HTTP/3 failed-handshake cleanup and the 128 KiB HTTP/2 upload scratch cap.
- Architecture, strong exports, exact source/copy provenance and archive SHA-256 are verified by the manual Apple runtime build workflow before publication.

This releases only `XRay.xcframework.zip`; it does not release the Flutter plugin or change its 1.1.7 unreleased status. Consumer manifests must use the exact verified public archive checksum.

Archive SHA-256: `66915e945357f1649eeeef131e31dc25ff486698a53d27b80e3a60d87e6d6d6e`.

Built from `e0274a62366f15f5119fdbdf8822154746875d41`; canonical iOS simulator runtime, architecture and ABI gates passed in [GitHub Actions](https://github.com/XIIIFOX/flutter_vless/actions/runs/40216827708/job/121239660760). Root verification independently binds all framework/source bytes, three architecture slices and six strong exports per slice.
