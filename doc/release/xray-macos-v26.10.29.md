# XRay macOS v26.10.29

Native runtime only for the unreleased flutter_vless 1.1.7 work. No Flutter
package, pub.dev package or plugin 1.1.7 GitHub release is published.

- Xray-core [v26.10.29](https://github.com/XTLS/Xray-core/releases/tag/v26.10.29),
  commit `0afec66085a85191e9dd2a4a6646c7c9a94688d1`.
- Built with Go 1.27.3; retain the 128 KiB HTTP/2 scratch cap, private preflight,
  native routing, mandatory Darwin interface binding and Classic DNS/XHTTP
  lifetime cleanup. Preserve upstream's corrected TCP keepalive values.
- Universal arm64/x86_64 archive; architecture, strong-export, exact-source and
  controlled privacy/DNS/routing runtime gates pass in
  [the canonical build](https://github.com/XIIIFOX/flutter_vless/actions/runs/40956099275/job/123736498939).
- Producer revision: `c381b13dd694ba415ef7d55302abdd0e43b86e2b`.
- Existing full project GeoDAT and HEV components remain selected separately.

Archive SHA-256: `9c451bd1e8db3ece6afbcb03ffdd4326035ea339a253b388ee83e2691cd5a1b1`.

Live VPN acceptance on the owner's Mac remains deferred until the owner is ready.
See [validation and remaining work](xray-v26.10.29-validation.md).
