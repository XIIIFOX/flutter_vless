# XRay iOS v26.10.29

Native runtime for flutter_vless 1.1.7.

- Xray-core [v26.10.29](https://github.com/XTLS/Xray-core/releases/tag/v26.10.29),
  commit `0afec66085a85191e9dd2a4a6646c7c9a94688d1`.
- Built with Go 1.27.3; retain the 128 KiB HTTP/2 scratch cap, private preflight,
  native routing, mandatory Darwin interface binding and Classic DNS/XHTTP
  lifetime cleanup. Preserve upstream's corrected TCP keepalive values.
- Device arm64 and simulator arm64/x86_64 slices; architecture, strong-export,
  exact-source and controlled simulator privacy/DNS/routing gates pass in
  [the canonical build](https://github.com/XIIIFOX/flutter_vless/actions/runs/40956099275/job/123736498619).
- Producer revision: `c381b13dd694ba415ef7d55302abdd0e43b86e2b`.
- Existing full project GeoDAT and HEV components remain selected separately.

Archive SHA-256: `c6b2070b24e7f150fea5460fd2c42beef3dda92ad94439069e6b933e2cfeee55`.

Signed physical-device VPN acceptance is recorded separately in
[validation and remaining work](https://github.com/XIIIFOX/flutter_vless/blob/main/doc/release/xray-v26.10.29-validation.md).
