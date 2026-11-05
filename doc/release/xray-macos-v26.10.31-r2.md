# Xray macOS 26.10.31-r2

Native runtime for flutter_vless 1.1.7.

This revision closes the allocated XHTTP TCP listener when invalid server `h2Params` is rejected. Successful configurations and the public SDK ABI are unchanged. Upstream Core stays at `26.10.31` (`a4a3dff5b20c2faae567b742c172c7b95e75c083`).

Produced from `2505694c4001e7d52f06d6a63f29780da8dc7d49` in [canonical Apple build](https://github.com/XIIIFOX/flutter_vless/actions/runs/41446770316), with Go 1.27.3 and H2BUF 128 KiB. Both macOS architecture slices have 16 verified strong C exports. The actual SDK passes the existing runtime/capability, domain-routing and DNS controls in Actions.

[Four-runner feature acceptance](https://github.com/XIIIFOX/flutter_vless/actions/runs/41446768463) covers gzip, XHTTP OPTIONS/H2 settings and invalid admission, HTTP 100-continue, QUIC fragmented-SNI routing and Windows-specific filter controls. Live VPN testing on the owner's Mac remains excluded.

`XRay.xcframework.zip` SHA-256: `59f41c9f8d6bafce3b15741adb0aefe37634737ff1b22075fa4ec9b56fdc2687`. Manifest and SHA256SUMS accompany the exact producer ZIP; it has not been rebuilt or repackaged for publication.
