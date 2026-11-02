# Xray iOS 26.10.31-r2

Native SDK only. Flutter plugin/packages remain **1.1.7**; no plugin publication is included.

Closes the owned XHTTP TCP listener when invalid server `h2Params` is rejected. The successful path and public SDK ABI are unchanged. Upstream Core is still `26.10.31` (`a4a3dff5b20c2faae567b742c172c7b95e75c083`).

Producer `2505694c4001e7d52f06d6a63f29780da8dc7d49`; [canonical Apple build](https://github.com/XIIIFOX/flutter_vless/actions/runs/41446770316), Go 1.27.3/H2BUF128. All iOS device/simulator architecture slices have 16 verified strong C exports. The exact simulator SDK passes runtime/capability/custom-root, domain-routing and DNS controls.

[Four-runner bounded acceptance](https://github.com/XIIIFOX/flutter_vless/actions/runs/41446768463) verifies the five follow-up feature groups and malformed-listener cleanup. Physical-device acceptance is tracked separately; it is not inferred from this producer.

`XRay.xcframework.zip` SHA-256: `8d693bc767b8f292f0ec0459850287f752c40499fa6542caef5b749c8bdc5f00`. Manifest and SHA256SUMS belong to the same unchanged producer ZIP.
