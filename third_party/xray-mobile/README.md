# Vendored xray-mobile source

This directory vendors the small Go wrapper that `gomobile bind` uses to build
the iOS and macOS `XRay.xcframework` artifacts.

The Go module path intentionally remains:

```text
github.com/EbrahimTahernejad/xray-mobile
```

Generated Objective-C headers and existing Swift bindings expose that package
name, so changing it would be an ABI/API change for the native artifacts.

The source is based on `EbrahimTahernejad/xray-mobile` `1.8.1`, with local
changes needed by `flutter_vless`:

- Xray-core dependency updated to the 26.x release line used by this package.
- Xray-core pinned to release `v26.10.29` commit `0afec66085a85191e9dd2a4a6646c7c9a94688d1` for the `1.1.7` release train.
- `GetVersion`, `MeasureDelay`, and `MeasureOutboundDelay` exported for the
  Flutter platform layer.
- `QueryStats` exported for macOS traffic counters.
- `SetAssetLocation` exported so Apple runtimes can select an App Group asset
  directory from inside Go before Xray reads `geoip.dat` and `geosite.dat`.
- `Stop` handles a nil or already-stopped core instance.
- Ordinary and optional routing builds share a strict final-config/spec
  validator and serialized session admission/teardown. The unpublished optional
  factory requires `flutter_vless_vpn_routing` and the separately pinned
  [Core overlay](../xray-vpn-routing/README.md). Default artifacts report
  capability zero and refuse optional start/check requests.

Build scripts copy this directory into a temporary build directory before
running `go get` and `go mod tidy`, so release builds do not mutate the tracked
vendored source.
