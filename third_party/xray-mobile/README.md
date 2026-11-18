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
- The native builds pin Xray-core `v26.11.9` at commit `676eaf66f8f05d4d558ee7a74b4736623d3feeb9`.
- `GetVersion`, `MeasureDelay`, and `MeasureOutboundDelay` exported for the
  Flutter platform layer.
- `QueryStats` exported for macOS traffic counters.
- `SetAssetLocation` exported so Apple runtimes can select an App Group asset
  directory from inside Go before Xray reads `geoip.dat` and `geosite.dat`.
- `Stop` handles a nil or already-stopped core instance.
- Ordinary and optional routing builds share a strict final-config/spec
  validator and serialized session admission/teardown. The optional routing
  factory requires `flutter_vless_vpn_routing` and the separately pinned
  [Core overlay](../xray-vpn-routing/README.md). Default artifacts report
  capability zero and refuse optional start/check requests.

Build scripts copy this directory into a temporary build directory before
running `go get` and `go mod tidy`, so release builds do not mutate the tracked
vendored source.

## Balancer diagnostics runtime

The opt-in dispatcher observer is available in compatible Xray 26.11.9 builds.
Set `XRAY_BALANCER_DIAGNOSTICS=1` when running `ios/build_xray_ios.sh` or
`packages/flutter_vless_macos/macos/build_xray_macos.sh`. The canonical Apple
workflow verifies the three diagnostic ABI exports on every slice. To build
an isolated Android runtime, set the same option and a private `TARGET_DIR`
when running `packages/flutter_vless_android/android/build_xray.sh`. For a
Windows candidate use `tool/build_native_routing_cli.py --balancer-diagnostics`
with a new output directory. The plugin enables its diagnostic view when the
installed runtime advertises the observation capability.

Selection history belongs to the active authenticated SOCKS tunnel. The new
startup function takes the provider-owned inbound tag and a bounded line count.
Apple uses the provider bridge. Android and Windows use inherited process
pipes. The read operation returns `sequence,group,node` rows as decimal ordinals. Group
and node numbers are the 1-based positions in the compiled profile. Sequence
numbers describe dispatch observation order, which may differ from the order
in which concurrent requests began. History exists only in memory and is
cleared on Stop.
