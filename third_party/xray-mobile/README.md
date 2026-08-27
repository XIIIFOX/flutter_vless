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
- Xray-core pinned to release `v26.7.28` commit `5ca6f4b7d4dc20a881d4330e498892697627ec0c` for the `1.1.6` release train.
- `GetVersion`, `MeasureDelay`, and `MeasureOutboundDelay` exported for the
  Flutter platform layer.
- `QueryStats` exported for macOS traffic counters.
- `Stop` handles a nil or already-stopped core instance.

Build scripts copy this directory into a temporary build directory before
running `go get` and `go mod tidy`, so release builds do not mutate the tracked
vendored source.
