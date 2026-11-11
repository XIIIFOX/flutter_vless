Native macOS runtime preview for flutter_vless based on Xray-core 26.11.9.
The static XCFramework contains arm64 and x86_64 slices.

The manifest records the Core commit, source inputs, exported capabilities and
archive checksum. Use the matching checksum when pinning the binary target.

The exact release framework passed the macOS arm64 suite for private startup,
native routing, DNS and FakeDNS, local authentication and listener cleanup.
The x86_64 slice was checked for architecture and exported symbols.

Archive SHA-256 `3a9c5b3c18a9706539d44c74cc176ba6232f663cf662d1cf2ce13ac40f3096c7`.

The runtime retains the managed DNS, socket binding, routing and service
cancellation capabilities. Drive slot pre-warming is disabled for managed
Core sessions until the upstream pool can follow the Core lifetime.
