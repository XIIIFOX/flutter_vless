Native iOS runtime preview for flutter_vless based on Xray-core 26.11.9.
The XCFramework contains the arm64 device and arm64/x86_64 simulator slices.

The manifest records the Core commit, source inputs, exported capabilities and
archive checksum. Use the matching checksum when pinning the binary target.

The exact release framework passed the iOS Simulator suite for private startup,
native routing, DNS and FakeDNS, local authentication and listener cleanup.
The arm64 device slice was checked for architecture and exported symbols.

Archive SHA-256 `d4c700415f3f61de9b7c6fa83cf5df10b48253eb36a5e6e16f09510a9829a837`.

The runtime retains the managed DNS, socket binding, routing and service
cancellation capabilities. Drive slot pre-warming is disabled for managed
Core sessions until the upstream pool can follow the Core lifetime.
