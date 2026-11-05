# Architecture

This package follows a federated plugin layout:

- `flutter_vless` is the app-facing Dart package.
- `flutter_vless_platform_interface` defines the shared contract.
- `flutter_vless_android`, `flutter_vless_macos`, and `flutter_vless_windows` provide platform implementations.
- iOS is implemented in the root package.

## Data Flow

```mermaid
graph TB
    A[Share link / subscription / JSON] --> B[FlutterVless.parse or parseMany]
    B --> C[FlutterVlessURL]
    C --> D[getFullConfiguration()]
    D --> E[MethodChannel startVless]
    E --> F[Native platform plugin]
    F --> G[Xray / tunnel / proxy backend]
    F --> H[Status EventChannel]
    H --> I[onStatusChanged callback]
```

## Why The API Looks Low Level

The package is not only a convenience wrapper. It also acts as a config bridge between user input, Xray JSON, and native tunnel backends.

That is why the Dart surface exposes:

- parsed URL objects
- raw Xray JSON generation
- typed Xray config helpers for advanced construction and validation
- platform channel methods for delay and core version checks
- mutable config maps for advanced routing work

## Platform Concerns

- Android emphasizes VPN service orchestration and app exclusions.
- iOS and macOS rely on Network Extension / Packet Tunnel behavior and group container configuration.
- Windows focuses on local Xray availability and system-level routing/proxy behavior.

For the macOS packet tunnel path, read the deeper note in [macos_packet_tunnel_architecture.md](macos_packet_tunnel_architecture.md).
