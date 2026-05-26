# Flutter Vless Companion

Desktop companion app for browser-extension controlled `flutter_vless`
sessions.

The companion:

- imports `vless://`, `vmess://`, `trojan://`, `ss://`, `socks://`,
  subscription, or raw Xray JSON input;
- starts the existing desktop `flutter_vless` backend in proxy-only mode;
- exposes a token-protected loopback API;
- writes a state file consumed by the Native Messaging host;
- can run without changing OS-wide proxy settings so the browser extension can
  control Chrome-only proxying.

Run during development:

```bash
flutter pub get
flutter run -d macos
```

On Windows, use:

```bash
flutter run -d windows
```
