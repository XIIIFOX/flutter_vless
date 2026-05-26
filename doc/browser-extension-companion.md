# Browser Extension Companion Architecture

The browser-extension path is intentionally split into separate runtime layers.
The extension is a browser controller, not an Xray/VLESS runtime.

## Desktop Flow

```text
Chrome extension
  -> Chrome Native Messaging
  -> flutter_vless_native_host
  -> Flutter Vless Companion local API
  -> flutter_vless desktop backend
  -> local Xray SOCKS/HTTP inbound
  -> remote VLESS/VMess/Trojan/Shadowsocks/SOCKS outbound
```

The extension applies `chrome.proxy` settings to route browser traffic to the
local proxy endpoint returned by the companion.

## Development Flow

```bash
dart run tool/setup_chrome_extension_dev.dart
cd apps/vless_companion
flutter run -d macos
```

Then open `chrome://extensions`, enable Developer mode, and load
`extensions/browser/chrome` as an unpacked extension. The dev extension id is
pinned to `pnknppmnnjjoajkpelpnccddodhheefb` through the Chrome manifest
`key` field so the Native Messaging `allowed_origins` entry stays stable.

## Code Ownership

- `apps/vless_companion/`
  - Desktop companion app.
  - Imports profiles with the existing `FlutterVless.parse` API.
  - Starts proxy-only Xray with `setSystemProxy: false` for browser-controlled
    proxying.
  - Exposes a token-protected loopback API.

- `native_hosts/flutter_vless_native_host/`
  - Minimal Native Messaging stdio bridge.
  - Reads the companion state file from the user profile.
  - Forwards browser commands to the companion local API.
  - Does not contain Xray protocol logic.

- `extensions/browser/chrome/`
  - Manifest V3 Chrome extension.
  - Talks to `dev.tfox.flutter_vless` through Native Messaging.
  - Sets or clears `chrome.proxy` for browser-only routing.

- `lib/` and `packages/flutter_vless_*`
  - Existing parser, config generation, platform channel, and native runtime
    implementations.

## Why `setSystemProxy` Exists

Desktop proxy-only mode can be useful as a standalone app feature, but browser
extensions should normally avoid changing OS-wide proxy settings. The
`setSystemProxy` flag keeps existing behavior as the default while allowing the
companion to run local Xray only and let the browser extension control browser
proxy settings.

## Mobile Boundary

Mobile browsers are not a primary extension target for this architecture.
Android and iOS should keep using native VPN/tunnel app paths. Safari Web
Extensions can be considered later as a companion UI inside a containing Apple
app, but the runtime remains native.
