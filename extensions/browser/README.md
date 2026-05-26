# Browser Extension

The first supported browser target is Chrome/Chromium Manifest V3.

Development loading:

1. Start `apps/vless_companion`.
2. Build and register the Native Messaging host:

   ```bash
   dart run tool/setup_chrome_extension_dev.dart
   ```

   The dev extension id is pinned by the manifest `key` field:
   `pnknppmnnjjoajkpelpnccddodhheefb`.

3. Open `chrome://extensions`, enable Developer mode, and load
   `extensions/browser/chrome` as an unpacked extension.
4. Open the toolbar popup, paste a supported profile, and press `Connect`.

The extension does not implement VLESS/Xray itself. It asks the native host to
start the local companion proxy, then applies `chrome.proxy` settings for the
browser.

Note: current branded Google Chrome builds ignore some command-line extension
loading switches. For development, use the `chrome://extensions` Load unpacked
flow after running the setup script.
