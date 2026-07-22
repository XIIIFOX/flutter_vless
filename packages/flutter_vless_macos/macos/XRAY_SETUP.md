# Xray-core Setup for macOS

This plugin uses **Xray-core** `v26.7.11` through the bundled framework for normal plugin flows. If you use an external `xray` executable for manual testing, keep it on `v26.7.11` or newer.

## Quick Setup

### 1. Download Xray-core

 Use latest Xray-core releases directly from [XTLS/Xray-core](https://github.com/XTLS/Xray-core/releases)

### 2. Place Binary

**For Main App:**
```bash
# Copy to app bundle
cp build/xray-macos-bin/xray example/macos/Runner/xray
```

**For Network Extension:**
The Network Extension needs access to the binary through a shared container:

1. **Enable App Groups** in both Runner and XrayTunnel targets
2. **Copy binary to shared container**:
   ```bash
   # Get container path (replace with your group identifier)
   CONTAINER_PATH=$(defaults read ~/Library/Group\ Containers/group.dev.tfox.flutterVlessExample 2>/dev/null || echo "")
   
   # Or manually copy to a location accessible by extension
   mkdir -p ~/Library/Application\ Support/flutter_vless
   cp build/xray-macos-bin/xray ~/Library/Application\ Support/flutter_vless/xray
   ```

3. **In Xcode**: Add the binary to XrayTunnel target's "Copy Bundle Resources" build phase

## Binary Search Paths

The plugin automatically searches for `xray` in these locations (in order):

1. App bundle: `Runner.app/Contents/Resources/xray`
2. Shared container: `group.dev.tfox.flutterVlessExample/xray`
3. Application Support: `~/Library/Application Support/flutter_vless/xray`
4. Home directory: `~/.flutter_vless/xray`
5. System paths: `/usr/local/bin/xray`, `/opt/homebrew/bin/xray`

## Manual Download

1. Visit: https://github.com/XTLS/Xray-core/releases
2. Download `Xray-macos-arm64-v8a.zip` (Apple Silicon) or `Xray-macos-64.zip` (Intel)
3. Extract and place `xray` binary in one of the search paths above
4. Make executable: `chmod +x xray`

## Verification

Check if Xray is found:
```bash
# Test version
./xray version

# Should output something like:
# Xray 26.7.11 (Xray, Penetrates Everything.) 50231ea
```

## Network Extension Considerations

Network Extensions run in a sandboxed environment. The binary must be:

1. **Included in the extension bundle**, OR
2. **Accessible via App Groups** (shared container), OR
3. **In a system location** accessible by the extension

**Recommended**: Include in extension bundle or use App Groups shared container.

## Troubleshooting

### Binary not found

- Verify binary exists: `ls -la <path-to-xray>`
- Check permissions: `chmod +x <path-to-xray>`
- Verify architecture matches: `file <path-to-xray>` should show arm64 or x86_64

### Network Extension can't find binary

- Ensure binary is in extension's bundle or shared container
- Check App Groups capability is enabled
- Verify group identifier matches in both targets

### Permission denied

- Make binary executable: `chmod +x xray`
- Check macOS Gatekeeper: `xattr -d com.apple.quarantine xray` (if needed)

## API Configuration

Xray uses HTTP API (default: `127.0.0.1:10085`) for statistics. Ensure your config includes:

```json
{
  "api": {
    "tag": "api",
    "services": ["StatsService"]
  },
  "inbound": [
    {
      "tag": "api",
      "port": 10085,
      "listen": "127.0.0.1",
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      }
    }
  ],
  "policy": {
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  },
  "stats": {}
}
```

## References

- [Xray-core Releases](https://github.com/XTLS/Xray-core/releases)
- [Xray Documentation](https://xtls.github.io/en/)
- [Network Extension Guide](https://developer.apple.com/documentation/networkextension)
