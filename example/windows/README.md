# Windows Example Setup

This directory contains the Windows-specific files for the flutter_vless example app.

## Xray Setup

Before running the example on Windows, you need to provide the Xray executable:

1. **Download the official Xray-core v26.10.21 security release**:
   - Visit: https://github.com/XTLS/Xray-core/releases/tag/v26.10.21
   - Download `Xray-windows-64.zip` (or `Xray-windows-32.zip` for 32-bit systems)
   - Verify the x64 archive SHA-256: `fc58c39ee2f2717b4c54d28d374362389e5319b20ae44aea76ea45a5243ec827`

2. **Extract and place xray.exe**:
   - Extract the downloaded archive
   - Locate `xray.exe` in the extracted files
   - Copy `xray.exe` to: `example/windows/xray/xray.exe`
   - For this repository's example, retain the full project `geoip.dat` and
     `geosite.dat` from `android_runtime/xray_android/src/main/assets/`, as the
     Windows validation workflow does. Caller-provided asset roots remain separate.
   - The upstream GeoIP dataset is now lite. Profiles using additional country
     lists such as `geoip:us` need a compatible full dataset in their asset directory.

3. **Verify the structure**:
   ```
   example/
     windows/
       xray/
         xray.exe  ← Should be here
   ```

## Running the Example

Once xray.exe is in place, you can run the example:

```bash
cd example
flutter run -d windows
```

Or build the Windows app:

```bash
cd example
flutter build windows
```

## Notes

- `example/windows/xray/` is the source staging directory. For a manual build,
  copy the runtime and required companion files into the built Runner's `xray/`
  directory; the Windows validation workflow performs this bundle step.
- Runtime lookup is relative to the running application, not CWD or AppData.
- If xray.exe is not found, the app will show an error message
- Make sure xray.exe has execute permissions
- The plugin will create temporary configuration files automatically

## Troubleshooting

**xray.exe not found:**
- Verify the file is named exactly `xray.exe` (not `xray.exe.exe`)
- Check that the file is in `example/windows/xray/` directory
- Ensure the file is not corrupted (try downloading again)

**Permission errors:**
- Run the app as Administrator if needed
- Check Windows Defender or antivirus isn't blocking xray.exe

**Connection issues:**
- Verify your Xray configuration is valid JSON
- Check that the server address and port are correct
- Ensure your firewall allows the connection

