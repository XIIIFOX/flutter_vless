# Windows Example Setup

This directory contains the Windows-specific files for the flutter_vless example app.

## Xray Setup

Before running the example on Windows, provide the x64 Xray executable.
The recommended [managed Core 26.10.31-r2](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-windows-v26.10.31-r2)
includes native routing and the owned XDRIVE/GeoDAT services (capability `7`).
Revision r2 also closes the allocated XHTTP listener when server `h2Params`
cannot be parsed, so a rejected configuration does not retain its TCP port.
Its `Xray-windows-managed-64.zip` SHA-256 is
`dfdf80c45268719d047cb14560fca11b6815b98961916c9b5dc68ad2a547f824`.
The extracted AMD64 `xray.exe` SHA-256 is
`78268f751286f3e02f460dffbb2d7be6be8d2d870f3879a1d872c1eeb086d030`.
Extract its Core and full datasets into `example/windows/xray/`, retaining the
compatible `tun2socks.exe` and `wintun.dll` already supplied there.

For ordinary profiles without these managed services, the separate official
runtime is also supported. Its checksum below identifies the upstream archive;
it does not identify the managed r2 executable or attest its listener fix:

1. **Download the official Xray-core v26.10.31 release**:
   - Visit: https://github.com/XTLS/Xray-core/releases/tag/v26.10.31
   - Download `Xray-windows-64.zip`
   - Verify the x64 archive SHA-256: `2e04a9995a6f2ad1b28c0bb25c708ecb2695e43a1c9c7889c4b6ac2b48cf7a6a`

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

