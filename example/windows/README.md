# Windows Example Setup

This directory contains the Windows-specific files for the flutter_vless example.

## Xray Setup

Use the [managed Core 26.11.9-r1 pre-release](https://github.com/XIIIFOX/flutter_vless/releases/tag/xray-windows-v26.11.9-r1)
for native routing and XDRIVE/GeoDAT services. The archive SHA-256 is
`81df36b77068fa7cf49f07311879a02d23e5d6bde9606c7d6cd024a5a01b6264`.
Its AMD64 `xray.exe` SHA-256 is
`8385a665b77fbe2c0ce31972668e520f36cd453d895f98689ba3435ecca1699e`.

Ordinary profiles without managed-service requirements can also use the
[official Xray-core 26.11.9 archive](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9).
Official archive SHA-256: `1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d`.
This is a different artifact from the managed companion.

From the repository root on Windows, install the checksum-pinned managed
Core with `py -3 tool/windows/install_published_runtime.py --directory example/windows/xray`.
Keep the Core and compatible helpers in this source staging directory:

```text
example/windows/xray/
  xray.exe
  tun2socks.exe
  wintun.dll
  geoip.dat
  geosite.dat
```

Datasets are required when referenced by the profile. The upstream GeoIP file is
lite; country rules such as `geoip:us` may require the project's compatible full
datasets or an explicit caller asset root. Keep `wintun.dll` beside tun2socks.
For manual builds, copy the runtime/helper files into the built Runner's `xray/`
directory. Runtime discovery is relative to the application, not CWD or AppData.

## Running the Example

```bash
cd example
flutter pub get
flutter run -d windows
# Or: flutter build windows
```

Run the application as Administrator for VPN mode. Proxy-only mode does not use
Wintun or machine-wide VPN protection.

## Notes

- The plugin does not download native executables automatically.
- Confirm both upload/download counters and real traffic after connecting.
- Test caller routing and DNS policy, then await Stop and verify cleanup.

## Troubleshooting

If `xray.exe` is not found, check its name and the built app's runtime directory.
For permission errors, confirm elevation and that security software permits the
chosen executable. For connection errors, inspect bounded diagnostics and
verify the configuration and remote endpoint. See the
[Windows platform guide](../../doc/platform/windows.md) for protection and recovery.
