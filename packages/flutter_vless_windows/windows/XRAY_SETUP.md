EXPERIMENTAL

# Xray Integration Setup for Windows

Provide Xray-core alongside the application; the plugin does not download it.

## Installation Steps

### 1. Download Xray-core

For flutter_vless 1.1.7, use the official Xray-core **v26.10.29** runtime:
- [Official v26.10.29 release](https://github.com/XTLS/Xray-core/releases/tag/v26.10.29)
- [Windows x64 archive](https://github.com/XTLS/Xray-core/releases/download/v26.10.29/Xray-windows-64.zip)
- Look for `Xray-windows-64.zip` or `Xray-windows-32.zip` depending on your system

The Windows x64 archive SHA-256 is
`fce33e81cccf50e7aab572b175519a50b5e0f9d2f5c8d1ed73012ea5c9ad4d58`.
This checksum applies only to the x64 archive. The upstream release includes
other architectures with their own checksums.

### 2. Extract Xray Executable

Extract the downloaded archive and locate `xray.exe`.

Keep compatible `geoip.dat` and `geosite.dat` files alongside `xray.exe` when
your configuration uses geodata. Existing explicit asset-directory options
continue to select caller-provided files.
The upstream archive now carries a lite GeoIP dataset. A profile using a list
such as `geoip:us` needs a compatible full dataset; updating the executable does
not require overwriting an existing caller-provided data directory.
This repository's Windows validation and example bundle retain the full project
GeoDAT from `android_runtime/xray_android/src/main/assets/` during the runtime update.

### 3. Place Xray Executable

The plugin searches these paths relative to the running application (in order):

1. `xray.exe`
2. `xray/xray.exe`
3. `data/flutter_assets/xray/xray.exe`
4. `data/flutter_assets/windows/xray/xray.exe`

Place the runtime in your built application's `xray/` directory. CWD, PATH,
AppData, parent directories and linked/reparse-point files are not searched.

### 4. Verify Installation

The plugin will automatically detect Xray when you start a connection. If Xray is not found, you'll see an error message in the console.

## Configuration

Xray requires a JSON configuration file. The plugin automatically:
- Validates the JSON configuration
- Creates a temporary configuration file
- Launches Xray with the configuration
- Monitors the Xray process
- Cleans up temporary files on exit

## API Access

The plugin uses Xray's built-in API (default: `127.0.0.1:10085`) for:
- Traffic statistics
- Delay measurement
- Version information

Make sure your Xray configuration includes the API settings:

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
  "stats": {},
  ...
}
```

## Troubleshooting

### Xray not found
- Ensure `xray.exe` is in one of the search locations
- Check file permissions
- Verify the executable is not corrupted

### API connection failed
- Check that Xray configuration includes API settings
- Verify API port (default: 10085) is not blocked
- Check Windows Firewall settings

### Process fails to start
- Ensure you have sufficient permissions
- Check Windows Event Viewer for errors
- Verify the JSON configuration is valid

## Modern C++ Features Used

This implementation uses modern C++17 features:
- `std::filesystem` for file system operations
- `std::optional` for nullable return values
- `std::unique_ptr` for automatic memory management
- `std::atomic` for thread-safe flags
- `std::future` and `std::async` for asynchronous operations
- RAII patterns for resource management

