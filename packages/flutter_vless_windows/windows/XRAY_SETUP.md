EXPERIMENTAL

# Xray Integration Setup for Windows

This plugin requires Xray-core version 25.10.15 or later to be available on the system.

## Installation Steps

### 1. Download Xray-core

For flutter_vless 1.1.7, use Xray-core **v26.10.17** (upstream pre-release):
- [Official v26.10.17 release](https://github.com/XTLS/Xray-core/releases/tag/v26.10.17)
- [Windows x64 archive](https://github.com/XTLS/Xray-core/releases/download/v26.10.17/Xray-windows-64.zip)
- Look for `Xray-windows-64.zip` or `Xray-windows-32.zip` depending on your system

### 2. Extract Xray Executable

Extract the downloaded archive and locate `xray.exe`.

//TODO: auto download xray
//TODO: add about geoip.dat files for Windows
//TODO: add release notes about assets folder info

### 3. Place Xray Executable

The plugin will automatically search for `xray.exe` in the following locations (in order):

1. Current working directory: `./xray.exe`
2. Current directory subfolder: `./xray/xray.exe`
3. Parent directory: `../xray.exe`
4. Parent directory subfolder: `../xray/xray.exe`
5. AppData folder: `%APPDATA%/flutter_vless/xray.exe`
6. Program Files: `%PROGRAMFILES%/Xray/xray.exe`

**Recommended location**: Place `xray.exe` in your Flutter app's directory or in `%APPDATA%/flutter_vless/`

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

