# Scheduled GeoDAT updates

`config.json` shows Core 26.10.29's full-config `geodata` section. Replace the
synthetic HTTPS URLs with your trusted compatible full datasets. No downloader
or new package is needed in the app; Core owns scheduling and transactions.

1. Choose a persistent, existing absolute directory. Put the initial complete
   `geoip.dat` and `geosite.dat` there **before** starting. Core requires every
   updater target to exist as a regular file; scheduling does not bootstrap a
   missing dataset. Custom `nested/caller.DAT` targets work too.
2. Pass its path as `geoAssetsDirectory` to `startVless` or
   `startVlessWithReport`. On iOS/macOS VPN, use a writable App Group directory
   accessible to both app and extension. App bundles are read-only. An explicit
   directory is used as-is and never populated with unrelated standard files.
3. Keep the directory and target parents readable/writable through Stop.
   Preparation tests owned temporary-file create/replace/delete operations;
   caller DAT bytes are never modified by this check. Windows VPN's default
   private runtime directory is temporary; use an explicit directory to retain
   downloaded data across sessions.
4. Use a runtime advertising GeoDAT lifetime capability 1. Earlier SDKs may
   report the same Core version but cannot safely cancel a scheduled download;
   the plugin rejects an active updater when this capability is absent.

```dart
await controller.startVlessWithReport(
  remark: 'Existing full profile with GeoDAT updates',
  config: yourFullConfigWithTheGeodataSection,
  geoAssetsDirectory: writableSharedDataDirectory,
);
```

The `outbound` value selects a case-sensitive existing outbound tag for asset
requests. Preserve your full profile and its routing; the example uses `direct`
only to demonstrate the configuration shape.

Core permits at most 100 scheduled assets, case-insensitive `.dat` extensions,
HTTPS URLs, and constant `@every` intervals of at least one minute. Standard
five-field cron and its supported descriptors/timezones are validated by Core.
Omit `cron` or set it to `null` to disable scheduling. A schedule with no assets
only reloads existing data and does not need a writable root.

Each response body is limited to 256 MiB by Core, including responses without
Content-Length. This fixed limit cannot be raised through plugin options. The
plugin preserves unknown full-config fields and delegates full cron/file/data
validation to Core rather than implementing another update engine.

Core stages downloads beside the target, swaps the complete set, rolls back a
failed replacement/reload, and removes its staging/backup files. The managed
runtime cancels its own downloader before waiting for scheduled jobs on Stop.
Android seeds bundled full GeoDAT only when missing, using atomic create-only
publication; recovery never replaces a downloaded or caller-managed dataset.
The project's existing full datasets are retained; no lite replacement occurs.

Sources: [JSON configuration](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/geodata.go),
[scheduler/lifecycle](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/geodata/geodata.go),
[download/transaction limits](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/geodata/download.go).

Before enabling automatic updates:

- Confirm GeoDAT capability 1 (CLI `native-services capabilities` has bit 0).
- Seed the initial compatible full datasets and select their writable root.
- Check valid/invalid schedules, custom targets, and the preparation error path.
- Verify bounded Stop during a tiny controlled update, preserving old files and
  leaving no staging/backup files after cancellation or rollback.
- Test the updated app/runtime together on the target devices before publishing.
