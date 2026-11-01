# XDRIVE S3 and Google Drive

## Account-free local acceptance

The repository includes a temporary S3 API simulator. From the repository root:

```sh
python3 tool/xdrive_s3_fixture.py --case-dir build/xdrive-local-01 --seconds 180
```

It binds only `127.0.0.1`, stores at most 32 MiB in memory, checks SigV4 and
automatically closes after three minutes. The new private `ready.json` contains
its port and synthetic test settings. Choose a fresh case directory for each
run. Objects disappear when the server stops.

An Android emulator can use a task-owned `adb reverse` mapping to this port.
Both Xray peers then run inside Android; the Mac only serves the HTTP fixture.
No host VPN, DNS or routing setting needs to change. Use path-style S3 and a
`remoteFolder` under `acceptance/` on both peers. This service implements the
bounded subset needed by the tests, including object CRUD and paged prefix
listing; it is a development fixture.

Actions also runs two real Core instances through this independent service and
checks application bytes in both directions. Google Drive tests simulate OAuth
and the files API, checking token fields, bearer authentication, data transfer
and cancellation. These tests need no registrations or cloud accounts; actual
cloud service availability, quotas and negotiated cloud TLS remain separate.

## Cloud configuration

[s3.json](s3.json) and [google-drive.json](google-drive.json) are complete client
configuration templates for Xray Core 26.10.29. They contain placeholders, not
working accounts. Both peers need compatible application protocol settings and
matching storage details. XDRIVE requires VLESS Encryption and client Mux, even
when the cloud endpoint already uses HTTPS. `encryption: "none"` is invalid for
this transport. These templates use VLESS without Vision.

Generate a matching pair with `xray vlessenc` on the server or test runtime.
Use the generated client `encryption` value for `XDRIVE_VLESS_ENCRYPTION` and
the paired server `decryption` value on the other peer. A UUID, a cloud secret
or a TLS certificate cannot substitute for this pair. Keep Mux enabled with
nonnegative concurrency values; XDRIVE does not support Vision `flow` or
`xudpProxyUDP443: "skip"`.

Replace every `${NAME}` string through your application's configuration code
before importing. Xray does **not** expand these placeholders or read cloud
secrets from environment variables automatically. Build the JSON with a JSON
encoder so quotes and backslashes in credentials remain intact. Keep the
rendered configuration outside version control and public artifacts; never
include credentials in logs, screenshots or bug reports.

| Template | Values to provide |
| --- | --- |
| Both | `XDRIVE_VLESS_UUID`: the peer's VLESS user ID; `XDRIVE_VLESS_ENCRYPTION`: the matching generated client encryption value |
| S3 | `XDRIVE_S3_HOST`, `XDRIVE_S3_REGION`, `XDRIVE_S3_BUCKET`, `XDRIVE_S3_PREFIX`, `XDRIVE_S3_ACCESS_KEY_ID`, `XDRIVE_S3_SECRET_ACCESS_KEY` |
| Google Drive | `XDRIVE_GOOGLE_FOLDER_ID`, `XDRIVE_GOOGLE_CLIENT_ID`, `XDRIVE_GOOGLE_CLIENT_SECRET`, `XDRIVE_GOOGLE_REFRESH_TOKEN` |

The S3 template uses an HTTPS endpoint and path-style bucket addressing. An
optional third `secrets` item is the S3 session token. With `pathStyle: false`,
the physical hostname becomes `bucket.endpoint-host`; it must be a DNS hostname.
`remoteFolder` is an object prefix for S3 or a folder ID for Google Drive, not a
local filesystem path. The Google secrets order is client ID, client secret,
refresh token. `google-drive` is the current service name; `Google Drive` remains
an upstream deprecated alias.

The logical VLESS `settings.address` is unused by this transport. The plugin
prepares the S3 service endpoint, or Google's `oauth2.googleapis.com` and
`www.googleapis.com`, for the existing protected socket/bootstrap path. The
original cloud URL, signing authority, TLS settings and credentials are retained.
An optional `streamSettings.address`/`port` changes the physical socket target
for fronting; it does not change the service request authority. Omit it unless
your deployment deliberately provides that fronting service.

## Native runtime requirement

XDRIVE admission requires the managed service lifetime patch as well as Core
26.10.29. The original public 26.10.29 runtime, the earlier r2 storage-only capability,
and custom runtimes without worker ownership are refused for active XDRIVE,
before replacing a running session.
Updating only the Flutter package or checking the Core version is insufficient.

| Platform | Required runtime capability |
| --- | --- |
| Android, Windows | `native-services capabilities`: code zero, `managed_service_lifetimes` containing both storage bit `2` and worker bit `4` (`6`; `7` with GeoDAT) |
| iOS, macOS | `XdriveLifetimeCapability()` exactly `2`, exposed through `FLVlessCoreXdriveLifetimeCapability()` |

The producer builds require both managed lifetime patches. If GeoDAT scheduling
is also enabled, its separate capability is required too. Use the immutable
native artifact selected by the plugin's consumer pins; candidate artifact
publication and device qualification are tracked separately. These examples do
not announce a plugin release.

## Validation scope

The shared native preparation corpus covers S3 path-style/virtual-hosted
addressing, Google Drive, the deprecated alias, fronting, malformed settings and
old runtime refusal. Controlled Core tests use synthetic credentials and local
HTTP/OAuth services for storage operations, owner isolation and cancellation.
The local S3 relay case additionally connects two Core peers with a generated
VLESS Encryption pair and validates the complete application byte path. The
tests do not establish a working real cloud account or the whole
HTTP/3/ECH/redirect matrix. `local` and `template` XDRIVE services remain outside
the plugin's admitted service set.

Primary sources at the pinned Core revision:
[JSON configuration](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_method.go),
[VLESS Encryption and Mux requirements](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go),
[S3](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/xdrive/s3.go),
[Google Drive](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/xdrive/drive.go).
