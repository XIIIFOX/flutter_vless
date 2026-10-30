# XDRIVE S3 and Google Drive

[s3.json](s3.json) and [google-drive.json](google-drive.json) are complete client
configuration templates for Xray Core 26.10.29. They contain placeholders, not
working accounts. Both peers need compatible application protocol settings and
matching storage details. These templates use VLESS without Vision.

Replace every `${NAME}` string through your application's configuration code
before importing. Xray does **not** expand these placeholders or read cloud
secrets from environment variables automatically. Build the JSON with a JSON
encoder so quotes and backslashes in credentials remain intact. Keep the
rendered configuration outside version control and public artifacts; never
include credentials in logs, screenshots or bug reports.

| Template | Values to provide |
| --- | --- |
| Both | `XDRIVE_VLESS_UUID`: the peer's VLESS user ID |
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
26.10.29. The original public 26.10.29 runtime and custom runtimes without the
capability are refused for active XDRIVE, before replacing a running session.
Updating only the Flutter package or checking the Core version is insufficient.

| Platform | Required runtime capability |
| --- | --- |
| Android, Windows | `native-services capabilities`: code zero, `managed_service_lifetimes` containing bit `2` |
| iOS, macOS | `XdriveLifetimeCapability()` exactly `1`, exposed through `FLVlessCoreXdriveLifetimeCapability()` |

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
Those tests do not establish a working real cloud account, a complete relay
between peers, or the whole HTTP/3/ECH/redirect matrix. `local` and `template`
XDRIVE services remain outside the plugin's admitted service set.

Primary sources at the pinned Core revision:
[JSON configuration](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_method.go),
[S3](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/xdrive/s3.go),
[Google Drive](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/xdrive/drive.go).
