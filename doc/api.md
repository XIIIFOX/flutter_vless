# API Contract

This document describes the app-facing Dart contract exposed by
`package:flutter_vless/flutter_vless.dart`.

Use this page when you need to know what a method expects, what it returns, and
which parts are platform-specific.

Exported Dart declarations include editor hover documentation. Complete the
platform setup before using VPN mode.

## Import

```dart
import 'package:flutter_vless/flutter_vless.dart';
```

## `FlutterVless`

`FlutterVless` is the app-facing controller for Xray/V2Ray proxy and
VPN/tunnel sessions.

Create one instance and keep it for the lifetime of the screen, service, or app
component that owns the connection.

Pass typed `VlessOptions` to the constructor for notification, quick access,
reconnect, protection and diagnostics settings. See [options and system
controls](options-and-system-controls.md) for defaults, platform availability,
host-extension setup and validation limits.

```dart
final flutterVless = FlutterVless(
  onStatusChanged: (status) {
    // Update app state from VlessStatus.
  },
);
```

## `initializeVless()`

Initializes the native backend and subscribes to status events.

```dart
await flutterVless.initializeVless(
  notificationIconResourceType: 'mipmap',
  notificationIconResourceName: 'ic_launcher',
  providerBundleIdentifier: 'com.example.myapp',
  groupIdentifier: 'group.com.example.myapp',
);
```

Parameters:

- `notificationIconResourceType`: Android notification resource type.
- `notificationIconResourceName`: Android notification resource name.
- `providerBundleIdentifier`: base app bundle id on iOS/macOS.
- `groupIdentifier`: Apple App Group shared by the app and Packet Tunnel
  extension.
- `keychainAccessGroup`: iOS shared Keychain group. The parameter can be omitted
  when `FlutterVlessKeychainAccessGroup` is set in Runner's Info.plist. VPN mode
  requires a group accessible to both targets: reuse their registered App Group
  or configure an optional dedicated Keychain group. `groupIdentifier` is not an
  automatic fallback. See [iOS setup](platform/ios.md#keychain-profile-migration).

Apple platforms append the Packet Tunnel extension suffix internally. Pass the
base app bundle id, not the extension bundle id.

## `requestPermission()`

Requests platform permission or profile state required for tunnel mode.

```dart
final allowed = await flutterVless.requestPermission();
```

Use it before VPN/tunnel startup. Proxy-only mode usually does not need it.

Platform notes:

- Android uses this path for VPN and notification permission flows.
- iOS and macOS depend on signing, App Groups, and Network Extension setup.
- Windows VPN requires administrator privileges. This call checks elevation;
  it does not elevate the application.

## `startVless()`

Starts an Xray-backed proxy-only or VPN/tunnel session.

```dart
await flutterVless.startVless(
  remark: parsed.remark,
  config: parsed.getFullConfiguration(),
  proxyOnly: false,
  geoAssetsDirectory: appGroupGeoDirectory,
);
```

Required parameters:

- `remark`: human-readable profile name used by native UI and notifications.
- `config`: JSON-encoded Xray configuration object.

Optional parameters:

- `blockedApps`: Android package names excluded from the VPN route.
- `bypassSubnets`: on macOS/Windows, IPv4 CIDRs become protected Core `direct`
  rules, with private system-DNS rules taking precedence; they do not create
  physical route exclusions. IPv6 bypass CIDRs are rejected. iOS VPN sessions
  reject non-empty values with `INCOMPATIBLE_ROUTING` before changing the
  current session. Use Xray `direct` rules on iOS; VPN protection is mandatory.
- `proxyOnly`: starts local proxy behavior without installing a VPN route.
- `geoAssetsDirectory`: existing absolute data directory on Android, iOS,
  macOS and Windows. Only files actually referenced by the profile are required;
  custom-only and asset-free directories need no unused standard datasets.
  Use an App Group directory for Apple VPN so the extension can read it. Keep
  files available through Stop/recovery; omit this parameter for bundled/default
  lookup. An explicit directory is not seeded with bundled files.
- `certificateAssetsDirectory`: existing absolute base for relative Core TLS
  certificate/key file references, independent of geodata. Absolute paths and
  inline certificates retain their meaning. Files remain caller-owned and must
  remain readable through recovery/reload; Apple VPN requires shared storage.
- `notificationDisconnectButtonName`: Android notification action label.
- `androidDnsPolicy`: `AndroidDnsPolicy.config` (default) sends private virtual
  resolver A/AAAA queries through the caller's Core DNS settings;
  `AndroidDnsPolicy.proxy` intentionally overrides system DNS through a selected
  proxy. The config policy preserves caller query strategy: `UseIPv4` produces
  AAAA NODATA intentionally. IPv6 payload capture is supported; IPv6-only
  underlay/NAT64 qualification is separate.
- `androidDnsProxyOutboundTag`: optional selected proxy tag, only with proxy DNS.
  Unsupported native backends reject explicitly requested new guarantees before
  starting or reconfiguring a session.
- `vpnRouting`: optional `VpnRoutingOptions` for one VPN session. Its
  `sourceInboundIndex` uses the original JSON's zero-based `inbounds` index and
  supplies that input's `inboundTag` context to VPN routing. It does not copy
  accounts, sniffing or other inbound settings. `defaultOutboundTag` selects the
  exact named outbound for unmatched VPN traffic; null/empty retains Core's
  default. Caller rules, imported listeners and private DNS/probe rules remain.
  Omit the whole option for ordinary startup; an explicit empty option still
  requires the routing factory. Proxy-only requests and unsupported runtimes
  fail before replacing the current session. The pinned published Android
  `26.10.31-protect2`, Apple `26.10.31-r2` and managed Windows `26.10.31-r2`
  runtimes supply the factory; the actual loaded artifact is checked. Update
  the copied iOS provider together with the plugin.

Traffic events use bytes for `upload`/`download` and bytes per second for
`uploadSpeed`/`downloadSpeed`. The plugin enables missing inbound statistics
defaults when it owns Core's API, including full profiles with caller policy
levels or `system: {}`. Explicit disabled values and caller API settings are
preserved; Core-based counters can be unavailable in those cases. Apple VPN
sessions use packet-worker counters. First samples and counter resets establish
a new speed baseline rather than producing a spike or a negative rate.

Validation:

`startVless()` validates `config` before forwarding it to native code. It throws
`ArgumentError` when the string is not valid JSON, is not a JSON object, has an
invalid `inbounds` section, or does not contain at least one valid outbound.
Core-style JSON comments and a leading BOM are accepted; trailing documents
remain invalid. Native semantic/preflight errors are reported separately.
Completion admits a start request; observe status for forwarding readiness.

## `startVlessWithReport()`

This optional alternative accepts the same arguments and starts the same
session as `startVless()`. Existing `Future<void>` callers remain supported.

```dart
final report = await flutterVless.startVlessWithReport(
  remark: parsed.remark,
  config: parsed.getFullConfiguration(),
);
// Only closed codes and enums; no profile values or file paths.
final safeSummary = report.toMap();
```

The report belongs to that invocation. `coreCheck: passed` means Core accepted
the candidate covered by `scope`; it does not mean the connection is ready or
has internet access. `host` covers preparation in the application process.
Apple VPN reports use this scope because the extension prepares another final
configuration later. Windows proxy-only checks also use `host`, because the
checker normalizes a separate input. `runtimeFinal` identifies the immutable
final candidate used by the native runtime. Android returns after candidate
admission, before asynchronous forwarding readiness. A runtime or older platform
implementation without this contract returns `unavailable`, never a guessed
successful check.

`changes` lists instrumented edits to known schema fields: certificate file
references, generated private listeners, managed system DNS guards, private
logging, bound endpoint/listener environment references, and shared Dart legacy
TLS/transport cleanup. Only actual edits are reported. Reading an environment
port for reservation alone is not a binding edit. Opaque data, arbitrary field
names, values, tags, addresses, paths, sizes and configuration fingerprints are
not included. This is a safe summary of known operations, not a general JSON
diff or a list of every Core default. Host reports omit provider-only changes.

Native rejection still throws `PlatformException`. Read closed locations with
`VlessConfigurationFailure.fromDetails(error.details)` rather than parsing Core
text. Where known, native backends distinguish preparation, Core checking,
persistence and startup; Apple also retains its safe Decode/Build location.
Unknown native details are ignored. A later startup failure can occur after
admission: this report does not promise rollback to the previous session.

Preparation reports are optional API results. The example displays connection
errors without adding a persistent report panel.

An Apple Core version string alone does not identify the loaded bridge ABI.
Use capabilities from the actual artifact; the pinned published r2 SDKs include
the Check/routing interfaces used by the adapters. A missing
Check ABI yields `coreCheck: unavailable`; an explicit native routing request
still requires native routing capability and fails closed when it is absent.
An Apple VPN report covers `host` preparation, not final provider-report
delivery or a network guarantee. See [Apple readiness and DNS](apple-readiness-and-dns.md)
for the distinction between forwarding readiness and remote reachability.

## `stopVless()`

Stops the active proxy or VPN/tunnel session.

On iOS, this disables automatic recovery before stopping the tunnel. If saving
that change fails, the call reports `VPN_STOP_ERROR` and retains protection;
the app can retry the explicit stop.

```dart
await flutterVless.stopVless();
```

Platform implementations also use this call to clean up foreground services,
system proxy settings, local Xray processes, and tunnel state.

## `getServerDelay()`

Measures delay for a provided Xray config without relying on an active session.

```dart
final delayMs = await flutterVless.getServerDelay(
  config: parsed.getFullConfiguration(),
  url: 'https://google.com/generate_204',
  geoAssetsDirectory: appGroupGeoDirectory,
);
```

The config is validated with the same validator used by `startVless()`.
Android and Apple use `geoAssetsDirectory` and `certificateAssetsDirectory`
with the same lookup rules as startup. The temporary measurement does not take
over an active VPN; Apple/Android omit imported API/metrics listeners for this
isolated probe. Windows standalone profile delay is unsupported and returns
`-1`; Apple also refuses to replace an active app-process proxy-only runtime.
Apple `+local` DNS preparation without a physical-path snapshot remains an
explicit unsupported case. A failed measurement is not a successful Core check.

## `getConnectedServerDelay()`

Measures delay through the currently active runtime.

```dart
final delayMs = await flutterVless.getConnectedServerDelay();
```

Use this after `startVless()` when the app needs a health signal for the active
profile. Choose `url:` according to the caller's routing policy. Apple readiness
means the current local packet worker and authenticated listener are ready;
an intentionally blocked external URL can fail without disconnecting that
runtime. Delay failures do not prove that every route or the server is unusable.

## Capabilities and quick access

`getCapabilities()` returns the typed options, system-control surfaces,
protection features and OS-managed Always-on/lockdown state of the loaded
backend. Required native routing/asset/service capabilities are checked
internally when their corresponding startup parameters are supplied; the
public `VlessCapabilities` model has no routing or preparation-report boolean.
Preparation reports express unsupported reporting with an unavailable scope.
Capabilities describe implementation availability, not whether a remote server
is reachable. `requestAddQuickTile()` requests Android's supported foreground
add-tile flow and returns its typed result. `clearQuickAccessProfile()` removes
the retained quick-access authorization/configuration while leaving an active
session running. See [the platform matrix](options-and-system-controls.md).

## `getCoreVersion()`

Returns the Xray core version reported by the active platform backend.

```dart
final version = await flutterVless.getCoreVersion();
```

The exact value can differ by platform package, release version, or externally
supplied Windows `xray.exe`.

## `getProviderDebugSnapshot()`

Returns bounded, human-readable diagnostics for the active or most recent VPN
or proxy-only runtime session. Standalone `getServerDelay()` probes are
excluded so they do not overwrite connection diagnostics.

```dart
final diagnostics = await flutterVless.getProviderDebugSnapshot();
```

The contents are intentionally platform-specific:

- Apple includes bounded provider lifecycle/worker metadata and safe app-process
  events; raw HEV contents and arbitrary Xray callback text are omitted.
- Android includes safe service/runtime stages, counters and exit codes.
- Windows includes safe native lifecycle and preparation events; raw child
  stdout/stderr is drained instead of exposed.

The snapshot remains available after a normal stop or startup failure.
In-process collectors reset when a new session begins; persisted Apple Packet
Tunnel tails can contain timestamped entries from an earlier extension run. It
returns an empty string before any diagnostics have been recorded, or when
collection is disabled. `DiagnosticsOptions` bounds collection and disabling it
clears retained buffers. Treat the text as support data, not a stable parser
format; current collectors omit raw configs, credentials and arbitrary native
error text. Let users review support attachments before sharing them.

## `parse()`

Parses one supported input into a `FlutterVlessURL`.

```dart
final parsed = FlutterVless.parse(input);
final config = parsed.getFullConfiguration();
```

Supported input:

- `vmess://`
- `vless://`
- `trojan://`
- `ss://`
- `socks://`
- `hysteria2://`
- `hy2://`
- raw Xray JSON
- base64 subscription payloads
- Clash YAML
- sing-box JSON

Clash YAML and sing-box JSON imports can also produce generated Xray configs
for supported profile objects such as WireGuard, Hysteria2, and HTTP proxy
outbounds.

If a subscription contains multiple supported profiles, `parse()` returns the
first one. Use `parseMany()` to keep the full list.

## `parseMany()`

Parses every supported profile from a subscription-style payload.

```dart
final profiles = FlutterVless.parseMany(subscriptionText);
```

Unsupported or not-yet-mapped protocols are skipped intentionally instead of
being converted into broken Xray JSON.

## `parseFromURL()`

Parses one share URL.

```dart
final parsed = FlutterVless.parseFromURL(vlessLink);
```

Use this only when the input is already known to be one of:

- `vmess://`
- `vless://`
- `trojan://`
- `ss://`
- `socks://`
- `hysteria2://`
- `hy2://`

For clipboard imports, subscriptions, raw JSON, Clash YAML, or sing-box JSON,
prefer `parse()` or `parseMany()`.

## `VlessStatus`

`VlessStatus` is the stable Dart model for runtime status events.

Fields:

- `duration`: seconds since session start.
- `uploadSpeed`: current upload speed reported by the platform.
- `downloadSpeed`: current download speed reported by the platform.
- `upload`: total uploaded bytes.
- `download`: total downloaded bytes.
- `state`: raw native state string.
- `connectionState`: normalized `VlessConnectionState`.

Example:

```dart
void handleStatus(VlessStatus status) {
  switch (status.connectionState) {
    case VlessConnectionState.connected:
      // Show connected UI.
      break;
    case VlessConnectionState.connecting:
      // Show progress UI.
      break;
    case VlessConnectionState.disconnected:
    case VlessConnectionState.disconnecting:
    case VlessConnectionState.unknown:
      // Show idle or fallback UI.
      break;
  }
}
```
