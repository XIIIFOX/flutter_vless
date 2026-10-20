## 1.1.7

* Cancel obsolete capability-gated starts after Stop or a newer Start. Use the redacted `VPN_START_CANCELLED` error consistently across all four platform adapters.

* Add optional startVlessWithReport, immutable closed preparation reports and safe configuration failure locations. Keep older platform implementations working with an explicit unavailable report.

* Add optional `VpnRoutingOptions` to `startVless`, with capability checks, original inbound indices and an exact default outbound tag. Keep ordinary calls unchanged and reject proxy-only requests.
* Add optional `certificateAssetsDirectory` to start and profile-delay calls. Require the native capability before forwarding the directory so older implementations cannot silently ignore it.
* Add validated `VlessOptions.fromMap` for application-owned settings persistence.
* Preserve the active status listener when native option reconfiguration is rejected.
* Add all five typed Options blocks, quick-action/protection enums, validation, wire versioning and backward-compatible optional initialization.
* Add native capabilities, add-tile result and clear-quick-profile contracts; refuse unsupported custom options before subscribing to status and clean up failed initialization.

## 1.1.2

* Add optional `keychainAccessGroup`, `AndroidDnsPolicy` and DNS outbound selection.
* Check native capabilities before requesting new security guarantees; older/unsupported native backends fail explicitly.

* Added the cross-platform `getProviderDebugSnapshot` diagnostics contract.

## 1.1.1

* Added optional `geoAssetsDirectory` forwarding for Xray session startup and
  standalone server-delay probes.

## 1.1.0

* Added `VlessMethodChannelAdapter` for shared platform channel implementations.
* Added typed `VlessConnectionState` and robust `VlessStatus` event parsing.
* Added `VlessStatus` value semantics, diagnostics, and map conversion.

## 1.0.0

* initial 
