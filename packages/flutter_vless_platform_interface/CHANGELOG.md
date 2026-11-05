## 1.1.7

* Add typed Notification, Quick Access, Reconnect, Protection and Diagnostics options, action/protection enums and validated `VlessOptions.fromMap` restoration.
* Add native capabilities, add-tile results and clear-quick-profile contracts with backward-compatible optional initialization and explicit rejection of unsupported custom guarantees.
* Add `VpnRoutingOptions` for original-inbound context and explicit default outbound selection; reject proxy-only use.
* Add `certificateAssetsDirectory` for startup/profile-delay and immutable optional per-start preparation reports with typed edit codes and safe failure stages.
* Cancel obsolete capability-gated starts on Stop, a newer start or successful options reconfiguration. Use the redacted `VPN_START_CANCELLED` error and preserve the active status listener when native reconfiguration fails.
* Document public constructors, fields, enum values, defaults, platform limits and backend contracts for editor assistance.

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
