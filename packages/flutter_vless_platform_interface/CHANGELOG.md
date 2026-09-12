## 1.2.0

* Add optional `keychainAccessGroup`, `AndroidDnsPolicy` and DNS outbound selection.
* Check native capabilities before requesting new security guarantees; older/unsupported native backends fail explicitly.

## 1.1.2 (Unreleased)

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
