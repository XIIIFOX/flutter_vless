// Copyright (c) 2024-2026 13FOX Studio / tfox.dev.
// SPDX-License-Identifier: MIT

import 'dart:convert';

import 'package:flutter_vless/url/hysteria2.dart';
import 'package:flutter_vless/url/shadowsocks.dart';
import 'package:flutter_vless/url/socks.dart';
import 'package:flutter_vless/url/subscription.dart';
import 'package:flutter_vless/url/trojan.dart';
import 'package:flutter_vless/url/url.dart';
import 'package:flutter_vless/url/vless.dart';
import 'package:flutter_vless/url/vmess.dart';
import 'package:flutter_vless/url/xray_config.dart';
import 'package:flutter_vless/url/xray_config_model.dart';
import 'package:flutter_vless/url/xray_config_validator.dart';
import 'package:flutter_vless_platform_interface/flutter_vless_platform_interface.dart';

export 'package:flutter_vless_platform_interface/flutter_vless_platform_interface.dart';
export 'url/url.dart';

/// App-facing controller for Xray/V2Ray proxy and VPN tunnel sessions.
///
/// Use this class to parse VLESS, VMESS, Trojan, Shadowsocks, SOCKS,
/// subscription, Clash, sing-box, or raw Xray input into an Xray JSON config,
/// initialize the native platform backend, start or stop the local runtime, and
/// observe traffic/status updates through [onStatusChanged].
///
/// The class intentionally keeps the generated Xray JSON visible. That makes
/// simple proxy/VPN flows easy while still allowing advanced routing and
/// transport configuration when an app needs to edit the config before calling
/// [startVless].
class FlutterVless {
  /// Creates a controller and registers the callback used for status updates.
  ///
  /// Call [initializeVless] before starting a connection so the platform
  /// implementation can attach its method channel and status event stream.
  /// [options] is validated during initialization. To apply replacement options
  /// on Apple, await [stopVless] before initializing the replacement controller.
  FlutterVless(
      {required this.onStatusChanged, this.options = const VlessOptions()});

  /// Native presentation, quick controls, recovery and protection preferences.
  final VlessOptions options;

  static const XrayConfigValidator _configValidator = XrayConfigValidator();

  /// Called whenever the active platform backend emits a new runtime status.
  ///
  /// Status values include elapsed duration, upload/download totals,
  /// upload/download speed, the raw native state string, and the normalized
  /// [VlessStatus.connectionState] enum.
  final void Function(VlessStatus status) onStatusChanged;

  /// Requests permission required by the current platform before tunnel mode.
  ///
  /// Android uses this for VPN/notification permission flows. iOS and macOS use
  /// their Network Extension profile/signing flow. Proxy-only mode usually does
  /// not need this call because it does not install a VPN route.
  ///
  /// Returns `true` when the platform reports that startup may continue.
  /// This does not validate a profile, prove connectivity or replace the Apple
  /// extension/signing setup required by the host application.
  Future<bool> requestPermission() {
    return VlessPlatform.instance.requestPermission();
  }

  /// Initializes the native backend and subscribes to status events.
  ///
  /// [notificationIconResourceType] and [notificationIconResourceName] are used
  /// by Android foreground-service notifications.
  ///
  /// [providerBundleIdentifier] is the base app bundle identifier on Apple
  /// platforms, for example `com.example.myapp`. The iOS/macOS implementations
  /// append the packet tunnel suffix internally when they need the extension
  /// identifier.
  ///
  /// [groupIdentifier] is the Apple App Group shared by the app and Packet
  /// Tunnel extension, for example `group.com.example.myapp`.
  /// [keychainAccessGroup] selects the shared iOS Keychain group. Reuse the
  /// registered App Group or configure an optional dedicated Keychain group.
  /// Omit this parameter to use `FlutterVlessKeychainAccessGroup` in Info.plist;
  /// [groupIdentifier] is not an automatic fallback. Shared Keychain access is
  /// required for iOS VPN mode, but not proxy-only mode.
  ///
  /// Call this once during app startup, before [startVless],
  /// [getConnectedServerDelay], or [getCoreVersion].
  /// Invalid [options] throw [ArgumentError]; unsupported requested native
  /// capabilities or invalid Apple integration settings fail explicitly.
  /// Legacy notification arguments override the corresponding option fields.
  Future<void> initializeVless({
    String? notificationIconResourceType,
    String? notificationIconResourceName,
    String providerBundleIdentifier = "",
    String groupIdentifier = "",
    String? keychainAccessGroup,
  }) async {
    options.validate();
    final effectiveOptions = VlessOptions(
      notification: NotificationOptions(
        iconResourceType: notificationIconResourceType ??
            options.notification.iconResourceType,
        iconResourceName: notificationIconResourceName ??
            options.notification.iconResourceName,
        buttonLabel: options.notification.buttonLabel,
        action: options.notification.action,
      ),
      quickAccess: options.quickAccess,
      reconnect: options.reconnect,
      protection: options.protection,
      diagnostics: options.diagnostics,
    );
    effectiveOptions.validate();
    await VlessPlatform.instance.initializeVless(
      onStatusChanged: onStatusChanged,
      notificationIconResourceType:
          notificationIconResourceType ?? options.notification.iconResourceType,
      notificationIconResourceName:
          notificationIconResourceName ?? options.notification.iconResourceName,
      providerBundleIdentifier: providerBundleIdentifier,
      groupIdentifier: groupIdentifier,
      keychainAccessGroup: keychainAccessGroup,
      options: options.isDefault ? null : effectiveOptions,
    );
  }

  /// Starts an Xray-backed proxy or VPN/tunnel session.
  ///
  /// [remark] is a human-readable profile name used by native notifications,
  /// logs, and platform UI where available.
  ///
  /// [config] must be a JSON-encoded Xray configuration object. The string is
  /// validated before the native layer sees it; an [ArgumentError] is thrown
  /// when the JSON is malformed, is not an object, has invalid `inbounds`, or
  /// has no valid `outbounds`.
  ///
  /// [blockedApps] is Android-specific and contains package names that should
  /// be excluded from the VPN route.
  ///
  /// [bypassSubnets] selects destination subnets that may bypass the proxy.
  /// On macOS and Windows VPN sessions, IPv4 CIDRs become Xray `direct` rules;
  /// private system-DNS protection takes precedence. They do not create
  /// physical route exclusions. IPv6 bypass CIDRs are rejected.
  /// iOS VPN sessions reject non-empty system route exclusions. Use Xray
  /// `direct` routing rules to bypass selected destinations while retaining
  /// mandatory traffic protection during connection and recovery.
  ///
  /// Set [proxyOnly] to `true` when the app should start local Xray proxy
  /// behavior without installing a system VPN or Packet Tunnel route.
  ///
  /// [geoAssetsDirectory] selects an existing absolute data directory for this
  /// session. Core validates the files referenced by the config, including
  /// custom `ext:` rules; standard geodata files are optional when unused.
  /// Apple VPN extensions need a readable App Group directory. Keep the files
  /// available until Stop completes. Omit it for bundled/default lookup.
  /// Scheduled GeoDAT downloads additionally require existing `.dat` targets
  /// and writable parent directories for atomic replacement. Apple downloads
  /// require an explicit writable App Group directory. Use a runtime with
  /// GeoDAT lifetime capability 1; the Core version alone is insufficient.
  /// Core owns HTTPS downloads, cron validation and the 256 MiB decoded-asset
  /// limit, including gzip input.
  ///
  /// [certificateAssetsDirectory] resolves relative TLS `certificateFile` and
  /// `keyFile` paths against an existing absolute directory, independently of
  /// geodata. Absolute paths and inline material keep their meaning. Files must
  /// remain readable through Stop, including certificate reload and recovery.
  /// Apple VPN files need App Group access. Omit it for Core's default lookup.
  ///
  /// [notificationDisconnectButtonName] overrides the Android foreground
  /// notification action label for this start. The action itself is selected by
  /// [NotificationOptions.action].
  /// [androidDnsPolicy] defaults to preserving the supplied config. The `proxy`
  /// policy protects virtual system DNS through [androidDnsProxyOutboundTag]
  /// or the unambiguous proxy outbound; unsupported backends reject it.
  /// [vpnRouting] selects the original inbound's tag context and/or a
  /// default VPN outbound without rewriting caller rules. It requires a runtime
  /// built with VPN routing support and cannot be used in proxy-only mode.
  ///
  /// Completion means the platform accepted startup; observe [onStatusChanged]
  /// for runtime state. On Apple, CONNECTED proves native worker/listener
  /// readiness. Use [getConnectedServerDelay] with an allowed URL to check its
  /// actual network path.
  ///
  /// A start superseded during capability checks by Stop, reinitialization or
  /// a newer start throws a native-channel error with code `VPN_START_CANCELLED`.
  /// Native preparation/start errors propagate; unsupported opt-in features
  /// throw [UnsupportedError]. An obsolete completion must not clear a newer
  /// session's UI state.
  Future<void> startVless({
    required String remark,
    required String config,
    List<String>? blockedApps,
    List<String>? bypassSubnets,
    bool proxyOnly = false,
    String? geoAssetsDirectory,
    String? certificateAssetsDirectory,
    AndroidDnsPolicy androidDnsPolicy = AndroidDnsPolicy.config,
    String? androidDnsProxyOutboundTag,
    VpnRoutingOptions? vpnRouting,
    String? notificationDisconnectButtonName,
  }) async {
    final normalizedConfig = _normalizeConfigString(config);
    await VlessPlatform.instance.startVless(
      remark: remark,
      config: normalizedConfig,
      blockedApps: blockedApps,
      proxyOnly: proxyOnly,
      bypassSubnets: bypassSubnets,
      geoAssetsDirectory: geoAssetsDirectory,
      certificateAssetsDirectory: certificateAssetsDirectory,
      androidDnsPolicy: androidDnsPolicy,
      androidDnsProxyOutboundTag: androidDnsProxyOutboundTag,
      vpnRouting: vpnRouting,
      notificationDisconnectButtonName:
          notificationDisconnectButtonName ?? options.notification.buttonLabel,
    );
  }

  /// Starts with the same validation and routing behavior as [startVless],
  /// returning a safe per-invocation preparation report. Legacy native backends
  /// report unavailability. A passed Core check is not network readiness.
  ///
  /// All parameters and startup errors follow [startVless]. The report contains
  /// closed operation codes without profile values. Native failures still
  /// complete the future with an error; use
  /// [VlessConfigurationFailure.fromDetails] on native exception details to
  /// extract a supported failure stage and optional entry index.
  Future<VlessPreparationReport> startVlessWithReport({
    required String remark,
    required String config,
    List<String>? blockedApps,
    List<String>? bypassSubnets,
    bool proxyOnly = false,
    String? geoAssetsDirectory,
    String? certificateAssetsDirectory,
    AndroidDnsPolicy androidDnsPolicy = AndroidDnsPolicy.config,
    String? androidDnsProxyOutboundTag,
    VpnRoutingOptions? vpnRouting,
    String? notificationDisconnectButtonName,
  }) async {
    final changes = <VlessPreparationChange>{};
    final decoded = _configValidator.validateJsonString(config);
    final normalizedConfig = jsonEncode(
        sanitizeXrayJson(decoded, preserveStructure: true, onChange: (change) {
      changes.add(switch (change) {
        XrayJsonChange.tlsOverrideRemoved =>
          VlessPreparationChange.tlsOverrideRemoved,
        XrayJsonChange.streamAliasNormalized =>
          VlessPreparationChange.streamAliasNormalized,
      });
    }));

    final report = await VlessPlatform.instance.startVlessWithReport(
      remark: remark,
      config: normalizedConfig,
      blockedApps: blockedApps,
      proxyOnly: proxyOnly,
      bypassSubnets: bypassSubnets,
      geoAssetsDirectory: geoAssetsDirectory,
      certificateAssetsDirectory: certificateAssetsDirectory,
      androidDnsPolicy: androidDnsPolicy,
      androidDnsProxyOutboundTag: androidDnsProxyOutboundTag,
      vpnRouting: vpnRouting,
      notificationDisconnectButtonName:
          notificationDisconnectButtonName ?? options.notification.buttonLabel,
    );
    return report.withChanges(changes);
  }

  /// Returns native feature support and current OS Always-on/lockdown state.
  ///
  /// Inspect supported quick-control surfaces before presenting their UI.
  /// Older backends can return conservative defaults; the Core version string
  /// alone does not prove that a particular managed capability is implemented.
  Future<VlessCapabilities> getCapabilities() =>
      VlessPlatform.instance.getCapabilities();

  /// Asks Android 13+ to show its user-controlled Add Tile dialog.
  ///
  /// Returns [QuickTileAddResult.unsupported] when the loaded backend cannot
  /// request this surface. Available, enabled quick access and a foreground
  /// Activity are required on supported Android versions; the user controls
  /// whether the tile is added.
  Future<QuickTileAddResult> requestAddQuickTile() =>
      VlessPlatform.instance.requestAddQuickTile();

  /// Forgets the retained quick-control profile, for example on account logout.
  ///
  /// The active session is stopped separately with [stopVless]. Reinitializing
  /// the app does not restore the forgotten quick profile; connect explicitly
  /// again. Throws [UnsupportedError] on a backend without profile storage.
  Future<void> clearQuickAccessProfile() =>
      VlessPlatform.instance.clearQuickAccessProfile();

  /// Stops the active proxy or VPN/tunnel session.
  ///
  /// Platform implementations also use this call to clean up foreground
  /// services, system proxy settings, local Xray processes, and tunnel state.
  /// Await successful completion before replacing a live Apple profile/options
  /// or reinstalling its app. A timeout or preference error does not confirm
  /// disconnection. Android OS-managed Always-on can reject this request with
  /// `ALWAYS_ON_MANAGED` until the owner disables that system policy.
  Future<void> stopVless() async {
    await VlessPlatform.instance.stopVless();
  }

  /// Measures delay for an Xray config without relying on an active session.
  ///
  /// [config] is validated with the same JSON validator used by [startVless].
  /// [url] should point to a lightweight HTTP(S) endpoint allowed by the
  /// profile's DNS and routing, such as `https://google.com/generate_204`.
  ///
  /// Returns delay in milliseconds, or the platform-specific failure value when
  /// the native backend cannot complete the probe.
  ///
  /// Apple and Android use [geoAssetsDirectory] as on [startVless]. Windows
  /// standalone profile delay remains unsupported and returns `-1`.
  /// [certificateAssetsDirectory] resolves TLS files as on [startVless].
  /// Apple preparation paths without a physical-interface snapshot reject
  /// local DNS modes that require that context. Prefer testing the active VPN
  /// with [getConnectedServerDelay] for those profiles.
  Future<int> getServerDelay(
      {required String config,
      String url = 'https://google.com/generate_204',
      String? geoAssetsDirectory,
      String? certificateAssetsDirectory}) async {
    final normalizedConfig = _normalizeConfigString(config);
    return await VlessPlatform.instance.getServerDelay(
      config: normalizedConfig,
      url: url,
      geoAssetsDirectory: geoAssetsDirectory,
      certificateAssetsDirectory: certificateAssetsDirectory,
    );
  }

  /// Measures delay through the currently connected runtime.
  ///
  /// Use this after [startVless] when you want a health signal for the active
  /// profile rather than a separate temporary delay probe.
  /// Choose a URL allowed by the profile's routing and DNS policy. On Apple,
  /// CONNECTED means the protected native runtime is ready; it does not imply
  /// that this URL, or an arbitrary public Internet destination, is reachable.
  /// A failed measurement does not disconnect the active tunnel.
  /// Returns milliseconds on success or the backend's negative failure result.
  /// This uses the active profile and its routing; it does not validate every
  /// outbound. HTTPS certificate and hostname validation remain enabled.
  Future<int> getConnectedServerDelay(
      {String url = 'https://google.com/generate_204'}) async {
    return await VlessPlatform.instance.getConnectedServerDelay(url);
  }

  /// Returns the embedded or discovered Xray core version string.
  ///
  /// The exact value is reported by the active platform implementation and can
  /// differ by package version, operating system, or externally supplied Windows
  /// `xray.exe`.
  Future<String> getCoreVersion() async {
    return await VlessPlatform.instance.getCoreVersion();
  }

  /// Returns bounded native diagnostics for the active or most recent VPN or
  /// proxy-only runtime.
  ///
  /// The snapshot is intended for support screens and failure reports. Its
  /// contents differ by platform and include privacy-filtered Core, provider
  /// and packet-forwarder events within the configured bounds. Arbitrary raw
  /// stdout/stderr, credentials and complete profiles are not exposed. The
  /// human-readable format is not a stable serialization contract.
  ///
  /// Returns an empty string when the platform has not recorded diagnostics
  /// yet, for example before the first connection attempt. Stateless
  /// [getServerDelay] probes are deliberately excluded from this snapshot.
  Future<String> getProviderDebugSnapshot() async {
    return await VlessPlatform.instance.getProviderDebugSnapshot();
  }

  /// Parse a share link, raw Xray JSON config, or subscription payload.
  ///
  /// Supports vmess://, vless://, trojan://, ss://, socks://, hysteria2://,
  /// hy2://, raw Xray JSON, base64 share-link subscriptions, Clash YAML, and
  /// sing-box JSON. Prefer this over [parseFromURL] for clipboard/subscription
  /// imports: raw JSON can carry VLESS Encryption keys that are not recoverable
  /// from a bare `vless://` link. If a subscription contains multiple supported
  /// profiles, this returns the first one; use [parseMany] to keep the full
  /// list.
  /// This is an offline import: subscription URLs are not downloaded. Parsing
  /// is separate from native Core validation and successful remote traffic.
  /// Throws [ArgumentError] for empty/unsupported input or invalid profiles;
  /// malformed recognized share links may propagate their parser errors.
  static FlutterVlessURL parse(String input) {
    final trimmed = input.trim();
    if (_isSingleShareLink(trimmed)) {
      return parseFromURL(trimmed);
    }
    return parseMany(trimmed).first;
  }

  /// Parse every supported profile from a subscription payload.
  ///
  /// Unsupported protocols are skipped intentionally. This plugin embeds Xray,
  /// so protocols that do not yet have a verified Xray import mapping should
  /// remain explicit product-scope gaps instead of silently producing broken
  /// Xray JSON. WireGuard, Hysteria2 and HTTP proxy definitions have import
  /// mappings; actual operation depends on the loaded native runtime and the
  /// server's configuration. Conversion from Clash/sing-box covers supported
  /// proxy fields, not their entire routing/service document.
  ///
  /// Throws [ArgumentError] when no supported payload is found. Malformed
  /// recognized entries can propagate parser errors; unsupported entries can
  /// be skipped. No remote subscription URL is fetched.
  static List<FlutterVlessURL> parseMany(String input) {
    return VlessSubscriptionParser.parseMany(
      input: input,
      parseUrl: parseFromURL,
      parseJson: (json) => XrayJsonConfig(url: json),
    );
  }

  /// Parses a single share link into a typed [FlutterVlessURL] object.
  ///
  /// Supports `vmess://`, `vless://`, `trojan://`, `ss://`, `socks://`,
  /// `hysteria2://`, and `hy2://`.
  /// For raw Xray JSON, Clash YAML, sing-box JSON, or subscription payloads,
  /// use [parse] or [parseMany].
  /// Throws [ArgumentError] for an unsupported scheme. Each concrete parser
  /// validates its fields and can throw for malformed credentials or values.
  static FlutterVlessURL parseFromURL(String url) {
    final separator = url.indexOf('://');
    if (separator <= 0) {
      throw ArgumentError('url is invalid');
    }
    final scheme = url.substring(0, separator).toLowerCase();
    // Only the scheme is case-insensitive. Base64, credentials and query
    // values must retain their original bytes.
    final normalized = scheme + url.substring(separator);
    switch (scheme) {
      case 'vmess':
        return VmessURL(url: normalized);
      case 'vless':
        return VlessURL(url: normalized);
      case 'trojan':
        return TrojanURL(url: normalized);
      case 'ss':
        return ShadowSocksURL(url: normalized);
      case 'socks':
        return SocksURL(url: normalized);
      case 'hysteria2':
      case 'hy2':
        return Hysteria2URL(url: normalized);
      default:
        throw ArgumentError('url is invalid');
    }
  }

  static bool _isSingleShareLink(String input) {
    if (input.contains('\n') || input.contains('\r')) {
      return false;
    }
    final separator = input.indexOf('://');
    if (separator <= 0) {
      return false;
    }
    return const {'vmess', 'vless', 'trojan', 'ss', 'socks', 'hysteria2', 'hy2'}
        .contains(input.substring(0, separator).toLowerCase());
  }

  static String _normalizeConfigString(String config) {
    final decoded = _configValidator.validateJsonString(config);
    return jsonEncode(sanitizeXrayJson(decoded, preserveStructure: true));
  }
}
