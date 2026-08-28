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
  FlutterVless({required this.onStatusChanged});

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
  ///
  /// Call this once during app startup, before [startVless],
  /// [getConnectedServerDelay], or [getCoreVersion].
  Future<void> initializeVless({
    String notificationIconResourceType = "mipmap",
    String notificationIconResourceName = "ic_launcher",
    String providerBundleIdentifier = "",
    String groupIdentifier = "",
  }) async {
    await VlessPlatform.instance.initializeVless(
      onStatusChanged: onStatusChanged,
      notificationIconResourceType: notificationIconResourceType,
      notificationIconResourceName: notificationIconResourceName,
      providerBundleIdentifier: providerBundleIdentifier,
      groupIdentifier: groupIdentifier,
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
  /// [bypassSubnets] contains CIDR routes that should be excluded from the
  /// tunnel on platforms that support route exclusions. Use it for local LAN,
  /// DNS, server-host, or app-specific bypass behavior.
  ///
  /// Set [proxyOnly] to `true` when the app should start local Xray proxy
  /// behavior without installing a system VPN or Packet Tunnel route.
  ///
  /// On iOS, [geoAssetsDirectory] can select an absolute App Group directory
  /// containing non-empty `geoip.dat` and `geosite.dat` files for this session.
  /// Omit it to use Xray's bundled/default asset lookup.
  ///
  /// [notificationDisconnectButtonName] controls the Android foreground
  /// notification disconnect action label.
  Future<void> startVless({
    required String remark,
    required String config,
    List<String>? blockedApps,
    List<String>? bypassSubnets,
    bool proxyOnly = false,
    String? geoAssetsDirectory,
    String notificationDisconnectButtonName = "DISCONNECT",
  }) async {
    final normalizedConfig = _normalizeConfigString(config);

    await VlessPlatform.instance.startVless(
      remark: remark,
      config: normalizedConfig,
      blockedApps: blockedApps,
      proxyOnly: proxyOnly,
      bypassSubnets: bypassSubnets,
      geoAssetsDirectory: geoAssetsDirectory,
      notificationDisconnectButtonName: notificationDisconnectButtonName,
    );
  }

  /// Stops the active proxy or VPN/tunnel session.
  ///
  /// Platform implementations also use this call to clean up foreground
  /// services, system proxy settings, local Xray processes, and tunnel state.
  Future<void> stopVless() async {
    await VlessPlatform.instance.stopVless();
  }

  /// Measures delay for an Xray config without relying on an active session.
  ///
  /// [config] is validated with the same JSON validator used by [startVless].
  /// [url] should point to a lightweight HTTP endpoint that returns quickly,
  /// such as `https://google.com/generate_204`.
  ///
  /// Returns delay in milliseconds, or the platform-specific failure value when
  /// the native backend cannot complete the probe.
  ///
  /// On iOS, [geoAssetsDirectory] has the same behavior and validation as the
  /// parameter on [startVless].
  Future<int> getServerDelay(
      {required String config,
      String url = 'https://google.com/generate_204',
      String? geoAssetsDirectory}) async {
    final normalizedConfig = _normalizeConfigString(config);
    return await VlessPlatform.instance.getServerDelay(
      config: normalizedConfig,
      url: url,
      geoAssetsDirectory: geoAssetsDirectory,
    );
  }

  /// Measures delay through the currently connected runtime.
  ///
  /// Use this after [startVless] when you want a health signal for the active
  /// profile rather than a separate temporary delay probe.
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

  /// Parse a share link, raw Xray JSON config, or subscription payload.
  ///
  /// Supports vmess://, vless://, trojan://, ss://, socks://, hysteria2://,
  /// hy2://, raw Xray JSON, base64 share-link subscriptions, Clash YAML, and
  /// sing-box JSON. Prefer this over [parseFromURL] for clipboard/subscription
  /// imports: raw JSON can carry VLESS Encryption keys that are not recoverable
  /// from a bare `vless://` link. If a subscription contains multiple supported
  /// profiles, this returns the first one; use [parseMany] to keep the full
  /// list.
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
  /// Xray JSON. WireGuard, Hysteria2, and HTTP proxy profiles are supported in
  /// subscription import paths, but their runtime behavior still needs
  /// platform artifact validation before release.
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
  static FlutterVlessURL parseFromURL(String url) {
    switch (url.split("://")[0].toLowerCase()) {
      case 'vmess':
        return VmessURL(url: url);
      case 'vless':
        return VlessURL(url: url);
      case 'trojan':
        return TrojanURL(url: url);
      case 'ss':
        return ShadowSocksURL(url: url);
      case 'socks':
        return SocksURL(url: url);
      case 'hysteria2':
      case 'hy2':
        return Hysteria2URL(url: url);
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
    return jsonEncode(sanitizeXrayJson(decoded));
  }
}
