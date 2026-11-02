// Copyright (c) 2024-2026 13FOX Studio / tfox.dev.
// SPDX-License-Identifier: MIT

import 'package:plugin_platform_interface/plugin_platform_interface.dart';
import 'vless_status.dart';
import 'android_dns_policy.dart';
import 'vpn_routing_options.dart';
import 'vless_options.dart';
import 'vless_preparation_report.dart';
import 'method_channel_vless_platform.dart';

/// Contract implemented by every federated `flutter_vless` platform package.
///
/// Application code normally talks to `FlutterVless` from the main package.
/// Platform packages implement this interface to bridge Dart calls to Android,
/// iOS, macOS, or Windows native Xray/proxy/tunnel backends.
abstract class VlessPlatform extends PlatformInterface {
  /// Creates a platform interface instance.
  VlessPlatform() : super(token: _token);

  static final Object _token = Object();

  static VlessPlatform _instance = MethodChannelVlessPlatform();

  /// The default instance of [VlessPlatform] to use.
  ///
  /// Defaults to [MethodChannelVlessPlatform].
  static VlessPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [VlessPlatform] when
  /// they register themselves.
  static set instance(VlessPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  /// Requests the platform permission or profile state needed for tunnel mode.
  ///
  /// Returns whether the native permission/profile request was accepted. The
  /// native backend can throw when setup is invalid. The host Apple
  /// extension and entitlements must already be configured; this call does not
  /// install them or start a VPN.
  Future<bool> requestPermission() {
    throw UnimplementedError('requestPermission() has not been implemented.');
  }

  /// Initializes platform channels and native configuration.
  ///
  /// [onStatusChanged] receives connection and traffic updates. Android icon
  /// arguments name app `mipmap`/`drawable` resources. Apple VPN hosts supply
  /// their base app [providerBundleIdentifier] and shared App Group
  /// [groupIdentifier]; native code appends `.XrayTunnel` to the base bundle id.
  /// iOS Keychain sharing uses [keychainAccessGroup] or the
  /// configured native Info.plist value, not an implicit App Group fallback.
  ///
  /// Non-default [options] require a compatible native backend. Invalid values
  /// throw [ArgumentError], unsupported features throw [UnsupportedError], and
  /// native failures propagate through the channel. A failed reinitialization
  /// must preserve the previous session owner and status listener.
  Future<void> initializeVless({
    required void Function(VlessStatus status) onStatusChanged,
    required String notificationIconResourceType,
    required String notificationIconResourceName,
    required String providerBundleIdentifier,
    required String groupIdentifier,
    String? keychainAccessGroup,
    VlessOptions? options,
  }) {
    throw UnimplementedError('initializeVless() has not been implemented.');
  }

  /// Reports implemented native options, control surfaces and OS policy state.
  ///
  /// Older implementations return a conservative, unavailable capability set.
  /// This is not the Core transport capability/preflight result.
  Future<VlessCapabilities> getCapabilities() async =>
      const VlessCapabilities();

  /// Requests Android's Add Quick Tile dialog from a supported foreground host.
  ///
  /// Returns [QuickTileAddResult.unsupported] on unavailable backends. Adding
  /// the tile does not start a connection or authorize a saved VPN profile.
  Future<QuickTileAddResult> requestAddQuickTile() async =>
      QuickTileAddResult.unsupported;

  /// Forgets native quick-access authorization without stopping an active VPN.
  ///
  /// A later explicit connection can authorize a new profile. Unsupported
  /// native storage reports [UnsupportedError] in the shared channel adapter.
  Future<void> clearQuickAccessProfile() {
    throw UnimplementedError(
        'clearQuickAccessProfile() has not been implemented.');
  }

  /// Starts a proxy-only or VPN/tunnel session with a JSON Xray config.
  ///
  /// [remark] labels the native profile; [config] is a JSON configuration object.
  /// [notificationDisconnectButtonName] labels the Android action button.
  /// Android-only [blockedApps] contains excluded application package names.
  /// [bypassSubnets] is platform-specific: iOS VPN rejects nonempty system-route
  /// exclusions; desktop IPv4 bypass selections become protected Core rules.
  /// Prefer explicit Core routing for portable per-domain policy.
  ///
  /// [proxyOnly] omits system VPN capture. [androidDnsPolicy] and optional
  /// [androidDnsProxyOutboundTag] select Android virtual-system-DNS handling;
  /// proxy DNS requires VPN mode and a nonempty, unambiguous outbound selection.
  /// [vpnRouting] selects the original input context/default outbound and also
  /// requires VPN mode plus native routing support.
  ///
  /// [geoAssetsDirectory] selects an existing absolute directory for data files
  /// referenced by this session. Apple VPN extensions require shared access.
  /// [certificateAssetsDirectory] separately resolves relative TLS certificate
  /// and key files; the files must remain readable throughout the session.
  ///
  /// Completion acknowledges native startup; use status events for readiness.
  /// A superseded capability-gated start throws the native-channel error code
  /// `VPN_START_CANCELLED`. Invalid options throw [ArgumentError], unsupported
  /// opt-in capabilities throw [UnsupportedError], and native errors propagate.
  Future<void> startVless({
    required String remark,
    required String config,
    required String notificationDisconnectButtonName,
    List<String>? blockedApps,
    List<String>? bypassSubnets,
    bool proxyOnly = false,
    String? geoAssetsDirectory,
    String? certificateAssetsDirectory,
    AndroidDnsPolicy androidDnsPolicy = AndroidDnsPolicy.config,
    String? androidDnsProxyOutboundTag,
    VpnRoutingOptions? vpnRouting,
  }) {
    throw UnimplementedError('startVless() has not been implemented.');
  }

  /// Starts with an optional safe report. Older third-party implementations
  /// keep their existing start behavior and explicitly report unavailability.
  ///
  /// Parameters and startup errors follow [startVless]. The report belongs to
  /// this invocation; a successful Core check does not prove traffic works.
  Future<VlessPreparationReport> startVlessWithReport({
    required String remark,
    required String config,
    required String notificationDisconnectButtonName,
    List<String>? blockedApps,
    List<String>? bypassSubnets,
    bool proxyOnly = false,
    String? geoAssetsDirectory,
    String? certificateAssetsDirectory,
    AndroidDnsPolicy androidDnsPolicy = AndroidDnsPolicy.config,
    String? androidDnsProxyOutboundTag,
    VpnRoutingOptions? vpnRouting,
  }) async {
    await startVless(
      remark: remark,
      config: config,
      notificationDisconnectButtonName: notificationDisconnectButtonName,
      blockedApps: blockedApps,
      bypassSubnets: bypassSubnets,
      proxyOnly: proxyOnly,
      geoAssetsDirectory: geoAssetsDirectory,
      certificateAssetsDirectory: certificateAssetsDirectory,
      androidDnsPolicy: androidDnsPolicy,
      androidDnsProxyOutboundTag: androidDnsProxyOutboundTag,
      vpnRouting: vpnRouting,
    );
    return const VlessPreparationReport.unavailable();
  }

  /// Stops the active proxy or VPN/tunnel session.
  ///
  /// Await successful completion before replacing a live Apple profile or
  /// reinstalling its app. A timeout or preference failure does not prove OFF.
  /// Android OS Always-on/lockdown can report `ALWAYS_ON_MANAGED`; the owner must
  /// disable that OS policy before stopping through the library.
  Future<void> stopVless() {
    throw UnimplementedError('stopVless() has not been implemented.');
  }

  /// Measures delay for a provided Xray config.
  ///
  /// [url] selects the HTTP(S) destination for the temporary runtime and must
  /// be permitted by its routing/DNS policy. Returns milliseconds or a negative
  /// failure result. TLS certificate/hostname validation remains enabled.
  /// Apple and Android use [geoAssetsDirectory] for the temporary runtime.
  /// [certificateAssetsDirectory] selects relative certificate/key assets
  /// independently of geodata; native support is required when supplied.
  /// Windows standalone profile delay is unsupported.
  Future<int> getServerDelay({
    required String config,
    required String url,
    String? geoAssetsDirectory,
    String? certificateAssetsDirectory,
  }) {
    throw UnimplementedError('getServerDelay() has not been implemented.');
  }

  /// Measures delay through the currently active runtime.
  ///
  /// Returns milliseconds or a negative failure result. Choose an allowed
  /// HTTP(S) [url]; a failed measurement itself does not stop the session.
  /// Apple CONNECTED reports local native readiness independently of this probe.
  Future<int> getConnectedServerDelay(String url) {
    throw UnimplementedError(
      'getConnectedServerDelay() has not been implemented.',
    );
  }

  /// Returns the Xray core version reported by the platform backend.
  ///
  /// An externally supplied Windows executable can report a different version
  /// from the package's bundled/pinned runtime.
  Future<String> getCoreVersion() {
    throw UnimplementedError(
      'getCoreVersion() has not been implemented.',
    );
  }

  /// Returns a bounded native diagnostic snapshot for the current or most
  /// recent VPN or proxy-only Xray runtime session.
  ///
  /// The exact contents are platform-specific safe lifecycle, worker, counters
  /// and preparation events. Current adapters omit raw child stdout/stderr,
  /// credentials, configurations and arbitrary native exception text. Apps
  /// should treat this as human-readable troubleshooting data rather than a
  /// stable machine-readable format. Stateless delay probes are deliberately
  /// excluded; disabling collection clears retained buffers and returns empty.
  Future<String> getProviderDebugSnapshot() {
    throw UnimplementedError(
      'getProviderDebugSnapshot() has not been implemented.',
    );
  }
}
