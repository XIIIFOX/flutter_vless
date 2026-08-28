// Copyright (c) 2024-2026 13FOX Studio / tfox.dev.
// SPDX-License-Identifier: MIT

import 'package:plugin_platform_interface/plugin_platform_interface.dart';
import 'vless_status.dart';
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
  Future<bool> requestPermission() {
    throw UnimplementedError('requestPermission() has not been implemented.');
  }

  /// Initializes platform channels and native configuration.
  Future<void> initializeVless({
    required void Function(VlessStatus status) onStatusChanged,
    required String notificationIconResourceType,
    required String notificationIconResourceName,
    required String providerBundleIdentifier,
    required String groupIdentifier,
  }) {
    throw UnimplementedError('initializeVless() has not been implemented.');
  }

  /// Starts a proxy-only or VPN/tunnel session with a JSON Xray config.
  ///
  /// The iOS implementation may use [geoAssetsDirectory] to select external
  /// `geoip.dat` and `geosite.dat` files for the new runtime session.
  Future<void> startVless({
    required String remark,
    required String config,
    required String notificationDisconnectButtonName,
    List<String>? blockedApps,
    List<String>? bypassSubnets,
    bool proxyOnly = false,
    String? geoAssetsDirectory,
  }) {
    throw UnimplementedError('startVless() has not been implemented.');
  }

  /// Stops the active proxy or VPN/tunnel session.
  Future<void> stopVless() {
    throw UnimplementedError('stopVless() has not been implemented.');
  }

  /// Measures delay for a provided Xray config.
  ///
  /// The iOS implementation may use [geoAssetsDirectory] to select external
  /// geodata files for the temporary runtime session.
  Future<int> getServerDelay({
    required String config,
    required String url,
    String? geoAssetsDirectory,
  }) {
    throw UnimplementedError('getServerDelay() has not been implemented.');
  }

  /// Measures delay through the currently active runtime.
  Future<int> getConnectedServerDelay(String url) {
    throw UnimplementedError(
      'getConnectedServerDelay() has not been implemented.',
    );
  }

  /// Returns the Xray core version reported by the platform backend.
  Future<String> getCoreVersion() {
    throw UnimplementedError(
      'getCoreVersion() has not been implemented.',
    );
  }
}
