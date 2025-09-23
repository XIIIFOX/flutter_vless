import 'package:flutter_vless/model/vless_status.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'flutter_vless_method_channel.dart';

abstract class FlutterVlessPlatform extends PlatformInterface {
  /// Constructs a FlutterVlessPlatform.
  FlutterVlessPlatform() : super(token: _token);

  static final Object _token = Object();

  static FlutterVlessPlatform _instance =
      MethodChannelFlutterVless() as FlutterVlessPlatform;

  /// The default instance of [FlutterVlessPlatform] to use.
  ///
  /// Defaults to [MethodChannelFlutterVless].
  static FlutterVlessPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [FlutterVlessPlatform] when
  /// they register themselves.
  static set instance(FlutterVlessPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<bool> requestPermission() {
    throw UnimplementedError('requestPermission() has not been implemented.');
  }

  Future<void> initializeVless({
    required void Function(VlessStatus status) onStatusChanged,
    required String notificationIconResourceType,
    required String notificationIconResourceName,
    required String providerBundleIdentifier,
    required String groupIdentifier,
  }) {
    throw UnimplementedError('initializeVless() has not been implemented.');
  }

  Future<void> startVless({
    required String remark,
    required String config,
    required String notificationDisconnectButtonName,
    List<String>? blockedApps,
    List<String>? bypassSubnets,
    bool proxyOnly = false,
  }) {
    throw UnimplementedError('startVless() has not been implemented.');
  }

  Future<void> stopVless() {
    throw UnimplementedError('stopVless() has not been implemented.');
  }

  Future<int> getServerDelay({required String config, required String url}) {
    throw UnimplementedError('getServerDelay() has not been implemented.');
  }

  Future<int> getConnectedServerDelay(String url) async {
    throw UnimplementedError(
      'getConnectedServerDelay() has not been implemented.',
    );
  }

  Future<String> getCoreVersion() async {
    throw UnimplementedError(
      'getCoreVersion() has not been implemented.',
    );
  }
}
