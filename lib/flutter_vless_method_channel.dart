import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'model/vless_status.dart' show VlessStatus;

import 'flutter_vless_platform_interface.dart';

/// An implementation of [FlutterVlessPlatform] that uses method channels.
class MethodChannelFlutterVless extends FlutterVlessPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('flutter_vless');
  final eventChannel = const EventChannel('flutter_vless/status');

  @override
  Future<void> initializeVless({
    required void Function(VlessStatus status) onStatusChanged,
    required String notificationIconResourceType,
    required String notificationIconResourceName,
    required String providerBundleIdentifier,
    required String groupIdentifier,
  }) async {
    eventChannel.receiveBroadcastStream().distinct().cast().listen((event) {
      if (event != null) {
        onStatusChanged.call(VlessStatus(
          duration: int.parse(event[0]),
          uploadSpeed: int.parse(event[1]),
          downloadSpeed: int.parse(event[2]),
          upload: int.parse(event[3]),
          download: int.parse(event[4]),
          state: event[5],
        ));
      }
    });
    await methodChannel.invokeMethod(
      'initializeVless',
      {
        "notificationIconResourceType": notificationIconResourceType,
        "notificationIconResourceName": notificationIconResourceName,
        "providerBundleIdentifier": providerBundleIdentifier,
        "groupIdentifier": "groupIdentifier",
      },
    );
  }

  @override
  Future<void> startVless({
    required String remark,
    required String config,
    required String notificationDisconnectButtonName,
    List<String>? blockedApps,
    List<String>? bypassSubnets,
    bool proxyOnly = false,
  }) async {
    await methodChannel.invokeMethod('startVless', {
      "remark": remark,
      "config": config,
      "blocked_apps": blockedApps,
      "bypass_subnets": bypassSubnets,
      "proxy_only": proxyOnly,
      "notificationDisconnectButtonName": notificationDisconnectButtonName,
    });
  }

  @override
  Future<void> stopVless() async {
    await methodChannel.invokeMethod('stopVless');
  }

  @override
  Future<int> getServerDelay(
      {required String config, required String url}) async {
    return await methodChannel.invokeMethod('getServerDelay', {
      "config": config,
      "url": url,
    });
  }

  @override
  Future<int> getConnectedServerDelay(String url) async {
    return await methodChannel
        .invokeMethod('getConnectedServerDelay', {"url": url});
  }

  @override
  Future<bool> requestPermission() async {
    return (await methodChannel.invokeMethod('requestPermission')) ?? false;
  }

  @override
  Future<String> getCoreVersion() async {
    return await methodChannel.invokeMethod('getCoreVersion');
  }
}
