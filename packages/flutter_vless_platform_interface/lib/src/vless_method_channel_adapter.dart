import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_vless_platform_interface/src/quick_settings_tile.dart';

import 'vless_platform.dart';
import 'vless_status.dart';

class VlessMethodChannelAdapter extends VlessPlatform {
  VlessMethodChannelAdapter({
    this.methodChannel = const MethodChannel('flutter_vless'),
    this.eventChannel = const EventChannel('flutter_vless/status'),
  });

  @visibleForTesting
  final MethodChannel methodChannel;

  @visibleForTesting
  final EventChannel eventChannel;

  StreamSubscription<dynamic>? _statusSubscription;

  @override
  Future<void> initializeVless({
    required void Function(VlessStatus status) onStatusChanged,
    required String notificationIconResourceType,
    required String notificationIconResourceName,
    required String providerBundleIdentifier,
    required String groupIdentifier,
    QuickSettingsTile? quickSettingsTile,
  }) async {
    await _statusSubscription?.cancel();
    _statusSubscription = eventChannel
        .receiveBroadcastStream()
        .distinct()
        .listen((Object? event) {
      final status = VlessStatus.tryParse(event);
      if (status != null) {
        onStatusChanged(status);
      } else {
        debugPrint('Ignoring malformed VLESS status payload: $event');
      }
    }, onError: (Object error, StackTrace stackTrace) {
      debugPrint('VLESS status stream error: $error');
    });

    final arguments = <String, dynamic>{
      'notificationIconResourceType': notificationIconResourceType,
      'notificationIconResourceName': notificationIconResourceName,
      'providerBundleIdentifier': providerBundleIdentifier,
      'groupIdentifier': groupIdentifier,
    };
    if (quickSettingsTile != null) {
      arguments['tileLabel'] = quickSettingsTile.tileLabel;
      arguments['tileIconResourceType'] =
          quickSettingsTile.tileIconResourceType;
      arguments['tileIconResourceName'] =
          quickSettingsTile.tileIconResourceName;
    }
    await methodChannel.invokeMethod('initializeVless', arguments);
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
      'remark': remark,
      'config': config,
      'blocked_apps': blockedApps,
      'bypass_subnets': bypassSubnets,
      'proxy_only': proxyOnly,
      'notificationDisconnectButtonName': notificationDisconnectButtonName,
    });
  }

  @override
  Future<void> stopVless() async {
    await methodChannel.invokeMethod('stopVless');
  }

  @override
  Future<int> getServerDelay({
    required String config,
    required String url,
  }) async {
    return await methodChannel.invokeMethod('getServerDelay', {
      'config': config,
      'url': url,
    });
  }

  @override
  Future<int> getConnectedServerDelay(String url) async {
    return await methodChannel.invokeMethod(
      'getConnectedServerDelay',
      {'url': url},
    );
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
