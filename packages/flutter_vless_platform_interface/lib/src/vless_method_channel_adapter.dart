import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'vless_platform.dart';
import 'vless_status.dart';
import 'android_dns_policy.dart';
import 'vpn_routing_options.dart';
import 'vless_options.dart';
import 'vless_preparation_report.dart';

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
  int _startGeneration = 0;
  static final Object _reportCaptureKey = Object();

  @override
  Future<void> initializeVless({
    required void Function(VlessStatus status) onStatusChanged,
    required String notificationIconResourceType,
    required String notificationIconResourceName,
    required String providerBundleIdentifier,
    required String groupIdentifier,
    String? keychainAccessGroup,
    VlessOptions? options,
  }) async {
    options?.validate();
    if (options != null && !options.isDefault) {
      final capabilities = await getCapabilities();
      if (capabilities.optionsVersion < 1) {
        throw UnsupportedError(
            'The native backend does not support VlessOptions.');
      }
    }
    if (keychainAccessGroup != null) {
      if (keychainAccessGroup.trim().isEmpty) {
        throw ArgumentError.value(keychainAccessGroup, 'keychainAccessGroup');
      }
      await _requireSecurityCapability('iosKeychainReference');
    }
    final previous = _statusSubscription;
    // Keep the active listener until native reconfiguration succeeds. A rejected
    // option must not leave a still-running VPN without status updates.
    if (previous == null) {
      _statusSubscription = _listenToStatus(onStatusChanged);
    }

    try {
      await methodChannel.invokeMethod(
        'initializeVless',
        {
          'notificationIconResourceType': notificationIconResourceType,
          'notificationIconResourceName': notificationIconResourceName,
          'providerBundleIdentifier': providerBundleIdentifier,
          'groupIdentifier': groupIdentifier,
          if (keychainAccessGroup != null)
            'keychainAccessGroup': keychainAccessGroup,
          if (options != null && !options.isDefault) 'options': options.toMap(),
        },
      );
    } catch (_) {
      if (previous == null) {
        await _statusSubscription?.cancel();
        _statusSubscription = null;
      }
      rethrow;
    }
    // A committed native configuration replaces the owner/options that an
    // older capability-gated Start expected. Revoke it before listener awaits;
    // rejected initialization leaves both pending Start and listener intact.
    ++_startGeneration;
    if (previous != null) {
      await previous.cancel();
      _statusSubscription = _listenToStatus(onStatusChanged);
    }
  }

  StreamSubscription<dynamic> _listenToStatus(
      void Function(VlessStatus) onStatusChanged) {
    return eventChannel.receiveBroadcastStream().distinct().listen(
        (Object? event) {
      final status = VlessStatus.tryParse(event);
      if (status != null) {
        onStatusChanged(status);
      } else {
        debugPrint('Ignoring malformed VLESS status payload: $event');
      }
    }, onError: (Object error, StackTrace stackTrace) {
      debugPrint('VLESS status stream error: $error');
    });
  }

  @override
  Future<VlessCapabilities> getCapabilities() async {
    try {
      final result = await methodChannel
          .invokeMapMethod<Object?, Object?>('getCapabilities');
      return VlessCapabilities.fromMap(result ?? const {});
    } on MissingPluginException {
      return const VlessCapabilities();
    }
  }

  @override
  Future<QuickTileAddResult> requestAddQuickTile() async {
    if (!(await getCapabilities()).requestAddQuickTile) {
      return QuickTileAddResult.unsupported;
    }
    final name =
        await methodChannel.invokeMethod<String>('requestAddQuickTile');
    return QuickTileAddResult.values.firstWhere((value) => value.name == name,
        orElse: () => QuickTileAddResult.unsupported);
  }

  @override
  Future<void> clearQuickAccessProfile() async {
    if ((await getCapabilities()).optionsVersion < 1) {
      throw UnsupportedError(
          'The native backend has no quick-access profile storage.');
    }
    await methodChannel.invokeMethod<void>('clearQuickAccessProfile');
  }

  @override
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
  }) async {
    vpnRouting?.validate();
    if (vpnRouting != null && proxyOnly) {
      throw ArgumentError('VPN routing selections require a VPN session.');
    }
    if (androidDnsProxyOutboundTag != null &&
        (androidDnsPolicy != AndroidDnsPolicy.proxy ||
            androidDnsProxyOutboundTag.trim().isEmpty)) {
      throw ArgumentError('A non-empty DNS outbound tag requires proxy DNS.');
    }
    if (androidDnsPolicy == AndroidDnsPolicy.proxy && proxyOnly) {
      throw ArgumentError('System DNS policy requires an Android VPN session.');
    }
    // Capability replies may arrive after Stop or a newer Start. They may not
    // turn that older request into a new native session afterward.
    final generation = ++_startGeneration;
    if (androidDnsPolicy == AndroidDnsPolicy.proxy) {
      await _requireStartupCapability('androidProxyDns', generation);
    }
    if (certificateAssetsDirectory != null) {
      await _requireStartupCapability('certificateAssetsDirectory', generation);
    }
    if (vpnRouting != null) {
      await _requireStartupCapability('vpnRouting', generation);
    }
    final arguments = <String, Object?>{
      'remark': remark,
      'config': config,
      'blocked_apps': blockedApps,
      'bypass_subnets': bypassSubnets,
      'proxy_only': proxyOnly,
      'notificationDisconnectButtonName': notificationDisconnectButtonName,
      if (androidDnsPolicy != AndroidDnsPolicy.config)
        'android_dns_policy': androidDnsPolicy.name,
      if (androidDnsProxyOutboundTag != null)
        'android_dns_proxy_outbound_tag': androidDnsProxyOutboundTag,
      if (vpnRouting != null) 'vpn_routing': vpnRouting.toMap(),
    };
    if (geoAssetsDirectory != null) {
      arguments['geo_assets_directory'] = geoAssetsDirectory;
    }
    if (certificateAssetsDirectory != null) {
      arguments['certificate_assets_directory'] = certificateAssetsDirectory;
    }
    _checkStartGeneration(generation);
    final capture = Zone.current[_reportCaptureKey] as _StartReportCapture?;
    capture?.begin();
    final reply =
        await methodChannel.invokeMethod<Object?>('startVless', arguments);
    capture?.complete(config, VlessPreparationReport.fromNativeReply(reply));
  }

  @override
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
    final capture = _StartReportCapture(config);
    await runZoned(
        () => startVless(
              remark: remark,
              config: config,
              notificationDisconnectButtonName:
                  notificationDisconnectButtonName,
              blockedApps: blockedApps,
              bypassSubnets: bypassSubnets,
              proxyOnly: proxyOnly,
              geoAssetsDirectory: geoAssetsDirectory,
              certificateAssetsDirectory: certificateAssetsDirectory,
              androidDnsPolicy: androidDnsPolicy,
              androidDnsProxyOutboundTag: androidDnsProxyOutboundTag,
              vpnRouting: vpnRouting,
            ),
        zoneValues: {_reportCaptureKey: capture});
    return capture.report;
  }

  Future<void> _requireSecurityCapability(String capability) async {
    try {
      final capabilities = await methodChannel
          .invokeMapMethod<String, dynamic>('getSecurityCapabilities');
      if (capabilities?[capability] == true) return;
    } on MissingPluginException {
      // Older native implementations must not silently ignore an opt-in.
    }
    throw UnsupportedError('Native backend does not support $capability.');
  }

  void _checkStartGeneration(int generation) {
    if (generation != _startGeneration) {
      throw PlatformException(
        code: 'VPN_START_CANCELLED',
        message: 'Startup was cancelled by a newer start or stop request.',
      );
    }
  }

  Future<void> _requireStartupCapability(
      String capability, int generation) async {
    try {
      await _requireSecurityCapability(capability);
    } finally {
      // Cancellation owns the old request even when its capability check fails.
      _checkStartGeneration(generation);
    }
  }

  @override
  Future<void> stopVless() async {
    ++_startGeneration;
    await methodChannel.invokeMethod('stopVless');
  }

  @override
  Future<int> getServerDelay({
    required String config,
    required String url,
    String? geoAssetsDirectory,
    String? certificateAssetsDirectory,
  }) async {
    if (certificateAssetsDirectory != null) {
      await _requireSecurityCapability('certificateAssetsDirectory');
    }
    final arguments = <String, Object?>{
      'config': config,
      'url': url,
    };
    if (geoAssetsDirectory != null) {
      arguments['geo_assets_directory'] = geoAssetsDirectory;
    }
    if (certificateAssetsDirectory != null) {
      arguments['certificate_assets_directory'] = certificateAssetsDirectory;
    }
    return await methodChannel.invokeMethod('getServerDelay', arguments);
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

  @override
  Future<String> getProviderDebugSnapshot() async {
    return await methodChannel.invokeMethod<String>(
          'getProviderDebugSnapshot',
        ) ??
        '';
  }
}

// A per-invocation observer preserves virtual dispatch to older adapter
// overrides. It never stores a process-wide last report. An override which
// uses another candidate or more than one native start cannot claim a report.
class _StartReportCapture {
  _StartReportCapture(this.expectedConfiguration);
  final String expectedConfiguration;
  int invocations = 0;
  VlessPreparationReport report = const VlessPreparationReport.unavailable();
  void begin() {
    invocations++;
    report = const VlessPreparationReport.unavailable();
  }

  void complete(String configuration, VlessPreparationReport result) {
    if (invocations == 1 && configuration == expectedConfiguration) {
      report = result;
    }
  }
}
