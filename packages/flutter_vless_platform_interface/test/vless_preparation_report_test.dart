import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless_platform_interface/flutter_vless_platform_interface.dart';

void main() {
  const canary = 'CANARY-secret-host-key-file';
  Map<String, Object?> reply(
          {Object? version = 1,
          Object? scope = 'host',
          Object? check = 'passed',
          Object? changes = const <String>[]}) =>
      {
        'preparationReport': {
          'version': version,
          'scope': scope,
          'coreCheck': check,
          'changes': changes,
          'raw': canary
        },
      };

  test('unsupported or malformed replies cannot become a passed check', () {
    for (final value in [
      null,
      true,
      {},
      {'preparationReport': canary},
      reply(version: 2),
      reply(version: 1.0),
      reply(scope: canary),
      reply(check: canary),
      reply(changes: canary),
      reply(changes: [7]),
      reply(scope: 'unavailable'),
    ]) {
      final report = VlessPreparationReport.fromNativeReply(value);
      expect(report.scope, VlessPreparationScope.unavailable);
      expect(report.coreCheck, VlessCoreCheck.unavailable);
      expect(jsonEncode(report.toMap()), isNot(contains(canary)));
    }
  });

  test('closed immutable operations discard arbitrary native data', () {
    final input = ['private_listener_added', canary, 'private_listener_added'];
    final report =
        VlessPreparationReport.fromNativeReply(reply(changes: input));
    input.clear();
    expect(report.changes, {VlessPreparationChange.privateListenerAdded});
    expect(() => report.changes.clear(), throwsUnsupportedError);
    expect(report.toMap(), {
      'version': 1,
      'scope': 'host',
      'coreCheck': 'passed',
      'changes': ['private_listener_added']
    });
    expect(jsonEncode(report.toMap()), isNot(contains(canary)));
  });

  test('legacy native check unavailability retains its precise scope', () {
    final report =
        VlessPreparationReport.fromNativeReply(reply(check: 'unavailable'));
    expect(report.scope, VlessPreparationScope.host);
    expect(report.coreCheck, VlessCoreCheck.unavailable);
  });

  test('an older platform implementation keeps its existing startup behavior',
      () async {
    final platform = _LegacyPlatform();
    final report = await platform.startVlessWithReport(
        remark: 'legacy',
        config: '{}',
        notificationDisconnectButtonName: 'Stop');
    expect(platform.starts, 1);
    expect(report.coreCheck, VlessCoreCheck.unavailable);
    expect(report.scope, VlessPreparationScope.unavailable);
  });

  test('native failure location is closed and never retains native text', () {
    for (final stage in VlessConfigurationFailure.stages) {
      final failure = VlessConfigurationFailure.fromDetails({
        'stage': stage,
        'section': 'outbounds',
        'index': 3,
        'message': canary,
        'feature': canary
      });
      expect(failure?.toMap(),
          {'stage': stage, 'section': 'outbounds', 'index': 3});
      expect(jsonEncode(failure?.toMap()), isNot(contains(canary)));
    }
    for (final value in [
      null,
      canary,
      {'stage': canary}
    ]) {
      expect(VlessConfigurationFailure.fromDetails(value), isNull);
    }
    for (final index in [-1, 1.5, 2147483648, canary]) {
      expect(
          VlessConfigurationFailure.fromDetails(
                  {'stage': 'build', 'section': 'outbounds', 'index': index})
              ?.toMap(),
          {'stage': 'build'});
    }
    expect(
        VlessConfigurationFailure.fromDetails(
            {'stage': 'build', 'section': canary, 'index': 0})?.toMap(),
        {'stage': 'build'});
    expect(
        VlessConfigurationFailure.fromDetails(
            {'stage': 'port-environment', 'inboundIndex': 0})?.toMap(),
        {'stage': 'port-environment', 'section': 'inbounds', 'index': 0});
  });
}

class _LegacyPlatform extends VlessPlatform {
  int starts = 0;

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
    starts++;
  }
}
