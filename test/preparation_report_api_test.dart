import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/flutter_vless_ios.dart';
import 'package:flutter_vless_android/flutter_vless_android.dart';
import 'package:flutter_vless_macos/flutter_vless_macos.dart';
import 'package:flutter_vless_windows/flutter_vless_windows.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('flutter_vless');
  const secret = 'CANARY-private-host-key-path';
  final adapters = <String, VlessPlatform Function()>{
    'Android': FlutterVlessAndroid.new,
    'iOS': FlutterVlessIOS.new,
    'macOS': FlutterVlessMacos.new,
    'Windows': FlutterVlessWindows.new,
  };
  late VlessPlatform previous;
  late List<MethodCall> calls;
  Object? reply;

  setUp(() {
    previous = VlessPlatform.instance;
    calls = [];
    reply = {
      'preparationReport': {
        'version': 1,
        'scope': 'host',
        'coreCheck': 'passed',
        'changes': ['certificate_refs_bound', secret],
        'unrecognized': secret,
      },
    };
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return reply;
    });
  });
  tearDown(() {
    VlessPlatform.instance = previous;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('custom legacy adapter overrides still receive old and new API starts',
      () async {
    final platform = _LegacyAdapter();
    VlessPlatform.instance = platform;
    final api = FlutterVless(onStatusChanged: (_) {});
    const config = '{"outbounds":[{"protocol":"freedom"}]}';
    await api.startVless(remark: 'old', config: config);
    expect(platform.starts, 1);
    final report =
        await api.startVlessWithReport(remark: 'optional', config: config);
    expect(platform.starts, 2);
    expect(report.coreCheck, VlessCoreCheck.unavailable);
    expect(calls, isEmpty);
  });

  for (final mode in ['forward', 'retarget', 'multiple']) {
    test('custom $mode adapter cannot misattribute a native report', () async {
      final platform = _LegacyAdapter()
        ..forward = true
        ..retarget = mode == 'retarget'
        ..multiple = mode == 'multiple';
      VlessPlatform.instance = platform;
      final report = await FlutterVless(onStatusChanged: (_) {})
          .startVlessWithReport(
              remark: 'custom',
              config: '{"outbounds":[{"protocol":"freedom"}]}');
      expect(platform.starts, 1);
      expect(calls, hasLength(mode == 'multiple' ? 2 : 1));
      expect(
          report.coreCheck,
          mode == 'forward'
              ? VlessCoreCheck.passed
              : VlessCoreCheck.unavailable);
    });
  }

  for (final adapter in adapters.entries) {
    test('${adapter.key} keeps a same-call safe report and Dart TLS edit',
        () async {
      VlessPlatform.instance = adapter.value();
      final source = jsonEncode({
        'metadata': {
          'tlsSettings': {'allowInsecure': secret}
        },
        'outbounds': [
          {
            'protocol': 'freedom',
            'streamSettings': {
              'tlsSettings': {'ALLOWINSECURE': false},
            },
          },
        ],
      });
      final api = FlutterVless(onStatusChanged: (_) {});
      final report =
          await api.startVlessWithReport(remark: secret, config: source);
      expect(report.toMap(), {
        'version': 1,
        'scope': 'host',
        'coreCheck': 'passed',
        'changes': ['certificate_refs_bound', 'tls_override_removed'],
      });
      expect(jsonEncode(report.toMap()), isNot(contains(secret)));
      expect(calls.map((call) => call.method), ['startVless']);
      final native = jsonDecode(calls.single.arguments['config'] as String);
      expect(native['outbounds'][0]['streamSettings']['tlsSettings'], isEmpty);
      expect(native['metadata']['tlsSettings']['allowInsecure'], secret);
    });

    test('${adapter.key} legacy reply never implies a passed Core check',
        () async {
      VlessPlatform.instance = adapter.value();
      reply = null;
      final api = FlutterVless(onStatusChanged: (_) {});
      final report = await api.startVlessWithReport(
          remark: 'legacy', config: '{"outbounds":[{"protocol":"freedom"}]}');
      expect(report.toMap(), {
        'version': 1,
        'scope': 'unavailable',
        'coreCheck': 'unavailable',
        'changes': <String>[],
      });
      expect(calls, hasLength(1));
    });

    test(
        '${adapter.key} out-of-order replies keep native and Dart edits paired',
        () async {
      VlessPlatform.instance = adapter.value();
      final pending = <String, Completer<Object?>>{
        'first': Completer<Object?>(),
        'second': Completer<Object?>(),
      };
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) {
        calls.add(call);
        return pending[call.arguments['remark']]!.future;
      });
      final api = FlutterVless(onStatusChanged: (_) {});
      final first = api.startVlessWithReport(
          remark: 'first',
          config:
              '{"outbounds":[{"protocol":"freedom","streamSettings":{"tlsSettings":{"allowInsecure":true}}}]}');
      final second = api.startVlessWithReport(
          remark: 'second',
          config:
              '{"outbounds":[{"protocol":"freedom","streamSettings":{"network":"TCP"}}]}');
      Map<String, Object> result(String change) => {
            'preparationReport': {
              'version': 1,
              'scope': 'runtimeFinal',
              'coreCheck': 'passed',
              'changes': [change]
            },
          };
      pending['second']!.complete(result('private_logging_applied'));
      final reportB = await second;
      pending['first']!.complete(result('certificate_refs_bound'));
      final reportA = await first;
      expect(reportA.changes, {
        VlessPreparationChange.certificateRefsBound,
        VlessPreparationChange.tlsOverrideRemoved
      });
      expect(reportB.changes, {
        VlessPreparationChange.privateLoggingApplied,
        VlessPreparationChange.streamAliasNormalized
      });
      expect(calls, hasLength(2));
    });
  }
}

class _LegacyAdapter extends VlessMethodChannelAdapter {
  int starts = 0;
  bool forward = false, retarget = false, multiple = false;

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
    if (!forward) return;
    Future<void> native() => super.startVless(
          remark: remark,
          config:
              retarget ? '{"outbounds":[{"protocol":"blackhole"}]}' : config,
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
    await native();
    if (multiple) await native();
  }
}
