import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/flutter_vless_ios.dart';
import 'package:flutter_vless/url/xray_config_model.dart';
import 'package:flutter_vless_android/flutter_vless_android.dart';
import 'package:flutter_vless_macos/flutter_vless_macos.dart';
import 'package:flutter_vless_windows/flutter_vless_windows.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final fixture = jsonDecode(File(
    'tool/fixtures/compatibility/routing-attrs.json',
  ).readAsStringSync()) as Map<String, dynamic>;
  final config = fixture['config'] as Map<String, dynamic>;
  final adapters = <String, VlessPlatform Function()>{
    'Android': FlutterVlessAndroid.new,
    'iOS': FlutterVlessIOS.new,
    'macOS': FlutterVlessMacos.new,
    'Windows': FlutterVlessWindows.new,
  };
  const channel = MethodChannel('flutter_vless');
  late List<MethodCall> calls;
  late VlessPlatform previousPlatform;
  setUp(() {
    calls = [];
    previousPlatform = VlessPlatform.instance;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return call.method == 'getServerDelay' ? 29 : null;
    });
  });
  tearDown(() {
    VlessPlatform.instance = previousPlatform;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('routing attributes retain literal regex and keys through imports', () {
    final source = jsonEncode(config);
    expect(sanitizeXrayJson(config, preserveStructure: true), config);
    for (final input in [source, '[$source]']) {
      final parsed = FlutterVless.parse(input);
      expect(parsed.fullConfiguration, config);
      expect(jsonDecode(parsed.getFullConfiguration()), config);
    }
    expect(jsonEncode(config), source);
  });

  for (final folded in [false, true]) {
    for (final adapter in adapters.entries) {
      test('routing attrs reach ${adapter.key} start/delay: folded=$folded',
          () async {
        final input = jsonDecode(jsonEncode(config)) as Map<String, dynamic>;
        if (folded) {
          final routing = input.remove('routing') as Map<String, dynamic>;
          final rules = routing.remove('rules') as List<dynamic>;
          for (final rule in rules.cast<Map<String, dynamic>>()) {
            rule['ATTRſ'] = rule.remove('attrs');
          }
          routing['RULEſ'] = rules;
          input['ROUTING'] = routing;
        }
        final source = jsonEncode(input);
        VlessPlatform.instance = adapter.value();
        calls.clear();
        final api = FlutterVless(onStatusChanged: (_) {});
        await api.startVless(remark: 'routing attributes', config: source);
        expect(await api.getServerDelay(config: source), 29);
        expect(
            calls.map((call) => call.method), ['startVless', 'getServerDelay']);
        for (final call in calls) {
          expect(
              jsonDecode((call.arguments as Map)['config'] as String), input);
        }
        expect(jsonEncode(input), source);
      });
    }
  }

  test('ignored routing fields stay intact while real TLS cleanup stays active',
      () {
    expect(
      sanitizeXrayJson({
        'routing': {
          'attrs': {'allowInsecure': true, 'network': 'TCP'},
        },
        'outbounds': [
          {
            'streamSettings': {
              'network': 'TCP',
              'tlsSettings': {
                'allowInsecure': true,
                'serverName': 'test.invalid'
              },
            },
          },
        ],
      }, preserveStructure: true),
      {
        'routing': {
          'attrs': {'allowInsecure': true, 'network': 'TCP'},
        },
        'outbounds': [
          {
            'streamSettings': {
              'network': 'tcp',
              'tlsSettings': {'serverName': 'test.invalid'},
            },
          },
        ],
      },
    );
  });
}
