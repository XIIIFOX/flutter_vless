import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/flutter_vless_ios.dart';
import 'package:flutter_vless_android/flutter_vless_android.dart';
import 'package:flutter_vless_macos/flutter_vless_macos.dart';
import 'package:flutter_vless_windows/flutter_vless_windows.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final cases = (jsonDecode(File(
    'tool/fixtures/compatibility/port-env.json',
  ).readAsStringSync()) as List<dynamic>)
      .cast<Map<String, dynamic>>();
  final adapters = <VlessPlatform Function()>[
    FlutterVlessAndroid.new,
    FlutterVlessIOS.new,
    FlutterVlessMacos.new,
    FlutterVlessWindows.new,
  ];
  const channel = MethodChannel('flutter_vless');
  late VlessPlatform previousPlatform;
  late List<MethodCall> calls;
  setUp(() {
    previousPlatform = VlessPlatform.instance;
    calls = [];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return call.method == 'getServerDelay' ? 23 : null;
    });
  });
  tearDown(() {
    VlessPlatform.instance = previousPlatform;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  for (final entry in cases) {
    test('port env remains native-owned on all four adapters: ${entry['name']}',
        () async {
      final config = {
        'inbounds': [
          {
            'protocol': 'http',
            'listen': '127.0.0.1',
            'port': entry['value'],
          },
        ],
        'outbounds': [
          {'protocol': 'freedom'},
        ],
      };
      final source = jsonEncode(config);
      // Missing/empty values are decided in the native Core environment, not
      // from the computer that imports or constructs this full configuration.
      for (final input in [source, '[$source]']) {
        final parsed = FlutterVless.parse(input);
        expect(parsed.fullConfiguration, config);
        expect(jsonDecode(parsed.getFullConfiguration()), config);
      }
      for (final adapter in adapters) {
        VlessPlatform.instance = adapter();
        calls.clear();
        final api = FlutterVless(onStatusChanged: (_) {});
        await api.startVless(remark: 'port environment', config: source);
        expect(await api.getServerDelay(config: source), 23);
        expect(
            calls.map((call) => call.method), ['startVless', 'getServerDelay']);
        for (final call in calls) {
          expect(
              jsonDecode((call.arguments as Map)['config'] as String), config);
        }
      }
      expect(jsonEncode(config), source);
    });
  }
}
