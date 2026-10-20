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
  final profiles = (jsonDecode(
          File('tool/fixtures/compatibility/dns-static-aliases.json')
              .readAsStringSync()) as List)
      .cast<Map<String, dynamic>>();
  const channel = MethodChannel('flutter_vless');
  late VlessPlatform previous;
  final calls = <MethodCall>[];
  setUp(() {
    previous = VlessPlatform.instance;
    calls.clear();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return call.method == 'getServerDelay' ? 31 : null;
    });
  });
  tearDown(() {
    VlessPlatform.instance = previous;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('static DNS alias maps survive full JSON and subscription imports', () {
    expect(profiles, hasLength(4));
    for (final profile in profiles) {
      final config = profile['config'] as Map<String, dynamic>;
      final source = jsonEncode(config);
      for (final input in [source, '[$source]']) {
        final parsed = FlutterVless.parse(input);
        expect(parsed.fullConfiguration, config,
            reason: profile['name'] as String);
        expect(jsonDecode(parsed.getFullConfiguration()), config);
      }
      expect(jsonEncode(config), source);
    }
  });

  for (final adapter in <String, VlessPlatform Function()>{
    'Android': FlutterVlessAndroid.new,
    'iOS': FlutterVlessIOS.new,
    'macOS': FlutterVlessMacos.new,
    'Windows': FlutterVlessWindows.new,
  }.entries) {
    test('${adapter.key} start and delay retain caller DNS aliases and URL',
        () async {
      VlessPlatform.instance = adapter.value();
      final api = FlutterVless(onStatusChanged: (_) {});
      for (final profile in profiles) {
        calls.clear();
        final config = profile['config'] as Map<String, dynamic>;
        final source = jsonEncode(config);
        await api.startVless(remark: 'Static DNS aliases', config: source);
        expect(await api.getServerDelay(config: source), 31);
        expect(
            calls.map((call) => call.method), ['startVless', 'getServerDelay']);
        for (final call in calls) {
          expect(
              jsonDecode((call.arguments as Map)['config'] as String), config);
        }
        expect(jsonEncode(config), source);
      }
    });
  }
}
