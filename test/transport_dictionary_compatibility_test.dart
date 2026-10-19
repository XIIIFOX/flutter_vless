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
  final profiles = (jsonDecode(File(
    'tool/fixtures/compatibility/transport-data-maps.json',
  ).readAsStringSync()) as List<dynamic>)
      .cast<Map<String, dynamic>>();
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
      return call.method == 'getServerDelay' ? 37 : null;
    });
  });
  tearDown(() {
    VlessPlatform.instance = previousPlatform;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  for (final profile in profiles) {
    final name = profile['name'] as String;
    final config = profile['config'] as Map<String, dynamic>;
    final source = jsonEncode(config);
    test('transport dictionary cleanup and imports preserve $name', () {
      expect(sanitizeXrayJson(config, preserveStructure: true), config);
      for (final input in [source, '[$source]']) {
        final parsed = FlutterVless.parse(input);
        expect(parsed.fullConfiguration, config);
        expect(jsonDecode(parsed.getFullConfiguration()), config);
      }
      expect(jsonEncode(config), source);
    });
    test('transport dictionary reaches all four start/delay adapters: $name',
        () async {
      for (final adapter in adapters.values) {
        VlessPlatform.instance = adapter();
        calls.clear();
        final api = FlutterVless(onStatusChanged: (_) {});
        await api.startVless(remark: name, config: source);
        expect(await api.getServerDelay(config: source), 37);
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

  test('transport dictionaries survive folded schema field names', () {
    dynamic foldFields(dynamic value) {
      if (value is Map) {
        return {
          for (final entry in value.entries)
            (entry.key as String).toUpperCase():
                (entry.key as String).toLowerCase() == 'headers'
                    ? entry.value
                    : foldFields(entry.value),
        };
      }
      if (value is List) return value.map(foldFields).toList();
      return value;
    }

    for (final profile in profiles) {
      final config =
          jsonDecode(jsonEncode(profile['config'])) as Map<String, dynamic>;
      for (final group in ['inbounds', 'outbounds']) {
        for (final handler in config[group] as List) {
          if ((handler as Map).containsKey('streamSettings')) {
            handler['streamSettings'] = foldFields(handler['streamSettings']);
          }
        }
      }
      final source = jsonEncode(config);
      expect(sanitizeXrayJson(config, preserveStructure: true), config);
      expect(FlutterVless.parse(source).fullConfiguration, config);
      expect(jsonEncode(config), source);
    }
  });
}
