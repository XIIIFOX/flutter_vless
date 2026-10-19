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
    'tool/fixtures/compatibility/dns-data-maps.json',
  ).readAsStringSync()) as List<dynamic>)
      .cast<Map<String, dynamic>>();
  const channel = MethodChannel('flutter_vless');
  late List<MethodCall> calls;
  late VlessPlatform previousPlatform;
  setUp(() {
    calls = [];
    previousPlatform = VlessPlatform.instance;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return call.method == 'getServerDelay' ? 31 : null;
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
    test('public DNS data survives start and delay: $name', () async {
      final api = FlutterVless(onStatusChanged: (_) {});
      await api.startVless(remark: name, config: source);
      expect(await api.getServerDelay(config: source), 31);
      expect(
          calls.map((call) => call.method), ['startVless', 'getServerDelay']);
      for (final call in calls) {
        expect(jsonDecode((call.arguments as Map)['config'] as String), config);
      }
      expect(jsonEncode(config), source);
    });
    test('DNS data survives object and subscription imports: $name', () {
      for (final input in [source, '[$source]']) {
        final parsed = FlutterVless.parse(input);
        expect(parsed.fullConfiguration, config);
        expect(jsonDecode(parsed.getFullConfiguration()), config);
      }
      expect(jsonEncode(config), source);
    });
  }

  final adapters = <String, VlessPlatform Function()>{
    'Android': FlutterVlessAndroid.new,
    'iOS': FlutterVlessIOS.new,
    'macOS': FlutterVlessMacos.new,
    'Windows': FlutterVlessWindows.new,
  };
  for (final adapter in adapters.entries) {
    test('DNS data reaches the concrete ${adapter.key} message adapter',
        () async {
      VlessPlatform.instance = adapter.value();
      for (final profile in profiles.take(2)) {
        calls.clear();
        final config = profile['config'] as Map<String, dynamic>;
        final api = FlutterVless(onStatusChanged: (_) {});
        await api.startVless(remark: 'DNS data', config: jsonEncode(config));
        expect(await api.getServerDelay(config: jsonEncode(config)), 31);
        expect(
            calls.map((call) => call.method), ['startVless', 'getServerDelay']);
        for (final call in calls) {
          expect(
              jsonDecode((call.arguments as Map)['config'] as String), config);
        }
      }
    });
  }

  test('DNS dictionary preservation keeps actual TLS compatibility cleanup',
      () async {
    final config = jsonDecode(jsonEncode(profiles.first['config']))
        as Map<String, dynamic>;
    final outbound =
        (config['outbounds'] as List).first as Map<String, dynamic>;
    outbound['streamSettings'] = {
      'network': 'XHTTP',
      'xHTTPSettings': <String, dynamic>{},
      'tlsSettings': {'allowInsecure': true, 'serverName': 'proxy.invalid'},
    };
    final before = jsonEncode(config);
    final expected = jsonDecode(before) as Map<String, dynamic>;
    ((expected['outbounds'] as List).first as Map)['streamSettings'] = {
      'network': 'xhttp',
      'xhttpSettings': <String, dynamic>{},
      'tlsSettings': {'serverName': 'proxy.invalid'},
    };
    final api = FlutterVless(onStatusChanged: (_) {});
    await api.startVless(remark: 'TLS control', config: before);
    expect(await api.getServerDelay(config: before), 31);
    for (final call in calls) {
      expect(jsonDecode((call.arguments as Map)['config'] as String), expected);
    }
    expect(FlutterVless.parse(before).fullConfiguration, expected);
    expect(jsonEncode(config), before);
  });

  test('typed cleanup preserves DNS dictionary keys and mixed-case data', () {
    final config = profiles.first['config'] as Map<String, dynamic>;
    final before = jsonEncode(config);
    final prepared = sanitizeXrayJson(config) as Map<String, dynamic>;
    expect(prepared['dns'], config['dns']);
    expect(prepared.containsKey('inbounds'), isFalse);
    expect(jsonEncode(config), before);
  });
}
