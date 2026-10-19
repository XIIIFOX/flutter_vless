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
    'tool/fixtures/compatibility/protocols.json',
  ).readAsStringSync()) as List<dynamic>)
      .cast<Map<String, dynamic>>();
  final prototype = profiles.singleWhere(
    (profile) => profile['name'] == 'vless_websocket_tls',
  )['config'];
  const headers = {
    'allowInsecure': 'literal-header-value',
    'network': 'MiXeD-CaSe',
    'xHTTPSettings': 'literal-alias-name',
    'type': 'xicmp',
    'Origin': 'quic+local://literal.invalid',
  };
  Map<String, dynamic> configWithHeaders({bool folded = false}) {
    final config = jsonDecode(jsonEncode(prototype)) as Map<String, dynamic>;
    final stream = ((config['outbounds'] as List).first
        as Map)['streamSettings'] as Map<String, dynamic>;
    final ws = stream.remove('wsSettings') as Map<String, dynamic>;
    ws[folded ? 'HeAdErS' : 'headers'] = headers;
    stream[folded ? 'wSſettings' : 'wsSettings'] = ws;
    return config;
  }

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

  for (final folded in [false, true]) {
    test('WebSocket header data survives raw cleanup (folded=$folded)', () {
      final config = configWithHeaders(folded: folded);
      final source = jsonEncode(config);
      expect(sanitizeXrayJson(config, preserveStructure: true), config);
      expect(jsonEncode(config), source);
    });
    test('WebSocket header data survives full JSON imports (folded=$folded)',
        () {
      final config = configWithHeaders(folded: folded);
      final source = jsonEncode(config);
      for (final input in [source, '[$source]']) {
        final parsed = FlutterVless.parse(input);
        expect(parsed.fullConfiguration, config);
        expect(jsonDecode(parsed.getFullConfiguration()), config);
      }
    });
  }

  test('inbound WebSocket headers are caller data too', () {
    final config = configWithHeaders();
    final stream =
        ((config['outbounds'] as List).first as Map)['streamSettings'];
    config['inbounds'] = [
      {'protocol': 'socks', 'port': 10808, 'streamSettings': stream},
    ];
    expect(sanitizeXrayJson(config, preserveStructure: true), config);
  });

  test('unknown headers objects remain caller metadata', () {
    final input = {
      'metadata': {'headers': headers},
    };
    expect(sanitizeXrayJson(input, preserveStructure: true), input);
  });

  final adapters = <String, VlessPlatform Function()>{
    'Android': FlutterVlessAndroid.new,
    'iOS': FlutterVlessIOS.new,
    'macOS': FlutterVlessMacos.new,
    'Windows': FlutterVlessWindows.new,
  };
  for (final adapter in adapters.entries) {
    test('WebSocket header data reaches ${adapter.key} start and delay',
        () async {
      VlessPlatform.instance = adapter.value();
      final config = configWithHeaders();
      final source = jsonEncode(config);
      final api = FlutterVless(onStatusChanged: (_) {});
      await api.startVless(remark: 'Transport data', config: source);
      expect(await api.getServerDelay(config: source), 31);
      expect(
          calls.map((call) => call.method), ['startVless', 'getServerDelay']);
      for (final call in calls) {
        expect(jsonDecode((call.arguments as Map)['config'] as String), config);
      }
      expect(jsonEncode(config), source);
    });
  }

  test('transport data preservation retains real TLS compatibility cleanup',
      () {
    final config = configWithHeaders();
    final stream = ((config['outbounds'] as List).first
        as Map)['streamSettings'] as Map<String, dynamic>;
    final tls = stream['tlsSettings'] as Map<String, dynamic>;
    tls['allowInsecure'] = true;
    final before = jsonEncode(config);
    final expected = jsonDecode(before) as Map<String, dynamic>;
    final expectedStream =
        ((expected['outbounds'] as List).first as Map)['streamSettings'] as Map;
    (expectedStream['tlsSettings'] as Map).remove('allowInsecure');
    expect(sanitizeXrayJson(config, preserveStructure: true), expected);
    expect(jsonEncode(config), before);
  });
}
