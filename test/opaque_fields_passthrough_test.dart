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
    'tool/fixtures/compatibility/opaque-fields.json',
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
      return call.method == 'getServerDelay' ? 73 : null;
    });
  });
  tearDown(() {
    VlessPlatform.instance = previousPlatform;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });
  final adapters = <String, VlessPlatform Function()>{
    'Android': FlutterVlessAndroid.new,
    'iOS': FlutterVlessIOS.new,
    'macOS': FlutterVlessMacos.new,
    'Windows': FlutterVlessWindows.new,
  };

  for (final profile in profiles) {
    final name = profile['name'] as String;
    final config = profile['config'] as Map<String, dynamic>;
    final source = jsonEncode(config);
    test('raw JSON keeps opaque fields: $name', () {
      expect(sanitizeXrayJson(config, preserveStructure: true), config);
      expect(jsonEncode(config), source);
    });
    test('object and subscription imports keep opaque fields: $name', () {
      for (final input in [source, '[$source]']) {
        final parsed = FlutterVless.parse(input);
        expect(parsed.fullConfiguration, config);
        expect(jsonDecode(parsed.getFullConfiguration()), config);
      }
      expect(jsonEncode(config), source);
    });
    for (final adapter in adapters.entries) {
      test('$name reaches ${adapter.key} start and delay intact', () async {
        VlessPlatform.instance = adapter.value();
        final api = FlutterVless(onStatusChanged: (_) {});
        await api.startVless(remark: name, config: source);
        expect(await api.getServerDelay(config: source), 73);
        expect(
            calls.map((call) => call.method), ['startVless', 'getServerDelay']);
        for (final call in calls) {
          expect(
              jsonDecode((call.arguments as Map)['config'] as String), config);
        }
        expect(jsonEncode(config), source);
      });
    }
  }

  Map<String, dynamic> withStream(Map<String, dynamic> stream) => {
        'outbounds': [
          {'protocol': 'freedom', 'streamSettings': stream},
        ],
      };

  test('schema cleanup retains real stream aliases and TLS compatibility', () {
    expect(
      sanitizeXrayJson(
          withStream({
            'network': 'XHTTP',
            'xHTTPSettings': <String, dynamic>{},
            'tlsSettings': {'allowInsecure': true, 'serverName': 'tls.invalid'},
          }),
          preserveStructure: true),
      withStream({
        'network': 'xhttp',
        'xhttpSettings': <String, dynamic>{},
        'tlsSettings': {'serverName': 'tls.invalid'},
      }),
    );
  });

  test('schema cleanup leaves shadowed XHTTP branches intact', () {
    final inactive = {
      'downloadSettings': {
        'network': 'XHTTP',
        'tlsSettings': {'allowInsecure': true},
      },
    };
    final config = withStream({
      'network': 'tcp',
      'xhttpSettings': {'extra': null, ...inactive},
      'splithttpSettings': inactive,
    });
    final source = jsonEncode(config);
    expect(sanitizeXrayJson(config, preserveStructure: true), config);
    expect(jsonEncode(config), source);
  });

  test('schema cleanup matches Go-folded TLS field names', () {
    expect(
      sanitizeXrayJson(
          withStream({
            'security': 'tls',
            'TLſSettings': {'AllowInſecure': true, 'serverName': 'tls.invalid'},
          }),
          preserveStructure: true),
      withStream({
        'security': 'tls',
        'TLſSettings': {'serverName': 'tls.invalid'},
      }),
    );
  });

  for (final type in ['realm', 'xdns']) {
    test('schema cleanup handles genuine $type mask TLS fields', () {
      const opaque = {
        'allowInsecure': 'metadata',
        'network': 'Case/Sensitive',
      };
      final tls = {'AllowInſecure': true, 'custom': opaque};
      final settings = type == 'realm'
          ? {'tlsConfig': tls}
          : {
              'resolvers': [
                {'TLſConfig': tls},
              ],
            };
      final config = withStream({
        'finalmask': {
          'udp': [
            {'type': type, 'settings': settings, 'custom': opaque},
          ],
        },
      });
      final expected = jsonDecode(jsonEncode(config)) as Map<String, dynamic>;
      final masks = (((expected['outbounds'] as List).first
          as Map)['streamSettings'] as Map)['finalmask'] as Map;
      final actualSettings =
          ((masks['udp'] as List).first as Map)['settings'] as Map;
      final actualTls = type == 'realm'
          ? actualSettings['tlsConfig'] as Map
          : ((actualSettings['resolvers'] as List).first as Map)['TLſConfig']
              as Map;
      actualTls.remove('AllowInſecure');
      final source = jsonEncode(config);
      expect(sanitizeXrayJson(config, preserveStructure: true), expected);
      expect(jsonEncode(config), source);
    });
  }
}
