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
    File('tool/fixtures/compatibility/fakedns.json').readAsStringSync(),
  ) as List<dynamic>)
      .cast<Map<String, dynamic>>();
  profiles.addAll([
    {
      'name': 'nested_empty_and_null_values',
      'config': {
        'outbounds': [
          {'protocol': 'freedom', 'settings': <String, dynamic>{}},
        ],
        'inbounds': <dynamic>[],
        'api': {'services': <dynamic>[]},
        'stats': <String, dynamic>{},
        'policy': {'levels': <String, dynamic>{}},
        'dns': {'hosts': <String, dynamic>{}, 'servers': <dynamic>[]},
        'extension': {
          'object': <String, dynamic>{},
          'array': <dynamic>[],
          'null': null,
          'items': [
            null,
            <String, dynamic>{},
            <dynamic>[],
            {
              'nested': [null, <String, dynamic>{}, <dynamic>[]],
            },
          ],
        },
      },
    },
    {
      'name': 'explicit_null_sections',
      'config': {
        'outbounds': [
          {'protocol': 'freedom', 'settings': null},
        ],
        'inbounds': null,
        'api': null,
        'stats': null,
        'policy': null,
        'dns': null,
        'fakedns': null,
        'extension': {'nested': null},
      },
    },
  ]);

  const channel = MethodChannel('flutter_vless');
  late List<MethodCall> calls;
  late VlessPlatform originalPlatform;
  setUp(() {
    calls = [];
    originalPlatform = VlessPlatform.instance;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return call.method == 'getServerDelay' ? 77 : null;
    });
  });
  tearDown(() {
    VlessPlatform.instance = originalPlatform;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  final adapters = <String, VlessPlatform Function()>{
    'iOS': FlutterVlessIOS.new,
    'Android': FlutterVlessAndroid.new,
    'macOS': FlutterVlessMacos.new,
    'Windows': FlutterVlessWindows.new,
  };
  for (final adapter in adapters.entries) {
    test('public raw structure reaches the actual ${adapter.key} adapter',
        () async {
      VlessPlatform.instance = adapter.value();
      final config = {
        ...profiles.singleWhere((profile) =>
                profile['name'] == 'nested_empty_and_null_values')['config']
            as Map<String, dynamic>,
        'fakedns': <dynamic>[],
      };
      final source = jsonEncode(config);
      final api = FlutterVless(onStatusChanged: (_) {});
      await api.startVless(remark: 'structure', config: source);
      expect(await api.getServerDelay(config: source), 77);
      expect(
          calls.map((call) => call.method), ['startVless', 'getServerDelay']);
      for (final call in calls) {
        expect(jsonDecode((call.arguments as Map)['config'] as String), config);
      }
    });
  }

  for (final profile in profiles) {
    final name = profile['name'] as String;
    final config = profile['config'] as Map<String, dynamic>;
    final source = jsonEncode(config);

    test('raw start and delay preserve structure: $name', () async {
      final api = FlutterVless(onStatusChanged: (_) {});
      await api.startVless(remark: name, config: source);
      expect(await api.getServerDelay(config: source), 77);

      expect(
          calls.map((call) => call.method), ['startVless', 'getServerDelay']);
      for (final call in calls) {
        expect(jsonDecode((call.arguments as Map)['config'] as String), config);
      }
      expect(jsonEncode(config), source);
    });

    test('raw JSON object and subscription import preserve structure: $name',
        () {
      final object = FlutterVless.parse(source);
      final subscription = FlutterVless.parse('[$source]');
      for (final parsed in [object, subscription]) {
        expect(parsed.fullConfiguration, config);
        expect(jsonDecode(parsed.getFullConfiguration()), config);
      }
      expect(jsonEncode(config), source);
    });
  }

  test('raw normalization retains aliases and removes allowInsecure only',
      () async {
    const source = {
      'outbounds': [
        {
          'protocol': 'vless',
          'streamSettings': {
            'network': 'XHTTP',
            'xHTTPSettings': <String, dynamic>{},
            'tlsSettings': {'allowInsecure': false},
            'sockopt': null,
          },
        },
      ],
      'extension': [null, <String, dynamic>{}, <dynamic>[]],
    };
    const expected = {
      'outbounds': [
        {
          'protocol': 'vless',
          'streamSettings': {
            'network': 'xhttp',
            'xhttpSettings': <String, dynamic>{},
            'tlsSettings': <String, dynamic>{},
            'sockopt': null,
          },
        },
      ],
      'extension': [null, <String, dynamic>{}, <dynamic>[]],
    };
    final raw = jsonEncode(source);
    final api = FlutterVless(onStatusChanged: (_) {});
    await api.startVless(remark: 'aliases', config: raw);
    await api.getServerDelay(config: raw);
    for (final call in calls) {
      expect(jsonDecode((call.arguments as Map)['config'] as String), expected);
    }
    expect(FlutterVless.parse(raw).fullConfiguration, expected);
    expect(jsonEncode(source), raw);
  });
}
