import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/url/xray_json.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final cases = jsonDecode(
    File('tool/fixtures/compatibility/json.json').readAsStringSync(),
  ) as List<dynamic>;
  for (final entry in cases.cast<Map<String, dynamic>>()) {
    test('shared JSON syntax: ${entry['name']}', () {
      final input = entry['input'] as String;
      if (entry['wrapperDecode'] == true) {
        expect(decodeXrayJson(input), isA<Map<String, dynamic>>());
      } else {
        expect(() => decodeXrayJson(input), throwsFormatException);
      }
    });
  }

  test('JSONC/BOM full profiles preserve string markers and unknown fields',
      () {
    const original = {
      'outbounds': [
        {'protocol': 'freedom', 'tag': 'direct'}
      ],
      'dns': {
        'hosts': {
          'service.invalid': ['192.0.2.1']
        }
      },
      'remarks': 'Тест // # /* */ " 日本語',
      'extension': {
        'url': 'https://example.invalid/#a',
        'integer': 9007199254740993
      },
    };
    final input = '\uFEFF// profile\n/* start */${jsonEncode(original)}\n# end';
    expect(
        jsonDecode(FlutterVless.parse(input).getFullConfiguration()), original);
    expect(
        FlutterVless.parseMany(
            '\uFEFF[\n// profile\n${jsonEncode(original)}\n]'),
        isNotEmpty);
  });

  test('start and delay forward the same canonical JSON to native backends',
      () async {
    const channel = MethodChannel('flutter_vless');
    final calls = <MethodCall>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return call.method == 'getServerDelay' ? 1 : null;
    });
    addTearDown(() => TestDefaultBinaryMessengerBinding
        .instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null));
    const input =
        '\uFEFF# profile\n{"outbounds":[/* native protocol */{"protocol":"freedom"}],"remarks":"https://example.invalid/#keep"}';
    final api = FlutterVless(onStatusChanged: (_) {});
    await api.startVless(remark: 'syntax', config: input);
    await api.getServerDelay(config: input);
    expect(calls.map((call) => call.method), ['startVless', 'getServerDelay']);
    for (final call in calls) {
      expect(jsonDecode((call.arguments as Map)['config'] as String), {
        'outbounds': [
          {'protocol': 'freedom'}
        ],
        'remarks': 'https://example.invalid/#keep',
      });
    }
  });
}
