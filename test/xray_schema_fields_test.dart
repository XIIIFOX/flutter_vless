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
    'tool/fixtures/compatibility/schema-fields.json',
  ).readAsStringSync()) as List<dynamic>)
      .cast<Map<String, dynamic>>();
  final adapters = <String, VlessPlatform Function()>{
    'Android': FlutterVlessAndroid.new,
    'iOS': FlutterVlessIOS.new,
    'macOS': FlutterVlessMacos.new,
    'Windows': FlutterVlessWindows.new,
  };
  const channel = MethodChannel('flutter_vless');
  late VlessPlatform previousPlatform;
  late List<MethodCall> calls;
  setUp(() {
    previousPlatform = VlessPlatform.instance;
    calls = [];
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

  for (final entry in cases) {
    final config = entry['config'] as Map<String, dynamic>;
    final source = jsonEncode(config);
    final name = entry['name'];
    if (entry['invalidSyntax'] == true) {
      test('non-string network remains invalid before all native handoffs',
          () async {
        expect(() => FlutterVless.parse(source), throwsArgumentError);
        for (final adapter in adapters.values) {
          VlessPlatform.instance = adapter();
          final api = FlutterVless(onStatusChanged: (_) {});
          await expectLater(api.startVless(remark: 'invalid', config: source),
              throwsArgumentError);
          await expectLater(
              api.getServerDelay(config: source), throwsArgumentError);
        }
        expect(calls, isEmpty);
      });
      continue;
    }
    test('schema fields preserve the complete imported document: $name', () {
      for (final input in [source, '[$source]']) {
        final parsed = FlutterVless.parse(input);
        expect(parsed.fullConfiguration, config);
        expect(jsonDecode(parsed.getFullConfiguration()), config);
        expect(parsed.outbound1,
            ((config['outbounds'] ?? config['OUTBOUNDS']) as List).first);
      }
      expect(jsonEncode(config), source);
    });
    for (final adapter in adapters.entries) {
      test('schema fields reach ${adapter.key} start/delay: $name', () async {
        VlessPlatform.instance = adapter.value();
        final api = FlutterVless(onStatusChanged: (_) {});
        // String transport semantics belong to Core preflight. The active
        // empty-network control is rejected there; method-overridden empty is
        // valid. The shared Go regression distinguishes those outcomes.
        await api.startVless(remark: 'schema fields', config: source);
        expect(await api.getServerDelay(config: source), 31);
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

  test('ambiguous schema aliases are rejected before native handoff', () async {
    final config = {
      'outbounds': [
        {'protocol': 'freedom'},
      ],
      'OUTBOUNDS': [
        {'protocol': 'blackhole'},
      ],
    };
    final source = jsonEncode(config);
    expect(() => FlutterVless.parse(source), throwsArgumentError);
    for (final adapter in adapters.values) {
      VlessPlatform.instance = adapter();
      final api = FlutterVless(onStatusChanged: (_) {});
      await expectLater(api.startVless(remark: 'ambiguous', config: source),
          throwsArgumentError);
    }
    expect(calls, isEmpty);
    expect(jsonEncode(config), source);
  });

  test('Go long-s folding keeps unrelated non-ASCII fields as caller data', () {
    final config = {
      'OUTBOUNDſ': [
        {'PROTOCOL': 'freedom'},
      ],
      'İNBOUNDS': 'unknown field data',
    };
    expect(FlutterVless.parse(jsonEncode(config)).fullConfiguration, config);
  });
}
