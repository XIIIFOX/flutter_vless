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
  const channel = MethodChannel('flutter_vless');
  final adapters = <String, VlessPlatform Function()>{
    'Android': FlutterVlessAndroid.new,
    'iOS': FlutterVlessIOS.new,
    'macOS': FlutterVlessMacos.new,
    'Windows': FlutterVlessWindows.new,
  };
  late VlessPlatform previous;
  late List<MethodCall> calls;
  setUp(() {
    previous = VlessPlatform.instance;
    calls = [];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return call.method == 'getServerDelay' ? 19 : null;
    });
  });
  tearDown(() {
    VlessPlatform.instance = previous;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });
  for (final name in ['legacy-freedom.json', 'finalmask.json']) {
    final source = File('example/configs/finalmask/$name').readAsStringSync();
    final expected = jsonDecode(source);
    for (final entry in adapters.entries) {
      test('$name remains caller data for ${entry.key} start and delay',
          () async {
        VlessPlatform.instance = entry.value();
        final api = FlutterVless(onStatusChanged: (_) {});
        await api.startVless(remark: 'Mask migration example', config: source);
        expect(await api.getServerDelay(config: source), 19);
        expect(calls.map((call) => call.method),
            ['startVless', 'getServerDelay']);
        for (final call in calls) {
          expect(jsonDecode((call.arguments as Map)['config'] as String),
              expected);
        }
      });
    }
  }
}
