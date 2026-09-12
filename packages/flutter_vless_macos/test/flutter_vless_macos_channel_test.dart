import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless_macos/flutter_vless_macos.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('flutter_vless');

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('getProviderDebugSnapshot uses the shared native diagnostics method',
      () async {
    final calls = <MethodCall>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return 'macOS provider diagnostics';
    });

    final plugin = FlutterVlessMacos();

    expect(
      await plugin.getProviderDebugSnapshot(),
      'macOS provider diagnostics',
    );
    expect(calls.single.method, 'getProviderDebugSnapshot');
    expect(calls.single.arguments, isNull);
  });

  test('getProviderDebugSnapshot normalizes a null native response', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (_) async => null);

    expect(await FlutterVlessMacos().getProviderDebugSnapshot(), isEmpty);
  });
}
