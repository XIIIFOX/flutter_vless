import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless_windows/flutter_vless_windows.dart';

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
      return 'Windows Xray diagnostics';
    });

    final plugin = FlutterVlessWindows();

    expect(
      await plugin.getProviderDebugSnapshot(),
      'Windows Xray diagnostics',
    );
    expect(calls.single.method, 'getProviderDebugSnapshot');
    expect(calls.single.arguments, isNull);
  });

  test('getProviderDebugSnapshot normalizes a null native response', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (_) async => null);

    expect(await FlutterVlessWindows().getProviderDebugSnapshot(), isEmpty);
  });
}
