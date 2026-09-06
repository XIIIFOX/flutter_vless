import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless_platform_interface/flutter_vless_platform_interface.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('flutter_vless/test');

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('diagnostics contract uses getProviderDebugSnapshot wire method',
      () async {
    MethodCall? received;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      received = call;
      return 'bounded diagnostics';
    });
    final adapter = VlessMethodChannelAdapter(methodChannel: channel);

    expect(await adapter.getProviderDebugSnapshot(), 'bounded diagnostics');
    expect(received?.method, 'getProviderDebugSnapshot');
    expect(received?.arguments, isNull);
  });

  test('diagnostics contract converts a null native result to empty text',
      () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (_) async => null);
    final adapter = VlessMethodChannelAdapter(methodChannel: channel);

    expect(await adapter.getProviderDebugSnapshot(), isEmpty);
  });
}
