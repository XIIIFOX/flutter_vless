import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:flutter_vless_example/main.dart';

void main() {
  testWidgets(
      'connection validation errors stay visible without an unhandled failure',
      (tester) async {
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    const channel = MethodChannel('flutter_vless');
    const status = MethodChannel('flutter_vless/status');
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'requestPermission') return true;
      if (call.method == 'getCoreVersion') return '26.10.17';
      return null;
    });
    messenger.setMockMethodCallHandler(status, (_) async => null);
    addTearDown(() {
      messenger.setMockMethodCallHandler(channel, null);
      messenger.setMockMethodCallHandler(status, null);
    });
    await tester.pumpWidget(const MyApp());
    await tester.pumpAndSettle();
    await tester.tap(find.text('Connect'));
    await tester.pumpAndSettle();
    expect(find.text('Check the JSON configuration before connecting.'),
        findsOneWidget);
    expect(tester.takeException(), isNull);
  });
  testWidgets('Example app opens in normal client mode',
      (WidgetTester tester) async {
    await tester.pumpWidget(const MyApp());

    expect(find.text('Flutter Vless — Example'), findsOneWidget);
    expect(find.text('Configuration (JSON)'), findsOneWidget);
    expect(find.text('Import (clipboard)'), findsOneWidget);
    expect(find.text('VPN Mode'), findsOneWidget);
    expect(find.text('VPN Diagnostics'), findsOneWidget);
  });
}
