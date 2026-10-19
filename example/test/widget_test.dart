import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter/material.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:flutter_vless_example/main.dart';

void main() {
  testWidgets(
    'profile delay passes the full editor profile and handles errors',
    (tester) async {
      final messenger =
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
      const channel = MethodChannel('flutter_vless');
      const status = MethodChannel('flutter_vless/status');
      final calls = <MethodCall>[];
      var reject = false;
      messenger.setMockMethodCallHandler(channel, (call) async {
        if (call.method == 'getCoreVersion') return '26.10.17';
        if (call.method == 'getSecurityCapabilities') {
          return {'certificateAssetsDirectory': true};
        }
        if (call.method == 'getServerDelay') {
          calls.add(call);
          if (reject) throw PlatformException(code: 'probe_failed');
          return 42;
        }
        return null;
      });
      messenger.setMockMethodCallHandler(status, (_) async => null);
      addTearDown(() {
        messenger.setMockMethodCallHandler(channel, null);
        messenger.setMockMethodCallHandler(status, null);
      });
      await tester.pumpWidget(const MyApp());
      await tester.pumpAndSettle();
      final profile = {
        'inbounds': [
          {'protocol': 'socks', 'listen': '127.0.0.1', 'port': 10808},
        ],
        'outbounds': [
          {'protocol': 'freedom', 'tag': 'direct'},
        ],
        'api': {'tag': 'fixture-api', 'listen': '127.0.0.1:10809'},
        'metrics': {'tag': 'fixture-metrics', 'listen': '127.0.0.1:10810'},
      };
      await tester.enterText(find.byType(TextField).first, jsonEncode(profile));
      await tester.ensureVisible(find.text('Certificate files'));
      await tester.tap(find.text('Certificate files'));
      await tester.pumpAndSettle();
      await tester.enterText(find.widgetWithText(TextField,
          'Certificate directory (optional)'), '/private/app-group/certificates');
      await tester.ensureVisible(find.text('Profile delay'));
      await tester.tap(find.text('Profile delay'));
      await tester.pumpAndSettle();
      expect(calls, hasLength(1));
      expect((calls.single.arguments as Map)['certificate_assets_directory'],
          '/private/app-group/certificates');
      expect(
        jsonDecode((calls.single.arguments as Map)['config'] as String),
        profile,
      );
      expect(find.text('42 ms'), findsOneWidget);
      reject = true;
      await tester.tap(find.text('Profile delay'));
      await tester.pumpAndSettle(const Duration(seconds: 5));
      expect(
        find.text('Unable to measure delay. Check the profile and connection.'),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
    },
  );
  testWidgets('disabled diagnostics explains the setting and cannot copy', (
    tester,
  ) async {
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    const channel = MethodChannel('flutter_vless');
    const status = MethodChannel('flutter_vless/status');
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'getCoreVersion') return '26.10.17';
      if (call.method == 'getProviderDebugSnapshot') return '';
      return null;
    });
    messenger.setMockMethodCallHandler(status, (_) async => null);
    addTearDown(() {
      messenger.setMockMethodCallHandler(channel, null);
      messenger.setMockMethodCallHandler(status, null);
    });
    await tester.pumpWidget(
      const MyApp(
        options: VlessOptions(diagnostics: DiagnosticsOptions(enabled: false)),
      ),
    );
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('VPN Diagnostics'));
    await tester.tap(find.text('VPN Diagnostics'));
    await tester.pumpAndSettle();
    expect(
      find.text('Diagnostics are disabled in Plugin options.'),
      findsOneWidget,
    );
    expect(
      tester
          .widget<ElevatedButton>(find.widgetWithText(ElevatedButton, 'Copy'))
          .onPressed,
      isNull,
    );
    expect(tester.takeException(), isNull);
  });
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
