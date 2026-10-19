import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter/material.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:flutter_vless_example/main.dart';
import 'package:flutter_vless_example/routing.dart';

void main() {
  for (final edit in ['JSON', 'certificates', 'VPN routing', 'mode', 'bypass', 'apps']) {
  testWidgets('$edit edits cannot receive an older pending report',
      (tester) async {
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    const channel = MethodChannel('flutter_vless');
    const status = MethodChannel('flutter_vless/status');
    final pending = Completer<Object?>();
    var starting = false;
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'getCoreVersion') return '26.10.17';
      if (call.method == 'requestPermission') return true;
      if (call.method == 'startVless') {
        starting = true;
        return pending.future;
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
    await tester.enterText(find.byType(TextField).first,
        '{"outbounds":[{"protocol":"freedom"}]}');
    await tester.tap(find.text('Connect'));
    await tester.pump();
    expect(starting, isTrue);
    switch (edit) {
      case 'JSON':
        await tester.enterText(find.byType(TextField).first,
            '{"outbounds":[{"protocol":"blackhole"}]}');
      case 'certificates':
        await tester.ensureVisible(find.text('Certificate files'));
        await tester.tap(find.text('Certificate files'));
        await tester.pumpAndSettle();
        await tester.enterText(find.widgetWithText(TextField,
            'Certificate directory (optional)'), '/private/test-certificates');
      case 'VPN routing':
        await tester.ensureVisible(find.text('VPN routing'));
        await tester.tap(find.text('VPN routing'));
      case 'mode':
        await tester.ensureVisible(find.text('VPN Mode'));
        await tester.tap(find.text('VPN Mode'));
      case 'bypass':
        await tester.ensureVisible(find.text('Bypass Subnets'));
        await tester.tap(find.text('Bypass Subnets'));
        await tester.pumpAndSettle();
        await tester.enterText(find.descendant(of: find.byType(AlertDialog),
            matching: find.byType(TextField)), '192.0.2.0/24');
        await tester.tap(find.text('Save'));
      case 'apps':
        await tester.tap(find.byTooltip('Routing / Rules'));
        await tester.pumpAndSettle();
        // App selection is Android-only. Exercise the actual live callback
        // separately from JSON, including a platform without that editor.
        tester.widget<Routing>(find.byType(Routing)).onApplyApps!(['test.excluded']);
        await tester.pageBack();
    }
    pending.complete({'preparationReport': {'version': 1, 'scope': 'runtimeFinal',
      'coreCheck': 'passed', 'changes': ['private_listener_added']}});
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('preparation-report')), findsNothing);
    expect(tester.takeException(), isNull);
  });
  }
  testWidgets('each startup displays its report and rejection clears stale success',
      (tester) async {
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    const channel = MethodChannel('flutter_vless');
    const status = MethodChannel('flutter_vless/status');
    const canary = 'CANARY-private-native-configuration';
    var starts = 0;
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'getCoreVersion') return '26.10.17';
      if (call.method == 'requestPermission') return true;
      if (call.method != 'startVless') return null;
      starts++;
      if (starts == 2) {
        throw PlatformException(code: 'CORE_CONFIG_ERROR', message: canary,
          details: {'stage': 'build', 'section': 'outbounds', 'index': 0,
            'raw': canary});
      }
      return {'preparationReport': {'version': 1, 'scope': 'host',
        'coreCheck': 'passed', 'changes': ['private_logging_applied'],
        'raw': canary}};
    });
    messenger.setMockMethodCallHandler(status, (_) async => null);
    addTearDown(() {
      messenger.setMockMethodCallHandler(channel, null);
      messenger.setMockMethodCallHandler(status, null);
    });
    await tester.pumpWidget(const MyApp());
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField).first,
        '{"outbounds":[{"protocol":"freedom"}]}');
    await tester.tap(find.text('Connect'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('preparation-report')), findsOneWidget);
    expect(find.text('App configuration · Xray check passed'), findsOneWidget);
    expect(find.textContaining(canary), findsNothing);
    await tester.tap(find.text('Connect'));
    await tester.pumpAndSettle();
    expect(starts, 2);
    expect(find.byKey(const Key('preparation-report')), findsNothing);
    expect(find.text('Xray could not build the configuration. Outbound 1.'),
        findsOneWidget);
    expect(find.textContaining(canary), findsNothing);
    expect(tester.takeException(), isNull);
  });
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
    expect(find.text('Check the configuration and VPN routing choices.'),
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
