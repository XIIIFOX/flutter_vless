import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import '../test_driver/acceptance_web_probe.dart';
import '../test_driver/live_main.dart' show handleLiveAcceptanceRequest;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  final calls = <MethodCall>[];

  tearDown(() {
    messenger.setMockMethodCallHandler(acceptanceWebChannel, null);
    messenger.setMockMethodCallHandler(SystemChannels.platform_views, null);
    debugDefaultTargetPlatformOverride = null;
    calls.clear();
  });

  testWidgets('ordinary app without native opt-in exposes no QA control', (
    tester,
  ) async {
    messenger.setMockMethodCallHandler(acceptanceWebChannel, (call) async {
      calls.add(call);
      return false;
    });
    await tester.pumpWidget(
      const MaterialApp(
        home: AcceptanceWebOverlay(child: Text('ordinary example')),
      ),
    );
    await tester.pump();
    expect(find.text('ordinary example'), findsOneWidget);
    expect(find.text('Website QA'), findsNothing);
    expect(calls.map((c) => c.method), ['available']);
  });

  test(
    'snapshot request carries no URL, script, path or configuration',
    () async {
      messenger.setMockMethodCallHandler(acceptanceWebChannel, (call) async {
        calls.add(call);
        return {'schema': 1, 'pid': 123, 'backend': 'WKWebView.takeSnapshot'};
      });
      final result =
          jsonDecode(
                await handleLiveAcceptanceRequest(
                  'acceptance-own-view-snapshot',
                ),
              )
              as Map<String, Object?>;
      expect(result['pid'], 123);
      expect(calls.single.method, 'snapshot');
      expect(calls.single.arguments, isNull);
    },
  );

  test('unsupported diagnostic requests never reach native WebKit', () async {
    messenger.setMockMethodCallHandler(acceptanceWebChannel, (call) async {
      calls.add(call);
      throw StateError('must not be called');
    });
    expect(
      await handleLiveAcceptanceRequest('snapshot:https://example.invalid'),
      'acceptance-unsupported',
    );
    expect(
      await handleLiveAcceptanceRequest('navigate:2ip'),
      'acceptance-unsupported',
    );
    expect(
      await handleLiveAcceptanceRequest('openSafari:2ip'),
      'acceptance-unsupported',
    );
    expect(calls, isEmpty);
  });

  test('native snapshot admission error stays fail closed', () async {
    messenger.setMockMethodCallHandler(acceptanceWebChannel, (call) async {
      throw PlatformException(
        code: 'ACCEPTANCE_UNAVAILABLE',
        message: 'private canary',
      );
    });
    expect(await captureAcceptanceOwnView(), 'acceptance-error');
  });

  testWidgets('Browser buttons pass only the two fixed target enums', (
    tester,
  ) async {
    debugDefaultTargetPlatformOverride = TargetPlatform.iOS;
    messenger.setMockMethodCallHandler(
      SystemChannels.platform_views,
      (_) async => null,
    );
    messenger.setMockMethodCallHandler(acceptanceWebChannel, (call) async {
      calls.add(call);
      return true;
    });
    await tester.pumpWidget(const MaterialApp(home: AcceptanceWebProbePage()));
    await tester.pump();
    await tester.tap(find.text('Open 2ip in browser'));
    await tester.pump();
    await tester.tap(find.text('Open tfox in browser'));
    await tester.pump();
    final browserCalls = calls
        .where((call) => call.method == 'openSafari')
        .toList();
    expect(browserCalls.map((call) => call.arguments), ['2ip', 'tfox']);
    expect(calls.any((call) => call.method == 'navigate'), isFalse);
    await tester.pumpWidget(const SizedBox.shrink());
    await tester.pump();
    debugDefaultTargetPlatformOverride = null;
  });
}
