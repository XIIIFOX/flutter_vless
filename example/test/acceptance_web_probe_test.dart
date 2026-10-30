import 'dart:convert';

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
}
