import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import '../test_driver/live_main.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const vpn = MethodChannel('flutter_vless');
  const core = MethodChannel('dev.tfox.flutterXrayExample/acceptance');
  final calls = <String>[];
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  setUp(() {
    calls.clear();
    messenger.setMockMethodCallHandler(vpn, (call) async {
      calls.add('vpn:${call.method}');
      return null;
    });
    messenger.setMockMethodCallHandler(core, (call) async {
      calls.add('core:${call.method}');
      return 'acceptance-core-stopped';
    });
  });
  tearDown(() {
    messenger.setMockMethodCallHandler(vpn, null);
    messenger.setMockMethodCallHandler(core, null);
  });

  test(
    'watchdog requests full native Stop without killing only Core',
    () async {
      expect(
        await handleLiveAcceptanceRequest('acceptance-full-stop'),
        'acceptance-vpn-stopped',
      );
      expect(calls, ['vpn:stopVless']);
    },
  );

  test('failed native Stop is not acknowledged or exposed', () async {
    messenger.setMockMethodCallHandler(vpn, (call) async {
      throw PlatformException(code: 'STOP_FAILED', message: 'private detail');
    });
    expect(
      await handleLiveAcceptanceRequest('acceptance-full-stop'),
      'acceptance-error',
    );
  });

  testWidgets('watchdog stops waiting for an unacknowledged Stop', (
    tester,
  ) async {
    messenger.setMockMethodCallHandler(vpn, (call) {
      calls.add(call.method);
      return Completer<Object?>().future;
    });
    final pending = handleLiveAcceptanceRequest('acceptance-full-stop');
    await tester.pump(const Duration(seconds: 31));
    expect(await pending, 'acceptance-error');
    expect(calls, ['stopVless']);
  });

  test('Core loss injection stays separate from full Stop', () async {
    expect(
      await handleLiveAcceptanceRequest('acceptance-stop-core'),
      'acceptance-core-stopped',
    );
    expect(calls, ['core:stopCore']);
  });

  test('unknown requests do not change the session', () async {
    expect(await handleLiveAcceptanceRequest(null), 'acceptance-unsupported');
    expect(await handleLiveAcceptanceRequest('stop'), 'acceptance-unsupported');
    expect(calls, isEmpty);
  });
}
