import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  const url = String.fromEnvironment('VPN_TEST_URL');

  testWidgets('macOS live test using an environment-provided configuration',
      (tester) async {
    expect(
      url,
      isNotEmpty,
      reason: 'Pass a test configuration with '
          '--dart-define=VPN_TEST_URL=<share-link-or-raw-xray-json>.',
    );

    final statuses = <VlessStatus>[];
    final vless = FlutterVless(
      onStatusChanged: (status) {
        statuses.add(status);
        debugPrint(
          '[LIVE_TEST_OUT] Status Updated -> state=${status.state} '
          'upSpeed=${status.uploadSpeed} B/s, '
          'downSpeed=${status.downloadSpeed} B/s, '
          'totalUp=${status.upload} B, totalDown=${status.download} B, '
          'duration=${status.duration}s',
        );
      },
    );

    debugPrint('[LIVE_TEST_OUT] Initializing FlutterVless...');
    await vless.initializeVless();
    final coreVersion = await vless.getCoreVersion();
    debugPrint('[LIVE_TEST_OUT] Xray Core Version: $coreVersion');
    expect(coreVersion, isNotEmpty);

    final parsed = FlutterVless.parse(url);
    final configJson = parsed.getFullConfiguration();

    debugPrint('[LIVE_TEST_OUT] Measuring server delay...');
    try {
      final delay = await vless.getServerDelay(config: configJson);
      debugPrint('[LIVE_TEST_OUT] Server Delay: ${delay}ms');
    } catch (error) {
      debugPrint('[LIVE_TEST_OUT] Server delay measurement failed: $error');
    }

    debugPrint('[LIVE_TEST_OUT] Starting proxy connection...');
    try {
      await vless.startVless(
        remark: parsed.remark,
        config: configJson,
        proxyOnly: true,
      );

      await Future<void>.delayed(const Duration(seconds: 6));

      debugPrint('[LIVE_TEST_OUT] Measuring connected server delay...');
      try {
        final delay = await vless.getConnectedServerDelay();
        debugPrint('[LIVE_TEST_OUT] Connected Server Delay: ${delay}ms');
      } catch (error) {
        debugPrint(
          '[LIVE_TEST_OUT] Connected server delay measurement failed: $error',
        );
      }
    } finally {
      debugPrint('[LIVE_TEST_OUT] Stopping connection...');
      await vless.stopVless();
    }

    debugPrint(
      '[LIVE_TEST_OUT] macOS Live Test Completed Successfully '
      'with ${statuses.length} status updates.',
    );
  });
}
