import 'dart:io' show Platform;

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('real device VPN provider health check', (tester) async {
    final statuses = <VlessStatus>[];
    final vless = FlutterVless(
      onStatusChanged: (status) {
        statuses.add(status);
        // Status output is the cross-platform traffic receipt: an external
        // Safari/Chrome launch during the test can be correlated with bytes
        // reported by the native VPN implementation.
        // ignore: avoid_print
        print(
          'VPN_STATUS state=${status.state} '
          'up=${status.upload} down=${status.download} '
          'upSpeed=${status.uploadSpeed} downSpeed=${status.downloadSpeed}',
        );
      },
    );

    await vless.initializeVless(
      providerBundleIdentifier: 'dev.tfox.flutterXrayExample',
      groupIdentifier: 'group.dev.tfox.flutterXray',
    );

    const proxyOnly = bool.fromEnvironment(
      'VPN_PROXY_ONLY',
      defaultValue: false,
    );
    if (!proxyOnly) {
      final permissionGranted = await vless.requestPermission();
      expect(permissionGranted, isTrue);
    }

    // Override VPN_TEST_URL when comparing transports on a real iPhone. The
    // assertions below require actual HTTP bytes through the provider, so a
    // green run means more than NEVPNStatus.connected or non-zero counters.
    const url = String.fromEnvironment(
      'VPN_TEST_URL',
      defaultValue: 'vless://',
    );
    // Use the universal importer here, not parseFromURL. The XHTTP/none
    // regression was caused by a Happ JSON config carrying VLESS Encryption
    // (`users[].encryption = mlkem768x25519plus...`) while the visible share
    // link did not. Real-device smoke tests must be able to compare both forms:
    // the bare URL should expose missing-key failures, and the raw JSON should
    // prove the tunnel works when the server-provisioned key is preserved.
    final parsed = FlutterVless.parse(url);

    try {
      await vless.startVless(
        remark: parsed.remark,
        config: parsed.getFullConfiguration(),
        proxyOnly: proxyOnly,
      );

      await _waitFor(
        () =>
            statuses.any((status) => status.state.toUpperCase() == 'CONNECTED'),
        timeout: const Duration(seconds: 30),
        description: 'VPN CONNECTED status',
      );

      if (proxyOnly) {
        final delay = await vless.getConnectedServerDelay(
            url: 'https://www.gstatic.com/generate_204');
        expect(delay, greaterThanOrEqualTo(0));
        return;
      }

      if (Platform.isAndroid) {
        await _validateBrowserTraffic(statuses, platformLabel: 'ANDROID');
        return;
      }

      final delay = await vless.getConnectedServerDelay(
          url: 'https://www.gstatic.com/generate_204');
      expect(delay, greaterThanOrEqualTo(0));

      await Future<void>.delayed(const Duration(seconds: 8));
      final snapshot = await vless.getProviderDebugSnapshot();

      // ignore: avoid_print
      print('VPN_PROVIDER_DEBUG_BEGIN\n$snapshot\nVPN_PROVIDER_DEBUG_END');

      // The HTTP health-check line is the important proof: TCP/Reality passed
      // only after Xray, HEV, DNS/routing, and public Internet response all
      // worked together. XHTTP links that connect locally but cannot fetch bytes
      // fail here instead of looking like a successful VPN session.
      expect(snapshot, contains('IPv6 tunnel routing disabled'));
      expect(snapshot, contains('SOCKS inbound health check: ok'));
      expect(snapshot, contains('SOCKS CONNECT health check: ok'));
      expect(snapshot, contains('SOCKS HTTP health check: ok'));

      const requireBrowserTraffic = bool.fromEnvironment(
        'VPN_REQUIRE_BROWSER_TRAFFIC',
        defaultValue: false,
      );
      if (requireBrowserTraffic) {
        await _validateBrowserTraffic(statuses, platformLabel: 'IOS');
      }
    } finally {
      await vless.stopVless();
    }
  });
}

/// Leaves the VPN connected while the host test driver opens a real browser:
/// Chrome on Android or Safari on iOS.
///
/// Unlike an Android plugin-specific debug API, the status stream is part of
/// the public plugin contract and carries the native traffic counters.
/// A browser page must therefore produce substantially more response data than
/// the 68-byte failed handshake observed for the affected XHTTP profile.
Future<void> _validateBrowserTraffic(
  List<VlessStatus> statuses, {
  required String platformLabel,
}) async {
  const holdSeconds =
      int.fromEnvironment('VPN_BROWSER_HOLD_SECONDS', defaultValue: 35);
  const minimumBrowserDownloadBytes = 4096;

  // ignore: avoid_print
  print('VPN_${platformLabel}_BROWSER_WINDOW_BEGIN seconds=$holdSeconds');
  await Future<void>.delayed(Duration(seconds: holdSeconds));

  final maximumDownload = statuses.fold<int>(
    0,
    (maximum, status) => status.download > maximum ? status.download : maximum,
  );
  // ignore: avoid_print
  print('VPN_${platformLabel}_BROWSER_WINDOW_END maxDown=$maximumDownload');

  expect(
    maximumDownload,
    greaterThan(minimumBrowserDownloadBytes),
    reason: 'The browser must receive page bytes through the VPN tunnel; '
        'a connect-only result is not a passed browser test.',
  );
}

Future<void> _waitFor(
  bool Function() predicate, {
  required Duration timeout,
  required String description,
}) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    if (predicate()) {
      return;
    }
    await Future<void>.delayed(const Duration(milliseconds: 500));
  }
  fail('Timed out waiting for $description');
}
