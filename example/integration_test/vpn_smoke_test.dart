import 'dart:async';
import 'dart:convert';
import 'dart:io';

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
    // ignore: avoid_print
    print('VPN_INITIALIZED');

    const proxyOnly = bool.fromEnvironment(
      'VPN_PROXY_ONLY',
      defaultValue: false,
    );
    if (!proxyOnly) {
      final permissionGranted = await vless.requestPermission();
      expect(permissionGranted, isTrue);
      // ignore: avoid_print
      print('VPN_PERMISSION_READY');
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

    const routing = bool.fromEnvironment('VPN_TEST_ROUTING');
    const lifecycle = bool.fromEnvironment('VPN_TEST_LIFECYCLE');
    const original = String.fromEnvironment('VPN_ORIGINAL_CONFIG');
    String? directBaseline;
    String? proxyBaseline;
    try {
      if (routing && original.isNotEmpty) {
        await vless.startVless(
            remark: 'Routing baseline', config: original, proxyOnly: true);
        await _waitFor(
            () => statuses.lastOrNull?.state.toUpperCase() == 'CONNECTED',
            timeout: const Duration(seconds: 60),
            description: 'proxy-only baseline');
        directBaseline = await _ip('https://api.ipify.org/', proxyPort: 10820);
        proxyBaseline = await _ip('https://api4.ipify.org/', proxyPort: 10808);
        expect(directBaseline, isNot(proxyBaseline),
            reason: 'The control exits must be distinguishable');
        await vless.stopVless();
        await _waitFor(
            () => statuses.lastOrNull?.state.toUpperCase() == 'DISCONNECTED',
            timeout: const Duration(seconds: 20),
            description: 'baseline stop');
      }
      statuses.clear();
      await vless.startVless(
        remark: parsed.remark,
        config: parsed.getFullConfiguration(),
        proxyOnly: proxyOnly,
      );

      await _waitFor(
        () =>
            statuses.any((status) => status.state.toUpperCase() == 'CONNECTED'),
        timeout: const Duration(seconds: 90),
        description: 'VPN CONNECTED status',
      );

      if (proxyOnly) {
        final delay = await vless.getConnectedServerDelay(
            url: 'https://www.gstatic.com/generate_204');
        expect(delay, greaterThanOrEqualTo(0));
        return;
      }

      if (routing) {
        Future<void> checkRoutes() async {
          final direct = await _ip('https://api.ipify.org/');
          final proxy = await _ip('https://api4.ipify.org/');
          expect(direct, directBaseline);
          // Providers can rotate their public proxy exit between connections.
          // The direct exit must remain the physical control, while the proxy
          // domain must have a different exit (both outbounds are exercised).
          expect(proxy, isNot(directBaseline));
          expect(direct, isNot(proxy));
          // Public control exits only; never print profiles or credentials.
          // ignore: avoid_print
          print('DOMAIN_ROUTING_PASS direct=$direct proxy=$proxy');
          await _rejectUnauthenticatedSocks(10808);
        }

        await checkRoutes();
        if (original.isNotEmpty) {
          await expectLater(
              vless.startVless(
                  remark: 'Incompatible replacement', config: original),
              throwsA(anything));
          await checkRoutes();
        }
        if (lifecycle) {
          await vless.stopVless();
          await _waitFor(
              () => statuses.lastOrNull?.state.toUpperCase() == 'DISCONNECTED',
              timeout: const Duration(seconds: 20),
              description: 'explicit stop');
          await Future<void>.delayed(const Duration(seconds: 5));
          expect(statuses.last.state.toUpperCase(), 'DISCONNECTED');
          statuses.clear();
          var nextConfig = parsed.getFullConfiguration();
          if (Platform.isIOS) {
            final object = jsonDecode(nextConfig) as Map<String, dynamic>;
            final inbound =
                (object['inbounds'] as List).first as Map<String, dynamic>;
            inbound['ſettings'] =
                inbound.remove('settings') ?? {'auth': 'noauth'};
            inbound['liſten'] = inbound.remove('listen') ?? '127.0.0.1';
            nextConfig = jsonEncode(object);
          }
          await vless.startVless(remark: parsed.remark, config: nextConfig);
          await _waitFor(
              () => statuses.lastOrNull?.state.toUpperCase() == 'CONNECTED',
              timeout: const Duration(seconds: 90),
              description: 'second native session');
          await checkRoutes();
        }
      }

      const recoveryWindow =
          int.fromEnvironment('VPN_TEST_RECOVERY_WINDOW_SECONDS');
      if (routing && recoveryWindow > 0) {
        // The host driver records a real extension/process failure in this window.
        // ignore: avoid_print
        print('VPN_RECOVERY_WINDOW_READY seconds=$recoveryWindow');
        final deadline = DateTime.now().add(Duration(seconds: recoveryWindow));
        while (DateTime.now().isBefore(deadline)) {
          try {
            final exit = await _ip('https://api4.ipify.org/',
                timeout: const Duration(seconds: 3));
            expect(exit, isNot(directBaseline),
                reason:
                    'The proxy domain must never fall back to the physical exit');
          } catch (error) {
            // Network failure is allowed during recovery; assertions (including
            // detection of a direct leak) must still propagate and fail the test.
            if (error is! SocketException &&
                error is! TimeoutException &&
                error is! HandshakeException &&
                error is! HttpException) {
              rethrow;
            }
          }
          await Future<void>.delayed(const Duration(seconds: 1));
        }
        await _waitFor(
            () => statuses.lastOrNull?.state.toUpperCase() == 'CONNECTED',
            timeout: const Duration(seconds: 90),
            description: 'forwarding after external recovery trigger');
        expect(await _ip('https://api.ipify.org/'), directBaseline);
        expect(await _ip('https://api4.ipify.org/'), isNot(directBaseline));
        await _rejectUnauthenticatedSocks(10808);
        // ignore: avoid_print
        print('RECOVERY_ROUTING_PASS');
      }

      if (Platform.isAndroid) {
        if (!routing) {
          await _validateBrowserTraffic(statuses, platformLabel: 'ANDROID');
        }
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
      expect(snapshot,
          contains('Protected tunnel routes and virtual DNS installed'));
      expect(snapshot, contains('success=true'));
      expect(snapshot, contains('Protected tunnel forwarding restored'));

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

Future<String> _ip(String url,
    {int? proxyPort, Duration timeout = const Duration(seconds: 20)}) async {
  final client = HttpClient()..connectionTimeout = timeout;
  if (proxyPort != null) client.findProxy = (_) => 'PROXY 127.0.0.1:$proxyPort';
  try {
    final request = await client.getUrl(Uri.parse(url)).timeout(timeout);
    request.headers.set(HttpHeaders.connectionHeader, 'close');
    final response = await request.close().timeout(timeout);
    expect(response.statusCode, 200);
    final address =
        (await utf8.decoder.bind(response).join().timeout(timeout)).trim();
    expect(InternetAddress.tryParse(address), isNotNull);
    return address;
  } finally {
    client.close(force: true);
  }
}

Future<void> _rejectUnauthenticatedSocks(int port) async {
  for (final method in [0, 2]) {
    final socket = await Socket.connect('127.0.0.1', port,
        timeout: const Duration(seconds: 3));
    final stream = StreamIterator<List<int>>(socket);
    final pending = <int>[];
    Future<List<int>> receive(int length) async {
      while (pending.length < length) {
        expect(await stream.moveNext().timeout(const Duration(seconds: 3)),
            isTrue);
        pending.addAll(stream.current);
      }
      final result = pending.sublist(0, length);
      pending.removeRange(0, length);
      return result;
    }

    try {
      socket.add([5, 1, method]);
      expect(await receive(2), method == 0 ? [5, 255] : [5, 2]);
      if (method == 2) {
        socket.add([1, 1, 120, 1, 120]);
        final rejection = await receive(2);
        expect(rejection[0], 1);
        expect(rejection[1], isNot(0),
            reason: 'Every non-zero RFC 1929 status rejects authentication');
      }
    } finally {
      socket.destroy();
      await stream.cancel();
    }
  }
  // ignore: avoid_print
  print('LOCAL_AUTH_REJECTION_PASS');
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
