import 'dart:convert';
import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import '../test_driver/acceptance_web_probe.dart';
import '../test_driver/acceptance_connection_probe.dart';
import '../test_driver/import_contract_probe.dart';
import '../test_driver/live_main.dart' show handleLiveAcceptanceRequest;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  const vpn = MethodChannel('flutter_vless');
  final calls = <MethodCall>[];

  setUp(() {
    messenger.setMockMethodCallHandler(acceptanceWebChannel, (call) async {
      calls.add(call);
      return call.method == 'available';
    });
    messenger.setMockMethodCallHandler(vpn, (call) async {
      calls.add(call);
      return 271;
    });
  });
  tearDown(() {
    messenger.setMockMethodCallHandler(acceptanceWebChannel, null);
    messenger.setMockMethodCallHandler(vpn, null);
    calls.clear();
  });

  test('Android debug driver admission needs no Apple channel', () async {
    messenger.setMockMethodCallHandler(acceptanceWebChannel, (call) async {
      calls.add(call);
      throw MissingPluginException();
    });
    expect(
      await acceptanceConnectionProbeAdmitted(
        isAndroidDebugRuntime: () => true,
      ),
      isTrue,
    );
    expect(calls, isEmpty);
  });

  test('other runtimes retain native opt-in rejection', () async {
    messenger.setMockMethodCallHandler(acceptanceWebChannel, (call) async {
      calls.add(call);
      return false;
    });
    expect(
      await acceptanceConnectionProbeAdmitted(
        isAndroidDebugRuntime: () => false,
      ),
      isFalse,
    );
    expect(calls.map((c) => c.method), ['available']);
  });

  for (final site in ['2ip', 'tfox']) {
    test('fixed $site delay uses the active native SOCKS path', () async {
      final result = await handleLiveAcceptanceRequest(
        'acceptance-connected-delay-$site',
      );
      expect(
        result,
        jsonEncode({
          'version': 1,
          'probe': 'connected_domain_socks',
          'target': site,
          'status': 'response',
          'delayMs': 271,
        }),
      );
      expect(calls.map((c) => c.method), [
        'available',
        'getConnectedServerDelay',
      ]);
      expect(calls.last.arguments, {
        'url': site == '2ip' ? 'https://2ip.io/ru/' : 'https://tfox.dev/ip/',
      });
    });
  }

  test('native opt-in admission is required before a delay request', () async {
    messenger.setMockMethodCallHandler(acceptanceWebChannel, (call) async {
      calls.add(call);
      return false;
    });
    expect(
      await handleLiveAcceptanceRequest('acceptance-connected-delay-2ip'),
      jsonEncode({
        'version': 1,
        'probe': 'connected_domain_socks',
        'target': '2ip',
        'status': 'unavailable',
      }),
    );
    expect(calls.map((c) => c.method), ['available']);
  });

  test(
    'failure is bounded metadata and never triggers a direct retry',
    () async {
      messenger.setMockMethodCallHandler(vpn, (call) async {
        calls.add(call);
        throw PlatformException(
          code: 'private-canary',
          message: 'private-detail',
        );
      });
      final result = await handleLiveAcceptanceRequest(
        'acceptance-connected-delay-2ip',
      );
      expect(result, isNot(contains('private')));
      expect(
        result,
        jsonEncode({
          'version': 1,
          'probe': 'connected_domain_socks',
          'target': '2ip',
          'status': 'unavailable',
        }),
      );
      expect(calls.map((c) => c.method), [
        'available',
        'getConnectedServerDelay',
      ]);
    },
  );

  test(
    'arbitrary targets and request suffixes never reach any channel',
    () async {
      for (final request in [
        'acceptance-connected-delay-2ip:https://other.invalid/',
        'acceptance-connected-delay-2ip\n',
        'acceptance-connected-delay-https://2ip.io/',
        'acceptance-network-inventory:details',
        'acceptance-import-contract:configuration',
      ]) {
        expect(
          await handleLiveAcceptanceRequest(request),
          'acceptance-unsupported',
        );
      }
      expect(calls, isEmpty);
    },
  );

  for (final invalid in <Object?>[-1, 60001, null]) {
    test(
      'non-response delay $invalid stays unavailable without retry',
      () async {
        messenger.setMockMethodCallHandler(vpn, (call) async {
          calls.add(call);
          return invalid;
        });
        final result =
            jsonDecode(
                  await handleLiveAcceptanceRequest(
                    'acceptance-connected-delay-2ip',
                  ),
                )
                as Map;
        expect(result['status'], 'unavailable');
        expect(result.containsKey('delayMs'), isFalse);
        expect(
          calls.where((c) => c.method == 'getConnectedServerDelay'),
          hasLength(1),
        );
      },
    );
  }

  testWidgets('delay deadline cannot trigger a retry or leak a late response', (
    tester,
  ) async {
    final response = Completer<int>();
    messenger.setMockMethodCallHandler(vpn, (call) {
      calls.add(call);
      return response.future;
    });
    final result = handleLiveAcceptanceRequest(
      'acceptance-connected-delay-2ip',
    );
    await tester.pump();
    await tester.pump(const Duration(seconds: 10));
    expect((jsonDecode(await result) as Map)['status'], 'unavailable');
    response.complete(123);
    await tester.pump();
    expect(
      calls.where((c) => c.method == 'getConnectedServerDelay'),
      hasLength(1),
    );
  });

  testWidgets('native admission itself has a one-second deadline', (
    tester,
  ) async {
    final admission = Completer<bool>();
    messenger.setMockMethodCallHandler(acceptanceWebChannel, (call) {
      calls.add(call);
      return admission.future;
    });
    final result = handleLiveAcceptanceRequest(
      'acceptance-connected-delay-2ip',
    );
    await tester.pump();
    await tester.pump(const Duration(seconds: 1));
    expect((jsonDecode(await result) as Map)['status'], 'unavailable');
    admission.complete(true);
    await tester.pump();
    expect(calls.map((c) => c.method), ['available']);
  });

  test(
    'inventory classifies assigned families without address disclosure',
    () async {
      final result = await runAcceptanceNetworkInventory(
        readInterfaces: () async => [
          _interface(7, [
            '192.0.2.1',
            '127.0.0.1',
            '::1',
            '2001:db8::1',
            'fd00::1',
            'fe80::1',
            '64:ff9b::c000:201',
          ]),
        ],
      );
      expect(result['scope'], 'assigned_addresses_only');
      expect(result['status'], 'observed');
      expect(result['interfaces'], [
        {
          'index': 7,
          'ipv4': 1,
          'ipv6Global': 1,
          'ipv6UniqueLocal': 1,
          'ipv6LinkLocal': 1,
          'ipv6Other': 1,
        },
      ]);
      final text = jsonEncode(result);
      expect(text, isNot(contains('192.0.2.1')));
      expect(text, isNot(contains('private-interface-name')));
      // A recognized translation prefix is not counted as native global IPv6,
      // and no address observation claims synthesized DNS or reachability.
      expect(result.containsKey('nat64Reachable'), isFalse);
    },
  );

  test('interface and address observation has finite output bounds', () async {
    final interfaces = List.generate(
      40,
      (i) => _interface(i, List.filled(300, '2001:db8::1')),
    );
    final result = await runAcceptanceNetworkInventory(
      readInterfaces: () async => interfaces,
    );
    expect(result['status'], 'bounded');
    final rows = result['interfaces'] as List;
    expect(rows, hasLength(32));
    expect(rows.fold<int>(0, (n, row) => n + (row['ipv6Global'] as int)), 256);
  });

  testWidgets('interface enumeration times out and ignores late completion', (
    tester,
  ) async {
    final response = Completer<List<AcceptanceInterfaceAddresses>>();
    final future = runAcceptanceNetworkInventory(
      readInterfaces: () => response.future,
    );
    final expectation = expectLater(future, throwsA(isA<TimeoutException>()));
    await tester.pump(const Duration(seconds: 2));
    await expectation;
    response.complete([]);
    await tester.pump();
  });

  test(
    'passive and import probes are rejected without native opt-in',
    () async {
      messenger.setMockMethodCallHandler(acceptanceWebChannel, (call) async {
        calls.add(call);
        return false;
      });
      for (final request in [
        'acceptance-network-inventory',
        'acceptance-import-contract',
      ]) {
        expect(
          await handleLiveAcceptanceRequest(request),
          'acceptance-unavailable',
        );
      }
      expect(calls.map((c) => c.method), ['available', 'available']);
    },
  );

  test(
    'synthetic parser and sandbox probe has independent expected output',
    () async {
      final created = <Directory>[];
      final result = await runAcceptanceImportContract(
        createDirectory: () async {
          final directory = await Directory.systemTemp.createTemp(
            'qa-import-test-',
          );
          created.add(directory);
          return directory;
        },
      );
      expect(result['vmessRemark'], '');
      expect(result['vmessSni'], 'certificate.example.invalid');
      expect(result['vmessHttpHost'], 'http-front.example.invalid');
      expect(result['trojanPassword'], 'пароль+@:%2F');
      expect(result['vlessId'], 'тест+%2F');
      expect(result['sandboxConfiguration'], {
        'outbounds': [
          {'protocol': 'freedom', 'tag': 'direct'},
        ],
        'extension': {
          'keep': [null, {}, [], '日本語 // # /* */'],
        },
      });
      expect(await created.single.exists(), isFalse);
      expect(calls, isEmpty);
    },
  );

  test('sandbox directory is removed after a file operation fails', () async {
    final directory = await Directory.systemTemp.createTemp(
      'qa-import-failure-',
    );
    await Directory('${directory.path}/profile.json').create();
    await expectLater(
      runAcceptanceImportContract(createDirectory: () async => directory),
      throwsA(isA<FileSystemException>()),
    );
    expect(await directory.exists(), isFalse);
    expect(calls, isEmpty);
  });
}

AcceptanceInterfaceAddresses _interface(int index, List<String> values) =>
    AcceptanceInterfaceAddresses(
      index,
      values.map(InternetAddress.new).toList(),
    );
