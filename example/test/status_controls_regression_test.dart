import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless_example/balancer_example.dart';
import 'package:flutter_vless_example/main.dart';
import 'package:flutter_vless_example/options.dart';
import 'package:flutter_vless_example/profile_import.dart';
import 'package:flutter_vless_example/routing.dart';
import 'package:shared_preferences/shared_preferences.dart';

const _profile = '{"outbounds":[{"protocol":"freedom","tag":"direct"}]}';
const _reply = {
  'preparationReport': {
    'version': 1,
    'scope': 'runtimeFinal',
    'coreCheck': 'passed',
    'changes': ['private_listener_added', 'private_logging_applied'],
  },
};

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  const methods = MethodChannel('flutter_vless');
  const events = MethodChannel('flutter_vless/status');
  late VlessPlatform previous;
  late List<MethodCall> calls;
  late List<String> statusOperations;
  String clipboard = '';

  Future<void> emit(WidgetTester tester, Object status) async {
    await messenger.handlePlatformMessage(
      events.name,
      const StandardMethodCodec().encodeSuccessEnvelope(status),
      (_) {},
    );
    await tester.pump();
  }

  Future<void> tap(WidgetTester tester, String label) async {
    await tester.ensureVisible(find.text(label));
    await tester.tap(find.text(label));
    await tester.pump(const Duration(milliseconds: 300));
    await tester.pump();
  }

  setUp(() {
    previous = VlessPlatform.instance;
    VlessPlatform.instance = VlessMethodChannelAdapter();
    calls = [];
    statusOperations = [];
    clipboard = '';
    SharedPreferences.setMockInitialValues({});
    messenger.setMockMethodCallHandler(methods, (call) async {
      calls.add(call);
      return switch (call.method) {
        'getCoreVersion' => '26.10.31',
        'requestPermission' => true,
        'getCapabilities' => {'optionsVersion': 1},
        'startVless' => _reply,
        'getServerDelay' => 42,
        'getConnectedServerDelay' => 17,
        'getProviderDebugSnapshot' => 'SESSION_START\nCOUNTERS_READY',
        _ => null,
      };
    });
    messenger.setMockMethodCallHandler(events, (call) async {
      statusOperations.add(call.method);
      return null;
    });
    messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      switch (call.method) {
        case 'Clipboard.hasStrings':
          return {'value': clipboard.isNotEmpty};
        case 'Clipboard.getData':
          return {'text': clipboard};
        case 'Clipboard.setData':
          clipboard = (call.arguments as Map)['text'] as String;
      }
      return null;
    });
  });
  tearDown(() async {
    await messenger.handlePlatformMessage(events.name, null, (_) {});
    VlessPlatform.instance = previous;
    messenger.setMockMethodCallHandler(methods, null);
    messenger.setMockMethodCallHandler(events, null);
    messenger.setMockMethodCallHandler(SystemChannels.platform, null);
  });

  test(
    'native options reinitialization replaces an active traffic listener',
    () async {
      final before = <VlessStatus>[], after = <VlessStatus>[];
      await FlutterVless(onStatusChanged: before.add).initializeVless();
      await messenger.handlePlatformMessage(
        events.name,
        const StandardMethodCodec().encodeSuccessEnvelope([
          '7',
          '2',
          '4',
          '128',
          '256',
          'CONNECTED',
        ]),
        (_) {},
      );
      await Future<void>.delayed(Duration.zero);
      await FlutterVless(
        onStatusChanged: after.add,
      ).initializeVless().timeout(const Duration(seconds: 2));
      await messenger.handlePlatformMessage(
        events.name,
        const StandardMethodCodec().encodeSuccessEnvelope([
          '8',
          '8',
          '16',
          '8192',
          '16384',
          'CONNECTED',
        ]),
        (_) {},
      );
      await Future<void>.delayed(Duration.zero);
      expect(statusOperations, ['listen', 'cancel', 'listen']);
      expect(before.single.upload, 128);
      expect(after.single.upload, 8192);
    },
  );

  testWidgets('successful connection adds no configuration check panel', (
    tester,
  ) async {
    await tester.pumpWidget(const MyApp());
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField).first, _profile);
    await tap(tester, 'Connect');
    expect(calls.where((call) => call.method == 'startVless'), hasLength(1));
    expect(find.text('Configuration check'), findsNothing);
    expect(find.byKey(const Key('preparation-report')), findsNothing);
    expect(find.text('VPN Mode'), findsOneWidget);
    expect(find.text('Profile delay'), findsOneWidget);
    expect(find.text('VPN Diagnostics'), findsOneWidget);
  });

  testWidgets('first connected status adds the pub.dev button and logs once', (
    tester,
  ) async {
    const launcher = MethodChannel('plugins.flutter.io/url_launcher');
    const label = 'Like on pub.dev';
    const pubDevUrl = 'https://pub.dev/packages/flutter_vless';
    final launchCalls = <MethodCall>[];
    messenger.setMockMethodCallHandler(launcher, (call) async {
      launchCalls.add(call);
      return true;
    });
    addTearDown(() => messenger.setMockMethodCallHandler(launcher, null));

    final pubDevLogs = <String>[];
    final originalDebugPrint = debugPrint;
    debugPrint = (message, {wrapWidth}) {
      if (message != null && message.contains(pubDevUrl)) {
        pubDevLogs.add(message);
      }
    };

    try {
      await tester.pumpWidget(const MyApp());
      await tester.pumpAndSettle();
      expect(find.text(label), findsNothing);
      expect(pubDevLogs, isEmpty);

      await emit(tester, {'state': 'CONNECTING'});
      expect(find.text(label), findsNothing);
      expect(pubDevLogs, isEmpty);

      await emit(tester, {'state': 'CONNECTED'});
      expect(find.text(label), findsOneWidget);
      final banner = pubDevLogs.single;
      final mask = banner.split('\n\n').first;
      expect(find.text(mask), findsNothing);
      expect(mask, contains('⢯⡉⠓⠦⣄'));
      expect(const LineSplitter().convert(banner).last, pubDevUrl);
      expect(
        mask.runes.every(
          (code) => code == 10 || (code >= 0x2800 && code <= 0x28FF),
        ),
        isTrue,
      );
      await tap(tester, label);
      expect(launchCalls.single.method, 'launch');
      expect(launchCalls.single.arguments['url'], pubDevUrl);

      await emit(tester, {'state': 'DISCONNECTED'});
      expect(find.text(label), findsOneWidget);
      await emit(tester, {'state': 'CONNECTED'});
      expect(find.text(label), findsOneWidget);
      expect(launchCalls, hasLength(1));
      expect(pubDevLogs, [banner]);
    } finally {
      debugPrint = originalDebugPrint;
    }
  });

  testWidgets('balancer shows the imported subscription size and sends all nodes', (
    tester,
  ) async {
    clipboard = 'https://example.org/subscription';
    final links = List.generate(34, (index) => 'socks://127.0.0.1:${12081 + index}');
    await tester.pumpWidget(
      MyApp(profileImporter: (input) => importBalancerInput(
        input,
        fetch: (_) async => FlutterVless.parseMany(links.join('\n')),
      )),
    );
    await tester.pumpAndSettle();
    await tap(tester, 'Import (clipboard)');
    expect(find.text('Configuration (JSON) · 34 balancer nodes'), findsOneWidget);
    await tap(tester, 'Connect');

    final start = calls.singleWhere((call) => call.method == 'startVless');
    final config = jsonDecode((start.arguments as Map)['config'] as String);
    final group = config['routing']['balancers'].single;
    expect(group['strategy']['type'], 'roundRobin');
    expect(group['selector'], hasLength(34));
    expect(config['outbounds'], hasLength(35));
    expect(config['routing']['rules'].last['balancerTag'], group['tag']);
    await tester.enterText(find.byType(TextField).first, '{}');
    await tester.pump();
    expect(find.text('Configuration (JSON) · 34 balancer nodes'), findsNothing);
  });

  testWidgets('a slow subscription cannot replace a newer clipboard import', (
    tester,
  ) async {
    final slow = Completer<ImportedProfile>();
    const first = 'https://example.org/slow';
    clipboard = first;
    await tester.pumpWidget(MyApp(profileImporter: (input) {
      if (input == first) return slow.future;
      return (config: _profile, remark: 'New profile', balancedNodeCount: null);
    }));
    await tester.pumpAndSettle();
    await tap(tester, 'Import (clipboard)');
    clipboard = 'https://example.org/fast';
    await tap(tester, 'Import (clipboard)');
    slow.complete((config: '{}', remark: 'Old profile', balancedNodeCount: null));
    await tester.pumpAndSettle();

    final editor = tester.widget<TextField>(find.byType(TextField).first);
    expect(editor.controller!.text, _profile);
  });

  for (final payload in <String, Object>{
    'legacy platform list': [
      '33',
      '2048',
      '4096',
      '8192',
      '32768',
      'CONNECTED',
    ],
    'numeric platform map': {
      'duration': 33,
      'uploadSpeed': 2048,
      'downloadSpeed': 4096,
      'upload': 8192,
      'download': 32768,
      'state': 'CONNECTED',
    },
    'decimal-string platform map': {
      'duration': '33',
      'upload_speed': '2048',
      'download_speed': '4096',
      'upload': '8192',
      'download': '32768',
      'status': 'CONNECTED',
    },
  }.entries) {
    testWidgets(
      '${payload.key} updates traffic, speed, duration and controls',
      (tester) async {
        await tester.pumpWidget(const MyApp());
        await tester.pumpAndSettle();
        await emit(tester, payload.value);
        expect(find.text('CONNECTED'), findsOneWidget);
        expect(find.text('33 s'), findsOneWidget);
        expect(find.text('8.0 KB'), findsOneWidget);
        expect(find.text('32 KB'), findsOneWidget);
        expect(find.text('2048 B/s'), findsOneWidget);
        expect(find.text('4096 B/s'), findsOneWidget);
        expect(find.text('Disconnect'), findsOneWidget);
        expect(find.text('Configuration check'), findsNothing);

        await emit(tester, ['34', '1024', '0', '12288', '65536', 'CONNECTED']);
        expect(find.text('34 s'), findsOneWidget);
        expect(find.text('12 KB'), findsOneWidget);
        expect(find.text('64 KB'), findsOneWidget);
        expect(find.text('1024 B/s'), findsOneWidget);
        expect(find.text('0 B/s'), findsOneWidget);
        expect(find.text('8.0 KB'), findsNothing);

        // Idle speed must not erase the already transferred session totals.
        await emit(tester, ['35', '0', '0', '12288', '65536', 'CONNECTED']);
        expect(find.text('0 B/s'), findsNWidgets(2));
        expect(find.text('12 KB'), findsOneWidget);
        expect(find.text('64 KB'), findsOneWidget);
        await emit(tester, ['0', '0', '0', '0', '0', 'DISCONNECTED']);
        expect(find.text('0.0 B'), findsNWidgets(2));
        expect(find.text('Connect'), findsOneWidget);
        expect(tester.takeException(), isNull);
      },
    );
  }

  testWidgets(
    'normal import, permission, proxy and VPN starts retain their arguments',
    (tester) async {
      await tester.pumpWidget(const MyApp());
      await tester.pumpAndSettle();
      clipboard = jsonEncode({
        'remarks': 'UI profile',
        'outbounds': [
          {'protocol': 'freedom', 'tag': 'direct'},
          {'protocol': 'blackhole', 'tag': 'block'},
        ],
      });
      await tap(tester, 'Import (clipboard)');
      expect(
        tester.widget<TextField>(find.byType(TextField).first).controller!.text,
        clipboard,
      );
      tester
          .state<ScaffoldMessengerState>(find.byType(ScaffoldMessenger))
          .removeCurrentSnackBar();
      await tap(tester, 'Request Permission');
      expect(find.text('Permission granted'), findsOneWidget);
      final permissions = calls
          .where((call) => call.method == 'requestPermission')
          .length;

      await tap(tester, 'VPN Mode');
      expect(find.text('Proxy Only'), findsOneWidget);
      await tap(tester, 'Connect');
      var start =
          calls.lastWhere((call) => call.method == 'startVless').arguments
              as Map;
      expect(start['proxy_only'], isTrue);
      expect(start['remark'], 'UI profile');
      expect(jsonDecode(start['config'] as String), jsonDecode(clipboard));
      expect(
        calls.where((call) => call.method == 'requestPermission'),
        hasLength(permissions),
      );

      await emit(tester, ['1', '12', '34', '56', '78', 'CONNECTED']);
      await tap(tester, 'Disconnect');
      expect(calls.where((call) => call.method == 'stopVless'), hasLength(1));
      await emit(tester, ['0', '0', '0', '0', '0', 'DISCONNECTED']);
      await tap(tester, 'Proxy Only');
      await tap(tester, 'Connect');
      start =
          calls.lastWhere((call) => call.method == 'startVless').arguments
              as Map;
      expect(start['proxy_only'], isFalse);
      expect(
        calls.where((call) => call.method == 'requestPermission'),
        hasLength(permissions + 1),
      );
      expect(find.text('Configuration check'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'delay selects the current session while profile delay retains the editor',
    (tester) async {
      await tester.pumpWidget(const MyApp());
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField).first, _profile);
      await tap(tester, 'Delay');
      expect(
        calls.where((call) => call.method == 'getServerDelay'),
        hasLength(1),
      );
      expect(find.text('42 ms'), findsOneWidget);

      tester
          .state<ScaffoldMessengerState>(find.byType(ScaffoldMessenger))
          .removeCurrentSnackBar();
      await emit(tester, ['7', '2', '4', '128', '256', 'CONNECTED']);
      await tap(tester, 'Delay');
      expect(
        calls.where((call) => call.method == 'getConnectedServerDelay'),
        hasLength(1),
      );
      expect(find.text('17 ms'), findsOneWidget);
      await tap(tester, 'Profile delay');
      final isolated = calls
          .where((call) => call.method == 'getServerDelay')
          .toList();
      expect(isolated, hasLength(2));
      expect(
        jsonDecode((isolated.last.arguments as Map)['config'] as String),
        jsonDecode(_profile),
      );
      await emit(tester, ['0', '0', '0', '0', '0', 'DISCONNECTED']);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('diagnostics copy and options replacement keep status delivery', (
    tester,
  ) async {
    await tester.pumpWidget(const MyApp());
    await tester.pumpAndSettle();
    await emit(tester, ['7', '2', '4', '128', '256', 'CONNECTED']);
    await tap(tester, 'VPN Diagnostics');
    expect(
      calls.where((call) => call.method == 'getBalancerSelections'),
      isEmpty,
    );
    expect(
      tester.widget<SelectableText>(find.byType(SelectableText)).data,
      'SESSION_START\nCOUNTERS_READY',
    );
    await tap(tester, 'Copy');
    expect(clipboard, 'SESSION_START\nCOUNTERS_READY');
    expect(find.byType(AlertDialog), findsNothing);

    await tester.tap(find.byTooltip('Plugin options'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 300));
    await tester.pump();
    expect(find.text('Apply options'), findsOneWidget);
    await tap(tester, 'Apply options');
    expect(
      calls.where((call) => call.method == 'initializeVless'),
      hasLength(2),
    );
    // EventChannel cancellation completes on the platform-response event loop;
    // fake animation-clock pumps alone cannot flush that completion.
    await tester.runAsync(() => Future<void>.delayed(Duration.zero));
    for (
      var frame = 0;
      frame < 20 && find.byType(PluginOptionsPage).evaluate().isNotEmpty;
      frame++
    ) {
      await tester.pump(const Duration(milliseconds: 50));
    }
    expect(
      find.byType(PluginOptionsPage),
      findsNothing,
      reason: 'Status operations: $statusOperations',
    );
    expect(statusOperations, ['listen', 'cancel', 'listen']);
    await emit(tester, ['8', '8', '16', '8192', '16384', 'CONNECTED']);
    expect(find.text('8 s'), findsOneWidget);
    expect(find.text('8.0 KB'), findsOneWidget);
    expect(find.text('16 KB'), findsOneWidget);
    expect(find.text('8 B/s'), findsOneWidget);
    expect(find.text('16 B/s'), findsOneWidget);
    await emit(tester, ['0', '0', '0', '0', '0', 'DISCONNECTED']);
    expect(tester.takeException(), isNull);
  });

  testWidgets('balancer ordinals stay separate from copied diagnostics', (
    tester,
  ) async {
    var latestChoices = '1,1,1\n2,1,2';
    messenger.setMockMethodCallHandler(methods, (call) async {
      calls.add(call);
      return switch (call.method) {
        'getCapabilities' => {'optionsVersion': 1, 'balancerSelections': true},
        'getCoreVersion' => '26.11.9',
        'getProviderDebugSnapshot' => 'SESSION_START',
        'getBalancerSelections' => latestChoices,
        _ => null,
      };
    });
    await tester.pumpWidget(
      const MyApp(
        options: VlessOptions(
          diagnostics: DiagnosticsOptions(recordBalancerSelections: true),
        ),
      ),
    );
    await tester.pumpAndSettle();
    await emit(tester, ['2', '0', '0', '0', '0', 'CONNECTED']);
    await tap(tester, 'VPN Diagnostics');
    expect(find.text('Recent balancer selections'), findsOneWidget);
    expect(
      find.text('#2 · Group 1 · Node 2\n#1 · Group 1 · Node 1'),
      findsOneWidget,
    );
    expect(
      tester.widget<SelectableText>(find.byType(SelectableText)).data,
      'SESSION_START',
    );
    latestChoices = '2,1,2\n3,1,1';
    await tap(tester, 'Refresh selections');
    expect(
      find.text('#3 · Group 1 · Node 1\n#2 · Group 1 · Node 2'),
      findsOneWidget,
    );
    await emit(tester, ['0', '0', '0', '0', '0', 'DISCONNECTED']);
    expect(find.textContaining('· Node'), findsNothing);
    await emit(tester, ['1', '0', '0', '0', '0', 'CONNECTED']);
    expect(find.textContaining('· Node'), findsNothing);
    latestChoices = '1,1,2';
    await tap(tester, 'Refresh selections');
    expect(find.text('#1 · Group 1 · Node 2'), findsOneWidget);

    await tap(tester, 'Copy');
    expect(clipboard, 'SESSION_START');
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'routing and bypass editors forward their applied values on Connect',
    (tester) async {
      await tester.pumpWidget(const MyApp());
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField).first, _profile);
      await tap(tester, 'Bypass Subnets');
      await tester.enterText(
        find.descendant(
          of: find.byType(AlertDialog),
          matching: find.byType(TextField),
        ),
        '192.0.2.0/24\n198.51.100.0/24',
      );
      await tap(tester, 'Save');
      await tester.tap(find.byTooltip('Routing / Rules'));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 300));
      await tester.enterText(
        find
            .descendant(
              of: find.byType(Routing),
              matching: find.byType(TextField),
            )
            .first,
        'api.ipify.org',
      );
      await tap(tester, 'Apply rules');
      await tester.pageBack();
      await tester.pump(const Duration(milliseconds: 300));
      await tap(tester, 'Connect');

      final start =
          calls.lastWhere((call) => call.method == 'startVless').arguments
              as Map;
      final config = jsonDecode(start['config'] as String) as Map;
      expect(start['bypass_subnets'], ['192.0.2.0/24', '198.51.100.0/24']);
      expect((config['routing']['rules'] as List).first['domain'], [
        'domain:api.ipify.org',
      ]);
      expect(
        (config['routing']['rules'] as List).first['outboundTag'],
        'direct',
      );
      expect(find.text('Configuration check'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );
}
