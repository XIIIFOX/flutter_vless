import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('flutter_vless');
  const status = MethodChannel('flutter_vless/status');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  late List<MethodCall> calls;
  late List<String> subscriptions;
  Map<String, Object?> capabilities = {};
  Object? nativeFailure;
  String tileResult = 'added';
  setUp(() {
    calls = [];
    subscriptions = [];
    capabilities = {'optionsVersion': 1, 'requestAddQuickTile': true};
    nativeFailure = null;
    messenger.setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      if (call.method == 'getCapabilities') return capabilities;
      if (call.method == 'initializeVless' && nativeFailure != null) {
        throw nativeFailure!;
      }
      if (call.method == 'requestAddQuickTile') return tileResult;
      return null;
    });
    messenger.setMockMethodCallHandler(status, (call) async {
      subscriptions.add(call.method);
      return null;
    });
  });
  tearDown(() {
    messenger.setMockMethodCallHandler(channel, null);
    messenger.setMockMethodCallHandler(status, null);
  });
  const options = VlessOptions(
    notification: NotificationOptions(
        iconResourceName: 'vpn',
        buttonLabel: 'Stop',
        action: VlessNotificationAction.openApp),
    quickAccess: QuickAccessOptions(enabled: true, label: 'Private VPN'),
    reconnect: ReconnectOptions(
        initialDelay: Duration(milliseconds: 200),
        maxDelay: Duration(seconds: 4),
        maxAttempts: 3),
    protection: ProtectionOptions(onDemand: OnDemandMode.disabled),
    diagnostics: DiagnosticsOptions(maxBytes: 4096, maxLines: 7),
  );
  test(
      'all option blocks reach the native backend after capability negotiation',
      () async {
    final plugin = FlutterVless(onStatusChanged: (_) {}, options: options);
    await plugin.initializeVless(
        providerBundleIdentifier: 'app', groupIdentifier: 'group.app');
    expect(calls.map((c) => c.method), ['getCapabilities', 'initializeVless']);
    expect((calls.last.arguments as Map)['options'], options.toMap());
    await plugin.startVless(
        remark: 'test', config: '{"outbounds":[{"protocol":"freedom"}]}');
    expect((calls.last.arguments as Map)['notificationDisconnectButtonName'],
        'Stop');
  });
  test(
      'explicit legacy arguments override notification options and survive cold tile restart',
      () async {
    final plugin = FlutterVless(onStatusChanged: (_) {}, options: options);
    await plugin.initializeVless(
        notificationIconResourceType: 'drawable',
        notificationIconResourceName: 'override_icon');
    final args = calls.last.arguments as Map;
    expect(args['notificationIconResourceName'], 'override_icon');
    expect((args['options'] as Map)['notification'],
        containsPair('iconResourceName', 'override_icon'));
    await plugin.startVless(
        remark: 'test',
        config: '{"outbounds":[{"protocol":"freedom"}]}',
        notificationDisconnectButtonName: 'Legacy');
    expect((calls.last.arguments as Map)['notificationDisconnectButtonName'],
        'Legacy');
  });
  test('old backends reject custom options before subscribing', () async {
    capabilities = {};
    await expectLater(
        FlutterVless(onStatusChanged: (_) {}, options: options)
            .initializeVless(),
        throwsUnsupportedError);
    expect(calls.map((c) => c.method), ['getCapabilities']);
    expect(subscriptions, isEmpty);
  });
  test(
      'legacy initialization retains its old wire contract without capabilities',
      () async {
    await FlutterVless(onStatusChanged: (_) {})
        .initializeVless(notificationIconResourceName: 'legacy_icon');
    expect(calls.map((c) => c.method), ['initializeVless']);
    expect(calls.last.arguments as Map, isNot(contains('options')));
  });
  test('invalid options fail before any native call', () async {
    final plugin = FlutterVless(
        onStatusChanged: (_) {},
        options:
            const VlessOptions(diagnostics: DiagnosticsOptions(maxLines: 0)));
    await expectLater(plugin.initializeVless(), throwsArgumentError);
    expect(calls, isEmpty);
    expect(subscriptions, isEmpty);
  });
  test('native initialization failure removes the status subscription',
      () async {
    nativeFailure = PlatformException(code: 'CONTROL_EXTENSION_REQUIRED');
    await expectLater(
        FlutterVless(onStatusChanged: (_) {}, options: options)
            .initializeVless(),
        throwsA(isA<PlatformException>()));
    expect(subscriptions.last, 'cancel');
  });
  test('tile result maps every response and refuses an unsupported OS',
      () async {
    final plugin = FlutterVless(onStatusChanged: (_) {});
    for (final value in QuickTileAddResult.values) {
      tileResult = value.name;
      expect(await plugin.requestAddQuickTile(), value);
    }
    tileResult = 'unknown';
    expect(await plugin.requestAddQuickTile(), QuickTileAddResult.unsupported);
    calls.clear();
    capabilities = {};
    expect(await plugin.requestAddQuickTile(), QuickTileAddResult.unsupported);
    expect(calls.map((c) => c.method), ['getCapabilities']);
  });
  test('clearing a quick profile requires support and forwards exactly once',
      () async {
    final plugin = FlutterVless(onStatusChanged: (_) {});
    await plugin.clearQuickAccessProfile();
    expect(calls.map((c) => c.method),
        ['getCapabilities', 'clearQuickAccessProfile']);
    capabilities = {};
    await expectLater(plugin.clearQuickAccessProfile(), throwsUnsupportedError);
  });
}
