import 'dart:convert';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless_example/main.dart';
import 'package:flutter_vless_example/options_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUp(() => SharedPreferences.setMockInitialValues({}));
  const options = VlessOptions(
      notification: NotificationOptions(
          buttonLabel: 'Open app', action: VlessNotificationAction.openApp),
      quickAccess: QuickAccessOptions(enabled: true, label: 'Saved VPN'),
      reconnect: ReconnectOptions(maxAttempts: 3),
      protection: ProtectionOptions(onDemand: OnDemandMode.disabled),
      diagnostics: DiagnosticsOptions(maxBytes: 4096, maxLines: 7));
  test(
      'all five blocks survive a fresh preferences instance without configuration data',
      () async {
    await ExampleOptionsStorage.save(options);
    final raw = (await SharedPreferences.getInstance())
        .getString(ExampleOptionsStorage.key)!;
    expect((jsonDecode(raw) as Map).keys.toSet(), {
      'version',
      'notification',
      'quickAccess',
      'reconnect',
      'protection',
      'diagnostics'
    });
    SharedPreferences.setMockInitialValues({ExampleOptionsStorage.key: raw});
    expect((await ExampleOptionsStorage.load()).toMap(), options.toMap());
  });
  test(
      'missing, corrupted and incompatible preferences fall back to disabled controls',
      () async {
    expect((await ExampleOptionsStorage.load()).isDefault, isTrue);
    for (final raw in [
      'bad',
      '[]',
      '{"version":2}',
      '{"quickAccess":{"enabled":"bad"}}'
    ]) {
      SharedPreferences.setMockInitialValues({ExampleOptionsStorage.key: raw});
      expect((await ExampleOptionsStorage.load()).isDefault, isTrue);
    }
  });
  testWidgets(
      'cold app restores controls before its first native initialization',
      (tester) async {
    SharedPreferences.setMockInitialValues(
        {ExampleOptionsStorage.key: jsonEncode(options.toMap())});
    final saved = await ExampleOptionsStorage.load();
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    const channel = MethodChannel('flutter_vless'),
        status = MethodChannel('flutter_vless/status');
    Object? initialized;
    messenger.setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'getCapabilities') return {'optionsVersion': 1};
      if (call.method == 'initializeVless') initialized = call.arguments;
      if (call.method == 'getCoreVersion') return '26.10.21';
      return null;
    });
    messenger.setMockMethodCallHandler(status, (_) async => null);
    addTearDown(() {
      messenger.setMockMethodCallHandler(channel, null);
      messenger.setMockMethodCallHandler(status, null);
    });
    await tester.pumpWidget(MyApp(options: saved));
    await tester.pumpAndSettle();
    expect((initialized as Map)['options'], options.toMap());
  });
}
