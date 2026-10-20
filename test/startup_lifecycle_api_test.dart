import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/flutter_vless_ios.dart';
import 'package:flutter_vless_android/flutter_vless_android.dart';
import 'package:flutter_vless_macos/flutter_vless_macos.dart';
import 'package:flutter_vless_windows/flutter_vless_windows.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('flutter_vless');
  const status = MethodChannel('flutter_vless/status');
  const config = '{"outbounds":[{"protocol":"freedom"}]}';
  const privatePath = '/private/startup-canary/certificates';
  const privateError = 'private-capability-transport-canary';
  final adapters = <String, VlessPlatform Function()>{
    'Android': FlutterVlessAndroid.new,
    'iOS': FlutterVlessIOS.new,
    'macOS': FlutterVlessMacos.new,
    'Windows': FlutterVlessWindows.new,
  };
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  late VlessPlatform previous;
  late List<MethodCall> calls;
  late Completer<Object?> capability;
  late Completer<void> capabilityRequested;
  late List<String> subscriptions;
  Object? initializationFailure;

  Future<void> emitStatus(String state) async {
    await messenger.handlePlatformMessage(
        status.name,
        const StandardMethodCodec()
            .encodeSuccessEnvelope(['0', '0', '0', '0', '0', state]),
        (_) {});
    await Future<void>.delayed(Duration.zero);
  }

  Matcher cancelled() => isA<PlatformException>()
      .having((error) => error.code, 'code', 'VPN_START_CANCELLED')
      .having(
          (error) => error.message,
          'redacted message',
          isNot(anyOf(contains(privatePath), contains('private-old-profile'),
              contains(privateError))))
      .having((error) => error.details, 'details', isNull);

  setUp(() {
    previous = VlessPlatform.instance;
    calls = [];
    capability = Completer<Object?>();
    capabilityRequested = Completer<void>();
    subscriptions = [];
    initializationFailure = null;
    messenger.setMockMethodCallHandler(channel, (call) {
      calls.add(call);
      if (call.method == 'getSecurityCapabilities') {
        if (!capabilityRequested.isCompleted) capabilityRequested.complete();
        return capability.future;
      }
      if (call.method == 'getCapabilities') {
        return Future<Object?>.value({'optionsVersion': 1});
      }
      if (call.method == 'initializeVless' && initializationFailure != null) {
        return Future<Object?>.error(initializationFailure!);
      }
      return Future<Object?>.value(null);
    });
    messenger.setMockMethodCallHandler(status, (call) async {
      subscriptions.add(call.method);
      return null;
    });
  });
  tearDown(() async {
    if (subscriptions.contains('listen')) {
      await messenger.handlePlatformMessage(status.name, null, (_) {});
      await Future<void>.delayed(Duration.zero);
    }
    VlessPlatform.instance = previous;
    messenger.setMockMethodCallHandler(channel, null);
    messenger.setMockMethodCallHandler(status, null);
  });

  for (final adapter in adapters.entries) {
    for (final outcome in ['accepted', 'refused', 'transport error']) {
      test(
          '${adapter.key} successful reinitialize cancels an old $outcome capability',
          () async {
        VlessPlatform.instance = adapter.value();
        final api = FlutterVless(onStatusChanged: (_) {});
        await api.initializeVless(
            providerBundleIdentifier: 'old.app', groupIdentifier: 'group.old');
        final pending = api.startVlessWithReport(
            remark: 'private-old-profile',
            config: config,
            certificateAssetsDirectory: privatePath);
        final refused = expectLater(pending, throwsA(cancelled()));
        await capabilityRequested.future;
        final replacement = FlutterVless(
            onStatusChanged: (_) {},
            options: const VlessOptions(
                protection:
                    ProtectionOptions(onDemand: OnDemandMode.disabled)));
        await replacement.initializeVless(
            providerBundleIdentifier: 'new.app', groupIdentifier: 'group.new');
        final initialization =
            calls.lastWhere((call) => call.method == 'initializeVless');
        expect(initialization.arguments['groupIdentifier'], 'group.new');
        expect(
            initialization.arguments['options'], replacement.options.toMap());
        switch (outcome) {
          case 'accepted':
            capability.complete({'certificateAssetsDirectory': true});
          case 'refused':
            capability.complete(<String, Object?>{});
          case 'transport error':
            capability.completeError(PlatformException(
                code: 'CAPABILITY_QUERY_FAILED',
                message: privateError,
                details: {'private-path': privatePath}));
        }
        await refused;
        expect(calls.where((call) => call.method == 'startVless'), isEmpty);
        await replacement.startVless(remark: 'new-profile', config: config);
        expect(
            calls
                .where((call) => call.method == 'startVless')
                .map((call) => call.arguments['remark']),
            ['new-profile']);
      });
    }

    test(
        '${adapter.key} failed reinitialize preserves pending Start and listener',
        () async {
      VlessPlatform.instance = adapter.value();
      final oldStates = <VlessConnectionState>[];
      final replacementStates = <VlessConnectionState>[];
      final api = FlutterVless(
          onStatusChanged: (state) => oldStates.add(state.connectionState));
      await api.initializeVless(
          providerBundleIdentifier: 'old.app', groupIdentifier: 'group.old');
      await emitStatus('DISCONNECTED');
      final pending = api.startVless(
          remark: 'private-old-profile',
          config: config,
          certificateAssetsDirectory: privatePath);
      await capabilityRequested.future;
      initializationFailure = PlatformException(code: 'INVALID_OPTIONS');
      final replacement = FlutterVless(
          onStatusChanged: (state) =>
              replacementStates.add(state.connectionState));
      await expectLater(
          replacement.initializeVless(
              providerBundleIdentifier: 'new.app',
              groupIdentifier: 'group.new'),
          throwsA(isA<PlatformException>()
              .having((error) => error.code, 'code', 'INVALID_OPTIONS')));
      await emitStatus('CONNECTED');
      expect(oldStates,
          [VlessConnectionState.disconnected, VlessConnectionState.connected]);
      expect(replacementStates, isEmpty);
      expect(subscriptions, ['listen']);
      capability.complete({'certificateAssetsDirectory': true});
      await pending;
      expect(
          calls
              .where((call) => call.method == 'startVless')
              .map((call) => call.arguments['remark']),
          ['private-old-profile']);
      await api.startVless(remark: 'new-profile', config: config);
      expect(
          calls
              .where((call) => call.method == 'startVless')
              .map((call) => call.arguments['remark']),
          ['private-old-profile', 'new-profile']);
    });

    test('${adapter.key} Stop cancels a pending capability-gated report start',
        () async {
      VlessPlatform.instance = adapter.value();
      final api = FlutterVless(onStatusChanged: (_) {});
      final pending = api.startVlessWithReport(
          remark: 'private-old-profile',
          config: config,
          certificateAssetsDirectory: privatePath);
      final refused = expectLater(pending, throwsA(cancelled()));
      await capabilityRequested.future;
      await api.stopVless();
      capability.complete({'certificateAssetsDirectory': true});
      await refused;
      expect(calls.map((call) => call.method),
          ['getSecurityCapabilities', 'stopVless']);
      // Stop invalidates old pending work, not future explicit connections.
      await api.startVless(remark: 'new-profile', config: config);
      expect(calls.last.method, 'startVless');
      expect(calls.last.arguments['remark'], 'new-profile');
    });

    test('${adapter.key} a newer Start supersedes older capability work',
        () async {
      VlessPlatform.instance = adapter.value();
      final api = FlutterVless(onStatusChanged: (_) {});
      final pending = api.startVless(
          remark: 'private-old-profile',
          config: config,
          certificateAssetsDirectory: privatePath);
      final refused = expectLater(pending, throwsA(cancelled()));
      await capabilityRequested.future;
      await api.startVless(remark: 'new-profile', config: config);
      capability.complete({'certificateAssetsDirectory': true});
      await refused;
      expect(
          calls
              .where((call) => call.method == 'startVless')
              .map((call) => call.arguments['remark']),
          ['new-profile']);
    });

    test('${adapter.key} cancellation wins over an old capability refusal',
        () async {
      VlessPlatform.instance = adapter.value();
      final api = FlutterVless(onStatusChanged: (_) {});
      final pending = api.startVless(
          remark: 'private-old-profile',
          config: config,
          certificateAssetsDirectory: privatePath);
      final refused = expectLater(pending, throwsA(cancelled()));
      await capabilityRequested.future;
      await api.stopVless();
      capability.complete(<String, Object?>{});
      await refused;
      expect(calls.where((call) => call.method == 'startVless'), isEmpty);
    });

    test('${adapter.key} cancellation stops further capability negotiation',
        () async {
      VlessPlatform.instance = adapter.value();
      final api = FlutterVless(onStatusChanged: (_) {});
      final pending = api.startVless(
          remark: 'private-old-profile',
          config: config,
          certificateAssetsDirectory: privatePath,
          vpnRouting: const VpnRoutingOptions(defaultOutboundTag: 'proxy'));
      final refused = expectLater(pending, throwsA(cancelled()));
      await capabilityRequested.future;
      await api.stopVless();
      capability
          .complete({'certificateAssetsDirectory': true, 'vpnRouting': true});
      await refused;
      expect(calls.map((call) => call.method),
          ['getSecurityCapabilities', 'stopVless']);
    });

    test('${adapter.key} cancellation masks a stale capability transport error',
        () async {
      VlessPlatform.instance = adapter.value();
      final api = FlutterVless(onStatusChanged: (_) {});
      final pending = api.startVless(
          remark: 'private-old-profile',
          config: config,
          certificateAssetsDirectory: privatePath);
      final refused = expectLater(pending, throwsA(cancelled()));
      await capabilityRequested.future;
      await api.startVless(remark: 'new-profile', config: config);
      capability.completeError(PlatformException(
          code: 'CAPABILITY_QUERY_FAILED',
          message: privateError,
          details: {
            'private-path': privatePath,
            'private-token': privateError
          }));
      await refused;
      expect(
          calls
              .where((call) => call.method == 'startVless')
              .map((call) => call.arguments['remark']),
          ['new-profile']);
    });
  }
}
