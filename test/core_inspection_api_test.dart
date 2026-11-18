import 'dart:async';
import 'dart:convert';

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
  const config = '{"outbounds":[{"protocol":"freedom"}]}';
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  final controller = FlutterVless(onStatusChanged: (_) {});
  final backends = <String, VlessPlatform Function()>{
    'Android': FlutterVlessAndroid.new,
    'iOS': FlutterVlessIOS.new,
    'macOS': FlutterVlessMacos.new,
    'Windows': FlutterVlessWindows.new,
  };
  late VlessPlatform previous;

  setUp(() => previous = VlessPlatform.instance);
  tearDown(() {
    VlessPlatform.instance = previous;
    messenger.setMockMethodCallHandler(channel, null);
  });

  for (final backend in backends.entries) {
    test('${backend.key} inspects profiles without initialization or startup',
        () async {
      VlessPlatform.instance = backend.value();
      final calls = <MethodCall>[];
      messenger.setMockMethodCallHandler(channel, (call) async {
        calls.add(call);
        return switch (call.method) {
          'getCoreCapabilities' => {
              'coreVersion': 'Xray 26.11.9 (build banner)',
              'profileValidation': true,
              'geoDataUpdates': true,
              'xdrive': true,
              'vpnRouting': true,
              'balancerSelections': false,
            },
          'validateProfile' => {'status': 'valid'},
          _ => throw StateError('Unexpected lifecycle call'),
        };
      });
      final source = XrayProfile.fromJson('''
        // An unrecognized Core field must reach the native checker.
        {"outbounds":[{"protocol":"freedom"}], "futureCoreField":{"opaque":true}}
      ''');
      final caps = await controller.getCoreCapabilities();
      expect(caps.coreVersion, '26.11.9');
      expect(caps.profileValidation, isTrue);
      expect(caps.geoDataUpdates && caps.xdrive && caps.vpnRouting, isTrue);
      expect(caps.balancerSelections, isFalse);
      final result = await controller.validateProfile(source,
          geoAssetsDirectory: '/fixture/assets',
          certificateAssetsDirectory: '/fixture/certificates');
      expect(result.status, VlessProfileValidationStatus.valid);
      expect(calls.map((call) => call.method),
          ['getCoreCapabilities', 'validateProfile']);
      expect(calls.first.arguments, isNull);
      final args = calls.last.arguments as Map;
      expect(jsonDecode(args['config'] as String), source.toCoreMap());
      expect(args['geo_assets_directory'], '/fixture/assets');
      expect(args['certificate_assets_directory'], '/fixture/certificates');
    });

    test('${backend.key} inspection does not supersede a pending start',
        () async {
      VlessPlatform.instance = backend.value();
      final pending = Completer<Object?>();
      final requested = Completer<void>();
      final calls = <String>[];
      messenger.setMockMethodCallHandler(channel, (call) async {
        calls.add(call.method);
        if (call.method == 'getSecurityCapabilities') {
          requested.complete();
          return pending.future;
        }
        return call.method == 'validateProfile' ? {'status': 'valid'} : null;
      });
      final start = controller.startVless(
          remark: 'profile',
          config: config,
          certificateAssetsDirectory: '/fixture');
      await requested.future;
      expect((await controller.validateProfileJson(config)).status,
          VlessProfileValidationStatus.valid);
      pending.complete({'certificateAssetsDirectory': true});
      await start;
      expect(
          calls, ['getSecurityCapabilities', 'validateProfile', 'startVless']);
    });
  }

  test('malformed JSON returns a closed preparation error locally', () async {
    messenger.setMockMethodCallHandler(channel, (_) async {
      fail('Invalid JSON must not invoke native code');
    });
    const privateInput = 'not a configuration with secret.example';
    final result = await controller.validateProfileJson(privateInput);
    expect(result.status, VlessProfileValidationStatus.invalid);
    expect(result.stage, VlessProfileValidationStage.prepare);
    expect(result.index, isNull);
    expect(result.toString(), isNot(contains('secret.example')));
  });

  test('older and unavailable channels use conservative outcomes', () async {
    VlessPlatform.instance = MethodChannelVlessPlatform();
    expect((await controller.getCoreCapabilities()).profileValidation, isFalse);
    expect((await controller.validateProfileJson(config)).status,
        VlessProfileValidationStatus.unsupported);
    messenger.setMockMethodCallHandler(channel, (_) async {
      throw PlatformException(code: 'native', message: 'secret.example');
    });
    expect((await controller.getCoreCapabilities()).coreVersion, isNull);
    expect((await controller.validateProfileJson(config)).status,
        VlessProfileValidationStatus.unavailable);
  });
}
