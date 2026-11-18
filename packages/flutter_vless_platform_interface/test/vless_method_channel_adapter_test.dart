import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless_platform_interface/flutter_vless_platform_interface.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('flutter_vless/test');

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('diagnostics contract uses getProviderDebugSnapshot wire method',
      () async {
    MethodCall? received;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      received = call;
      return 'bounded diagnostics';
    });
    final adapter = VlessMethodChannelAdapter(methodChannel: channel);

    expect(await adapter.getProviderDebugSnapshot(), 'bounded diagnostics');
    expect(received?.method, 'getProviderDebugSnapshot');
    expect(received?.arguments, isNull);
  });

  test('diagnostics contract converts a null native result to empty text',
      () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (_) async => null);
    final adapter = VlessMethodChannelAdapter(methodChannel: channel);

    expect(await adapter.getProviderDebugSnapshot(), isEmpty);
  });

  test('balancer diagnostics decode private numeric selections in order',
      () async {
    MethodCall? received;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      received = call;
      return '4,1,2\n5,1,1\n6,1,2';
    });
    final adapter = VlessMethodChannelAdapter(methodChannel: channel);
    final choices = await adapter.getBalancerSelections();

    expect(received?.method, 'getBalancerSelections');
    expect(received?.arguments, isNull);
    expect(choices.map((row) => (row.sequence, row.group, row.node)),
        [(4, 1, 2), (5, 1, 1), (6, 1, 2)]);
    expect(choices.clear, throwsUnsupportedError);
  });

  test('balancer diagnostics reject untrusted text, invalid rows and overflow',
      () async {
    for (final reply in [
      'balancer choices pending for secret.example',
      '1,1,2\n2,1,secret.example',
      '1,1,2\n1,1,1',
      '1,1,0',
      '1,1,9999999999999999999',
      List.generate(301, (index) => '${index + 1},1,2').join('\n'),
      {'unsolicited': 'secret.example'},
    ]) {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (_) async => reply);
      final adapter = VlessMethodChannelAdapter(methodChannel: channel);

      expect(await adapter.getBalancerSelections(), isEmpty);
    }
  });

  test('older backends can omit the balancer diagnostics method', () async {
    final adapter = VlessMethodChannelAdapter(methodChannel: channel);

    expect(await adapter.getBalancerSelections(), isEmpty);
  });

  test('Core capability decoder retains only the version and known flags', () {
    final capabilities = VlessCoreCapabilities.fromNativeReply({
      'coreVersion': 'Xray 26.11.9 (secret.example)',
      'profileValidation': true,
      'xdrive': 'true',
      'future': 'secret.example',
    });
    expect(capabilities.coreVersion, '26.11.9');
    expect(capabilities.profileValidation, isTrue);
    expect(capabilities.xdrive, isFalse);
    expect(
        VlessCoreCapabilities.fromNativeReply(
            {'coreVersion': '/private/26.11.9'}).coreVersion,
        isNull);
  });

  test(
      'profile result validates authored entry locations and drops arbitrary text',
      () {
    final result = VlessProfileValidation.fromNativeReply({
      'status': 'invalid',
      'stage': 'coreCheck',
      'section': 'outbounds',
      'index': 2,
      'message': 'secret.example',
    });
    expect(result.status, VlessProfileValidationStatus.invalid);
    expect(result.stage, VlessProfileValidationStage.coreCheck);
    expect(result.section, VlessProfileSection.outbounds);
    expect(result.index, 2);
    for (final wire in [
      null,
      'valid',
      {'status': 'future'},
      {'status': true}
    ]) {
      expect(VlessProfileValidation.fromNativeReply(wire).status,
          VlessProfileValidationStatus.unavailable);
    }
    for (final index in [-1, 2147483648, '2']) {
      final bad = VlessProfileValidation.fromNativeReply({
        'status': 'invalid',
        'stage': 'secret.example',
        'section': 'inbounds',
        'index': index,
      });
      expect((bad.stage, bad.section, bad.index), (null, null, null));
    }
  });
}
