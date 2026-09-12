import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';

const validConfig = '{"outbounds":[{"protocol":"freedom"}]}';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('flutter_vless');
  const statusChannel = MethodChannel('flutter_vless/status');
  late List<MethodCall> calls;

  setUp(() {
    calls = [];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      if (call.method == 'getServerDelay') {
        return 77;
      }
      if (call.method == 'getProviderDebugSnapshot') {
        return 'native diagnostics';
      }
      return null;
    });
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(statusChannel, (_) async => null);
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(statusChannel, null);
  });

  test('P0 startVless validates JSON before forwarding to native layer',
      () async {
    final plugin = FlutterVless(onStatusChanged: (_) {});

    await expectLater(
      plugin.startVless(remark: 'bad', config: 'not-json'),
      throwsArgumentError,
    );

    expect(calls, isEmpty);
  });

  test('P0 startVless validates Xray config shape before native layer',
      () async {
    final plugin = FlutterVless(onStatusChanged: (_) {});

    await expectLater(
      plugin.startVless(remark: 'bad', config: '{"outbounds":[]}'),
      throwsArgumentError,
    );
    await expectLater(
      plugin.startVless(remark: 'bad', config: '{"outbounds":[{}]}'),
      throwsArgumentError,
    );
    await expectLater(
      plugin.startVless(remark: 'bad', config: '[]'),
      throwsArgumentError,
    );

    expect(calls, isEmpty);
  });

  test('P0 startVless forwards validated tunnel parameters', () async {
    final plugin = FlutterVless(onStatusChanged: (_) {});

    await plugin.startVless(
      remark: 'API wrapper',
      config: validConfig,
      blockedApps: ['com.blocked.app'],
      bypassSubnets: ['172.16.0.0/12'],
      proxyOnly: false,
      geoAssetsDirectory: '/private/app-group/geodata',
      notificationDisconnectButtonName: 'STOP',
    );

    expect(calls, hasLength(1));
    expect(calls.single.method, 'startVless');
    expect(calls.single.arguments, {
      'remark': 'API wrapper',
      'config': validConfig,
      'blocked_apps': ['com.blocked.app'],
      'bypass_subnets': ['172.16.0.0/12'],
      'proxy_only': false,
      'geo_assets_directory': '/private/app-group/geodata',
      'notificationDisconnectButtonName': 'STOP',
    });
  });

  test('P0 startVless normalizes Xray 26.x incompatible config fields',
      () async {
    final plugin = FlutterVless(onStatusChanged: (_) {});

    await plugin.startVless(
      remark: 'Legacy raw JSON',
      config: jsonEncode({
        'outbounds': [
          {
            'protocol': 'vless',
            'streamSettings': {
              'network': 'XHTTP',
              'security': 'tls',
              'tlsSettings': {
                'allowInsecure': false,
                'serverName': 'edge.example.com',
              },
              'xHTTPSettings': {'path': '/'},
            },
          }
        ],
      }),
    );

    final sentConfig = jsonDecode(
      (calls.single.arguments as Map<Object?, Object?>)['config'] as String,
    ) as Map<String, dynamic>;
    final outbound = (sentConfig['outbounds'] as List<dynamic>).single
        as Map<String, dynamic>;
    final stream = outbound['streamSettings'] as Map<String, dynamic>;
    final tls = stream['tlsSettings'] as Map<String, dynamic>;

    expect(stream['network'], 'xhttp');
    expect(stream.containsKey('xHTTPSettings'), isFalse);
    expect(stream['xhttpSettings'], {'path': '/'});
    expect(tls.containsKey('allowInsecure'), isFalse);
  });

  test('P0 getServerDelay validates JSON and forwards probe URL', () async {
    final plugin = FlutterVless(onStatusChanged: (_) {});

    await expectLater(
      plugin.getServerDelay(config: 'not-json'),
      throwsArgumentError,
    );
    expect(calls, isEmpty);

    final delay = await plugin.getServerDelay(
      config: validConfig,
      url: 'https://example.com/generate_204',
    );

    expect(delay, 77);
    expect(calls, hasLength(1));
    expect(calls.single.method, 'getServerDelay');
    expect(calls.single.arguments, {
      'config': validConfig,
      'url': 'https://example.com/generate_204',
    });
  });

  test('P1 getProviderDebugSnapshot forwards to the native log method',
      () async {
    final plugin = FlutterVless(onStatusChanged: (_) {});

    expect(await plugin.getProviderDebugSnapshot(), 'native diagnostics');
    expect(calls, hasLength(1));
    expect(calls.single.method, 'getProviderDebugSnapshot');
    expect(calls.single.arguments, isNull);
  });
}
