import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless_companion/src/companion_controller.dart';
import 'package:flutter_vless_companion/src/local_api_server.dart';

const validConfig = '''
{
  "inbounds": [
    {
      "tag": "in_proxy",
      "listen": "127.0.0.1",
      "port": 19080,
      "protocol": "socks",
      "settings": {"auth": "noauth", "udp": true}
    }
  ],
  "outbounds": [
    {"protocol": "freedom"}
  ]
}
''';

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
          return switch (call.method) {
            'getCoreVersion' => 'Xray test',
            'getServerDelay' => 12,
            _ => null,
          };
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

  test(
    'connect starts local proxy-only runtime without system proxy',
    () async {
      final controller = CompanionController();
      await controller.initialize();

      await controller.connect(
        config: validConfig,
        remark: 'Browser profile',
        setSystemProxy: false,
      );

      final startCall = calls.singleWhere(
        (call) => call.method == 'startVless',
      );
      expect(startCall.arguments, containsPair('proxy_only', true));
      expect(startCall.arguments, containsPair('set_system_proxy', false));
      expect(controller.proxyEndpoint.toJson(), {
        'scheme': 'socks5',
        'host': '127.0.0.1',
        'port': 19080,
      });
    },
  );

  test('local API requires token and forwards connect command', () async {
    final previousOverrides = HttpOverrides.current;
    HttpOverrides.global = null;
    addTearDown(() => HttpOverrides.global = previousOverrides);

    final tempDir = await Directory.systemTemp.createTemp('vless_api_test_');
    final controller = CompanionController();
    final server = LocalApiServer(
      controller: controller,
      preferredPort: 0,
      stateFilePath: '${tempDir.path}/state.json',
    );
    await server.start();
    addTearDown(() async {
      await server.dispose();
      await tempDir.delete(recursive: true);
    });

    final client = HttpClient();
    addTearDown(() => client.close(force: true));

    final unauthorized = await client.getUrl(
      Uri.parse('${server.origin}/status'),
    );
    final unauthorizedResponse = await unauthorized.close();
    expect(unauthorizedResponse.statusCode, HttpStatus.unauthorized);

    final request = await client.postUrl(Uri.parse('${server.origin}/connect'));
    request.headers
      ..set(HttpHeaders.authorizationHeader, 'Bearer ${server.token}')
      ..contentType = ContentType.json;
    request.write(jsonEncode({'config': validConfig, 'setSystemProxy': false}));
    final response = await request.close();
    final text = await utf8.decoder.bind(response).join();

    expect(response.statusCode, HttpStatus.ok);
    expect(jsonDecode(text), containsPair('state', 'DISCONNECTED'));
    final startCall = calls.singleWhere((call) => call.method == 'startVless');
    expect(startCall.arguments, containsPair('set_system_proxy', false));
  });
}
