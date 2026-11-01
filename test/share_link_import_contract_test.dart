import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/flutter_vless_ios.dart';
import 'package:flutter_vless_android/flutter_vless_android.dart';
import 'package:flutter_vless_macos/flutter_vless_macos.dart';
import 'package:flutter_vless_windows/flutter_vless_windows.dart';

import 'xray_config_test_utils.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final vmessFields = {
    'v': '2',
    'add': '192.0.2.10',
    'port': '443',
    'id': '11111111-1111-4111-8111-111111111111',
    'aid': '0',
    'net': 'ws',
    'type': 'none',
    'host': 'http-front.example.invalid',
    'path': '/fixture',
    'tls': 'tls',
    'sni': 'certificate.example.invalid',
  };
  final vmess = vmessLink(vmessFields);

  test('VMess explicit TLS identity is independent of WebSocket Host', () {
    final config = decodedConfig(FlutterVless.parse(vmess));
    final stream = streamSettings(config);
    expect((stream['tlsSettings'] as Map)['serverName'],
        'certificate.example.invalid');
    expect((stream['wsSettings'] as Map)['headers'],
        {'Host': 'http-front.example.invalid'});
  });

  test('VMess optional display name does not prevent config import', () {
    final parsed = FlutterVless.parse(vmess);
    expect(parsed.remark, '');
    expect(decodedConfig(parsed)['outbounds'], isNotEmpty);
  });

  for (final sni in [null, '']) {
    test('VMess absent/empty SNI keeps the transport Host fallback: $sni', () {
      final fields = {...vmessFields}..remove('sni');
      if (sni != null) fields['sni'] = sni;
      final config = decodedConfig(FlutterVless.parse(vmessLink(fields)));
      expect((streamSettings(config)['tlsSettings'] as Map)['serverName'],
          'http-front.example.invalid');
      expect(firstVnextServer(config)['address'], '192.0.2.10');
    });
  }

  for (final credential in ['p@ss:word+with/%2F', 'пароль+%25']) {
    test('Trojan authentication decodes once: $credential', () {
      final encoded = Uri.encodeComponent(credential);
      final config = decodedConfig(FlutterVless.parse(
        'trojan://$encoded@proxy.example.invalid:443?security=tls',
      ));
      expect(firstOutboundServer(config)['password'], credential);
    });
  }

  test('VLESS custom ID decodes UTF-8 and reserved characters once', () {
    const id = 'тест+%2F';
    final config = decodedConfig(FlutterVless.parse(
      'vless://${Uri.encodeComponent(id)}@proxy.example.invalid:443?security=tls',
    ));
    expect(firstVnextUser(config)['id'], id);
  });

  test('case-insensitive URI schemes preserve case-sensitive payloads', () {
    for (final link in [
      vmess,
      'vless://11111111-1111-4111-8111-111111111111@proxy.example.invalid:443?security=tls&sni=TLS.example.invalid',
      'trojan://CaseSensitivePassword@proxy.example.invalid:443?security=tls',
      'ss://${base64UrlNoPadding('aes-128-gcm:CaseSensitivePassword')}@proxy.example.invalid:8388',
      'socks://CaseSensitiveUser:CaseSensitivePassword@proxy.example.invalid:1080',
      'hy2://CaseSensitivePassword@proxy.example.invalid:443?sni=TLS.example.invalid',
    ]) {
      final split = link.indexOf('://');
      final uppercase =
          link.substring(0, split).toUpperCase() + link.substring(split);
      final expected = decodedConfig(FlutterVless.parseFromURL(link));
      expect(decodedConfig(FlutterVless.parseFromURL(uppercase)), expected);
      expect(decodedConfig(FlutterVless.parse(uppercase)), expected);
      expect(decodedConfig(FlutterVless.parseMany(uppercase).single), expected);
    }
  });

  test('UTF-8 file/subscription import carries identity to all four adapters',
      () async {
    final directory = await Directory.systemTemp.createTemp('vless-import-');
    addTearDown(() => directory.delete(recursive: true));
    final file = File('${directory.path}/profiles.txt');
    await file
        .writeAsBytes(utf8.encode('\uFEFF${base64Encode(utf8.encode(vmess))}'));
    final imported = FlutterVless.parseMany(await file.readAsString()).single;
    final config = imported.getFullConfiguration();
    final calls = <MethodCall>[];
    const channel = MethodChannel('flutter_vless');
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return call.method == 'getServerDelay' ? 17 : null;
    });
    final previous = VlessPlatform.instance;
    addTearDown(() {
      VlessPlatform.instance = previous;
      messenger.setMockMethodCallHandler(channel, null);
    });
    for (final adapter in <VlessPlatform>[
      FlutterVlessIOS(),
      FlutterVlessAndroid(),
      FlutterVlessMacos(),
      FlutterVlessWindows(),
    ]) {
      VlessPlatform.instance = adapter;
      calls.clear();
      final api = FlutterVless(onStatusChanged: (_) {});
      await api.startVless(remark: imported.remark, config: config);
      expect(await api.getServerDelay(config: config), 17);
      expect(
          calls.map((call) => call.method), ['startVless', 'getServerDelay']);
      for (final call in calls) {
        final native = jsonDecode((call.arguments as Map)['config'] as String)
            as Map<String, dynamic>;
        final stream = streamSettings(native);
        expect((stream['tlsSettings'] as Map)['serverName'],
            'certificate.example.invalid');
        expect((stream['wsSettings'] as Map)['headers'],
            {'Host': 'http-front.example.invalid'});
      }
    }
  });
}
