import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless_example/profile_import.dart';
import 'package:integration_test/integration_test.dart';

/// Device-compiled import and sandbox-file checks only. This test deliberately
/// never initializes a VPN, requests VPN permission or starts a connection.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Device import preserves TLS identity and encoded credentials', (
    tester,
  ) async {
    final vmess =
        'vmess://${base64Encode(utf8.encode(jsonEncode({'v': '2', 'add': '192.0.2.10', 'port': '443', 'id': '11111111-1111-4111-8111-111111111111', 'aid': '0', 'net': 'ws', 'type': 'none', 'host': 'http-front.example.invalid', 'path': '/fixture', 'tls': 'tls', 'sni': 'certificate.example.invalid'})))}';
    final imported = importProfile(vmess.replaceFirst('vmess:', 'VMESS:'));
    final config = jsonDecode(imported.config) as Map<String, dynamic>;
    final stream = config['outbounds'][0]['streamSettings'] as Map;
    expect(imported.remark, '');
    expect(stream['tlsSettings']['serverName'], 'certificate.example.invalid');
    expect(
      stream['wsSettings']['headers']['Host'],
      'http-front.example.invalid',
    );

    const password = 'пароль+@:%2F';
    final trojan =
        jsonDecode(
              importProfile(
                'trojan://${Uri.encodeComponent(password)}@proxy.example.invalid:443?security=tls',
              ).config,
            )
            as Map;
    expect(
      trojan['outbounds'][0]['settings']['servers'][0]['password'],
      password,
    );

    const id = 'тест+%2F';
    final vless =
        jsonDecode(
              importProfile(
                'vless://${Uri.encodeComponent(id)}@proxy.example.invalid:443?security=tls',
              ).config,
            )
            as Map;
    expect(vless['outbounds'][0]['settings']['vnext'][0]['users'][0]['id'], id);

    final directory = await Directory.systemTemp.createTemp('xray-import-');
    try {
      final file = File('${directory.path}/profile.json');
      const full = {
        'outbounds': [
          {'protocol': 'freedom', 'tag': 'direct'},
        ],
        'extension': {
          'keep': [null, {}, [], '日本語 // # /* */'],
        },
      };
      await file.writeAsBytes(
        utf8.encode('\uFEFF// sandbox file\n${jsonEncode(full)}'),
      );
      final read = importProfile(await file.readAsString());
      expect(
        jsonDecode(FlutterVless.parse(read.config).getFullConfiguration()),
        full,
      );
    } finally {
      await directory.delete(recursive: true);
    }
  });
}
