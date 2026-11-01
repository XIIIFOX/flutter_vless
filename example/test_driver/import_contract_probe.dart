// Fixed synthetic inputs only. Safe to run with a disconnected example:
// no FlutterVless instance, native channel call, permission request or VPN start.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless_example/profile_import.dart';

Future<Map<String, Object?>> runAcceptanceImportContract({
  Future<Directory> Function()? createDirectory,
}) async {
  final vmess =
      'vmess://${base64Encode(utf8.encode(jsonEncode({'v': '2', 'add': '192.0.2.10', 'port': '443', 'id': '11111111-1111-4111-8111-111111111111', 'aid': '0', 'net': 'ws', 'type': 'none', 'host': 'http-front.example.invalid', 'path': '/fixture', 'tls': 'tls', 'sni': 'certificate.example.invalid'})))}';
  final imported = importProfile(vmess.replaceFirst('vmess:', 'VMESS:'));
  final config = jsonDecode(imported.config) as Map<String, dynamic>;
  final stream = config['outbounds'][0]['streamSettings'] as Map;
  const password = 'пароль+@:%2F';
  final trojan =
      jsonDecode(
            importProfile(
              'trojan://${Uri.encodeComponent(password)}@proxy.example.invalid:443?security=tls',
            ).config,
          )
          as Map;
  const id = 'тест+%2F';
  final vless =
      jsonDecode(
            importProfile(
              'vless://${Uri.encodeComponent(id)}@proxy.example.invalid:443?security=tls',
            ).config,
          )
          as Map;
  final directory =
      await (createDirectory ??
          () => Directory.systemTemp.createTemp('xray-import-'))();
  Object? sandboxConfiguration;
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
    sandboxConfiguration = jsonDecode(
      FlutterVless.parse(read.config).getFullConfiguration(),
    );
  } finally {
    await directory.delete(recursive: true);
  }
  return {
    'version': 1,
    'probe': 'synthetic_import_contract',
    'vmessRemark': imported.remark,
    'vmessSni': stream['tlsSettings']['serverName'],
    'vmessHttpHost': stream['wsSettings']['headers']['Host'],
    'trojanPassword':
        trojan['outbounds'][0]['settings']['servers'][0]['password'],
    'vlessId': vless['outbounds'][0]['settings']['vnext'][0]['users'][0]['id'],
    'sandboxConfiguration': sandboxConfiguration,
  };
}
