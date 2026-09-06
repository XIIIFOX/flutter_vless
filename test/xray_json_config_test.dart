import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/url/xray_config.dart';

import 'xray_config_test_utils.dart';

const visionSeedEncryption =
    'mlkem768x25519plus.native.1rtt.100-500-2000.75-0-100.80-0-5000.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';

void main() {
  group('P0 raw Xray JSON import', () {
    test('preserves VLESS Encryption from Happ-style JSON config', () {
      final rawJson = jsonEncode({
        'remarks': 'Happ XHTTP JSON',
        'inbounds': [
          {
            'listen': '127.0.0.1',
            'port': 10808,
            'protocol': 'socks',
            'settings': {'auth': 'noauth', 'udp': true},
          }
        ],
        'outbounds': [
          {
            'tag': 'proxy',
            'protocol': 'vless',
            'settings': {
              'vnext': [
                {
                  'address': '',
                  'port': 2043,
                  'users': [
                    {
                      'id': '22222222-2222-4222-8222-222222222222',
                      'encryption': visionSeedEncryption,
                      'level': 8,
                      'security': 'auto',
                    }
                  ],
                }
              ],
            },
            'streamSettings': {
              'network': 'XHTTP',
              'security': 'tls',
              'tlsSettings': {
                'allowInsecure': false,
                'serverName': 'edge.example.com',
                'alpn': ['h3'],
              },
              'xHTTPSettings': {
                'host': 'storage.example.com',
                'mode': 'stream-up',
                'path': '/my-bucket',
              },
            },
          }
        ],
        'routing': {'domainStrategy': 'AsIs'},
      });

      final parsed = FlutterVless.parse(rawJson);
      final config = decodedConfig(parsed);

      expect(parsed, isA<XrayJsonConfig>());
      expect(parsed.remark, 'Happ XHTTP JSON');
      expect(firstVnextUser(config)['encryption'], visionSeedEncryption);
      expect(streamSettings(config)['network'], 'xhttp');
      expect(streamSettings(config)['security'], 'tls');
      expect(streamSettings(config).containsKey('xHTTPSettings'), isFalse);
      expect(streamSettings(config)['xhttpSettings'], {
        'host': 'storage.example.com',
        'mode': 'stream-up',
        'path': '/my-bucket',
      });
      expect(
        (streamSettings(config)['tlsSettings'] as Map<String, dynamic>)
            .containsKey('allowInsecure'),
        isFalse,
      );
    });

    test('accepts JSON arrays by selecting the first config object', () {
      final rawJson = jsonEncode([
        {
          'remarks': 'First JSON config',
          'outbounds': [
            {'tag': 'direct', 'protocol': 'freedom'}
          ],
        },
        {
          'remarks': 'Second JSON config',
          'outbounds': [
            {'tag': 'proxy', 'protocol': 'blackhole'}
          ],
        },
      ]);

      final parsed = FlutterVless.parse(rawJson);

      expect(parsed.remark, 'First JSON config');
      expect(proxyOutbound(decodedConfig(parsed))['protocol'], 'freedom');
    });

    test('rejects JSON without outbounds', () {
      expect(
        () => FlutterVless.parse('{"remarks":"Broken"}'),
        throwsArgumentError,
      );
    });
  });
}
