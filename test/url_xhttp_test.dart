import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/url/vless.dart';

import 'xray_config_test_utils.dart';

const xhttpNoneLink =
    'vless://22222222-2222-4222-8222-222222222222@:2043?type=xhttp&host=storage.example.com&path=/my-bucket&mode=stream-up&security=none';

const tcpRealityLink =
    'vless://22222222-2222-4222-8222-222222222222@:443?type=tcp&headerType=none&security=reality&fp=chrome&sni=reality.example.com&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0123456789abcdef&flow=xtls-rprx-vision#%D0%A4%D0%B8%D0%BD%D0%BB%D1%8F%D0%BD%D0%B4%D0%B8%D1%8F%20%E2%9A%A1%EF%B8%8F';

const visionSeedEncryption =
    'mlkem768x25519plus.native.1rtt.100-500-2000.75-0-100.80-0-5000.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';

void main() {
  group('P0 VLESS XHTTP/none', () {
    test('generates the expected XHTTP transport shape', () {
      final parsed = FlutterVless.parseFromURL(xhttpNoneLink);
      final config = decodedConfig(parsed);
      final inbound =
          (config['inbounds'] as List<dynamic>).first as Map<String, dynamic>;
      final server = firstVnextServer(config);
      final user = firstVnextUser(config);
      final stream = streamSettings(config);
      final xhttp = stream['xhttpSettings'] as Map<String, dynamic>;

      expect(parsed, isA<VlessURL>());
      expect(
        parsed.remark,
        '',
      );
      expect(config.containsKey('dns'), isFalse);
      expect(config['routing'], {'domainStrategy': 'AsIs'});
      expect(inbound['protocol'], 'socks');
      expect(inbound['listen'], '127.0.0.1');
      expect(inbound['port'], 10807);
      expect(inbound['settings'], containsPair('udp', true));
      expect(inbound['sniffing'], {
        'enabled': true,
        'destOverride': ['http', 'tls', 'quic'],
        'metadataOnly': false,
      });
      expect(proxyOutbound(config)['protocol'], 'vless');
      expect(
        server['address'],
        '',
      );
      expect(server['port'], 2043);
      expect(user['id'], '22222222-2222-4222-8222-222222222222');
      expect(user['encryption'], 'none');
      expect(user['security'], 'auto');
      expect(user['level'], 8);
      expect(user['flow'], '');
      expect(stream['network'], 'xhttp');
      expect(stream['security'], 'none');
      expect(stream.containsKey('tlsSettings'), isFalse);
      expect(stream.containsKey('realitySettings'), isFalse);
      expect(xhttp, {
        'host': 'storage.example.com',
        'mode': 'stream-up',
        'path': '/my-bucket',
      });
    });

    test('preserves Vision Seed encryption when it is present in the link', () {
      final link = xhttpNoneLink.replaceFirst(
        '&mode=stream-up',
        '&mode=stream-up&encryption=$visionSeedEncryption',
      );
      final config = decodedConfig(VlessURL(url: link));

      expect(firstVnextUser(config)['encryption'], visionSeedEncryption);
    });

    test('defaults missing XHTTP path/mode and decodes double encoded extra',
        () {
      const extra =
          '%257B%2522noGRPCHeader%2522%253Afalse%252C%2522scMaxConcurrentPosts%2522%253A100%252C%2522xPaddingBytes%2522%253A%2522100-1000%2522%257D';
      const link =
          'vless://00000000-0000-0000-0000-000000000000@example.com:8443?type=xhttp&host=cdn.example&security=none&extra=$extra#XHTTP';
      final config = decodedConfig(VlessURL(url: link));
      final xhttp =
          streamSettings(config)['xhttpSettings'] as Map<String, dynamic>;

      expect(xhttp['host'], 'cdn.example');
      expect(xhttp['mode'], 'auto');
      expect(xhttp['path'], '/');
      expect(xhttp['extra'], {
        'noGRPCHeader': false,
        'scMaxConcurrentPosts': 100,
        'xPaddingBytes': '100-1000',
      });
    });

    test('drops invalid XHTTP extra instead of emitting malformed JSON', () {
      const link =
          'vless://00000000-0000-0000-0000-000000000000@example.com:8443?type=xhttp&security=none&extra=not-json#XHTTP';
      final config = decodedConfig(VlessURL(url: link));
      final xhttp =
          streamSettings(config)['xhttpSettings'] as Map<String, dynamic>;

      expect(xhttp.containsKey('extra'), isFalse);
    });
  });

  group('P0 VLESS TCP/Reality', () {
    test('preserves the Reality transport fields', () {
      final config = decodedConfig(VlessURL(url: tcpRealityLink));
      final user = firstVnextUser(config);
      final stream = streamSettings(config);
      final tcp = stream['tcpSettings'] as Map<String, dynamic>;
      final reality = stream['realitySettings'] as Map<String, dynamic>;

      expect(firstVnextServer(config)['address'], '');
      expect(firstVnextServer(config)['port'], 443);
      expect(user['id'], '22222222-2222-4222-8222-222222222222');
      expect(user['flow'], 'xtls-rprx-vision');
      expect(user['encryption'], 'none');
      expect(stream['network'], 'tcp');
      expect(stream['security'], 'reality');
      expect(tcp['header'], {'type': 'none'});
      expect(reality['serverName'], 'reality.example.com');
      expect(reality['fingerprint'], 'chrome');
      expect(
          reality['publicKey'], 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8');
      expect(reality['shortId'], '0123456789abcdef');
      expect(reality['spiderX'], '');
    });

    test('imports the Reality fixture through the universal parser', () {
      final parsed = FlutterVless.parse(tcpRealityLink);
      final config = decodedConfig(parsed);

      expect(parsed, isA<VlessURL>());
      expect(parsed.remark, 'Финляндия ⚡️');
      expect(firstVnextServer(config)['address'], '');
      expect(streamSettings(config)['network'], 'tcp');
      expect(streamSettings(config)['security'], 'reality');
      expect(firstVnextUser(config)['flow'], 'xtls-rprx-vision');
      expect(firstVnextUser(config)['encryption'], 'none');
    });
  });
}
