import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless_example/profile_import.dart';

// Synthetic credentials and reserved DNS names: these tests never contact a
// server and must not incorporate account links from a live acceptance run.
const _realityLink =
    'vless://22222222-2222-4222-8222-222222222222@reality.example.invalid:443'
    '?flow=xtls-rprx-vision&type=tcp&headerType=none&security=reality'
    '&fp=firefox&sni=cover.example.invalid'
    '&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&spx=/'
    '#%F0%9F%87%A7%F0%9F%87%BE%20Test%20Reality';
const _secondLink =
    'trojan://test-password@secondary.example.invalid:443'
    '?security=tls&type=tcp#Second';

Map<String, dynamic> _decode(String source) =>
    (jsonDecode(source) as Map).cast<String, dynamic>();

Map<String, dynamic> _firstOutbound(Map<String, dynamic> config) =>
    (config['outbounds'] as List).first as Map<String, dynamic>;

void main() {
  test('clipboard Reality import needs neither sid nor certificate files', () {
    final imported = importProfile(' \n$_realityLink\n ');
    final config = _decode(imported.config);
    final outbound = _firstOutbound(config);
    final server = ((outbound['settings'] as Map)['vnext'] as List).single;
    final user = (server['users'] as List).single;
    final stream = outbound['streamSettings'] as Map;

    expect(imported.remark, '🇧🇾 Test Reality');
    expect(outbound['protocol'], 'vless');
    expect(server['address'], 'reality.example.invalid');
    expect(server['port'], 443);
    expect(user['id'], '22222222-2222-4222-8222-222222222222');
    expect(user['encryption'], 'none');
    expect(user['flow'], 'xtls-rprx-vision');
    expect(stream['network'], 'tcp');
    expect(stream['security'], 'reality');
    expect(stream['realitySettings'], {
      'show': false,
      'fingerprint': 'firefox',
      'serverName': 'cover.example.invalid',
      'publicKey': 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
      'shortId': '',
      'spiderX': '/',
    });
    expect(stream.containsKey('tlsSettings'), isFalse);
    expect(config.containsKey('dns'), isFalse);
    expect(config['routing'], {'domainStrategy': 'AsIs'});
  });

  final sip002User = base64UrlEncode(
    utf8.encode('aes-128-gcm:synthetic:p@ss'),
  ).replaceAll('=', '');
  final vmessPayload = base64Encode(
    utf8.encode(
      jsonEncode({
        'v': '2',
        'ps': 'VMess import',
        'add': 'vmess.example.invalid',
        'port': '443',
        'id': '11111111-1111-4111-8111-111111111111',
        'aid': '0',
        'scy': 'auto',
        'net': 'ws',
        'type': 'none',
        'host': 'front.example.invalid',
        'path': '/vmess-stream',
        'tls': 'tls',
      }),
    ),
  );
  final shareLinks =
      <
        ({
          String name,
          String link,
          String protocol,
          String serverKey,
          String address,
          int port,
          String network,
          bool tls,
        })
      >[
        (
          name: 'VLESS WebSocket TLS',
          link:
              'vless://11111111-1111-4111-8111-111111111111'
              '@vless.example.invalid:443?type=ws&security=tls'
              '&sni=front.example.invalid&host=front.example.invalid'
              '&path=%2Fvless-stream#VLESS%20import',
          protocol: 'vless',
          serverKey: 'vnext',
          address: 'vless.example.invalid',
          port: 443,
          network: 'ws',
          tls: true,
        ),
        (
          name: 'Trojan gRPC TLS',
          link:
              'trojan://synthetic-password@trojan.example.invalid:443'
              '?type=grpc&security=tls&sni=front.example.invalid'
              '&serviceName=edge#Trojan%20import',
          protocol: 'trojan',
          serverKey: 'servers',
          address: 'trojan.example.invalid',
          port: 443,
          network: 'grpc',
          tls: true,
        ),
        (
          name: 'Shadowsocks SIP002',
          link: 'ss://$sip002User@ss.example.invalid:8388#Shadowsocks%20import',
          protocol: 'shadowsocks',
          serverKey: 'servers',
          address: 'ss.example.invalid',
          port: 8388,
          network: 'tcp',
          tls: false,
        ),
        (
          name: 'VMess JSON base64 WebSocket TLS',
          link: 'vmess://$vmessPayload',
          protocol: 'vmess',
          serverKey: 'vnext',
          address: 'vmess.example.invalid',
          port: 443,
          network: 'ws',
          tls: true,
        ),
      ];
  for (final fixture in shareLinks) {
    test('${fixture.name} crosses the example import boundary intact', () {
      final imported = importProfile(fixture.link);
      final outbound = _firstOutbound(_decode(imported.config));
      final settings = outbound['settings'] as Map;
      final server = (settings[fixture.serverKey] as List).single as Map;
      final stream = outbound['streamSettings'] as Map;

      expect(outbound['protocol'], fixture.protocol);
      expect(server['address'], fixture.address);
      expect(server['port'], fixture.port);
      expect(stream['network'], fixture.network);
      if (fixture.tls) {
        expect(stream['security'], 'tls');
        expect(
          (stream['tlsSettings'] as Map)['serverName'],
          'front.example.invalid',
        );
      } else {
        expect(stream['security'], anyOf(isNull, '', 'none'));
        expect(stream.containsKey('tlsSettings'), isFalse);
      }
      if (fixture.network == 'ws') {
        final ws = stream['wsSettings'] as Map;
        expect(ws['headers'], {'Host': 'front.example.invalid'});
        expect(ws['path'], '/${fixture.protocol}-stream');
      }
      if (fixture.protocol == 'shadowsocks') {
        expect(server['method'], 'aes-128-gcm');
        expect(server['password'], 'synthetic:p@ss');
      } else if (fixture.protocol == 'trojan') {
        expect(server['password'], 'synthetic-password');
        expect((stream['grpcSettings'] as Map)['serviceName'], 'edge');
      } else {
        expect(
          (server['users'] as List).single['id'],
          '11111111-1111-4111-8111-111111111111',
        );
      }
    });
  }

  final subscription =
      '# Список тестовых профилей\r\n'
      'https://subscription.example.invalid/not-a-profile\r\n'
      '$_realityLink\r\n\r\n$_secondLink\r\n';
  final encoded = base64Encode(utf8.encode(subscription));
  final urlEncoded = base64UrlEncode(
    utf8.encode(subscription),
  ).replaceAll('=', '');
  final wrapped = RegExp(
    '.{1,37}',
  ).allMatches(urlEncoded).map((part) => part.group(0)).join('\n');

  for (final variant in <String, String>{
    'plain link list': subscription,
    'base64 link list': encoded,
    'wrapped unpadded URL-safe base64 link list': wrapped,
  }.entries) {
    test('${variant.key} selects first supported profile without merging', () {
      final choices = FlutterVless.parseMany(variant.value);
      expect(choices.map((profile) => profile.remark), [
        '🇧🇾 Test Reality',
        'Second',
      ]);

      final imported = importProfile(variant.value);
      final config = _decode(imported.config);
      expect(imported.remark, '🇧🇾 Test Reality');
      expect(config, _decode(importProfile(_realityLink).config));
      expect(
        (config['outbounds'] as List).where(
          (outbound) => outbound['protocol'] == 'trojan',
        ),
        isEmpty,
      );
    });
  }

  test('complex JSON remains source-exact before native validation', () {
    // Import must not require local files, supported native transports, host
    // environment values or an active network. Admission performs those checks.
    const source = '''{
  "remarks": "Complete configuration",
  "dns": {
    "queryStrategy": "UseIP",
    "hosts": {"resolver.example.invalid": ["192.0.2.53", "2001:db8::53"]},
    "servers": [
      "https+local://resolver.example.invalid/dns-query?cache=1",
      {"address": "2001:db8::53", "domains": ["domain:example.invalid"], "futureResolverOption": null}
    ]
  },
  "inbounds": [
    {"tag": "first", "listen": "env:IMPORT_TEST_LISTEN", "port": "env:IMPORT_TEST_PORT", "protocol": "socks", "settings": {"auth": "password", "accounts": [{"user": "test", "pass": "synthetic"}]}},
    {"tag": "second", "listen": "127.0.0.1", "port": 10820, "protocol": "http"}
  ],
  "outbounds": [{"tag": "future", "protocol": "future-core-protocol", "settings": {"certificateFile": "not-present.pem", "extension": [{"enabled": true}, null]}}],
  "routing": {"rules": [{"inboundTag": ["second"], "domain": ["full:example.invalid"], "outboundTag": "future"}]},
  "futureRoot": {"dns": {"servers": ["untouched metadata"]}}
}''';
    final imported = importProfile('\n\t$source\n');

    expect(imported.config, source);
    expect(imported.remark, 'Complete configuration');
    expect(_decode(imported.config), _decode(source));
    expect((_decode(imported.config)['inbounds'] as List), hasLength(2));
  });

  for (final comment in [
    '# JSON profile\n',
    '// JSON profile\n',
    '/* JSON profile */\n',
    '/* Core retains a star across LF *\n/\n',
  ]) {
    test(
      'leading JSON comment retains source and malformed JSON errors: $comment',
      () {
        const json = '{"outbounds":[{"protocol":"freedom"}]}';
        expect(importProfile('$comment$json').config, '$comment$json');
        expect(
          () => importProfile('$comment{invalid JSON}'),
          throwsFormatException,
        );
      },
    );
  }

  test('base64 JSON subscription keeps the selected complete profile', () {
    final first = <String, dynamic>{
      'remarks': 'First full profile',
      'dns': {
        'hosts': {'resolver.example.invalid': '192.0.2.53'},
        'servers': [
          {
            'address': 'https://resolver.example.invalid/dns-query',
            'domains': ['domain:example.invalid'],
          },
        ],
      },
      'inbounds': [
        {'protocol': 'socks', 'listen': '127.0.0.1', 'port': 10808},
        {'protocol': 'http', 'listen': '127.0.0.1', 'port': 10820},
      ],
      'outbounds': [
        {'protocol': 'freedom', 'tag': 'direct'},
      ],
      'opaqueExtension': {
        'values': [null, true, 1, 'literal // # /* */'],
      },
    };
    final second = {
      'remarks': 'Second full profile',
      'outbounds': [
        {'protocol': 'blackhole', 'tag': 'block'},
      ],
    };
    final source = base64Encode(utf8.encode(jsonEncode([first, second])));

    final imported = importProfile(source);
    expect(imported.remark, 'First full profile');
    expect(_decode(imported.config), first);
    expect(FlutterVless.parseMany(source), hasLength(2));
  });

  test('malformed recognized link does not silently return a partial list', () {
    const malformed = 'vless://[';
    for (final source in [
      malformed,
      '$_realityLink\n$malformed',
      base64Encode(utf8.encode('$_realityLink\n$malformed')),
    ]) {
      expect(() => importProfile(source), throwsArgumentError);
    }
  });

  test('unterminated JSON comment cannot expose an embedded share link', () {
    expect(
      () => importProfile('/* unfinished JSON comment\n$_realityLink'),
      throwsFormatException,
    );
  });

  for (final source in ['', ' \n ', '[]', '{invalid JSON}', 'null', 'true']) {
    test('unsupported or invalid input cannot produce a profile: $source', () {
      expect(
        () => importProfile(source),
        throwsA(anyOf(isA<ArgumentError>(), isA<FormatException>())),
      );
    });
  }
}
