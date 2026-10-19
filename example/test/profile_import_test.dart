import 'dart:convert';
import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless_example/profile_import.dart';

void main() {
  final dnsProfiles =
      (jsonDecode(
                File(
                  '../tool/fixtures/compatibility/dns-data-maps.json',
                ).readAsStringSync(),
              )
              as List<dynamic>)
          .cast<Map<String, dynamic>>();
  for (final profile in dnsProfiles) {
    test('DNS data survives example import: ${profile['name']}', () {
      final config = profile['config'] as Map<String, dynamic>;
      final source = jsonEncode(config);
      for (final input in [source, '[$source]']) {
        expect(jsonDecode(importProfile(input).config), config);
      }
      expect(jsonEncode(config), source);
    });
  }

  test('Raw JSON retains existing remark aliases', () {
    for (final key in ['remarks', 'remark', 'ps']) {
      final input = jsonEncode({
        key: 'Profile title',
        'outbounds': [
          {'protocol': 'freedom'},
        ],
      });
      expect(importProfile(input).remark, 'Profile title');
    }
  });
  test(
    'Subscription arrays still import their first supported full profile',
    () {
      final profile = {
        'remarks': 'First profile',
        'outbounds': [
          {'protocol': 'freedom'},
        ],
      };
      final imported = importProfile(
        jsonEncode([
          profile,
          {...profile, 'remarks': 'Second profile'},
        ]),
      );
      expect(imported.remark, 'First profile');
      expect(
        jsonDecode(imported.config)['outbounds'][0]['protocol'],
        'freedom',
      );
    },
  );
  test(
    'Full JSON keeps all listeners, passwords, routing and unknown fields',
    () {
      const text =
          '''{"remarks":"Full profile","inbounds":[{"protocol":"socks","port":10808,"settings":{"auth":"noauth"}},{"protocol":"http","port":10820,"settings":{"accounts":[{"user":"local","pass":"password"}]}}],"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[{"inboundTag":["second"],"outboundTag":"direct"}]},"futureField":{"value":true}}''';
      final imported = importProfile('  $text  ');
      expect(imported.config, text);
      expect(imported.remark, 'Full profile');
      expect(jsonDecode(imported.config)['inbounds'], hasLength(2));
    },
  );
  test('Invalid JSON and non-object documents report import errors', () {
    expect(() => importProfile('{invalid}'), throwsFormatException);
    expect(() => importProfile('[]'), throwsFormatException);
  });
  test('JSONC/BOM imports keep the full source and quoted comment markers', () {
    const source =
        '// profile\n{"remarks":"JSONC // # /* */","outbounds":[{"protocol":"freedom"}],"extension":{"keep":true}}';
    final imported = importProfile('\uFEFF$source');
    expect(imported.remark, 'JSONC // # /* */');
    expect(imported.config, source);
  });
  test('Share links continue to use the protocol parser', () {
    final imported = importProfile(
      'vless://22222222-2222-4222-8222-222222222222@example.com:443?security=tls&type=tcp#Example',
    );
    expect(imported.remark, 'Example');
    expect(jsonDecode(imported.config)['outbounds'][0]['protocol'], 'vless');
  });
}
