import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/url/xray_config_validator.dart';

Map<String, dynamic> profile(Object? geodata) => {
      'outbounds': [
        {'protocol': 'freedom', 'tag': 'direct'}
      ],
      'geodata': geodata,
    };

Map<String, dynamic> asset([String file = 'custom.dat']) => {
      'url': 'https://assets.example.test/custom.dat',
      'file': file,
    };

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('Core26.10.29 GeoDAT admission', () {
    final invalid = <String, Object>{
      'non-object section': 42,
      'non-string schedule': {'cron': 5},
      'explicit empty JSON cron': {'cron': ''},
      'non-string outbound': {'outbound': 5},
      'non-array assets': {'assets': 'custom.dat'},
      'null asset': {
        'assets': [null]
      },
      'non-string file': {
        'assets': [asset()..['file'] = 42]
      },
      'HTTP URL even without schedule': {
        'assets': [asset()..['url'] = 'http://assets.example.test/custom.dat']
      },
      'empty HTTPS host': {
        'assets': [asset()..['url'] = 'https:///custom.dat']
      },
      'missing URL': {
        'assets': [
          {'file': 'custom.dat'}
        ]
      },
      'active non-DAT target': {
        'cron': '@daily',
        'assets': [asset('script.lua')]
      },
      'active missing target': {
        'cron': '@daily',
        'assets': [asset('')]
      },
      'active101 assets': {
        'cron': '* * * * *',
        'assets': List.generate(101, (i) => asset('custom-$i.dat')),
      },
      for (final cron in [
        '@every 59s',
        '@every 59.999s',
        '@every 0s',
        '@every -1h',
        '@every .5m',
        '@every 59999999999ns',
        '@every 0.999999999999999999999m'
      ])
        'short interval $cron': {'cron': cron},
    };

    for (final entry in invalid.entries) {
      test('${entry.key} fails shared validation and raw import', () {
        final config = profile(entry.value);
        expect(() => const XrayConfigValidator().validate(config),
            throwsArgumentError);
        expect(
            () => FlutterVless.parse(jsonEncode(config)), throwsArgumentError);
      });
    }

    test('bad schedule fails Start before any platform call', () async {
      final client = FlutterVless(onStatusChanged: (_) {});
      await expectLater(
          client.startVless(
              remark: 'synthetic',
              config: jsonEncode(profile({'cron': '@every 59s'}))),
          throwsArgumentError);
    });

    for (final cron in [
      '* * * * *',
      '@every 1m',
      '@every 1m0s',
      '@every 1.5m',
      '@every 59s1000ms',
      '@every .5m30s',
      '@every 60000000000ns',
      '@daily'
    ]) {
      test('$cron and100 custom DAT assets preserve full config', () {
        final config = profile({
          'cron': cron,
          'outbound': 'direct',
          'assets': List.generate(100, (i) => asset('nested/custom-$i.DAT')),
          'opaque': {'future': true},
        });
        final before = jsonEncode(config);
        final imported = FlutterVless.parse(before);
        expect(jsonDecode(imported.getFullConfiguration())['geodata'],
            config['geodata']);
        expect(jsonEncode(config), before);
      });
    }

    test('null schedule preserves dormant upstream fields', () {
      for (final cron in [null]) {
        final config = profile({
          'cron': cron,
          'assets': List.generate(101, (i) => asset('dormant-$i.lua')),
        });
        expect(
            jsonDecode(FlutterVless.parse(jsonEncode(config))
                .getFullConfiguration())['geodata'],
            config['geodata']);
      }
    });

    test('reload-only schedule and null section need no asset files', () {
      for (final value in [
        null,
        {'cron': '@hourly'},
        {'cron': '@daily', 'assets': []}
      ]) {
        expect(() => FlutterVless.parse(jsonEncode(profile(value))),
            returnsNormally);
      }
    });

    test('HTTPS scheme case, userinfo and query retain upstream values', () {
      for (final url in [
        'HTTPS://assets.example.test/custom.dat',
        'https://user:password@assets.example.test/custom.dat?key=synthetic'
      ]) {
        final config = profile({
          'assets': [asset()..['url'] = url]
        });
        expect(
            jsonDecode(
                FlutterVless.parse(jsonEncode(config)).getFullConfiguration()),
            config);
      }
      final dormant = profile({
        'cron': null,
        'assets': [asset()..['file'] = null]
      });
      expect(
          jsonDecode(
              FlutterVless.parse(jsonEncode(dormant)).getFullConfiguration()),
          dormant);
    });

    test('Go schema aliases validate without rewriting keys or values', () {
      final config = {
        'outbounds': [
          {'protocol': 'freedom'}
        ],
        'GEODATA': {
          'Cron': '@daily',
          'Aſſets': [asset('nested/custom.DAT')],
          'Outbound': 'CaseSensitive'
        },
      };
      expect(
          jsonDecode(
              FlutterVless.parse(jsonEncode(config)).getFullConfiguration()),
          config);
      (config['GEODATA'] as Map)['Cron'] = '@every 59s';
      expect(() => FlutterVless.parse(jsonEncode(config)), throwsArgumentError);
    });
  });
}
