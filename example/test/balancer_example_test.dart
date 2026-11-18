import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless_example/balancer_example.dart';
import 'package:flutter_vless_example/profile_import.dart';
import 'package:flutter_vless_example/routing_config.dart';

const _links = 'socks://127.0.0.1:12081\r\n\r\nsocks://127.0.0.1:12082';

void main() {
  for (final strategy in ExampleBalanceStrategy.values) {
    test('clipboard share links produce a ${strategy.name} balancer', () {
      final imported = importBalancerProfile(
        _links,
        strategy: strategy,
        probeUrl: Uri.parse('https://example.org/204'),
      );
      final config = jsonDecode(imported.config) as Map<String, dynamic>;
      final outbounds = config['outbounds'] as List<dynamic>;
      final group = config['routing']['balancers'].single;
      final expectedTags = outbounds
          .take(2)
          .map((node) => node['tag'])
          .toList();
      expect(group['selector'], expectedTags);
      expect(group['strategy']['type'], strategy.name);
      expect(config['routing']['rules'].last['balancerTag'], group['tag']);
      expect(outbounds.last, {'tag': 'direct', 'protocol': 'freedom'});
      expect(imported.remark, contains('2 nodes'));

      if (strategy == ExampleBalanceStrategy.leastPing ||
          strategy == ExampleBalanceStrategy.leastLoad) {
        final observer = strategy == ExampleBalanceStrategy.leastPing
            ? 'observatory'
            : 'burstObservatory';
        expect(config[observer]['subjectSelector'], expectedTags);
        expect(
          outbounds.singleWhere(
            (node) => node['tag'] == group['fallbackTag'],
          )['protocol'],
          'blackhole',
        );
      } else {
        expect(group, isNot(contains('fallbackTag')));
        expect(config, isNot(contains('observatory')));
        expect(config, isNot(contains('burstObservatory')));
      }

      final routed = jsonDecode(
        routingConfig(config: imported.config, selectedSites: ['example.org']),
      );
      expect(routed['routing']['rules'].first['outboundTag'], 'direct');
      expect(routed['routing']['rules'].last['balancerTag'], group['tag']);
    });
  }

  test('single links and raw JSON retain ordinary import', () {
    for (final input in [
      'socks://127.0.0.1:12081',
      '{\n // comment\n "outbounds":[{"protocol":"freedom"}],"future":null\n}',
    ]) {
      expect(importBalancerProfile(input), importProfile(input));
    }
  });

  test('a base64 subscription balances all supported share links', () {
    final payload = base64UrlEncode(
      utf8.encode('# Provider\n$_links'),
    ).replaceAll('=', '');
    expect(importBalancerProfile(payload), importBalancerProfile(_links));
  });

  test(
    'a pasted subscription URL is fetched once and imports all nodes',
    () async {
      final url = Uri.parse('https://example.org/subscription?token=fixture');
      final requests = <Uri>[];
      final profile = await importBalancerInput(
        '$url',
        fetch: (uri) async {
          requests.add(uri);
          return FlutterVless.parseMany(_links);
        },
      );
      expect(requests, [url]);
      expect(profile, importBalancerProfile(_links));
    },
  );

  test(
    'separate full JSON profiles keep their routing as separate profiles',
    () {
      const input =
          '[{"outbounds":[{"protocol":"freedom"}]},'
          '{"outbounds":[{"protocol":"blackhole"}]}]';
      expect(FlutterVless.parseMany(input), hasLength(2));
      expect(() => importBalancerProfile(input), throwsFormatException);
    },
  );

  test('identical proxy endpoints with different titles are deduplicated', () {
    final imported = importBalancerProfile(
      '$_links\nsocks://127.0.0.1:12081#copy',
    );
    expect(imported.remark, contains('2 nodes'));
  });

  test(
    'measured strategies require a probe and invalid links redact secrets',
    () {
      expect(
        () => importBalancerProfile(
          _links,
          strategy: ExampleBalanceStrategy.leastPing,
        ),
        throwsFormatException,
      );
      expect(
        () => importBalancerProfile(
          'socks://127.0.0.1:12081\nvmess://!private',
        ),
        throwsA(
          isA<FormatException>().having(
            (error) => error.toString(),
            'message',
            isNot(contains('private')),
          ),
        ),
      );
    },
  );
}
