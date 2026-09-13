import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless_example/routing.dart';
import 'package:flutter_vless_example/routing_config.dart';

Map<String, dynamic> fixture() => {
      'dns': {
        'servers': ['localhost'],
        'queryStrategy': 'UseIPv4'
      },
      'outbounds': [
        {
          'protocol': 'socks',
          'tag': 'proxy',
          'settings': {
            'servers': [
              {'address': '127.0.0.1', 'port': 19090}
            ]
          }
        },
        {
          'protocol': 'freedom',
          'tag': 'direct',
          'settings': {'domainStrategy': 'UseIPv4'}
        },
      ],
      'inbounds': [
        {
          'protocol': 'socks',
          'listen': '127.0.0.1',
          'port': 19091,
          'sniffing': {
            'enabled': false,
            'destOverride': ['tls', 'quic'],
            'routeOnly': true,
            'domainsExcluded': ['excluded.invalid'],
          },
        },
      ],
      'routing': {
        'domainStrategy': 'IPIfNonMatch',
        'rules': [
          {
            'type': 'field',
            'ip': ['192.0.2.1'],
            'outboundTag': 'direct'
          },
          {
            'type': 'field',
            'domain': ['domain:custom.invalid'],
            'outboundTag': 'proxy'
          },
        ],
      },
    };

void main() {
  testWidgets('Reopening routing shows the applied domains', (tester) async {
    await tester.pumpWidget(const MaterialApp(
      home: Routing(
        config: '{}',
        blockedApps: [],
        blockedDomains: ['2ip.io'],
      ),
    ));

    final field = tester.widget<TextField>(find.byType(TextField).first);
    expect(field.controller!.text, '2ip.io');
  });

  test('Domain bypass does not expand to shared destination IPs', () {
    final result = jsonDecode(routingConfig(
      config: jsonEncode(fixture()),
      selectedSites: ['2ip.io', '2ip.io'],
    )) as Map;
    final rules = result['routing']['rules'] as List;
    expect(rules.first, {
      'type': 'field',
      'ruleTag': exampleBypassRuleTag,
      'domain': ['domain:2ip.io'],
      'outboundTag': 'direct',
    });
    expect(rules.skip(1).toList(), fixture()['routing']['rules']);
    expect(result['outbounds'], fixture()['outbounds']);
    expect(result['dns'], fixture()['dns']);
    expect(result['routing']['domainStrategy'], 'IPIfNonMatch');
  });

  test('Replace and clear remove old editor rules while keeping imported rules',
      () {
    final original = jsonEncode(fixture());
    final first = routingConfig(config: original, selectedSites: ['myip.com']);
    final second = routingConfig(config: first, selectedSites: ['2ip.io']);
    expect(routingDomainsFromConfig(second), ['domain:2ip.io']);
    expect(jsonDecode(second)['routing']['rules'], hasLength(3));
    expect(routingConfig(config: second, selectedSites: ['2ip.io']), second);
    final cleared = jsonDecode(routingConfig(config: second));
    expect(cleared['routing'], fixture()['routing']);
    expect(cleared['outbounds'], fixture()['outbounds']);
  });

  test('Sniffing retains exclusions and includes HTTP, TLS and QUIC', () {
    final result = jsonDecode(routingConfig(
        config: jsonEncode(fixture()), selectedSites: ['2ip.io']));
    final sniffing = result['inbounds'][0]['sniffing'];
    expect(sniffing['enabled'], true);
    expect(sniffing['destOverride'], unorderedEquals(['http', 'tls', 'quic']));
    expect(sniffing['routeOnly'], true);
    expect(sniffing['domainsExcluded'], ['excluded.invalid']);
  });

  test('Domain suffixes and explicit rules keep their matching boundaries', () {
    expect(normalizeDomainEntry(' https://2ip.io/check '), 'domain:2ip.io');
    expect(normalizeDomainEntry('full:myip.com'), 'full:myip.com');
    expect(normalizeDomainEntry('domain:ru'), 'domain:ru');
    for (final input in ['.io', '*.io']) {
      final regex = RegExp(normalizeDomainEntry(input).substring(7));
      expect(regex.hasMatch('2ip.io'), true);
      expect(regex.hasMatch('www.2ip.io'), true);
      expect(regex.hasMatch('myip.com'), false);
      expect(regex.hasMatch('2ip.io.attacker.com'), false);
    }
  });

  test('Missing direct outbound fails instead of emitting a broken rule', () {
    expect(() => routingConfig(config: '{}', selectedSites: ['2ip.io']),
        throwsFormatException);
    expect(jsonDecode(routingConfig(config: '{}')), isEmpty);
  });

  testWidgets('Clear and Apply remove saved bypass on screen', (tester) async {
    String? applied;
    final config = routingConfig(
        config: jsonEncode(fixture()), selectedSites: ['myip.com']);
    await tester.pumpWidget(MaterialApp(
      home: Routing(
        config: config,
        blockedApps: const [],
        blockedDomains: const [],
        onApplyConfig: (value) => applied = value,
      ),
    ));
    expect(
        tester.widget<TextField>(find.byType(TextField).first).controller!.text,
        'domain:myip.com');
    await tester.tap(find.text('Clear'));
    await tester.tap(find.text('Apply rules'));
    await tester.pump();
    expect(jsonDecode(applied!)['routing'], fixture()['routing']);
  });
}
