import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/xray_profile.dart';

void main() {
  test('native VPN fixture uses the routing emitted by the Dart builder', () {
    final fixture = jsonDecode(
        File('tool/fixtures/compatibility/typed-profile-balancer.json')
            .readAsStringSync()) as Map<String, dynamic>;
    ProxyNode socks(String address) => ProxyNode.fromMap({
          'protocol': 'socks',
          'settings': {
            'servers': [
              {'address': address, 'port': 1080}
            ]
          }
        });
    final profile = XrayProfile.build((draft) {
      final first = draft.addNode(socks('192.0.2.10'));
      final second = draft.addNode(socks('192.0.2.20'));
      final group = draft.addGroup(
        nodes: [first, second],
        strategy: const BalanceStrategy.leastPing(),
        fallback: const GroupFallback.block(),
      );
      draft.setHealthProbe(HealthProbe.http(
        Uri.parse('http://192.0.2.88/profile-observe'),
        interval: const Duration(milliseconds: 250),
        enableConcurrency: true,
      ));
      draft.addRule(RouteRule.domains(['full:profile-direct.invalid'],
          to: const RouteTarget.direct()));
      draft.setDefaultRoute(RouteTarget.group(group));
    });
    final generated = profile.toCoreMap();
    for (final key in ['outbounds', 'routing', 'observatory']) {
      expect(generated[key], fixture[key], reason: key);
    }
  });

  test('share links receive distinct tags in the same balancer', () {
    final profile = XrayProfile.build((draft) {
      final first = draft.addNode(ProxyNode.fromLink('socks://127.0.0.1:1234'));
      final second =
          draft.addNode(ProxyNode.fromLink('socks://127.0.0.1:1235'));
      final group = draft.addGroup(
        nodes: [first, second],
        strategy: const BalanceStrategy.roundRobin(),
      );
      draft.setDefaultRoute(RouteTarget.group(group));
    });

    final json = profile.toCoreMap();
    final outbounds = json['outbounds'] as List;
    final tags = outbounds
        .where((outbound) => outbound['protocol'] == 'socks')
        .map((outbound) => outbound['tag'])
        .toList();
    final group = json['routing']['balancers'][0];
    expect(tags, hasLength(2));
    expect(tags.toSet(), hasLength(2));
    expect(group['selector'], unorderedEquals(tags));
    expect(group['strategy']['type'], 'roundRobin');
    expect(group, isNot(contains('fallbackTag')));
  });

  test('serializes least-load settings and its burst probe', () {
    final profile = XrayProfile.build((draft) {
      final node = draft.addNode(ProxyNode.fromMap({
        'tag': 'custom-node',
        'protocol': 'freedom',
      }));
      final group = draft.addGroup(
        nodes: [node],
        strategy: BalanceStrategy.leastLoad(
          expected: 1,
          maxRtt: const Duration(milliseconds: 250),
          baselines: const [Duration(milliseconds: 100)],
          tolerance: 0.25,
        ),
        fallback: const GroupFallback.block(),
      );
      draft.setHealthProbe(HealthProbe.burst(
        Uri.parse('https://example.org/health'),
        interval: const Duration(seconds: 12),
        timeout: const Duration(seconds: 1),
        sampling: 3,
      ));
      draft.setDefaultRoute(RouteTarget.group(group));
    });

    final json = profile.toCoreMap();
    final group = json['routing']['balancers'][0];
    expect(group['strategy'], {
      'type': 'leastLoad',
      'settings': {
        'expected': 1,
        'maxRTT': '250000us',
        'baselines': ['100000us'],
        'tolerance': 0.25,
      },
    });
    expect(json['burstObservatory'], {
      'subjectSelector': ['custom-node'],
      'pingConfig': {
        'destination': 'https://example.org/health',
        'interval': '12000000us',
        'timeout': '1000000us',
        'sampling': 3,
      },
    });
    expect(json, isNot(contains('observatory')));
  });

  test('typed nodes and raw strategy settings take independent snapshots', () {
    final outbound = {
      'protocol': 'freedom',
      'futureOutboundField': [true],
    };
    final settings = {
      'futureStrategyField': [1],
    };
    final node = ProxyNode.fromMap(outbound);
    final strategy = BalanceStrategy.raw(
      type: 'futureStrategy',
      settings: settings,
    );
    (outbound['futureOutboundField'] as List).clear();
    settings['futureStrategyField']!.clear();

    final profile = XrayProfile.build((draft) {
      final group = draft.addGroup(
        nodes: [draft.addNode(node)],
        strategy: strategy,
      );
      draft.setDefaultRoute(RouteTarget.group(group));
    });
    final json = profile.toCoreMap();
    final group = json['routing']['balancers'][0];
    final nodeJson = (json['outbounds'] as List).singleWhere(
      (outbound) => outbound['tag'] == group['selector'][0],
    );
    expect(nodeJson['futureOutboundField'], [true]);
    expect(group['strategy'], {
      'type': 'futureStrategy',
      'settings': {
        'futureStrategyField': [1],
      },
    });
  });

  test('specific direct rule precedes group catch-all with explicit fallback',
      () {
    final profile = XrayProfile.build((draft) {
      final node = draft.addNode(ProxyNode.fromMap({
        'tag': 'measured-node',
        'protocol': 'freedom',
      }));
      final group = draft.addGroup(
        nodes: [node],
        strategy: const BalanceStrategy.leastPing(),
        fallback: const GroupFallback.direct(),
      );
      draft.setHealthProbe(
          HealthProbe.http(Uri.parse('http://127.0.0.1/health')));
      draft.setDefaultRoute(RouteTarget.group(group));
      draft.addRule(RouteRule.domains(['full:direct.example.org'],
          to: const RouteTarget.direct()));
    });

    final json = profile.toCoreMap();
    final group = json['routing']['balancers'][0];
    final fallback = (json['outbounds'] as List)
        .singleWhere((outbound) => outbound['tag'] == group['fallbackTag']);
    expect(fallback['protocol'], 'freedom');
    expect(fallback['tag'], isNot('measured-node'));
    expect(group['selector'], ['measured-node']);
    expect(json['observatory'], {
      'subjectSelector': ['measured-node'],
      'probeURL': 'http://127.0.0.1/health',
    });
    expect(json['routing']['rules'], [
      {
        'type': 'field',
        'domain': ['full:direct.example.org'],
        'outboundTag': group['fallbackTag'],
      },
      {'type': 'field', 'network': 'tcp,udp', 'balancerTag': group['tag']},
    ]);
  });

  test('measured strategies require a fallback and compatible observer', () {
    expect(
      () => XrayProfile.build((draft) {
        final node = draft.addNode(ProxyNode.fromMap({'protocol': 'freedom'}));
        draft.addGroup(
            nodes: [node], strategy: const BalanceStrategy.leastPing());
      }),
      throwsA(isA<ArgumentError>()
          .having((error) => error.message, 'message', contains('fallback'))),
    );
    expect(
      () => XrayProfile.build((draft) {
        final node = draft.addNode(ProxyNode.fromMap({'protocol': 'freedom'}));
        draft.addGroup(
          nodes: [node],
          strategy: const BalanceStrategy.leastPing(),
          fallback: const GroupFallback.block(),
        );
      }),
      throwsArgumentError,
    );
    expect(
      () => XrayProfile.build((draft) {
        final node = draft.addNode(ProxyNode.fromMap({'protocol': 'freedom'}));
        draft.addGroup(
          nodes: [node],
          strategy: BalanceStrategy.leastLoad(),
          fallback: const GroupFallback.block(),
        );
        draft.setHealthProbe(
            HealthProbe.http(Uri.parse('http://127.0.0.1/health')));
      }),
      throwsArgumentError,
    );
  });

  test('rejects references from a different draft or a replaced entry', () {
    late final NodeRef foreign;
    XrayProfile.build((draft) {
      foreign = draft.addNode(ProxyNode.fromMap({'protocol': 'freedom'}));
    });
    expect(
      () => XrayProfile.build((draft) {
        draft.addNode(ProxyNode.fromMap({'protocol': 'freedom'}));
        draft.addGroup(
            nodes: [foreign], strategy: const BalanceStrategy.random());
      }),
      throwsArgumentError,
    );
    final source = XrayProfile.fromMap({
      'outbounds': [
        {'protocol': 'freedom', 'tag': 'original'},
      ],
    });
    expect(
      () => source.edit((draft) {
        final stale = draft.nodeAt(0);
        draft.setRaw(CorePath.root.key('outbounds').index(0), {
          'protocol': 'freedom',
          'tag': 'original',
          'future': true,
        });
        draft.addRule(RouteRule.domains(['domain:example.org'],
            to: RouteTarget.node(stale)));
      }),
      throwsArgumentError,
    );
    expect(
        (source.toCoreMap()['outbounds'][0] as Map), isNot(contains('future')));
  });

  test('adds to an imported observer using its existing key spelling', () {
    final source = XrayProfile.fromMap({
      'Outbounds': [
        {'Protocol': 'freedom', 'Tag': 'new-member'},
      ],
      'BurstObservatory': {
        'SubjectSelector': ['existing-member'],
        'PingConfig': {
          'destination': 'http://127.0.0.1/health',
          'future': [],
        },
      },
    });
    final edited = source.edit((draft) {
      draft.addGroup(
        nodes: [draft.nodeAt(0)],
        strategy: BalanceStrategy.leastLoad(),
        fallback: const GroupFallback.block(),
      );
    });
    final original = source.toCoreMap();
    final json = edited.toCoreMap();
    expect(json, isNot(contains('burstObservatory')));
    expect(json['BurstObservatory'], {
      'SubjectSelector': ['existing-member', 'new-member'],
      'PingConfig': original['BurstObservatory']['PingConfig'],
    });
    expect(
        original['BurstObservatory']['SubjectSelector'], ['existing-member']);
  });

  test('rejects Core prefix selectors that would also match a different node',
      () {
    expect(
      () => XrayProfile.build((draft) {
        final node = draft.addNode(ProxyNode.fromMap({
          'protocol': 'freedom',
          'tag': 'member',
        }));
        draft.addNode(ProxyNode.fromMap({
          'protocol': 'freedom',
          'tag': 'member-extra',
        }));
        draft.addGroup(nodes: [node], strategy: const BalanceStrategy.random());
      }),
      throwsArgumentError,
    );
  });
}
