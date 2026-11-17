import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';

void main() {
  const root = CorePath.root;

  test('JSONC and a detached edit preserve authored structure', () {
    final original = XrayProfile.fromJson('''
      {
        // Imported spelling and unknown siblings belong to the user.
        "Version": {"Min": "26.10", "max": "27", "future": null},
        "future": {"feature.with.dot": [null, {}, [], {"Case": true}]}
      }
    ''');
    final supplied = [
      {'new': 1}
    ];
    late XrayProfileDraft retained;
    final edited = original.edit((draft) {
      retained = draft;
      draft.requireCoreAtLeast('26.11.9');
      draft.setRaw(root.key('future').key('added'), supplied);
      draft.setRaw(root.key('future').key('explicitNull'), null);
    });
    supplied.single['new'] = 2;
    retained.setRaw(root.key('future').key('later'), 'draft-only');
    final exported = edited.toCoreMap();
    exported['future']['added'][0]['new'] = 3;
    expect(edited.toCoreMap(), {
      'Version': {'Min': '26.11.9', 'max': '27', 'future': null},
      'future': {
        'feature.with.dot': [
          null,
          {},
          [],
          {'Case': true}
        ],
        'added': [
          {'new': 1}
        ],
        'explicitNull': null,
      },
    });
    expect(original.toCoreMap()['Version']['Min'], '26.10');
    expect(original.toCoreMap()['future'].keys, ['feature.with.dot']);
    expect(XrayProfile.fromJson(edited.toCoreJson()).toCoreMap(),
        edited.toCoreMap());
  });

  test('a failed edit leaves the source independent of the draft', () {
    final input = {
      'future': [1, 2, 3]
    };
    final original = XrayProfile.fromMap(input);
    expect(
        () => original.edit((draft) {
              draft.removeRaw(root.key('future').index(1));
              draft.setRaw(root.key('future').index(1), 9);
            }),
        throwsStateError);
    expect(original.toCoreMap(), {
      'future': [1, 2, 3]
    });
    input['future']!.clear();
    expect(original.toCoreMap(), {
      'future': [1, 2, 3]
    });
  });

  test('replacements are explicit and null differs from removing a key', () {
    final original = XrayProfile.fromMap({
      'nested': {
        'value': true,
        'list': [1, 2]
      },
    });
    final nested = root.key('nested');
    final edited = original.edit((draft) {
      draft.setRaw(nested.key('value'), null);
      draft.setRaw(nested.key('list'), [3]);
      draft.removeRaw(nested.key('value'), replace: true);
    });
    expect(edited.toCoreMap(), {
      'nested': {
        'list': [3]
      },
    });
    expect(
        () => original.edit((draft) {
              draft.setRaw(nested.key('missing').key('child'), true);
            }),
        throwsArgumentError);
  });

  test('minimum preserves stronger pins and rejects ambiguous or invalid range',
      () {
    final pinned =
        XrayProfile.fromJson('{"version":{"min":"26.12","max":"27"}}');
    expect(
        pinned.edit((draft) => draft.requireCoreAtLeast('26.11.9')).toCoreMap(),
        pinned.toCoreMap());
    expect(() => pinned.edit((draft) => draft.requireCoreAtLeast('28')),
        throwsArgumentError);
    final ambiguous =
        XrayProfile.fromJson('{"version":{"min":"26","Min":"27"}}');
    expect(() => ambiguous.edit((draft) => draft.requireCoreAtLeast('26.11.9')),
        throwsArgumentError);
  });

  test('non-JSON and cyclic objects are rejected without logging values', () {
    expect(() => XrayProfile.fromMap({'nested': DateTime(2026)}),
        throwsArgumentError);
    final cyclic = <String, dynamic>{};
    cyclic['cycle'] = cyclic;
    expect(() => XrayProfile.fromMap(cyclic), throwsArgumentError);
    expect(() => XrayProfile.fromMap({'nonfinite': double.nan}),
        throwsArgumentError);
  });

  test('a copied typed group cannot lose its Blackhole or observer', () {
    final profile = XrayProfile.build((draft) {
      final direct = draft
          .addNode(ProxyNode.fromMap({'protocol': 'freedom', 'tag': 'direct'}));
      final group = draft.addGroup(
        nodes: [direct],
        strategy: const BalanceStrategy.leastPing(),
        fallback: const GroupFallback.block(),
      );
      draft.setHealthProbe(
          HealthProbe.http(Uri.parse('http://localhost/probe')));
      draft.setDefaultRoute(RouteTarget.group(group));
    });
    final group = root.key('routing').key('balancers').index(0);
    expect(
        () =>
            profile.edit((draft) => draft.removeRaw(group.key('fallbackTag'))),
        throwsArgumentError);
    expect(
        () => profile.edit((draft) => draft.setRaw(
            root.key('outbounds').index(1).key('protocol'), 'freedom')),
        throwsArgumentError);
    expect(
        () => profile.edit((draft) => draft.removeRaw(root.key('observatory'))),
        throwsArgumentError);
  });

  test('editing the generated default keeps new specific routes ahead of it',
      () {
    final profile = XrayProfile.build((draft) {
      draft.setDefaultRoute(const RouteTarget.block());
    });
    final changed = profile.edit((draft) {
      draft.addRule(RouteRule.domains(['full:one.example'],
          to: const RouteTarget.block()));
      draft.setDefaultRoute(const RouteTarget.direct());
    });
    final rules = changed.toCoreMap()['routing']['rules'] as List;
    expect(rules.length, 2);
    expect(rules.first['domain'], ['full:one.example']);
    expect(rules.last['network'], 'tcp,udp');
    expect(
        changed.toCoreMap()['outbounds'].singleWhere((outbound) =>
            outbound['tag'] == rules.last['outboundTag'])['protocol'],
        'freedom');
    final imported = XrayProfile.fromJson(profile.toCoreJson());
    expect(
        () => imported
            .edit((draft) => draft.setDefaultRoute(const RouteTarget.direct())),
        throwsArgumentError);
  });

  test('typed additions avoid a preserved imported selector prefix', () {
    final profile = XrayProfile.fromMap({
      'routing': {
        'balancers': [
          {
            'tag': 'legacy',
            'selector': ['fv-profile-']
          }
        ],
      },
      'outbounds': [
        {'tag': 'fv-profile-legacy', 'protocol': 'freedom'},
      ],
    });
    final updated = profile.edit(
        (draft) => draft.addNode(ProxyNode.fromMap({'protocol': 'freedom'})));
    final tag = updated.toCoreMap()['outbounds'][1]['tag'] as String;
    expect(tag.startsWith('fv-profile-'), isFalse);
    expect(updated.toCoreMap()['routing'], profile.toCoreMap()['routing']);
  });

  test('typed tags escape when imported selectors cover every numeric suffix',
      () {
    final selectors = [
      for (var digit = 1; digit <= 9; digit++) 'fv-profile-node-$digit',
    ];
    final imported = XrayProfile.fromMap({
      'routing': {
        'balancers': [
          {'tag': 'legacy', 'selector': selectors}
        ],
      },
      'outbounds': <Object?>[],
    });
    final updated = imported.edit(
        (draft) => draft.addNode(ProxyNode.fromMap({'protocol': 'freedom'})));
    final tag = updated.toCoreMap()['outbounds'][0]['tag'] as String;
    expect(selectors.any(tag.startsWith), isFalse);
    expect(updated.toCoreMap()['routing'], imported.toCoreMap()['routing']);
  });

  test('an imported array-form catch-all cannot shadow a typed default', () {
    final profile = XrayProfile.fromMap({
      'routing': {
        'rules': [
          {
            'type': 'field',
            'network': ['tcp', 'udp'],
            'outboundTag': 'old',
          },
        ],
      },
    });
    expect(
        () => profile
            .edit((draft) => draft.setDefaultRoute(const RouteTarget.block())),
        throwsArgumentError);
  });
}
