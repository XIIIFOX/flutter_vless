import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';

const _key1 = '11111111-1111-4111-8111-111111111111';
const _key2 = '22222222-2222-4222-8222-222222222222';

FlutterVlessURL _link(String host, String label, {String credential = _key1}) =>
    FlutterVless.parse('vless://$credential@$host:443?type=tcp#$label');

FlutterVlessURL _raw(String remark, Map<String, dynamic> extra) =>
    FlutterVless.parse(jsonEncode({
      'remarks': remark,
      'outbounds': [
        {'protocol': 'freedom', 'tag': 'direct'},
      ],
      ...extra,
    }));

void main() {
  test('selected ID survives reorder, rename and a unique credential rotation',
      () {
    final first = _link('one.example', 'One');
    final second = _link('two.example', 'Two');
    final initial = XraySubscription.fromProfiles([first, second]);
    final selected = initial.select(initial.nodes.first.id);
    final edited = selected.editProfile(selected.selectedNodeId!, (draft) {
      draft.setRaw(CorePath.root.key('dns'), {
        'servers': ['1.1.1.1'],
      });
    });

    final rotated = _link('one.example', 'Renamed', credential: _key2);
    final result = edited.refresh([second, rotated]);
    final node = result.subscription.selectedNode!;
    expect(result.subscription.nodes.map((node) => node.remark),
        ['Two', 'Renamed']);
    expect(node.id, same(selected.selectedNodeId));
    expect(node.profile.toCoreMap()['dns'], {
      'servers': ['1.1.1.1']
    });
    expect(node.profile.toCoreMap()['outbounds'],
        rotated.fullConfiguration['outbounds']);
    expect(node.sourceProfile.toCoreMap().containsKey('dns'), isFalse);
    expect(result.removedNodes, isEmpty);
    expect(result.conflictedNodeIds, isEmpty);
    expect(initial.selectedNodeId, isNull);
    expect(edited.selectedNode!.remark, 'One');
    expect(edited.selectedNode!.profile.toCoreJson(), contains(_key1));
  });

  test('raw profiles merge separate dictionary changes, nulls and deletions',
      () {
    final source = _raw('Before', {
      'future': {'nullHere': 'before', 'deleted': 1, 'old': true},
    });
    final previous = XraySubscription.fromProfiles([source]);
    final id = previous.nodes.single.id;
    final future = CorePath.root.key('future');
    final edited = previous.select(id).editProfile(id, (draft) {
      draft.removeRaw(future.key('deleted'));
      draft.setRaw(future.key('nullHere'), null);
      draft.setRaw(future.key('clientOnly'), true);
      draft.setRaw(CorePath.root.key('newObject'), {'client': 'value'});
    });
    final next = _raw('After', {
      'future': {'remote': 2, 'deleted': 1, 'nullHere': 'before'},
      'newObject': {'provider': true},
    });
    final refreshed = edited.refresh([next]);
    final merged = refreshed.subscription.selectedNode!.profile.toCoreMap();
    expect(
        merged['future'], {'remote': 2, 'nullHere': null, 'clientOnly': true});
    expect(merged['newObject'], {'provider': true, 'client': 'value'});
    expect(merged['remarks'], 'After');
    expect(refreshed.conflictedNodeIds, isEmpty);
    expect(previous.nodes.single.profile.toCoreMap()['future'], {
      'nullHere': 'before',
      'deleted': 1,
      'old': true,
    });
  });

  test('concurrent array changes retain local list and expose latest source',
      () {
    final initial =
        XraySubscription.fromProfiles([_link('node.example', 'Node')]);
    final id = initial.nodes.single.id;
    final tag = CorePath.root.key('outbounds').index(0).key('tag');
    final edited = initial.select(id).editProfile(id, (draft) {
      draft.setRaw(tag, 'local-tag');
    });
    final rotated = _link('node.example', 'Node', credential: _key2);
    final result = edited.refresh([rotated]);
    final node = result.subscription.selectedNode!;
    expect(node.profile.toCoreJson(), contains('local-tag'));
    expect(node.profile.toCoreJson(), contains(_key1));
    expect(node.sourceProfile.toCoreJson(), contains(_key2));
    expect(result.conflictedNodeIds, {id});
    final reset = result.subscription.resetProfile(id);
    expect(reset.selectedNode!.profile, same(node.sourceProfile));
    expect(edited.selectedNode!.profile.toCoreJson(), contains('local-tag'));
  });

  test('ambiguous identical nodes never inherit ID, local edits or selection',
      () {
    final source = _link('duplicate.example', 'A');
    final duplicate = _link('duplicate.example', 'B');
    final initial = XraySubscription.fromProfiles([source, duplicate]);
    final id = initial.nodes.last.id;
    final edited = initial.select(id).editProfile(id, (draft) {
      draft.setRaw(CorePath.root.key('local'), true);
    });

    final result = edited.refresh([duplicate, source]);
    expect(result.subscription.selectedNode, isNull);
    expect(result.conflictedNodeIds, isEmpty);
    expect(result.removedNodes.map((node) => node.id),
        initial.nodes.map((node) => node.id));
    expect(result.removedNodes.last.profile.toCoreMap()['local'], isTrue);
    expect(
        result.subscription.nodes
            .every((node) => !node.profile.toCoreMap().containsKey('local')),
        isTrue);
    expect(result.subscription.nodes.map((node) => node.remark), ['B', 'A']);
  });

  test(
      'unchanged exact match does not enable a fallback for duplicate endpoints',
      () {
    final source = _link('duplicate.example', 'A');
    final alternate = _link('duplicate.example', 'B', credential: _key2);
    final old = XraySubscription.fromProfiles([source, alternate]);
    final chosen = old.select(old.nodes.last.id);
    const newCredential = '33333333-3333-4333-8333-333333333333';
    final third = _link('duplicate.example', 'C', credential: newCredential);
    final result = chosen.refresh([source, third]);
    expect(result.subscription.nodes.first.id, same(old.nodes.first.id));
    expect(result.subscription.selectedNodeId, isNull);
    expect(result.removedNodes.single.id, same(chosen.selectedNodeId));
  });

  test('explicit provider IDs can cover readdressing and reject duplicates',
      () {
    final one = _link('one.example', 'node-1');
    final previous =
        XraySubscription.fromProfiles([one], sourceId: (url) => url.remark);
    final id = previous.nodes.single.id;
    final edited = previous.select(id).editProfile(id, (draft) {
      draft.setRaw(CorePath.root.key('local'), true);
    });
    final moved = _link('moved.example', 'node-1', credential: _key2);
    final result = edited.refresh([moved]);
    expect(result.subscription.selectedNodeId, same(id));
    expect(
        result.subscription.selectedNode!.profile.toCoreMap()['local'], isTrue);
    expect(result.subscription.selectedNode!.profile.toCoreMap()['outbounds'],
        moved.fullConfiguration['outbounds']);
    expect(result.removedNodes, isEmpty);

    final duplicate = result.subscription.refresh([moved, one]);
    expect(duplicate.subscription.selectedNodeId, isNull);
    expect(duplicate.removedNodes.single.id, same(id));
    expect(id.toString(), isNot(contains('node-1')));
    expect(id.toString(), isNot(contains('one.example')));
  });

  test(
      'unchanged selected raw profile is independent of source map and member ordering',
      () {
    final source = _raw('Label', {
      'future': {'b': 2, 'a': 1}
    });
    final initial = XraySubscription.fromProfiles([source]);
    final id = initial.nodes.single.id;
    source.fullConfiguration['future'] = 'outside change';
    expect(
        initial.nodes.single.profile.toCoreMap()['future'], {'a': 1, 'b': 2});
    final incoming = _raw('Renamed', {
      'future': {'a': 1, 'b': 2}
    });
    final result = initial.select(id).refresh([incoming]);
    expect(result.subscription.selectedNodeId, same(id));
    expect(result.subscription.selectedNode!.remark, 'Renamed');
    expect(result.removedNodes, isEmpty);
  });

  test('failure, deletion and unrelated IDs leave existing state intact', () {
    final source = _link('node.example', 'Node');
    final initial = XraySubscription.fromProfiles([source], sourceId: (url) {
      if (url.remark == 'Error') {
        throw StateError('application callback failed');
      }
      return null;
    });
    final id = initial.nodes.single.id;
    final selected = initial.select(id);
    final unrelated = XraySubscription.fromProfiles([source]).nodes.single.id;
    expect(() => selected.select(unrelated), throwsArgumentError);
    expect(() => selected.refresh([source, _link('node.example', 'Error')]),
        throwsStateError);
    expect(selected.selectedNode!.id, same(id));
    expect(selected.nodes, hasLength(1));
    expect(selected.select(null).selectedNode, isNull);

    final deleted = selected.refresh([]);
    expect(deleted.subscription.nodes, isEmpty);
    expect(deleted.subscription.selectedNode, isNull);
    expect(deleted.removedNodes.single, same(selected.selectedNode));
    expect(() => deleted.removedNodes.clear(), throwsUnsupportedError);
    expect(() => selected.nodes.clear(), throwsUnsupportedError);
  });
}
