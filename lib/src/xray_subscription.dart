// Copyright (c) 2024-2026 13FOX Studio / tfox.dev.
// SPDX-License-Identifier: MIT

import 'dart:convert';

import '../url/url.dart';
import '../url/xray_config_model.dart' show JsonMap;
import '../url/xray_json.dart' show readXraySchemaField;
import '../xray_profile.dart';

/// Returns a provider's stable node identifier, when one is available.
///
/// Return `null` to use built-in matching. Provide unique nonempty IDs across
/// refreshes. IDs are compared exactly and kept private inside the snapshot.
typedef XraySubscriptionSourceId = String? Function(FlutterVlessURL source);

/// An opaque node identifier retained across unambiguous refreshes.
///
/// It belongs to a subscription snapshot and its descendants. It contains no
/// URL or profile data and is intended for in-memory selection.
final class XraySubscriptionNodeId {
  XraySubscriptionNodeId._();
}

/// A source node and its current configuration, including any local edits.
final class XraySubscriptionNode {
  XraySubscriptionNode._(
      this.id, this.remark, this.sourceProfile, this.profile, this._identity);

  /// Identity used for selections and local edits in this subscription.
  final XraySubscriptionNodeId id;

  /// The latest display label supplied by the source.
  final String remark;

  /// The latest source configuration before local edits.
  final XrayProfile sourceProfile;

  /// The effective configuration with local edits applied.
  final XrayProfile profile;

  final _SourceIdentity _identity;

  XraySubscriptionNode _withProfile(XrayProfile profile) =>
      XraySubscriptionNode._(id, remark, sourceProfile, profile, _identity);
}

/// The result of refreshing one immutable subscription snapshot.
final class XraySubscriptionRefresh {
  XraySubscriptionRefresh._(
      this.subscription,
      Iterable<XraySubscriptionNode> removed,
      Iterable<XraySubscriptionNodeId> conflicted)
      : removedNodes = List.unmodifiable(removed),
        conflictedNodeIds = Set.unmodifiable(conflicted);

  /// The updated snapshot in the provider's latest order.
  final XraySubscription subscription;

  /// Previous nodes with no unambiguous match, including their local edits.
  final List<XraySubscriptionNode> removedNodes;

  /// Matched nodes with competing changes to the same value.
  ///
  /// The effective profile retains the local value. The new source value
  /// remains available through [XraySubscriptionNode.sourceProfile].
  final Set<XraySubscriptionNodeId> conflictedNodeIds;
}

/// An immutable list of subscribed nodes, local edits and optional selection.
///
/// Use [fromProfiles] with parsed or downloaded profiles. [refresh] is a
/// synchronous comparison of snapshots and has no network or disk effects.
final class XraySubscription {
  XraySubscription._(
      Iterable<XraySubscriptionNode> nodes, this.selectedNodeId, this._sourceId)
      : nodes = List.unmodifiable(nodes);

  /// Captures independent snapshots of the supplied profiles in source order.
  factory XraySubscription.fromProfiles(Iterable<FlutterVlessURL> sources,
          {XraySubscriptionSourceId? sourceId}) =>
      XraySubscription._(sources.map((source) => _takeSource(source, sourceId)),
          null, sourceId);

  /// All nodes in the order supplied by the latest source snapshot.
  final List<XraySubscriptionNode> nodes;

  /// The chosen node, or `null` if no node was chosen or its match was lost.
  final XraySubscriptionNodeId? selectedNodeId;

  /// The chosen node's current source label and effective configuration.
  XraySubscriptionNode? get selectedNode =>
      nodes.where((node) => node.id == selectedNodeId).firstOrNull;

  final XraySubscriptionSourceId? _sourceId;

  /// Returns a snapshot selecting [id], or clears the selection with `null`.
  /// Throws [ArgumentError] if the ID does not belong to this snapshot.
  XraySubscription select(XraySubscriptionNodeId? id) {
    if (id != null) _indexOf(id);
    return XraySubscription._(nodes, id, _sourceId);
  }

  /// Applies local edits to an independent draft of the current node profile.
  XraySubscription editProfile(
      XraySubscriptionNodeId id, void Function(XrayProfileDraft) configure) {
    final index = _indexOf(id);
    final node = nodes[index];
    return _replace(index, node._withProfile(node.profile.edit(configure)));
  }

  /// Discards all local edits for [id] and returns its latest source profile.
  XraySubscription resetProfile(XraySubscriptionNodeId id) {
    final index = _indexOf(id);
    final node = nodes[index];
    return _replace(index, node._withProfile(node.sourceProfile));
  }

  /// Matches and merges a complete source snapshot into this subscription.
  ///
  /// For nodes without a source ID, matching tries unchanged profiles, then
  /// unchanged outbound lists, then the endpoint and transport of share links.
  /// A key must be unique on both sides. Labels and list positions do not match
  /// nodes. A disappeared or ambiguous selection is cleared.
  ///
  /// Independent edits to map members merge. Lists and scalar values merge as
  /// single units, including ordered outbounds, DNS servers and routing rules.
  /// If both sides change a unit differently, the local value is retained and
  /// the node appears in [XraySubscriptionRefresh.conflictedNodeIds]. For
  /// example, a credential rotation in a locally edited outbound list needs
  /// reconciliation from the new source profile. The old snapshot stays usable
  /// if reading a source or resolving an ID throws.
  XraySubscriptionRefresh refresh(Iterable<FlutterVlessURL> sources) {
    final incoming =
        sources.map((source) => _takeSource(source, _sourceId)).toList();
    final matches = <int, int>{};
    final matchedPrevious = <int>{};

    void match(String? Function(_SourceIdentity) key) {
      final previous = _uniqueIndices(nodes, key);
      final next = _uniqueIndices(incoming, key);
      for (final entry in next.entries) {
        final oldIndex = previous[entry.key];
        if (oldIndex == null ||
            matches.containsKey(entry.value) ||
            !matchedPrevious.add(oldIndex)) {
          continue;
        }
        matches[entry.value] = oldIndex;
      }
    }

    match((identity) => identity.source);
    match((identity) => identity.source == null ? identity.document : null);
    match((identity) => identity.source == null ? identity.outbounds : null);
    match((identity) => identity.source == null ? identity.endpoint : null);

    final conflicted = <XraySubscriptionNodeId>{};
    for (final entry in matches.entries) {
      final old = nodes[entry.value];
      final next = incoming[entry.key];
      final (profile, conflict) = _mergeProfile(old, next);
      if (conflict) conflicted.add(old.id);
      incoming[entry.key] = XraySubscriptionNode._(
          old.id, next.remark, next.sourceProfile, profile, next._identity);
    }

    final removed = [
      for (var index = 0; index < nodes.length; index++)
        if (!matchedPrevious.contains(index)) nodes[index],
    ];
    final selected = incoming.any((node) => node.id == selectedNodeId)
        ? selectedNodeId
        : null;
    return XraySubscriptionRefresh._(
        XraySubscription._(incoming, selected, _sourceId), removed, conflicted);
  }

  int _indexOf(XraySubscriptionNodeId id) {
    final index = nodes.indexWhere((node) => node.id == id);
    if (index == -1) throw ArgumentError('Unknown subscription node');
    return index;
  }

  XraySubscription _replace(int index, XraySubscriptionNode replacement) =>
      XraySubscription._(
          nodes.toList()..[index] = replacement, selectedNodeId, _sourceId);
}

final class _SourceIdentity {
  _SourceIdentity(
      {required this.source, this.document, this.outbounds, this.endpoint});

  final String? source;
  final String? document;
  final String? outbounds;
  final String? endpoint;
}

XraySubscriptionNode _takeSource(
    FlutterVlessURL source, XraySubscriptionSourceId? identify) {
  final sourceId = identify?.call(source);
  if (sourceId == '') {
    throw ArgumentError('A subscription source ID must be nonempty');
  }
  final profile = XrayProfile.fromMap(source.fullConfiguration);
  final identity = sourceId == null
      ? _automaticIdentity(profile.toCoreMap(), source)
      : _SourceIdentity(source: sourceId);
  return XraySubscriptionNode._(
      XraySubscriptionNodeId._(), source.remark, profile, profile, identity);
}

_SourceIdentity _automaticIdentity(JsonMap document, FlutterVlessURL source) {
  const labels = {'remark', 'remarks', 'ps'};
  final outbounds = readXraySchemaField(document, 'outbounds');
  final list =
      outbounds is List<Object?> && outbounds.isNotEmpty ? outbounds : null;
  final first = list?.first;
  String? endpoint;
  if (first is JsonMap && source.address.isNotEmpty) {
    final protocol = readXraySchemaField(first, 'protocol');
    final transport = readXraySchemaField(first, 'streamSettings');
    if (protocol is String && source.port >= 1 && source.port <= 65535) {
      endpoint = _canonicalJson(
          [protocol, source.address.toLowerCase(), source.port, transport]);
    }
  }
  return _SourceIdentity(
    source: null,
    document: _canonicalJson({
      for (final field in document.entries)
        if (!(labels.contains(field.key) && field.value is String))
          field.key: field.value,
    }),
    outbounds: list == null ? null : _canonicalJson(list),
    endpoint: endpoint,
  );
}

String _canonicalJson(Object? value) => jsonEncode(_ordered(value));

Object? _ordered(Object? value) => switch (value) {
      JsonMap() => {
          for (final key in value.keys.toList()..sort())
            key: _ordered(value[key])
        },
      List<Object?>() => value.map(_ordered).toList(),
      _ => value,
    };

Map<String, int> _uniqueIndices(
    List<XraySubscriptionNode> nodes, String? Function(_SourceIdentity) key) {
  final indices = <String, int>{};
  final repeated = <String>{};
  for (var index = 0; index < nodes.length; index++) {
    final value = key(nodes[index]._identity);
    if (value != null) {
      if (indices.containsKey(value)) repeated.add(value);
      indices[value] = index;
    }
  }
  repeated.forEach(indices.remove);
  return indices;
}

(XrayProfile, bool) _mergeProfile(
    XraySubscriptionNode previous, XraySubscriptionNode next) {
  if (identical(previous.profile, previous.sourceProfile)) {
    return (next.sourceProfile, false);
  }
  final local = previous.profile.toCoreMap();
  final remote = next.sourceProfile.toCoreMap();
  var conflict = false;
  final merged = _mergeValue(previous.sourceProfile.toCoreMap(), local, remote,
      () => conflict = true) as JsonMap;
  if (_same(merged, local)) return (previous.profile, conflict);
  if (_same(merged, remote)) return (next.sourceProfile, conflict);
  return (XrayProfile.fromMap(merged), conflict);
}

const _missing = Object();

Object? _value(JsonMap object, String key) =>
    object.containsKey(key) ? object[key] : _missing;

Object? _mergeValue(
    Object? base, Object? local, Object? remote, void Function() onConflict) {
  if (_same(local, base)) return remote;
  if (_same(remote, base) || _same(local, remote)) return local;
  if (local is JsonMap &&
      remote is JsonMap &&
      (base is JsonMap || identical(base, _missing))) {
    final old = base is JsonMap ? base : <String, dynamic>{};
    final merged = <String, dynamic>{};
    for (final key in {...remote.keys, ...local.keys}) {
      final value = _mergeValue(_value(old, key), _value(local, key),
          _value(remote, key), onConflict);
      if (!identical(value, _missing)) merged[key] = value;
    }
    return merged;
  }
  onConflict();
  return local;
}

bool _same(Object? left, Object? right) {
  if (identical(left, right)) return true;
  if (left is JsonMap && right is JsonMap) {
    return left.length == right.length &&
        left.entries.every((entry) =>
            right.containsKey(entry.key) &&
            _same(entry.value, right[entry.key]));
  }
  if (left is List<Object?> && right is List<Object?>) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (!_same(left[index], right[index])) return false;
    }
    return true;
  }
  return left == right && left.runtimeType == right.runtimeType;
}
