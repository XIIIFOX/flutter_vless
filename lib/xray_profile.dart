// Copyright (c) 2024-2026 13FOX Studio / tfox.dev.
// SPDX-License-Identifier: MIT

import 'dart:collection';
import 'dart:convert';

import 'flutter_vless.dart' show FlutterVless;
import 'url/xray_config_model.dart';
import 'url/xray_geodata_update.dart';
import 'url/xray_json.dart';

part 'src/xray_profile_routing.dart';
part 'src/xray_profile_dns.dart';
part 'src/xray_profile_freedom.dart';
part 'src/xray_profile_geodata.dart';

/// An exact path into an authored Xray JSON document.
final class CorePath {
  const CorePath._(this._segments);

  /// The document itself. A write must select a member below the root.
  static const root = CorePath._([]);

  final List<Object> _segments;

  /// Appends a literal JSON member name, including any punctuation.
  CorePath key(String name) => CorePath._([..._segments, name]);

  /// Appends an existing array index.
  CorePath index(int index) {
    RangeError.checkNotNegative(index, 'index');
    return CorePath._([..._segments, index]);
  }
}

/// An immutable snapshot of the full authored Xray configuration.
///
/// Use [edit] to apply typed and raw changes to a new snapshot. Pass
/// [toCoreJson] to the existing `startVless` API for runtime preparation.
/// A profile can contain credentials. Keep it out of application logs.
final class XrayProfile {
  XrayProfile._(this._document,
      {Map<String, Set<String>> memberTags = const {},
      Set<String> blockingGroups = const {},
      int? defaultRuleIndex})
      : _memberTags = memberTags,
        _blockingGroups = blockingGroups,
        _defaultRuleIndex = defaultRuleIndex;

  /// Imports one JSON or JSONC object, preserving its fields and array order.
  factory XrayProfile.fromJson(String source) {
    final document = decodeXrayJson(source);
    if (document is! JsonMap) {
      throw const FormatException('An Xray profile must be a JSON object');
    }
    return XrayProfile.fromMap(document);
  }

  /// Takes an independent snapshot of a complete JSON-compatible document.
  factory XrayProfile.fromMap(JsonMap document) =>
      XrayProfile._(_freezeMap(document));

  /// Builds a profile with the plugin's standard local SOCKS inbound.
  static XrayProfile build(void Function(XrayProfileDraft) configure) {
    final draft = XrayProfileDraft._({
      'log': const XrayLog().toJson(),
      'inbounds': [XrayInbound.localSocksTunnel().toJson()],
      'outbounds': <Object?>[],
    });
    configure(draft);
    return draft._finish();
  }

  final JsonMap _document;
  final Map<String, Set<String>> _memberTags;
  final Set<String> _blockingGroups;
  final int? _defaultRuleIndex;

  /// Edits a separate draft and snapshots its result once [configure] returns.
  /// References from another draft can be reacquired by index.
  XrayProfile edit(void Function(XrayProfileDraft) configure) {
    final draft = XrayProfileDraft._(_copyMap(_document),
        tags: _memberTags,
        blockingGroups: _blockingGroups,
        defaultRuleIndex: _defaultRuleIndex);
    configure(draft);
    return draft._finish();
  }

  /// Returns a deep, independently mutable copy of the authored JSON.
  JsonMap toCoreMap() => _copyMap(_document);

  /// Serializes the authored profile for Xray. Formatting and comments from
  /// the source are replaced by JSON serialization.
  String toCoreJson({String? indent}) =>
      JsonEncoder.withIndent(indent).convert(_document);
}

/// Changes a single Xray profile snapshot within a build or edit callback.
final class XrayProfileDraft {
  XrayProfileDraft._(this._document,
      {Map<String, Set<String>> tags = const {},
      Set<String> blockingGroups = const {},
      int? defaultRuleIndex})
      : _memberTags = Map.of(tags),
        _blockingGroups = Set.of(blockingGroups) {
    if (defaultRuleIndex != null) {
      _previousDefault = _entryAt(_routingArray('rules'), defaultRuleIndex);
    }
  }

  final JsonMap _document;
  final Map<String, Set<String>> _memberTags;
  final Set<String> _blockingGroups;
  final List<CorePath> _writes = [];
  final Map<Object, JsonMap> _references = {};
  final Map<Object, CorePath> _newOutboundPaths = {};
  final Map<String, _HealthProbeKind?> _observed = {};
  final List<(JsonMap, RouteTarget)> _typedRules = [];
  final Map<_RouteTargetKind, NodeRef> _builtIn = {};
  HealthProbe? _probe;
  RouteTarget? _defaultRoute;
  (String, JsonMap, String, NodeRef)? _geoDataOutbound;
  CorePath? _minimumVersionWrite;
  JsonMap? _previousDefault;
  bool _addedRule = false;
  int _nextTag = 0;

  /// Adds an outbound and returns a reference usable in this draft.
  NodeRef addNode(ProxyNode node) {
    final outbounds = _array(CorePath.root, _document, 'outbounds');
    final outbound = _copyMap(node._outbound);
    final tagKey = _schemaKey(outbound, 'tag');
    final suppliedTag = outbound[tagKey];
    final tag = suppliedTag == null || suppliedTag == ''
        ? _allocateTag('node', outbounds.$2)
        : _tag(outbound);
    if (outbounds.$2
        .whereType<JsonMap>()
        .any((entry) => _maybeTag(entry) == tag)) {
      throw ArgumentError('An outbound with this tag already exists');
    }
    outbound[tagKey] = tag;
    final path = _append(outbounds, outbound);
    final id = _reference(outbound);
    _newOutboundPaths[id] = path;
    return NodeRef._(id, tag);
  }

  /// References an existing tagged outbound by its document index.
  NodeRef nodeAt(int index) {
    final entry =
        _entryAt(_array(CorePath.root, _document, 'outbounds'), index);
    return NodeRef._(_reference(entry), _tag(entry));
  }

  /// Adds a balancer for [nodes]. Observed strategies require a compatible
  /// profile-level probe. Specify [fallback] to control the no-candidate case.
  GroupRef addGroup({
    required List<NodeRef> nodes,
    required BalanceStrategy strategy,
    GroupFallback? fallback,
  }) {
    if (strategy._requiredProbe != null && fallback == null) {
      throw ArgumentError('Choose a fallback for a health-based balancer');
    }
    final members = {for (final node in nodes) _nodeTag(node)};
    if (members.isEmpty || members.length != nodes.length) {
      throw ArgumentError('A group requires distinct outbound references');
    }
    final groups = _routingArray('balancers');
    final tag = _allocateTag('group', groups.$2);
    final definition = <String, dynamic>{
      'tag': tag,
      'selector': members.toList(),
      'strategy': {
        'type': strategy._type,
        if (strategy._settings != null) 'settings': strategy._settings,
      },
      if (fallback != null)
        'fallbackTag': _target(fallback._target)['outboundTag'],
    };
    _append(groups, definition);
    _memberTags[tag] = Set.unmodifiable(members);
    if (fallback?._target._kind == _RouteTargetKind.block) {
      _blockingGroups.add(tag);
    }
    return GroupRef._(_reference(definition), tag);
  }

  /// References an existing tagged balancer by its document index.
  GroupRef groupAt(int index) {
    final entry = _entryAt(_routingArray('balancers'), index);
    return GroupRef._(_reference(entry), _tag(entry));
  }

  /// Sets the observation provider for groups added in this transaction.
  void setHealthProbe(HealthProbe probe) {
    if (_probe != null) throw StateError('Use one profile-level health probe');
    _probe = probe;
  }

  /// Appends a routing rule in call order, before a generated default.
  void addRule(RouteRule rule) {
    final rules = _routingArray('rules');
    final entry = <String, dynamic>{
      'type': 'field',
      ..._copyMap(rule._conditions),
      ..._target(rule._to),
    };
    _append(rules, entry);
    _typedRules.add((entry, rule._to));
    _addedRule = true;
  }

  /// Sets when Xray resolves destinations for IP-based route matching.
  /// Other routing fields retain their authored values and ordering.
  void setRoutingDomainStrategy(XrayRoutingDomainStrategy strategy) {
    final (key, routing) = _routingObject();
    final field = _schemaKey(routing, 'domainStrategy');
    _record(CorePath.root.key(key).key(field));
    routing[field] = strategy._wire;
    _document[key] = routing;
  }

  /// Appends a resolver to the authored DNS list in call order.
  /// Existing resolver definitions, including raw entries, are preserved.
  void addDnsServer(XrayDnsServer server) {
    final (key, dns) = _object('dns');
    if (server._usesSplitQueries) _checkDnsScript(dns);
    final field = _schemaKey(dns, 'servers');
    final servers = dns[field] ?? <Object?>[];
    if (servers is! List<Object?>) {
      throw ArgumentError('Xray DNS servers must be an array');
    }
    _record(CorePath.root.key(key).key(field).index(servers.length));
    servers.add(_copyMap(server._settings));
    dns[field] = servers;
    _document[key] = dns;
  }

  /// Sets the supplied DNS options and retains every other authored member.
  void setDnsOptions(XrayDnsOptions options) {
    final optionFields = options._toCore();
    if (optionFields.isEmpty) return;
    final (key, dns) = _object('dns');
    if (options.disableFallbackIfMatch == true) _checkDnsScript(dns);
    final changes = {
      for (final field in optionFields.entries)
        _schemaKey(dns, field.key): field.value,
    };
    final path = CorePath.root.key(key);
    final writes = changes.keys.map(path.key).toList();
    for (final write in writes) {
      _checkWrite(write);
    }
    _writes.addAll(writes);
    dns.addAll(changes);
    _document[key] = dns;
  }

  /// Replaces the ordered final rules on an existing Freedom outbound.
  /// Other outbound settings stay intact. A rule with an explicit delay or
  /// log level also sets the minimum Core version to 26.11.9.
  void setFreedomFinalRules(
    NodeRef node,
    List<XrayFreedomFinalRule> rules,
  ) {
    _nodeTag(node);
    final (outboundPath, outbounds) =
        _array(CorePath.root, _document, 'outbounds');
    final outbound = _references[node._id]!;
    final protocol = readXraySchemaField(outbound, 'protocol');
    if (protocol is! String ||
        !const {'freedom', 'direct'}.contains(protocol.toLowerCase())) {
      throw ArgumentError('Final rules require a Freedom outbound');
    }
    final settingsKey = _schemaKey(outbound, 'settings');
    final settings = outbound[settingsKey] ?? <String, dynamic>{};
    if (settings is! JsonMap) {
      throw ArgumentError('Freedom settings must be an object');
    }
    final field = _schemaKey(settings, 'finalRules');
    final index = outbounds.indexWhere((value) => identical(value, outbound));
    final path = outboundPath.index(index).key(settingsKey).key(field);
    _checkWrite(path, permittedWrite: _newOutboundPaths[node._id]);
    if (rules.any((rule) => rule._needsNewCore)) {
      requireCoreAtLeast('26.11.9');
    }
    _writes.add(path);
    settings[field] = [for (final rule in rules) _copyMap(rule._definition)];
    outbound[settingsKey] = settings;
  }

  /// Sets the GeoDAT reload schedule and optionally its download outbound.
  /// Omitted asset and outbound settings retain their existing values.
  /// Check the installed Core's `geoDataUpdates` capability before starting.
  void setGeoDataSchedule(XrayGeoDataSchedule schedule, {NodeRef? outbound}) {
    final (key, geodata) = _object('geodata');
    final assets = schedule._assets;
    final outboundKey =
        outbound == null ? null : _schemaKey(geodata, 'outbound');
    final changes = {
      _schemaKey(geodata, 'cron'): schedule._expression,
      if (assets != null)
        _schemaKey(geodata, 'assets'): [
          for (final asset in assets) asset._toCore()
        ],
      if (outbound != null) outboundKey!: _nodeTag(outbound),
    };
    XrayGeodataUpdate.validate({
      key: {...geodata, ...changes}
    });
    final path = CorePath.root.key(key);
    final writes = changes.keys.map(path.key).toList();
    for (final write in writes) {
      _checkWrite(write);
    }
    _writes.addAll(writes);
    geodata.addAll(changes);
    _document[key] = geodata;
    if (outbound != null) {
      _geoDataOutbound = (key, geodata, outboundKey!, outbound);
    }
  }

  /// Sets a TCP/UDP catch-all after the authored rules. If this profile has a
  /// previous default generated by this API, replaces it.
  ///
  /// This applies to any inlet that reaches the catch-all, including the
  /// platform's managed VPN inlet. Put existing exceptions ahead of it.
  void setDefaultRoute(RouteTarget target) {
    if (_defaultRoute != null) {
      throw StateError('A default route is already set');
    }
    _defaultRoute = target;
  }

  /// Sets one member or replaces one existing array element. Use [replace]
  /// to explicitly override an overlapping write in this transaction.
  void setRaw(CorePath path, Object? value, {bool replace = false}) {
    final parent = _parent(path);
    final copy = _copyJson(value, HashSet.identity(), freeze: false);
    final last = path._segments.last;
    if (last is String && parent is JsonMap) {
      _record(path, replace: replace);
      parent[last] = copy;
      return;
    }
    if (last is int && parent is List<Object?> && last < parent.length) {
      _record(path, replace: replace);
      parent[last] = copy;
      return;
    }
    throw ArgumentError('Raw path does not select a writable member');
  }

  /// Removes an object member or existing array element at [path]. Removing
  /// an absent member of an existing object has no effect.
  void removeRaw(CorePath path, {bool replace = false}) {
    final parent = _parent(path);
    final last = path._segments.last;
    if (last is String && parent is JsonMap) {
      if (!parent.containsKey(last)) return;
      _record(path, replace: replace);
      parent.remove(last);
      return;
    }
    if (last is int && parent is List<Object?> && last < parent.length) {
      // Removing an element shifts the positions of its following siblings.
      _record(CorePath._(path._segments.sublist(0, path._segments.length - 1)),
          replace: replace);
      parent.removeAt(last);
      return;
    }
    throw ArgumentError('Raw path does not select a removable member');
  }

  /// Sets Xray's minimum supported version, retaining any stricter minimum,
  /// existing maximum and other version members.
  void requireCoreAtLeast(String version) {
    final requested = _versionParts(version);
    final versionKey = _schemaKey(_document, 'version');
    final existing = _document[versionKey];
    if (existing != null && existing is! JsonMap) {
      throw ArgumentError('Xray version must be an object');
    }
    final versions = existing as JsonMap? ?? <String, dynamic>{};
    final minKey = _schemaKey(versions, 'min');
    final min = versions[minKey];
    final max = versions[_schemaKey(versions, 'max')];
    final minimum = min == null || min == '' ? null : _versionParts(min);
    final maximum = max == null || max == '' ? null : _versionParts(max);
    final keepMin =
        minimum != null && _compareVersions(minimum, requested) >= 0;
    if (maximum != null &&
        _compareVersions(keepMin ? minimum : requested, maximum) > 0) {
      throw ArgumentError('Minimum Xray version exceeds the profile maximum');
    }
    if (keepMin) return;
    final versionPath = CorePath.root.key(versionKey);
    final path = existing == null ? versionPath : versionPath.key(minKey);
    _checkWrite(path, permittedWrite: _minimumVersionWrite);
    if (_minimumVersionWrite == null) {
      _minimumVersionWrite = path;
      _writes.add(path);
    }
    versions[minKey] = version;
    _document[versionKey] = versions;
  }

  XrayProfile _finish() {
    if (_geoDataOutbound
        case (final key, final geodata, final field, final node)
        when identical(_document[key], geodata) &&
            geodata[field] == node._tag) {
      _nodeTag(node);
    }
    if (_typedRules.isNotEmpty) {
      final rules = _routingEntries('rules');
      for (final (entry, target) in _typedRules) {
        if (rules.any((rule) => identical(rule, entry))) _target(target);
      }
    }
    final defaultRuleIndex = _finishDefaultRoute();
    _validateGroups();
    _writeObserver();
    return XrayProfile._(_freezeMap(_document),
        memberTags: Map.unmodifiable(_memberTags),
        blockingGroups: Set.unmodifiable(_blockingGroups),
        defaultRuleIndex: defaultRuleIndex);
  }

  int? _finishDefaultRoute() {
    final target = _defaultRoute;
    final previous = _previousDefault;
    if (target == null && previous == null) return null;
    if (target == null && !_addedRule) {
      final index = _routingEntries('rules')
          .indexWhere((entry) => identical(entry, previous));
      return index < 0 ? null : index;
    }
    final array = _routingArray('rules');
    final rules = array.$2;
    final index = previous == null
        ? -1
        : rules.indexWhere((entry) => identical(entry, previous));
    if (target != null &&
        index < 0 &&
        rules.whereType<JsonMap>().any(_isCatchAll)) {
      throw ArgumentError(
          'Replace the existing catch-all explicitly before setting a default');
    }
    if (target == null && (index < 0 || !_addedRule)) {
      return index < 0 ? null : index;
    }
    if (index >= 0) {
      _record(array.$1.index(index));
    }
    final entry = target == null
        ? previous!
        : {
            'type': 'field',
            'network': 'tcp,udp',
            ..._target(target),
          };
    _append(array, entry);
    if (index >= 0) rules.removeAt(index);
    return rules.length - 1;
  }

  List<Object?> _routingEntries(String key) {
    final routing = readXraySchemaField(_document, 'routing');
    final value = routing is JsonMap ? readXraySchemaField(routing, key) : null;
    return value is List<Object?> ? value : const [];
  }

  (CorePath, List<Object?>) _routingArray(String name) {
    final (key, routing) = _routingObject();
    final result = _array(CorePath.root.key(key), routing, name);
    _document[key] = routing;
    return result;
  }

  (String, JsonMap) _routingObject() {
    final (key, routing) = _object('routing');
    final script = readXraySchemaField(routing, 'script');
    if (script != null && script != '') {
      throw ArgumentError(
          'Typed routes cannot be combined with a routing script');
    }
    return (key, routing);
  }

  (String, JsonMap) _object(String name) {
    final key = _schemaKey(_document, name);
    final data = _document[key] ?? <String, dynamic>{};
    if (data is! JsonMap) throw ArgumentError('Xray $name must be an object');
    return (key, data);
  }

  (CorePath, List<Object?>) _array(CorePath path, JsonMap parent, String name) {
    final key = _schemaKey(parent, name);
    final current = parent[key];
    if (current is List<Object?>) return (path.key(key), current);
    if (current != null) throw ArgumentError('Xray $name must be an array');
    final list = <Object?>[];
    parent[key] = list;
    return (path.key(key), list);
  }

  CorePath _append((CorePath, List<Object?>) array, JsonMap entry) {
    final path = array.$1.index(array.$2.length);
    _record(path);
    array.$2.add(entry);
    return path;
  }

  JsonMap _entryAt((CorePath, List<Object?>) array, int index) {
    final entry = array.$2[index];
    if (entry is! JsonMap) throw ArgumentError('Xray entry must be an object');
    return entry;
  }

  Object _reference(JsonMap entry) {
    final id = Object();
    _references[id] = entry;
    return id;
  }

  String _boundTag(Object id, String tag, List<Object?> entries) {
    final entry = _references[id];
    final matches =
        entries.whereType<JsonMap>().where((item) => _maybeTag(item) == tag);
    if (entry == null ||
        matches.length != 1 ||
        !identical(matches.single, entry)) {
      throw ArgumentError('Reference is foreign, deleted or replaced');
    }
    return tag;
  }

  String _nodeTag(NodeRef node) => _boundTag(
      node._id, node._tag, _array(CorePath.root, _document, 'outbounds').$2);

  JsonMap _target(RouteTarget target) {
    switch (target._kind) {
      case _RouteTargetKind.node:
        return {'outboundTag': _nodeTag(target._node!)};
      case _RouteTargetKind.group:
        final group = target._group!;
        return {
          'balancerTag':
              _boundTag(group._id, group._tag, _routingArray('balancers').$2)
        };
      case _RouteTargetKind.direct:
      case _RouteTargetKind.block:
        final node = _builtIn.putIfAbsent(
            target._kind,
            () => addNode(ProxyNode.fromMap({
                  'protocol': target._kind == _RouteTargetKind.direct
                      ? 'freedom'
                      : 'blackhole',
                })));
        return {'outboundTag': _nodeTag(node)};
    }
  }

  String _allocateTag(String kind, List<Object?> entries) {
    final tags = _tagReferences(_document).toSet();
    final existing =
        entries.whereType<JsonMap>().map(_maybeTag).whereType<String>();
    final prefixes = kind == 'node' ? _selectorPrefixes().toSet() : <String>{};
    final stem = 'fv-profile-$kind-';
    bool unused(String tag) =>
        !tags.contains(tag) && !existing.any((name) => name.startsWith(tag));
    // A collection of numbered prefixes can cover every decimal suffix.
    // Try the human-readable stem a bounded number of times before escaping.
    for (var attempt = 0; attempt < 32; attempt++) {
      if (prefixes.any(stem.startsWith)) break;
      final tag = '$stem${++_nextTag}!';
      if (unused(tag) && !prefixes.any(tag.startsWith)) return tag;
    }
    final leading = prefixes.map((prefix) => prefix.runes.first).toSet();
    for (var scalar = 0xe000; scalar <= 0xf8ff; scalar++) {
      if (leading.contains(scalar)) continue;
      while (true) {
        final tag = '${String.fromCharCode(scalar)}$stem${++_nextTag}!';
        if (unused(tag)) return tag;
      }
    }
    throw StateError('No generated tag can avoid the imported selectors');
  }

  Iterable<String> _selectorPrefixes() sync* {
    for (final group in _routingEntries('balancers').whereType<JsonMap>()) {
      final selector = readXraySchemaField(group, 'selector');
      final members = selector is String ? selector.split(',') : selector;
      if (members is List) {
        yield* members.whereType<String>().where((value) => value.isNotEmpty);
      }
    }
    for (final key in ['observatory', 'burstObservatory']) {
      final observer = readXraySchemaField(_document, key);
      if (observer is! JsonMap) continue;
      final subjects = readXraySchemaField(observer, 'subjectSelector');
      if (subjects is List) {
        yield* subjects.whereType<String>().where((value) => value.isNotEmpty);
      }
    }
  }

  void _validateGroups() {
    _observed.clear();
    if (_memberTags.isEmpty) return;
    final groups = _routingEntries('balancers').whereType<JsonMap>().toList();
    for (final tag in _memberTags.keys.toList()) {
      final matches = groups.where((group) => _maybeTag(group) == tag).length;
      if (matches > 1) throw ArgumentError('A typed group tag is ambiguous');
      if (matches == 0) {
        if (_routingEntries('rules')
            .whereType<JsonMap>()
            .any((rule) => readXraySchemaField(rule, 'balancerTag') == tag)) {
          throw ArgumentError('Remove rules that target the deleted group');
        }
        _memberTags.remove(tag);
        _blockingGroups.remove(tag);
      }
    }
    if (_memberTags.isEmpty) return;
    final outboundEntries = _array(CorePath.root, _document, 'outbounds')
        .$2
        .whereType<JsonMap>()
        .toList();
    final outbounds =
        outboundEntries.map(_maybeTag).whereType<String>().toList();
    for (final group in groups) {
      final tag = _maybeTag(group);
      final members = _memberTags[tag];
      if (members == null) continue;
      final selectors = readXraySchemaField(group, 'selector');
      if (selectors is! List || selectors.any((item) => item is! String)) {
        throw ArgumentError('A typed balancer must retain string selectors');
      }
      final selected = outbounds
          .where((tag) => selectors.cast<String>().any(tag.startsWith))
          .toList();
      if (selected.length != members.length || !members.containsAll(selected)) {
        throw ArgumentError(
            'Balancer selectors must match exactly the requested outbounds');
      }
      final strategy = readXraySchemaField(group, 'strategy');
      final type =
          strategy is JsonMap ? readXraySchemaField(strategy, 'type') : null;
      final requiredProbe = switch (type is String ? type.toLowerCase() : '') {
        'leastping' => _HealthProbeKind.http,
        'leastload' => _HealthProbeKind.burst,
        _ => null,
      };
      final fallback = readXraySchemaField(group, 'fallbackTag');
      if (_blockingGroups.contains(tag) &&
          (fallback == null ||
              !outboundEntries.any((entry) =>
                  _maybeTag(entry) == fallback &&
                  readXraySchemaField(entry, 'protocol') == 'blackhole'))) {
        throw ArgumentError(
            'The balancer block fallback must remain a Blackhole outbound');
      }
      if (requiredProbe != null || fallback != null && fallback != '') {
        if (fallback is! String ||
            outbounds.where((entry) => entry == fallback).length != 1) {
          throw ArgumentError('A typed balancer needs a concrete fallback');
        }
        _observed[tag!] = requiredProbe;
      }
    }
  }

  void _writeObserver() {
    if (_observed.isEmpty && _probe == null) return;
    final httpKey = _schemaKey(_document, 'observatory');
    final burstKey = _schemaKey(_document, 'burstObservatory');
    final http = _document[httpKey];
    final burst = _document[burstKey];
    if (http != null && burst != null) {
      throw ArgumentError('Typed groups require one observation provider');
    }
    final existing = burst ?? http;
    final existingKind =
        burst != null ? _HealthProbeKind.burst : _HealthProbeKind.http;
    final kind = _probe?._kind ?? (existing == null ? null : existingKind);
    if (kind == null ||
        kind == _HealthProbeKind.http &&
            _observed.containsValue(_HealthProbeKind.burst)) {
      throw ArgumentError('Configure a compatible profile-level health probe');
    }
    final key = kind == _HealthProbeKind.burst ? burstKey : httpKey;
    final subjects = {
      for (final group in _observed.keys) ...?_memberTags[group],
    };
    if (existing == null) {
      setRaw(CorePath.root.key(key), _probe!._toJson(subjects.toList()));
      return;
    }
    if (existing is! JsonMap || _probe != null) {
      throw ArgumentError(
          'Preserve the imported observer or replace it explicitly before configuring a probe');
    }
    final settings = kind == _HealthProbeKind.http
        ? existing
        : readXraySchemaField(existing, 'pingConfig');
    final url = settings is JsonMap
        ? readXraySchemaField(settings,
            kind == _HealthProbeKind.http ? 'probeURL' : 'destination')
        : null;
    final parsed = url is String ? Uri.tryParse(url) : null;
    if (parsed == null) {
      throw ArgumentError('The existing observer needs an explicit probe URL');
    }
    _probeUrl(parsed);
    final selector = _schemaKey(existing, 'subjectSelector');
    final previous = existing[selector];
    if (previous is! List || previous.any((item) => item is! String)) {
      throw ArgumentError(
          'The existing observer requires string subject selectors');
    }
    final additions = subjects.where((subject) => !previous.contains(subject));
    if (additions.isNotEmpty) {
      setRaw(CorePath.root.key(key).key(selector), [...previous, ...additions]);
    }
  }

  Object? _parent(CorePath path) {
    if (path._segments.isEmpty) {
      throw ArgumentError('Select a member below the Xray profile root');
    }
    Object? current = _document;
    for (final segment in path._segments.take(path._segments.length - 1)) {
      current = switch ((current, segment)) {
        (JsonMap object, String key) when object.containsKey(key) =>
          object[key],
        (List<Object?> list, int index) when index < list.length => list[index],
        _ => throw ArgumentError('Raw path has a missing or invalid parent'),
      };
    }
    return current;
  }

  void _record(CorePath path, {bool replace = false}) {
    if (!replace) _checkWrite(path);
    _writes.add(path);
  }

  void _checkWrite(CorePath path, {CorePath? permittedWrite}) {
    if (_writes.any((write) =>
        !identical(write, permittedWrite) && _overlap(write, path))) {
      throw StateError('An overlapping profile edit requires replace: true');
    }
  }
}

bool _overlap(CorePath first, CorePath second) {
  final a = first._segments;
  final b = second._segments;
  for (var i = 0; i < a.length && i < b.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

String _schemaKey(JsonMap object, String name) {
  readXraySchemaField(object, name);
  return object.keys.firstWhere(
      (key) => foldXraySchemaField(key) == foldXraySchemaField(name),
      orElse: () => name);
}

String? _maybeTag(JsonMap entry) {
  final value = readXraySchemaField(entry, 'tag');
  return value is String && value.isNotEmpty ? value : null;
}

String _tag(JsonMap entry) =>
    _maybeTag(entry) ?? (throw ArgumentError('Select a tagged Xray entry'));

bool _isCatchAll(JsonMap rule) {
  const fields = {'type', 'network', 'outboundtag', 'balancertag'};
  if (!rule.keys.every((key) => fields.contains(foldXraySchemaField(key)))) {
    return false;
  }
  final network = readXraySchemaField(rule, 'network');
  final names = network is String ? network.split(',') : network;
  if (names is! List) return false;
  final protocols = names
      .whereType<String>()
      .map((name) => name.trim().toLowerCase())
      .toSet();
  return protocols.containsAll(const {'tcp', 'udp'});
}

Iterable<String> _tagReferences(Object? value) sync* {
  const fields = {
    'tag',
    'inboundtag',
    'outboundtag',
    'balancertag',
    'fallbacktag',
    'dialerproxy',
  };
  if (value is JsonMap) {
    for (final entry in value.entries) {
      final child = entry.value;
      if (fields.contains(foldXraySchemaField(entry.key))) {
        if (child is String) yield child;
        if (child is List) yield* child.whereType<String>();
      }
      yield* _tagReferences(child);
    }
  } else if (value is List) {
    for (final item in value) {
      yield* _tagReferences(item);
    }
  }
}

List<int> _versionParts(Object value) {
  if (value is! String || !RegExp(r'^\d+(?:\.\d+)*$').hasMatch(value)) {
    throw ArgumentError('Expected an Xray version such as 26.11.9');
  }
  return value.split('.').map(int.parse).toList(growable: false);
}

int _compareVersions(List<int> first, List<int> second) {
  for (var i = 0; i < first.length || i < second.length; i++) {
    final a = i < first.length ? first[i] : 0;
    final b = i < second.length ? second[i] : 0;
    final result = a.compareTo(b);
    if (result != 0) return result;
  }
  return 0;
}

JsonMap _copyMap(JsonMap source) =>
    _copyJson(source, HashSet.identity(), freeze: false) as JsonMap;

JsonMap _freezeMap(JsonMap source) =>
    _copyJson(source, HashSet.identity(), freeze: true) as JsonMap;

Object? _copyJson(Object? value, Set<Object> seen, {required bool freeze}) {
  if (value == null ||
      value is String ||
      value is bool ||
      value is num && value.isFinite) {
    return value;
  }
  if (value is! Map && value is! List) {
    throw ArgumentError('Profile values must be JSON-compatible');
  }
  if (!seen.add(value)) throw ArgumentError('Cyclic JSON value');
  try {
    if (value is List) {
      final copy = [
        for (final member in value) _copyJson(member, seen, freeze: freeze),
      ];
      return freeze ? List<Object?>.unmodifiable(copy) : copy;
    }
    final copy = <String, dynamic>{};
    for (final entry in (value as Map).entries) {
      final key = entry.key;
      if (key is! String) throw ArgumentError('JSON keys must be strings');
      copy[key] = _copyJson(entry.value, seen, freeze: freeze);
    }
    return freeze ? Map<String, dynamic>.unmodifiable(copy) : copy;
  } finally {
    seen.remove(value);
  }
}
