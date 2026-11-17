part of '../xray_profile.dart';

/// An immutable Xray outbound that can be added to a profile.
final class ProxyNode {
  ProxyNode._(this._outbound);

  /// Imports a single share link using the existing protocol parsers.
  factory ProxyNode.fromLink(String link) {
    final trimmed = link.trim();
    if (trimmed.contains('\n') || trimmed.contains('\r')) {
      throw ArgumentError('Expected a single proxy share link');
    }
    final outbound = _copyMap(FlutterVless.parseFromURL(trimmed).outbound1);
    if (outbound['tag'] == 'proxy') {
      outbound.remove('tag');
    }
    return ProxyNode.fromMap(outbound);
  }

  /// Snapshots an outbound, including protocol-specific and unknown fields.
  factory ProxyNode.fromMap(JsonMap outbound) {
    final protocol = readXraySchemaField(outbound, 'protocol');
    if (protocol is! String || protocol.trim().isEmpty) {
      throw ArgumentError('An outbound must have a protocol');
    }
    return ProxyNode._(_freezeMap(outbound));
  }

  final JsonMap _outbound;
}

/// A reference to an outbound in the current profile draft.
final class NodeRef {
  const NodeRef._(this._id, this._tag);

  final Object _id;
  final String _tag;
}

/// A reference to a balancer in the current profile draft.
final class GroupRef {
  const GroupRef._(this._id, this._tag);

  final Object _id;
  final String _tag;
}

enum _RouteTargetKind { node, group, direct, block }

/// A destination for a typed routing rule.
final class RouteTarget {
  const RouteTarget._(this._kind, {NodeRef? node, GroupRef? group})
      : _node = node,
        _group = group;

  /// Sends matching traffic to a specific outbound.
  const RouteTarget.node(NodeRef node)
      : this._(_RouteTargetKind.node, node: node);

  /// Sends matching traffic to a balancer.
  const RouteTarget.group(GroupRef group)
      : this._(_RouteTargetKind.group, group: group);

  /// Sends matching traffic directly.
  const RouteTarget.direct() : this._(_RouteTargetKind.direct);

  /// Blocks matching traffic with a Blackhole outbound.
  const RouteTarget.block() : this._(_RouteTargetKind.block);

  final _RouteTargetKind _kind;
  final NodeRef? _node;
  final GroupRef? _group;
}

/// A domain routing rule in Xray's ordered rule list.
final class RouteRule {
  RouteRule._(this._domains, this._to);

  /// Matches Xray domain expressions such as `domain:example.org` or
  /// `full:example.org` and sends the matching flow to [to].
  factory RouteRule.domains(List<String> domains, {required RouteTarget to}) {
    if (domains.isEmpty || domains.any((domain) => domain.trim().isEmpty)) {
      throw ArgumentError('A domain rule requires nonempty domain expressions');
    }
    return RouteRule._(List<String>.unmodifiable(domains), to);
  }

  final List<String> _domains;
  final RouteTarget _to;
}

/// A concrete outbound used when Core cannot select a balancer member.
final class GroupFallback {
  const GroupFallback._(this._target);

  /// Blocks traffic when the group has no eligible member.
  const GroupFallback.block() : this._(const RouteTarget.block());

  /// Uses a designated backup outbound when the group has no eligible member.
  GroupFallback.node(NodeRef node) : this._(RouteTarget.node(node));

  /// Explicitly allows direct traffic when the group has no eligible member.
  const GroupFallback.direct() : this._(const RouteTarget.direct());

  final RouteTarget _target;
}

/// An Xray balancing strategy and its optional Core settings.
final class BalanceStrategy {
  const BalanceStrategy._(this._type, [this._settings]);

  /// Selects an outbound at random.
  const BalanceStrategy.random() : this._('random');

  /// Cycles through eligible outbounds on new flows.
  const BalanceStrategy.roundRobin() : this._('roundRobin');

  /// Selects an eligible outbound using latency measured by Observatory.
  const BalanceStrategy.leastPing() : this._('leastPing');

  /// Uses Burst Observatory latency, dispersion and failure measurements.
  ///
  /// [expected] is the requested candidate count. [maxRtt] and [baselines]
  /// are Xray delay filters. [tolerance] is an accepted failure rate from zero
  /// to one. Omitted settings use Core defaults.
  factory BalanceStrategy.leastLoad({
    int? expected,
    Duration? maxRtt,
    List<Duration> baselines = const [],
    double? tolerance,
  }) {
    if (expected != null && (expected < 0 || expected > 0x7fffffff)) {
      throw ArgumentError('Expected candidate count is outside the Core range');
    }
    if (tolerance != null &&
        (!tolerance.isFinite || tolerance < 0 || tolerance > 1)) {
      throw ArgumentError('Failure tolerance must be between zero and one');
    }
    final settings = <String, dynamic>{
      if (expected != null) 'expected': expected,
      if (maxRtt != null) 'maxRTT': _profileDuration(maxRtt, allowZero: true),
      if (baselines.isNotEmpty)
        'baselines': [for (final value in baselines) _profileDuration(value)],
      if (tolerance != null) 'tolerance': tolerance,
    };
    return BalanceStrategy._(
      'leastLoad',
      settings.isEmpty ? null : _freezeMap(settings),
    );
  }

  /// Supplies an exact strategy name and optional settings for Core to check.
  ///
  /// The active Core must support [type]. Settings are copied as JSON.
  factory BalanceStrategy.raw({required String type, JsonMap? settings}) {
    if (type.trim().isEmpty) {
      throw ArgumentError('A balancing strategy requires a type');
    }
    return BalanceStrategy._(
        type, settings == null ? null : _freezeMap(settings));
  }

  final String _type;
  final JsonMap? _settings;

  _HealthProbeKind? get _requiredProbe => switch (_type.toLowerCase()) {
        'leastping' => _HealthProbeKind.http,
        'leastload' => _HealthProbeKind.burst,
        _ => null,
      };
}

enum _HealthProbeKind { http, burst }

/// The profile-level Xray observation provider used by typed balancers.
final class HealthProbe {
  HealthProbe._(this._kind, this._settings);

  /// Configures Observatory with an explicit HTTP or HTTPS probe destination.
  factory HealthProbe.http(
    Uri url, {
    Duration? interval,
    bool enableConcurrency = false,
  }) {
    return HealthProbe._(_HealthProbeKind.http, {
      'probeURL': _probeUrl(url),
      if (interval != null) 'probeInterval': _profileDuration(interval),
      if (enableConcurrency) 'enableConcurrency': true,
    });
  }

  /// Configures Burst Observatory with an explicit HTTP or HTTPS destination.
  ///
  /// Core defaults apply to omitted [interval], [timeout], and [sampling].
  factory HealthProbe.burst(
    Uri url, {
    Duration? interval,
    Duration? timeout,
    int? sampling,
  }) {
    if (sampling != null && (sampling <= 0 || sampling > 0x7fffffff)) {
      throw ArgumentError('Probe sample count is outside the Core range');
    }
    return HealthProbe._(_HealthProbeKind.burst, {
      'destination': _probeUrl(url),
      if (interval != null) 'interval': _profileDuration(interval),
      if (timeout != null) 'timeout': _profileDuration(timeout),
      if (sampling != null) 'sampling': sampling,
    });
  }

  final _HealthProbeKind _kind;
  final JsonMap _settings;

  JsonMap _toJson(List<String> subjectSelector) => {
        'subjectSelector': subjectSelector,
        if (_kind == _HealthProbeKind.http) ..._settings,
        if (_kind == _HealthProbeKind.burst) 'pingConfig': _copyMap(_settings),
      };
}

String _profileDuration(Duration duration, {bool allowZero = false}) {
  final value = duration.inMicroseconds;
  // Go's time.Duration stores nanoseconds in a signed 64-bit integer.
  if (value < (allowZero ? 0 : 1) || value > 9223372036854775) {
    throw ArgumentError('Duration is outside the Core range');
  }
  return '${value}us';
}

String _probeUrl(Uri url) {
  if ((url.scheme != 'http' && url.scheme != 'https') || url.host.isEmpty) {
    throw ArgumentError('Probe destination must be an HTTP or HTTPS URL');
  }
  return url.toString();
}
