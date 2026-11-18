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

/// A destination network for an Xray routing rule.
enum XrayRouteNetwork {
  /// Matches TCP connections.
  tcp,

  /// Matches UDP flows.
  udp,
}

/// Controls DNS resolution by the Xray router for IP-based matching.
enum XrayRoutingDomainStrategy {
  /// Uses the destination as received, without resolving it in the router.
  asIs('AsIs'),

  /// Resolves domain destinations when checking an IP condition.
  ipOnDemand('IPOnDemand'),

  /// Retries rules with a resolved destination after no rule matches.
  /// A catch-all rule prevents this second pass.
  ipIfNonMatch('IPIfNonMatch');

  const XrayRoutingDomainStrategy(this._wire);

  final String _wire;
}

/// A literal IPv4 or IPv6 destination prefix for an Xray routing rule.
final class XrayCidr {
  const XrayCidr._(this.address, this.prefixLength);

  /// Parses a numeric address and prefix length, such as `192.0.2.0/24` or
  /// `2001:db8::/32`. Scoped and IPv4-mapped IPv6 literals are excluded.
  factory XrayCidr.parse(String source) {
    final parts = source.split('/');
    if (parts.length != 2 || !RegExp(r'^[0-9]+$').hasMatch(parts[1])) {
      throw const FormatException('Expected an IP address and CIDR prefix');
    }
    final address = parts[0];
    final bytes = _parseProfileIpLiteral(address);
    final prefix = int.tryParse(parts[1]);
    final mapped = bytes.length == 16 &&
        bytes.take(10).every((byte) => byte == 0) &&
        bytes[10] == 255 &&
        bytes[11] == 255;
    if (prefix == null || prefix > bytes.length * 8 || mapped) {
      throw const FormatException('Invalid Xray CIDR address or prefix length');
    }
    return XrayCidr._(address, prefix);
  }

  /// Numeric address portion of the prefix, without the mask.
  final String address;

  /// Mask length in bits.
  final int prefixLength;

  String get _wire => '$address/$prefixLength';
}

/// One destination port or an inclusive range for an Xray routing rule.
final class XrayPortRange {
  const XrayPortRange._(this.first, this.last);

  /// Matches [port], a value from 1 to 65535.
  factory XrayPortRange.single(int port) => XrayPortRange.range(port, port);

  /// Matches ports from [first] through [last], inclusive.
  factory XrayPortRange.range(int first, int last) {
    _checkProfilePort(first);
    _checkProfilePort(last);
    if (first > last) throw ArgumentError('Port range must be ordered');
    return XrayPortRange._(first, last);
  }

  /// First matching port, inclusive.
  final int first;

  /// Last matching port, inclusive.
  final int last;

  String get _wire => first == last ? '$first' : '$first-$last';
}

/// A rule in Xray's ordered route list.
final class RouteRule {
  RouteRule._(this._conditions, this._to);

  /// Matches Xray domain expressions such as `domain:example.org` or
  /// `full:example.org` and sends the matching flow to [to].
  factory RouteRule.domains(List<String> domains, {required RouteTarget to}) {
    if (domains.isEmpty || domains.any((domain) => domain.trim().isEmpty)) {
      throw ArgumentError('A domain rule requires nonempty domain expressions');
    }
    return RouteRule._(_freezeMap({'domain': domains}), to);
  }

  /// Matches destinations and sends matching traffic to [to]. At least one
  /// condition is required. Xray combines different fields with AND and
  /// entries within the same field with OR. Use `setDefaultRoute` for TCP and
  /// UDP traffic that reaches the end of the rule list.
  ///
  /// [domains] accepts Core domain expressions. [inboundTags] can match the
  /// tag of a remote Xray DNS resolver to route its queries independently.
  factory RouteRule.match({
    required RouteTarget to,
    List<String> domains = const [],
    List<XrayCidr> destinationCidrs = const [],
    List<XrayPortRange> destinationPorts = const [],
    Set<XrayRouteNetwork> networks = const {},
    List<String> inboundTags = const [],
  }) {
    if (domains.any((domain) => domain.trim().isEmpty) ||
        inboundTags.any((tag) => tag.trim().isEmpty)) {
      throw ArgumentError('Routing domains and inbound tags must be nonempty');
    }
    if (domains.isEmpty &&
        destinationCidrs.isEmpty &&
        destinationPorts.isEmpty &&
        inboundTags.isEmpty &&
        networks.length != 1) {
      throw ArgumentError('Choose a match condition or use setDefaultRoute');
    }
    final conditions = <String, dynamic>{
      if (domains.isNotEmpty) 'domain': domains,
      if (destinationCidrs.isNotEmpty)
        'ip': [for (final cidr in destinationCidrs) cidr._wire],
      if (destinationPorts.isNotEmpty)
        'port': destinationPorts.map((port) => port._wire).join(','),
      if (networks.isNotEmpty)
        'network': XrayRouteNetwork.values
            .where(networks.contains)
            .map((network) => network.name)
            .join(','),
      if (inboundTags.isNotEmpty) 'inboundTag': inboundTags,
    };
    return RouteRule._(_freezeMap(conditions), to);
  }

  final JsonMap _conditions;
  final RouteTarget _to;
}

void _checkProfilePort(int port) {
  if (port < 1 || port > 65535) {
    throw ArgumentError('Port must be between 1 and 65535');
  }
}

List<int> _parseProfileIpLiteral(String address) {
  try {
    if (address.contains(':')) {
      if (address.contains('%') ||
          address.contains('[') ||
          address.contains(']')) {
        throw const FormatException();
      }
      if (address.contains('.')) {
        _parseProfileIpv4(address.split(':').last);
      }
      return Uri.parseIPv6Address(address);
    }
    return _parseProfileIpv4(address);
  } on FormatException {
    throw const FormatException('Expected a numeric IPv4 or IPv6 address');
  }
}

List<int> _parseProfileIpv4(String address) {
  if (!_profileIpv4Pattern.hasMatch(address)) throw const FormatException();
  return Uri.parseIPv4Address(address);
}

final _profileIpv4Pattern = RegExp(r'^(?:0|[1-9][0-9]{0,2})'
    r'(?:\.(?:0|[1-9][0-9]{0,2})){3}$');

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
