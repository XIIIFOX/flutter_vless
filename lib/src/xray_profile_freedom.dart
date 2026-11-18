part of '../xray_profile.dart';

/// Severity used when a Freedom rule blocks a destination.
enum XrayFreedomLogLevel {
  /// Suppresses the per-destination event.
  none,

  /// Emits the event at debug severity.
  debug,

  /// Emits the event at info severity, the Core default.
  info,

  /// Emits the event at warning severity.
  warning,

  /// Emits the event at error severity.
  error,
}

/// Time Core keeps a blocked Freedom connection open.
final class XrayFreedomBlockDelay {
  const XrayFreedomBlockDelay._(this.minimum, this.maximum);

  /// Uses a fixed [delay]. Zero closes the blocked connection immediately.
  factory XrayFreedomBlockDelay.fixed(Duration delay) =>
      XrayFreedomBlockDelay.range(delay, delay);

  /// Selects an ordered, inclusive range of whole seconds.
  /// Values must fit a signed 32-bit number of seconds.
  factory XrayFreedomBlockDelay.range(Duration minimum, Duration maximum) {
    if (minimum.isNegative ||
        maximum < minimum ||
        maximum.inSeconds > 0x7fffffff ||
        minimum.inMicroseconds % Duration.microsecondsPerSecond != 0 ||
        maximum.inMicroseconds % Duration.microsecondsPerSecond != 0) {
      throw ArgumentError('Freedom delay requires ordered whole seconds');
    }
    return XrayFreedomBlockDelay._(minimum, maximum);
  }

  /// Shortest permitted delay.
  final Duration minimum;

  /// Longest permitted delay.
  final Duration maximum;

  Object get _wire => minimum == maximum
      ? minimum.inSeconds
      : '${minimum.inSeconds}-${maximum.inSeconds}';
}

/// An ordered destination check on a final Freedom outbound.
///
/// Core combines different conditions with AND and entries in the same field
/// with OR. Omitting every condition matches all destinations on this outbound.
/// Rules run before Core's built-in policy. Core skips them when Freedom
/// dials through a `sockopt.dialerProxy`.
final class XrayFreedomFinalRule {
  XrayFreedomFinalRule._(
    String action,
    List<XrayCidr> cidrs,
    List<XrayPortRange> ports,
    Set<XrayRouteNetwork> networks, {
    XrayFreedomBlockDelay? delay,
    XrayFreedomLogLevel? logLevel,
  })  : _needsNewCore = delay != null || logLevel != null,
        _definition = {
          'action': action,
          if (cidrs.isNotEmpty) 'ip': [for (final cidr in cidrs) cidr._wire],
          if (ports.isNotEmpty)
            'port': ports.map((port) => port._wire).join(','),
          if (networks.isNotEmpty)
            'network': XrayRouteNetwork.values
                .where(networks.contains)
                .map((network) => network.name)
                .join(','),
          if (delay != null) 'delay': delay._wire,
          if (logLevel != null) 'logLevel': logLevel.name,
        };

  /// Permits the first matching destination using this outbound.
  factory XrayFreedomFinalRule.allow({
    List<XrayCidr> destinationCidrs = const [],
    List<XrayPortRange> destinationPorts = const [],
    Set<XrayRouteNetwork> networks = const {},
  }) =>
      XrayFreedomFinalRule._(
          'allow', destinationCidrs, destinationPorts, networks);

  /// Blocks the first matching destination using this outbound.
  ///
  /// Omitted [delay] and [logLevel] use Core defaults. Explicit values require
  /// Core 26.11.9 or newer. Use [XrayFreedomLogLevel.none] to suppress the
  /// per-destination log entry.
  factory XrayFreedomFinalRule.block({
    List<XrayCidr> destinationCidrs = const [],
    List<XrayPortRange> destinationPorts = const [],
    Set<XrayRouteNetwork> networks = const {},
    XrayFreedomBlockDelay? delay,
    XrayFreedomLogLevel? logLevel,
  }) =>
      XrayFreedomFinalRule._(
          'block', destinationCidrs, destinationPorts, networks,
          delay: delay, logLevel: logLevel);

  final bool _needsNewCore;
  final JsonMap _definition;
}
