part of '../xray_profile.dart';

/// Selects address families for the built-in Xray DNS resolver.
enum XrayDnsQueryStrategy {
  /// Requests IPv4 and IPv6 addresses.
  useIp('UseIP'),

  /// Requests IPv4 addresses.
  useIpv4('UseIPv4'),

  /// Requests IPv6 addresses.
  useIpv6('UseIPv6'),

  /// Selects address families using Core's view of system connectivity.
  useSystem('UseSystem');

  const XrayDnsQueryStrategy(this._wire);

  final String _wire;
}

/// Optional fields for the profile's built-in DNS configuration.
final class XrayDnsOptions {
  /// Omitted settings retain the profile's original values or Core defaults.
  const XrayDnsOptions({this.queryStrategy, this.disableFallbackIfMatch});

  /// The address family policy for all built-in DNS queries.
  final XrayDnsQueryStrategy? queryStrategy;

  /// Excludes unmatched fallback resolvers after a domain matches at least
  /// one resolver. Multiple matching resolvers can still be tried in order.
  final bool? disableFallbackIfMatch;

  JsonMap _toCore() => {
        if (queryStrategy != null) 'queryStrategy': queryStrategy!._wire,
        if (disableFallbackIfMatch != null)
          'disableFallbackIfMatch': disableFallbackIfMatch,
      };
}

/// An immutable resolver definition for the built-in Xray DNS service.
final class XrayDnsServer {
  XrayDnsServer._(
    String address, {
    int? port,
    List<String> domains = const [],
    String? tag,
    XrayDnsQueryStrategy? queryStrategy,
    bool? skipFallback,
    bool? finalQuery,
  }) : _settings = _freezeMap({
          'address': address,
          if (port != null) 'port': port,
          if (domains.isNotEmpty) 'domains': domains,
          if (tag != null) 'tag': tag,
          if (queryStrategy != null) 'queryStrategy': queryStrategy._wire,
          if (skipFallback != null) 'skipFallback': skipFallback,
          if (finalQuery != null) 'finalQuery': finalQuery,
        }) {
    if (domains.any((expression) => expression.trim().isEmpty)) {
      throw ArgumentError('DNS domain expressions must be nonempty');
    }
    if (tag != null && tag.trim().isEmpty) {
      throw ArgumentError('DNS routing tag must be nonempty');
    }
  }

  /// Adds a classic UDP resolver at a literal IPv4 or IPv6 [address].
  ///
  /// [domains] prioritizes this resolver for matching domain expressions.
  /// [skipFallback] excludes it from normal fallback for unrelated domains.
  /// [finalQuery] ends resolver selection when this resolver is selected.
  /// [tag] identifies its outbound queries in Xray inbound-tag routing rules.
  /// Put an explicit default resolver first since Core may use the first
  /// server when the selection rules leave no other candidate.
  factory XrayDnsServer.udp(
    String address, {
    int? port,
    List<String> domains = const [],
    String? tag,
    XrayDnsQueryStrategy? queryStrategy,
    bool? skipFallback,
    bool? finalQuery,
  }) {
    _parseProfileIpLiteral(address);
    if (port != null) _checkProfilePort(port);
    return XrayDnsServer._(
      address,
      port: port,
      domains: domains,
      tag: tag,
      queryStrategy: queryStrategy,
      skipFallback: skipFallback,
      finalQuery: finalQuery,
    );
  }

  /// Adds a DNS-over-HTTPS resolver whose requests follow Xray routing.
  ///
  /// [endpoint] is an HTTPS URI with an explicit host. If that host is a
  /// domain, make its bootstrap resolution reachable through your profile.
  /// Resolver options have the same meaning as for [XrayDnsServer.udp].
  factory XrayDnsServer.doh(
    Uri endpoint, {
    List<String> domains = const [],
    String? tag,
    XrayDnsQueryStrategy? queryStrategy,
    bool? skipFallback,
    bool? finalQuery,
  }) {
    if (endpoint.scheme != 'https' ||
        endpoint.host.isEmpty ||
        endpoint.userInfo.isNotEmpty ||
        endpoint.hasFragment) {
      throw ArgumentError('DNS-over-HTTPS requires an HTTPS resolver URI');
    }
    if (endpoint.hasPort) _checkProfilePort(endpoint.port);
    return XrayDnsServer._(
      endpoint.toString(),
      domains: domains,
      tag: tag,
      queryStrategy: queryStrategy,
      skipFallback: skipFallback,
      finalQuery: finalQuery,
    );
  }

  final JsonMap _settings;

  bool get _usesSplitQueries =>
      _settings.containsKey('domains') ||
      _settings['skipFallback'] == true ||
      _settings['finalQuery'] == true;
}

void _checkDnsScript(JsonMap dns) {
  final script = readXraySchemaField(dns, 'script');
  if (script != null && script != '') {
    throw ArgumentError('Split DNS cannot be combined with a DNS script');
  }
}
