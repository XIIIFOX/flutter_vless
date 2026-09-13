import 'dart:convert';

const exampleBypassRuleTag = 'flutter-vless-example-domain-bypass';

/// Replaces only rules owned by this editor. Imported routing stays intact.
String routingConfig({
  required String config,
  List<String> selectedSites = const [],
}) {
  final configMap = jsonDecode(config) as Map<String, dynamic>;
  final routing = Map<String, dynamic>.from(configMap['routing'] ?? {});
  final rules = List<dynamic>.from(routing['rules'] ?? [])
    ..removeWhere(
        (rule) => rule is Map && rule['ruleTag'] == exampleBypassRuleTag);
  final domains = selectedSites
      .map(normalizeDomainEntry)
      .where((domain) => domain.isNotEmpty)
      .toSet()
      .toList();

  if (domains.isNotEmpty) {
    final outbounds = configMap['outbounds'] as List? ?? [];
    if (!outbounds.any((outbound) =>
        outbound is Map &&
        outbound['tag'] == 'direct' &&
        outbound['protocol'] == 'freedom')) {
      throw const FormatException(
          'Domain bypass requires a freedom outbound tagged "direct".');
    }
    // An IP can serve unrelated domains. DNS resolution must never turn a
    // selected domain into an address-wide exception to the VPN.
    rules.insert(0, {
      'type': 'field',
      'ruleTag': exampleBypassRuleTag,
      'domain': domains,
      'outboundTag': 'direct',
    });

    for (final inbound in configMap['inbounds'] as List? ?? []) {
      if (inbound is! Map ||
          !['socks', 'http', 'tun'].contains(inbound['protocol'])) {
        continue;
      }
      final sniffing = Map<String, dynamic>.from(inbound['sniffing'] ?? {});
      sniffing['enabled'] = true;
      sniffing['destOverride'] = {
        ...List<String>.from(sniffing['destOverride'] ?? []),
        'http',
        'tls',
        'quic',
      }.toList();
      sniffing['routeOnly'] ??= true;
      sniffing['metadataOnly'] = false;
      inbound['sniffing'] = sniffing;
    }
  }

  if (configMap.containsKey('routing') || rules.isNotEmpty) {
    routing['rules'] = rules;
    configMap['routing'] = routing;
  }
  return jsonEncode(configMap);
}

/// Read back the editor's rule after pasting a previously generated config.
List<String>? routingDomainsFromConfig(String config) {
  try {
    final map = jsonDecode(config) as Map<String, dynamic>;
    final rules = (map['routing'] as Map?)?['rules'] as List? ?? [];
    final owned = rules.where(
        (rule) => rule is Map && rule['ruleTag'] == exampleBypassRuleTag);
    if (owned.isEmpty) return null;
    return owned
        .expand((rule) => List<String>.from(rule['domain'] ?? []))
        .toSet()
        .toList();
  } on FormatException {
    return null;
  } on TypeError {
    return null;
  }
}

String normalizeDomainEntry(String raw) {
  raw = raw.trim();
  if (raw.isEmpty) return '';
  for (final prefix in [
    'geosite:',
    'domain:',
    'full:',
    'regexp:',
    'keyword:'
  ]) {
    if (raw.startsWith(prefix)) return raw;
  }
  if (raw.startsWith('https://') || raw.startsWith('http://')) {
    final uri = Uri.parse(raw);
    if (uri.host.isEmpty) throw const FormatException('Enter a domain name.');
    raw = uri.host;
  }
  raw = raw.toLowerCase();
  if (raw.startsWith('*.')) {
    return 'regexp:\\.${RegExp.escape(raw.substring(2))}\$';
  }
  if (raw.startsWith('.')) {
    return 'regexp:${RegExp.escape(raw)}\$';
  }
  if (raw.contains('*')) {
    final escaped = RegExp.escape(raw).replaceAll('\\*', '.*');
    return 'regexp:^$escaped\$';
  }
  return 'domain:$raw';
}
