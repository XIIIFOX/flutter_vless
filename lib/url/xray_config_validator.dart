import 'package:flutter_vless/url/xray_json.dart';
import 'package:flutter_vless/url/xray_geodata_update.dart';

/// Early structural checks for imported Xray configurations.
///
/// These checks do not run Core, resolve names, inspect files or prove platform
/// support/network reachability. Unknown protocol and transport values are
/// left to final native validation rather than a fixed Dart allowlist.
class XrayConfigValidator {
  /// Creates the stateless structural validator.
  const XrayConfigValidator();

  /// Decodes and checks one JSON configuration object, returning its map.
  ///
  /// Supported Core-style comments and a leading BOM are accepted. Throws
  /// [ArgumentError] for malformed JSON, a non-object root or invalid inspected
  /// sections. The returned map is not a prepared native VPN configuration.
  Map<String, dynamic> validateJsonString(String config) {
    final decoded = _decodeJson(config);
    if (decoded is! Map<String, dynamic>) {
      throw ArgumentError('Xray config must be a JSON object');
    }
    validate(decoded);
    return decoded;
  }

  /// Checks inspected root, inbound, outbound and GeoDAT fields in [config].
  ///
  /// Allows missing inputs and Core-style inbound port syntax. Throws
  /// [ArgumentError] for malformed inspected fields or conflicting schema aliases.
  /// This does not mutate [config] or validate every Core-specific setting.
  void validate(Map<String, dynamic> config) {
    _validateObjectSection(config, 'log', required: false);
    _validateObjectSection(config, 'routing', required: false);
    _validateInbounds(readXraySchemaField(config, 'inbounds'));
    _validateOutbounds(readXraySchemaField(config, 'outbounds'));
    XrayGeodataUpdate.validate(config);
  }

  Object? _decodeJson(String config) {
    try {
      return decodeXrayJson(config);
    } on FormatException {
      throw ArgumentError('The provided string is not valid JSON');
    }
  }

  void _validateObjectSection(
    Map<String, dynamic> config,
    String key, {
    required bool required,
  }) {
    final value = readXraySchemaField(config, key);
    if (value == null) {
      if (required) {
        throw ArgumentError('Xray config must contain "$key"');
      }
      return;
    }
    if (value is! Map<String, dynamic>) {
      throw ArgumentError('Xray config "$key" must be a JSON object');
    }
  }

  void _validateInbounds(Object? value) {
    if (value == null) {
      return;
    }
    if (value is! List<dynamic>) {
      throw ArgumentError('Xray config "inbounds" must be a JSON array');
    }
    for (var i = 0; i < value.length; i++) {
      final inbound = value[i];
      if (inbound is! Map<String, dynamic>) {
        throw ArgumentError('Xray inbound at index $i must be a JSON object');
      }
      _validateRequiredString(inbound, 'protocol', 'inbound', i);
      final port = readXraySchemaField(inbound, 'port');
      if (port != null && !_isValidPort(port)) {
        throw ArgumentError('Xray inbound at index $i has invalid port');
      }
    }
  }

  void _validateOutbounds(Object? value) {
    if (value is! List<dynamic>) {
      throw ArgumentError('Xray config must contain an "outbounds" array');
    }
    if (value.isEmpty) {
      throw ArgumentError('Xray config must contain at least one outbound');
    }
    for (var i = 0; i < value.length; i++) {
      final outbound = value[i];
      if (outbound is! Map<String, dynamic>) {
        throw ArgumentError('Xray outbound at index $i must be a JSON object');
      }
      _validateRequiredString(outbound, 'protocol', 'outbound', i);
      final streamSettings = readXraySchemaField(outbound, 'streamSettings');
      if (streamSettings != null) {
        if (streamSettings is! Map<String, dynamic>) {
          throw ArgumentError(
            'Xray outbound at index $i has invalid streamSettings',
          );
        }
        final network = readXraySchemaField(streamSettings, 'network');
        // Core chooses the effective method before validating its string
        // transport. An empty network can be dormant under an explicit method.
        if (network != null && network is! String) {
          throw ArgumentError(
            'Xray outbound at index $i has invalid streamSettings.network',
          );
        }
      }
    }
  }

  void _validateRequiredString(
    Map<String, dynamic> section,
    String key,
    String sectionName,
    int index,
  ) {
    final value = readXraySchemaField(section, key);
    if (value is! String || value.isEmpty) {
      throw ArgumentError(
        'Xray $sectionName at index $index must contain "$key"',
      );
    }
  }

  bool _isValidPort(Object value) {
    if (value is int) return value >= 0 && value <= 65535;
    if (value is! String) return false;
    for (final raw in value.split(',')) {
      final part = raw.trim();
      if (part.isEmpty) continue; // Core ignores empty list entries.
      if (part.startsWith('env:')) {
        // Presence/value belong to the native Core process environment.
        // Do not resolve them using the development computer's environment.
        if (part.length == 4) return false;
        continue;
      }
      final limits = part.split('-');
      if (limits.length > 2) return false;
      for (final text in limits) {
        final syntax = limits.length == 1
            ? RegExp(r'^(0|[1-9][0-9]*)$')
            : RegExp(r'^[0-9]+$');
        final number = int.tryParse(text);
        if (!syntax.hasMatch(text) || number == null || number > 65535) {
          return false;
        }
      }
    }
    return true;
  }
}
