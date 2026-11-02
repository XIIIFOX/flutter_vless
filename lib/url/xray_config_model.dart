import 'dart:collection';

import 'package:flutter_vless/url/xray_json.dart';

/// String-keyed settings/JSON map used by the typed configuration helpers.
typedef JsonMap = Map<String, dynamic>;

/// A typed configuration value that can produce an Xray JSON object.
abstract interface class XrayJsonModel {
  /// Returns this value as JSON fields.
  ///
  /// Implementations may reject invalid typed values with [StateError]; native
  /// Core validation and connection startup are separate operations.
  JsonMap toJson();
}

/// Typed subset used to generate a basic Xray share-link configuration.
///
/// This models logging, inputs, outputs and routing. Preserve a complete raw
/// profile with `XrayJsonConfig` when it contains additional Core fields. Lists
/// and nested settings are caller-owned; this constructor does not deep-freeze
/// them. [toJson] requires at least one input and output.
class XrayConfigDocument implements XrayJsonModel {
  /// Creates a generated configuration from [log], [inbounds], [outbounds] and
  /// [routing]. Structural checks occur during [toJson].
  const XrayConfigDocument({
    required this.log,
    required this.inbounds,
    required this.outbounds,
    required this.routing,
  });

  /// Logging settings for generated JSON; native VPN preparation can replace
  /// log destinations to fit platform storage and diagnostics policy.
  final XrayLog log;

  /// Generated inputs; [toJson] rejects an empty list.
  final List<XrayInbound> inbounds;

  /// Generated outputs in dispatch order; [toJson] rejects an empty list.
  final List<XrayOutbound> outbounds;

  /// Core routing rules for the generated configuration.
  final XrayRouting routing;

  @override
  JsonMap toJson() {
    if (inbounds.isEmpty) {
      throw StateError('Xray config must contain at least one inbound');
    }
    if (outbounds.isEmpty) {
      throw StateError('Xray config must contain at least one outbound');
    }

    final json = <String, dynamic>{
      'log': log.toJson(),
      'inbounds': inbounds.map((inbound) => inbound.toJson()).toList(),
      'outbounds': outbounds.map((outbound) => outbound.toJson()).toList(),
      'routing': routing.toJson(),
    };
    return sanitizeXrayJson(json) as JsonMap;
  }
}

/// Logging fields for generated Xray JSON.
///
/// Native VPN preparation may replace paths and logging policy. These values
/// do not configure the plugin diagnostics buffer.
class XrayLog implements XrayJsonModel {
  /// Creates logging settings; defaults to error-level logging with empty paths
  /// and DNS logging disabled.
  const XrayLog({
    this.access = '',
    this.error = '',
    this.logLevel = 'error',
    this.dnsLog = false,
  });

  /// Access-log destination passed to Core; empty by default.
  final String access;

  /// Error-log destination passed to Core; empty by default.
  final String error;

  /// Core log level, serialized as `loglevel`; defaults to `error`.
  final String logLevel;

  /// Whether generated JSON requests Core DNS logging; defaults to false.
  final bool dnsLog;

  @override
  JsonMap toJson() => {
        'access': access,
        'error': error,
        'loglevel': logLevel,
        'dnsLog': dnsLog,
      };
}

/// One typed Xray input for generated configurations.
///
/// This typed model uses a single TCP/UDP port in 1–65535. Import full JSON
/// when a Core input needs port zero, ranges, lists or a Unix listener. Native
/// VPN preparation preserves imported inputs and adds its own managed adapter.
class XrayInbound implements XrayJsonModel {
  /// Creates an input with [tag], [protocol] and one [port].
  ///
  /// Protocol/port validation occurs in [toJson]. Additional settings are passed
  /// as supplied; native Core performs full schema validation.
  const XrayInbound({
    required this.tag,
    required this.port,
    required this.protocol,
    this.listen,
    this.settings = const {},
    this.sniffing,
    this.streamSettings,
    this.allocate,
  });

  /// Creates a loopback SOCKS input with UDP support and HTTP/TLS/QUIC sniffing.
  ///
  /// The default listener is 127.0.0.1:10807 with no authentication in this
  /// generated document. Supplying [username] and [password] enables password
  /// authentication; both must be printable ASCII values of 1–255 bytes or an
  /// [ArgumentError] is thrown. Native VPN preparation allocates its own private
  /// authenticated adapter rather than relying on these default credentials.
  factory XrayInbound.localSocksTunnel({
    String tag = 'in_proxy',
    String listen = '127.0.0.1',
    int port = 10807,
    int userLevel = 8,
    String? username,
    String? password,
  }) {
    if ((username == null) != (password == null) ||
        username != null &&
            (username.isEmpty ||
                password!.isEmpty ||
                username.codeUnits.any((c) => c < 0x21 || c > 0x7e) ||
                password.codeUnits.any((c) => c < 0x21 || c > 0x7e) ||
                username.length > 255 ||
                password.length > 255)) {
      throw ArgumentError('Local SOCKS credentials require printable ASCII '
          'username and password, each 1–255 bytes.');
    }
    return XrayInbound(
      tag: tag,
      listen: listen,
      port: port,
      protocol: 'socks',
      settings: {
        'auth': username == null ? 'noauth' : 'password',
        if (username != null)
          'accounts': [
            {'user': username, 'pass': password}
          ],
        'udp': true,
        'userLevel': userLevel,
        'address': null,
        'port': null,
        'network': null,
      },
      sniffing: const XraySniffing(
        enabled: true,
        destOverride: ['http', 'tls', 'quic'],
        metadataOnly: false,
      ),
    );
  }

  /// Input identifier referenced by Core routing rules.
  final String tag;

  /// Single listening port; [toJson] requires a value in 1–65535.
  final int port;

  /// Core input protocol name; [toJson] rejects an empty string.
  final String protocol;

  /// Optional bind address passed to Core; null leaves the setting absent after
  /// root configuration cleanup.
  final String? listen;

  /// Protocol-specific input settings; values can include credentials.
  final JsonMap settings;

  /// Optional destination sniffing settings for routing.
  final XraySniffing? sniffing;

  /// Optional raw input transport settings, validated by native Core.
  final JsonMap? streamSettings;

  /// Optional Core input allocation policy passed through as supplied.
  final JsonMap? allocate;

  @override
  JsonMap toJson() {
    if (protocol.isEmpty) {
      throw StateError('Xray inbound protocol must not be empty');
    }
    if (port <= 0 || port > 65535) {
      throw StateError('Xray inbound port is out of range: $port');
    }

    return {
      'tag': tag,
      'port': port,
      'protocol': protocol,
      'listen': listen,
      'settings': settings,
      'sniffing': sniffing?.toJson(),
      'streamSettings': streamSettings,
      'allocate': allocate,
    };
  }
}

/// Destination-sniffing fields used by a generated Xray input.
class XraySniffing implements XrayJsonModel {
  /// Creates sniffing settings with explicit [enabled], [destOverride] and
  /// [metadataOnly] values.
  const XraySniffing({
    required this.enabled,
    required this.destOverride,
    required this.metadataOnly,
  });

  /// Whether Core should inspect supported traffic metadata.
  final bool enabled;

  /// Protocols whose detected destinations can be used, such as `http`, `tls`
  /// and `quic`; support is decided by native Core.
  final List<String> destOverride;

  /// Whether Core should use metadata-only sniffing rather than reading payload.
  final bool metadataOnly;

  @override
  JsonMap toJson() => {
        'enabled': enabled,
        'destOverride': destOverride,
        'metadataOnly': metadataOnly,
      };
}

/// One typed Xray output, with optional transport and protocol settings.
///
/// This helper does not prove that a protocol or transport is supported by the
/// selected platform. Credential and encryption values are passed to Core.
class XrayOutbound implements XrayJsonModel {
  /// Creates an output with [tag] and [protocol].
  ///
  /// Additional maps remain caller-owned. [toJson] rejects an empty protocol;
  /// native preparation validates the remaining configuration.
  const XrayOutbound({
    required this.tag,
    required this.protocol,
    this.settings = const {},
    this.streamSettings,
    this.proxySettings,
    this.sendThrough,
    this.mux,
  });

  /// Creates the generated `direct` Freedom output using `AsIs` DNS strategy.
  ///
  /// Platform VPN preparation applies its protected physical dialing policy.
  factory XrayOutbound.direct() {
    return const XrayOutbound(
      tag: 'direct',
      protocol: 'freedom',
      settings: {
        'vnext': null,
        'servers': null,
        'response': null,
        'network': null,
        'address': null,
        'port': null,
        'domainStrategy': 'AsIs',
        'redirect': null,
        'userLevel': null,
        'inboundTag': null,
        'secretKey': null,
        'peers': null,
      },
    );
  }

  /// Creates the generated `blackhole` output used to reject matching traffic.
  factory XrayOutbound.blackhole() {
    return const XrayOutbound(
      tag: 'blackhole',
      protocol: 'blackhole',
      settings: {
        'vnext': null,
        'servers': null,
        'response': null,
        'network': null,
        'address': null,
        'port': null,
        'domainStrategy': null,
        'redirect': null,
        'userLevel': null,
        'inboundTag': null,
        'secretKey': null,
        'peers': null,
      },
    );
  }

  /// Creates the generated `proxy` output with mux disabled.
  ///
  /// [settings] contains the protocol credentials and server parameters;
  /// [streamSettings] describes the transport/TLS layer.
  factory XrayOutbound.proxy({
    required String protocol,
    required JsonMap settings,
    required XrayStreamSettings streamSettings,
  }) {
    return XrayOutbound(
      tag: 'proxy',
      protocol: protocol,
      settings: settings,
      streamSettings: streamSettings,
      mux: const {'enabled': false, 'concurrency': 8},
    );
  }

  /// Output identifier used by routing rules and chained socket policies.
  final String tag;

  /// Core output protocol name; [toJson] rejects an empty string.
  final String protocol;

  /// Protocol-specific settings, potentially including server credentials.
  final JsonMap settings;

  /// Optional transport, TLS/Reality and socket settings.
  final XrayStreamSettings? streamSettings;

  /// Legacy outbound-chaining fields passed to Core.
  ///
  /// Use the chaining settings supported by the active Core version; this map
  /// is not a compatibility guarantee for removed fields.
  final JsonMap? proxySettings;

  /// Optional source address requested for this output; platform protection may
  /// reject a value incompatible with its selected physical path.
  final String? sendThrough;

  /// Optional Core multiplexing settings; the proxy factory disables mux.
  final JsonMap? mux;

  @override
  JsonMap toJson() {
    if (protocol.isEmpty) {
      throw StateError('Xray outbound protocol must not be empty');
    }

    return {
      'tag': tag,
      'protocol': protocol,
      'settings': settings,
      'streamSettings': streamSettings?.toJson(),
      'proxySettings': proxySettings,
      'sendThrough': sendThrough,
      'mux': mux,
    };
  }
}

/// Core routing fields for a generated configuration.
///
/// This is Core JSON routing, separate from the plugin native VPN-routing
/// options. Native preparation adds only its managed service rules.
class XrayRouting implements XrayJsonModel {
  /// Creates routing with `AsIs` domain strategy and empty rules/balancers by
  /// default. Rule order is preserved.
  const XrayRouting({
    this.domainStrategy = 'AsIs',
    this.domainMatcher,
    this.rules = const [],
    this.balancers = const [],
  });

  /// Core domain-resolution strategy used while matching routing rules.
  final String domainStrategy;

  /// Optional Core domain matcher implementation name.
  final String? domainMatcher;

  /// Ordered Core rule objects, retained as supplied.
  final List<JsonMap> rules;

  /// Core balancer definitions referenced by routing rules.
  final List<JsonMap> balancers;

  @override
  JsonMap toJson() => {
        'domainStrategy': domainStrategy,
        'domainMatcher': domainMatcher,
        'rules': rules,
        'balancers': balancers,
      };
}

/// Typed transport settings used by share-link JSON generation.
///
/// Optional maps retain protocol-specific values; [toJson] does not test server
/// compatibility or activate a native transport. Prefer raw full-profile import
/// when settings are outside this helper surface.
class XrayStreamSettings implements XrayJsonModel {
  /// Creates transport settings with an explicit [network] and [security].
  ///
  /// [network] must be nonempty when serialized. An empty [security] leaves
  /// transport security unspecified; TLS and Reality have separate settings maps.
  const XrayStreamSettings({
    required this.network,
    required this.security,
    this.rawSettings,
    this.tcpSettings,
    this.kcpSettings,
    this.wsSettings,
    this.httpSettings,
    this.h2Settings,
    this.tlsSettings,
    this.quicSettings,
    this.realitySettings,
    this.grpcSettings,
    this.xhttpSettings,
    this.httpupgradeSettings,
    this.hysteriaSettings,
    this.dsSettings,
    this.sockopt,
  });

  /// Core transport name; serialization rejects an empty value.
  final String network;

  /// Transport security mode such as `tls` or `reality`; empty when unspecified.
  final String security;

  /// RAW transport settings, retained as supplied.
  final JsonMap? rawSettings;

  /// TCP transport settings, retained as supplied.
  final JsonMap? tcpSettings;

  /// mKCP transport settings, retained as supplied.
  final JsonMap? kcpSettings;

  /// WebSocket path, headers and other transport settings.
  final JsonMap? wsSettings;

  /// Legacy HTTP transport settings; native Core decides compatibility.
  final JsonMap? httpSettings;

  /// Legacy HTTP/2 settings, serialized under the historical `h2Setting` key.
  ///
  /// Support for legacy transports is decided by native Core.
  final JsonMap? h2Settings;

  /// TLS settings including server identity, ALPN and verification parameters.
  final JsonMap? tlsSettings;

  /// Legacy QUIC transport settings; native Core decides compatibility.
  final JsonMap? quicSettings;

  /// Reality server identity, public key and related transport parameters.
  final JsonMap? realitySettings;

  /// gRPC transport settings such as the service name.
  final JsonMap? grpcSettings;

  /// XHTTP settings including mode, path and optional `extra` configuration.
  final JsonMap? xhttpSettings;

  /// HTTPUpgrade path, host and additional transport fields.
  final JsonMap? httpupgradeSettings;

  /// Hysteria transport settings, including version-2 authentication.
  final JsonMap? hysteriaSettings;

  /// Legacy domain-socket transport settings, subject to native Core support.
  final JsonMap? dsSettings;

  /// Core socket policy; VPN adapters can reject unsafe physical dialing options.
  final JsonMap? sockopt;

  @override
  JsonMap toJson() {
    if (network.isEmpty) {
      throw StateError('Xray streamSettings.network must not be empty');
    }

    return {
      'network': network,
      'security': security,
      'rawSettings': rawSettings,
      'tcpSettings': tcpSettings,
      'kcpSettings': kcpSettings,
      'wsSettings': wsSettings,
      'httpSettings': httpSettings,
      'h2Setting': h2Settings,
      'tlsSettings': tlsSettings,
      'quicSettings': quicSettings,
      'realitySettings': realitySettings,
      'grpcSettings': grpcSettings,
      'xhttpSettings': xhttpSettings,
      'httpupgradeSettings': httpupgradeSettings,
      'hysteriaSettings': hysteriaSettings,
      'dsSettings': dsSettings,
      'sockopt': sockopt,
    };
  }
}

/// Mutable transport settings assembled while parsing a share link.
///
/// [build] wraps each supplied settings map in a read-only top-level view.
/// Nested values and changes made through the original maps remain shared;
/// this is not a deep immutable snapshot.
class XrayStreamSettingsBuilder {
  /// Creates a builder for [network] with transport security initially empty.
  XrayStreamSettingsBuilder({required this.network});

  /// Core transport name; serialization rejects an empty value.
  String network;

  /// Transport security mode such as `tls` or `reality`; empty when unspecified.
  String security = '';

  /// RAW transport settings, retained as supplied.
  JsonMap? rawSettings;

  /// TCP transport settings, retained as supplied.
  JsonMap? tcpSettings;

  /// mKCP transport settings, retained as supplied.
  JsonMap? kcpSettings;

  /// WebSocket path, headers and other transport settings.
  JsonMap? wsSettings;

  /// Legacy HTTP transport settings; native Core decides compatibility.
  JsonMap? httpSettings;

  /// Legacy HTTP/2 settings, serialized under the historical `h2Setting` key.
  ///
  /// Support for legacy transports is decided by native Core.
  JsonMap? h2Settings;

  /// TLS settings including server identity, ALPN and verification parameters.
  JsonMap? tlsSettings;

  /// Legacy QUIC transport settings; native Core decides compatibility.
  JsonMap? quicSettings;

  /// Reality server identity, public key and related transport parameters.
  JsonMap? realitySettings;

  /// gRPC transport settings such as the service name.
  JsonMap? grpcSettings;

  /// XHTTP settings including mode, path and optional `extra` configuration.
  JsonMap? xhttpSettings;

  /// HTTPUpgrade path, host and additional transport fields.
  JsonMap? httpupgradeSettings;

  /// Hysteria transport settings, including version-2 authentication.
  JsonMap? hysteriaSettings;

  /// Legacy domain-socket transport settings, subject to native Core support.
  JsonMap? dsSettings;

  /// Core socket policy; VPN adapters can reject unsafe physical dialing options.
  JsonMap? sockopt;

  /// Configured TLS fingerprint, or null when the TLS settings do not supply one.
  ///
  /// This getter does not read the Reality settings map.
  String? get tlsFingerprint => tlsSettings?['fingerprint'] as String?;

  /// Builds a typed settings value using read-only top-level views of current
  /// settings maps.
  ///
  /// Later mutation of an original map is still visible in the built value.
  /// Validation of a nonempty network occurs when that value is serialized.
  XrayStreamSettings build() {
    return XrayStreamSettings(
      network: network,
      security: security,
      rawSettings: _immutableMap(rawSettings),
      tcpSettings: _immutableMap(tcpSettings),
      kcpSettings: _immutableMap(kcpSettings),
      wsSettings: _immutableMap(wsSettings),
      httpSettings: _immutableMap(httpSettings),
      h2Settings: _immutableMap(h2Settings),
      tlsSettings: _immutableMap(tlsSettings),
      quicSettings: _immutableMap(quicSettings),
      realitySettings: _immutableMap(realitySettings),
      grpcSettings: _immutableMap(grpcSettings),
      xhttpSettings: _immutableMap(xhttpSettings),
      httpupgradeSettings: _immutableMap(httpupgradeSettings),
      hysteriaSettings: _immutableMap(hysteriaSettings),
      dsSettings: _immutableMap(dsSettings),
      sockopt: _immutableMap(sockopt),
    );
  }
}

JsonMap? _immutableMap(JsonMap? value) {
  if (value == null) {
    return null;
  }
  return UnmodifiableMapView<String, dynamic>(value);
}

/// Compatibility edits reported for schema-owned fields of full-profile JSON.
enum XrayJsonChange {
  /// An unsupported TLS certificate-verification bypass field was removed.
  tlsOverrideRemoved,

  /// A known legacy transport setting alias or network spelling was normalized.
  streamAliasNormalized
}

/// Normalizes legacy fields while optionally retaining raw JSON structure.
///
/// Typed generators omit absent values by default. Raw configurations must keep
/// explicit nulls and empty containers because Core can distinguish them from
/// omitted fields. Unknown settings and dictionary keys remain caller data.
///
/// With [preserveStructure] true, known compatibility edits are limited to their
/// schema owners: transport aliases and unsupported TLS verification overrides.
/// [onChange] reports those edits in this mode without exposing private values.
/// With false, typed-generator cleanup also removes null values and empty maps
/// or lists. The result is copied recursively; the input is not modified.
/// Conflicting aliases in inspected full-profile fields throw [ArgumentError].
dynamic sanitizeXrayJson(
  dynamic params, {
  bool preserveStructure = false,
  void Function(XrayJsonChange)? onChange,
}) {
  final sanitized = _sanitizeXrayJson(
    params,
    preserveStructure: preserveStructure,
    root: true,
  );
  if (preserveStructure && sanitized is JsonMap) {
    _normalizeRawStreamFields(sanitized, onChange);
  }
  return sanitized;
}

JsonMap? _rawObjectField(JsonMap object, String name) {
  final value = readXraySchemaField(object, name);
  return value is JsonMap ? value : null;
}

void _normalizeRawTls(JsonMap? tls, void Function(XrayJsonChange)? onChange) {
  if (tls == null) return;
  // Match Core's field folding, but never treat nested user maps as TLS.
  readXraySchemaField(tls, 'allowInsecure');
  final keys =
      tls.keys.where((key) => _matchesXrayField(key, 'allowinsecure')).toList();
  for (final key in keys) {
    tls.remove(key);
  }
  if (keys.isNotEmpty) onChange?.call(XrayJsonChange.tlsOverrideRemoved);
}

void _normalizeRawStreamFields(
    JsonMap config, void Function(XrayJsonChange)? onChange) {
  for (final name in ['inbounds', 'outbounds']) {
    final handlers = readXraySchemaField(config, name);
    if (handlers is! Iterable) continue;
    for (final handler in handlers) {
      if (handler is! JsonMap) continue;
      final stream = _rawObjectField(handler, 'streamSettings');
      if (stream != null) _normalizeRawStream(stream, onChange);
    }
  }
}

void _normalizeRawStream(
    JsonMap stream, void Function(XrayJsonChange)? onChange) {
  if (_normalizeStreamSettingsAliases(stream)) {
    onChange?.call(XrayJsonChange.streamAliasNormalized);
  }
  _normalizeRawTls(_rawObjectField(stream, 'tlsSettings'), onChange);

  // These are Core's two other TLSConfig owners. A tlsConfig-looking key in
  // another mask, or in any arbitrary metadata, remains caller data.
  final mask = _rawObjectField(stream, 'finalmask');
  final udp = mask == null ? null : readXraySchemaField(mask, 'udp');
  if (udp is Iterable) {
    for (final entry in udp) {
      if (entry is! JsonMap) continue;
      final type = readXraySchemaField(entry, 'type');
      final settings = _rawObjectField(entry, 'settings');
      if (type is! String || settings == null) continue;
      switch (type.toLowerCase()) {
        case 'realm':
          _normalizeRawTls(_rawObjectField(settings, 'tlsConfig'), onChange);
        case 'xdns':
          final resolvers = readXraySchemaField(settings, 'resolvers');
          if (resolvers is Iterable) {
            for (final resolver in resolvers) {
              if (resolver is JsonMap) {
                _normalizeRawTls(
                    _rawObjectField(resolver, 'tlsConfig'), onChange);
              }
            }
          }
      }
    }
  }

  // StreamConfig Build consumes the preferred XHTTP alias even if another
  // network is selected. Extra replaces the outer object, including null.
  final xhttp = _rawObjectField(stream, 'xhttpSettings') ??
      _rawObjectField(stream, 'splithttpSettings');
  if (xhttp == null) return;
  final extra = readXraySchemaField(xhttp, 'extra');
  final hasExtra = xhttp.keys.any((key) => _matchesXrayField(key, 'extra'));
  final effective = hasExtra ? (extra is JsonMap ? extra : null) : xhttp;
  if (effective == null) return;
  final download = _rawObjectField(effective, 'downloadSettings');
  if (download != null) _normalizeRawStream(download, onChange);
}

String _xrayField(String key) => foldXraySchemaField(key);

bool _matchesXrayField(String key, String field) => _xrayField(key) == field;

bool _isRoutingAttrs(List<String> path) =>
    path.length == 4 &&
    _matchesXrayField(path[0], 'routing') &&
    _matchesXrayField(path[1], 'rules') &&
    path[2] == '*' &&
    _matchesXrayField(path[3], 'attrs');

bool _isTransportHeaders(List<String> path) {
  if (path.length < 5 || !_matchesXrayField(path.last, 'headers')) {
    return false;
  }
  final fields = path.map(_xrayField).toList(growable: false);
  if (!{'inbounds', 'outbounds'}.contains(fields[0]) ||
      fields[1] != '*' ||
      fields[2] != 'streamsettings') {
    return false;
  }
  var cursor = 3;
  while (cursor < fields.length - 1) {
    final transport = fields[cursor++];
    switch (transport) {
      case 'xhttpsettings':
      case 'splithttpsettings':
        if (fields[cursor] == 'extra') cursor++;
        if (cursor < fields.length - 1 &&
            fields[cursor] == 'downloadsettings') {
          cursor++;
          continue;
        }
        return cursor == fields.length - 1;
      case 'wssettings':
      case 'httpupgradesettings':
      case 'masquesettings':
        return cursor == fields.length - 1;
      case 'tcpsettings':
      case 'rawsettings':
        return cursor + 3 == fields.length &&
            fields[cursor] == 'header' &&
            {'request', 'response'}.contains(fields[cursor + 1]);
      case 'hysteriasettings':
        return cursor + 2 == fields.length && fields[cursor] == 'masquerade';
      default:
        return false;
    }
  }
  return false;
}

dynamic _sanitizeXrayJson(
  dynamic params, {
  required bool preserveStructure,
  bool root = false,
  bool dnsFields = false,
  bool dictionaryData = false,
  List<String> path = const [],
}) {
  if (params is XrayJsonModel) {
    return _sanitizeXrayJson(
      params.toJson(),
      preserveStructure: preserveStructure,
      root: root,
      dnsFields: dnsFields,
      dictionaryData: dictionaryData,
      path: path,
    );
  }
  if (params is Map) {
    final source = Map<String, dynamic>.fromEntries(
      params.entries
          .map((entry) => MapEntry(entry.key.toString(), entry.value)),
    );
    // Typed generators keep their legacy cleanup. Raw JSON is copied intact;
    // only the schema-owned objects visited above receive compatibility edits.
    if (!preserveStructure && !dictionaryData) {
      _normalizeStreamSettingsAliases(source);
      source.remove('allowInsecure');
    }

    final map = <String, dynamic>{};
    source.forEach((key, value) {
      final childPath = [...path, key];
      final sanitized = _sanitizeXrayJson(
        value,
        preserveStructure: preserveStructure,
        dnsFields: root && _matchesXrayField(key, 'dns'),
        dictionaryData: dictionaryData ||
            (dnsFields && _matchesXrayField(key, 'hosts')) ||
            _isTransportHeaders(childPath) ||
            _isRoutingAttrs(childPath),
        path: childPath,
      );
      if (preserveStructure || sanitized != null) {
        map[key] = sanitized;
      }
    });
    return !preserveStructure && map.isEmpty ? null : map;
  }
  if (params is Iterable) {
    final list = <dynamic>[];
    for (final value in params) {
      final sanitized = _sanitizeXrayJson(
        value,
        preserveStructure: preserveStructure,
        dictionaryData: dictionaryData,
        path: [...path, '*'],
      );
      if (preserveStructure || sanitized != null) {
        list.add(sanitized);
      }
    }
    return !preserveStructure && list.isEmpty ? null : list;
  }
  return params;
}

bool _normalizeStreamSettingsAliases(JsonMap map) {
  var changed = false;
  void moveAlias(String from, String to) {
    if (!map.containsKey(from)) {
      return;
    }
    changed = true;
    final value = map.remove(from);
    map.putIfAbsent(to, () => value);
  }

  moveAlias('xHTTPSettings', 'xhttpSettings');
  moveAlias('httpUpgradeSettings', 'httpupgradeSettings');
  moveAlias('splitHTTPSettings', 'splithttpSettings');

  final network = map['network'];
  if (network is String && network != network.toLowerCase()) {
    changed = true;
    map['network'] = network.toLowerCase();
  }
  return changed;
}
