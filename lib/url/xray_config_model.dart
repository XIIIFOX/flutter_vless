import 'dart:collection';

import 'package:flutter_vless/url/xray_json.dart';

typedef JsonMap = Map<String, dynamic>;

abstract interface class XrayJsonModel {
  JsonMap toJson();
}

class XrayConfigDocument implements XrayJsonModel {
  const XrayConfigDocument({
    required this.log,
    required this.inbounds,
    required this.outbounds,
    required this.routing,
  });

  final XrayLog log;
  final List<XrayInbound> inbounds;
  final List<XrayOutbound> outbounds;
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

class XrayLog implements XrayJsonModel {
  const XrayLog({
    this.access = '',
    this.error = '',
    this.logLevel = 'error',
    this.dnsLog = false,
  });

  final String access;
  final String error;
  final String logLevel;
  final bool dnsLog;

  @override
  JsonMap toJson() => {
        'access': access,
        'error': error,
        'loglevel': logLevel,
        'dnsLog': dnsLog,
      };
}

class XrayInbound implements XrayJsonModel {
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

  final String tag;
  final int port;
  final String protocol;
  final String? listen;
  final JsonMap settings;
  final XraySniffing? sniffing;
  final JsonMap? streamSettings;
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

class XraySniffing implements XrayJsonModel {
  const XraySniffing({
    required this.enabled,
    required this.destOverride,
    required this.metadataOnly,
  });

  final bool enabled;
  final List<String> destOverride;
  final bool metadataOnly;

  @override
  JsonMap toJson() => {
        'enabled': enabled,
        'destOverride': destOverride,
        'metadataOnly': metadataOnly,
      };
}

class XrayOutbound implements XrayJsonModel {
  const XrayOutbound({
    required this.tag,
    required this.protocol,
    this.settings = const {},
    this.streamSettings,
    this.proxySettings,
    this.sendThrough,
    this.mux,
  });

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

  final String tag;
  final String protocol;
  final JsonMap settings;
  final XrayStreamSettings? streamSettings;
  final JsonMap? proxySettings;
  final String? sendThrough;
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

class XrayRouting implements XrayJsonModel {
  const XrayRouting({
    this.domainStrategy = 'AsIs',
    this.domainMatcher,
    this.rules = const [],
    this.balancers = const [],
  });

  final String domainStrategy;
  final String? domainMatcher;
  final List<JsonMap> rules;
  final List<JsonMap> balancers;

  @override
  JsonMap toJson() => {
        'domainStrategy': domainStrategy,
        'domainMatcher': domainMatcher,
        'rules': rules,
        'balancers': balancers,
      };
}

class XrayStreamSettings implements XrayJsonModel {
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

  final String network;
  final String security;
  final JsonMap? rawSettings;
  final JsonMap? tcpSettings;
  final JsonMap? kcpSettings;
  final JsonMap? wsSettings;
  final JsonMap? httpSettings;
  final JsonMap? h2Settings;
  final JsonMap? tlsSettings;
  final JsonMap? quicSettings;
  final JsonMap? realitySettings;
  final JsonMap? grpcSettings;
  final JsonMap? xhttpSettings;
  final JsonMap? httpupgradeSettings;
  final JsonMap? hysteriaSettings;
  final JsonMap? dsSettings;
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

class XrayStreamSettingsBuilder {
  XrayStreamSettingsBuilder({required this.network});

  String network;
  String security = '';
  JsonMap? rawSettings;
  JsonMap? tcpSettings;
  JsonMap? kcpSettings;
  JsonMap? wsSettings;
  JsonMap? httpSettings;
  JsonMap? h2Settings;
  JsonMap? tlsSettings;
  JsonMap? quicSettings;
  JsonMap? realitySettings;
  JsonMap? grpcSettings;
  JsonMap? xhttpSettings;
  JsonMap? httpupgradeSettings;
  JsonMap? hysteriaSettings;
  JsonMap? dsSettings;
  JsonMap? sockopt;

  String? get tlsFingerprint => tlsSettings?['fingerprint'] as String?;

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

enum XrayJsonChange { tlsOverrideRemoved, streamAliasNormalized }

/// Normalizes legacy fields while optionally retaining raw JSON structure.
///
/// Typed generators omit absent values by default. Raw configurations must keep
/// explicit nulls and empty containers because Core can distinguish them from
/// omitted fields.
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
