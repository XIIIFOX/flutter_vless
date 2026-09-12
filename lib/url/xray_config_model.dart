import 'dart:collection';

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
  }) {
    return XrayInbound(
      tag: tag,
      listen: listen,
      port: port,
      protocol: 'socks',
      settings: {
        'auth': 'noauth',
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

dynamic sanitizeXrayJson(dynamic params) {
  if (params is XrayJsonModel) {
    return sanitizeXrayJson(params.toJson());
  }
  if (params is Map) {
    final source = Map<String, dynamic>.fromEntries(
      params.entries
          .map((entry) => MapEntry(entry.key.toString(), entry.value)),
    );
    _normalizeStreamSettingsAliases(source);
    source.remove('allowInsecure');

    final map = <String, dynamic>{};
    source.forEach((key, value) {
      final sanitized = sanitizeXrayJson(value);
      if (sanitized != null) {
        map[key] = sanitized;
      }
    });
    return map.isEmpty ? null : map;
  }
  if (params is Iterable) {
    final list = <dynamic>[];
    for (final value in params) {
      final sanitized = sanitizeXrayJson(value);
      if (sanitized != null) {
        list.add(sanitized);
      }
    }
    return list.isEmpty ? null : list;
  }
  return params;
}

void _normalizeStreamSettingsAliases(JsonMap map) {
  void moveAlias(String from, String to) {
    if (!map.containsKey(from)) {
      return;
    }
    final value = map.remove(from);
    map.putIfAbsent(to, () => value);
  }

  moveAlias('xHTTPSettings', 'xhttpSettings');
  moveAlias('httpUpgradeSettings', 'httpupgradeSettings');
  moveAlias('splitHTTPSettings', 'splithttpSettings');

  final network = map['network'];
  if (network is String) {
    map['network'] = network.toLowerCase();
  }
}
