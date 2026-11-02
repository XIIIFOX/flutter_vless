import 'dart:convert';

import 'package:flutter_vless/url/xray_config_model.dart';

/// A parsed share link or imported Xray configuration.
///
/// Use `FlutterVless.parse` or `FlutterVless.parseMany` to select an importer.
/// Parsing and JSON generation do not connect, resolve names or establish that
/// the active native backend supports every requested transport. Configurations
/// and source links can contain credentials; keep them out of application logs.
abstract class FlutterVlessURL {
  /// Creates a parsed-profile base with the original source text in [url].
  FlutterVlessURL({required this.url});

  /// Original share link or configuration text, which may include credentials.
  final String url;

  /// Legacy insecure-TLS hint; the base implementation is always false.
  ///
  /// JSON normalization removes unsupported certificate-verification overrides.
  bool get allowInsecure => false;

  /// Default protocol-level cipher selection used by generated user settings.
  ///
  /// This is separate from the transport TLS/Reality security setting.
  String get security => "auto";

  /// User policy level included in generated inbound and outbound settings.
  int get level => 8;

  /// Remote server port; share-link implementations use 443 when omitted.
  int get port => 443;

  /// Initial transport network used when creating [streamSettingsBuilder].
  String get network => "tcp";

  /// Remote endpoint host exposed by this importer, or an empty base default.
  ///
  /// Full raw profiles can have several endpoints and retain the empty base
  /// value; inspect their configuration instead of treating this as a summary.
  String get address => '';

  /// Display name for the profile; the base implementation has no name.
  String get remark => '';

  /// Primary outbound JSON for this profile.
  ///
  /// A generated share-link profile normally tags this outbound as `proxy`.
  /// Imported full configurations can contain a different first outbound.
  Map<String, dynamic> get outbound1;

  /// Full generated configuration with a local SOCKS input and proxy, direct
  /// and blackhole outputs.
  ///
  /// Native VPN adapters add their managed authenticated input during preparation.
  /// Raw-JSON importers override this getter to retain the imported configuration.
  Map<String, dynamic> get fullConfiguration {
    final proxyOutbound = outbound1;
    final document = XrayConfigDocument(
      log: const XrayLog(),
      // Keep the generated caller input in the document. Native VPN
      // preparation adds its own private authenticated packet adapter.
      inbounds: [XrayInbound.localSocksTunnel(userLevel: level)],
      outbounds: [
        XrayOutbound(
          tag: proxyOutbound['tag'] as String? ?? 'proxy',
          protocol: proxyOutbound['protocol'] as String? ?? '',
          settings: (proxyOutbound['settings'] as Map).cast<String, dynamic>(),
          streamSettings: _streamSettingsFromOutbound(proxyOutbound),
          proxySettings:
              (proxyOutbound['proxySettings'] as Map?)?.cast<String, dynamic>(),
          sendThrough: proxyOutbound['sendThrough'] as String?,
          mux: (proxyOutbound['mux'] as Map?)?.cast<String, dynamic>(),
        ),
        XrayOutbound.direct(),
        XrayOutbound.blackhole(),
      ],
      // Keep the generated Core routing strategy deterministic. Native VPN
      // preparation plans transport endpoint bootstrap separately from caller
      // DNS selection and domain-routing rules.
      routing: const XrayRouting(),
    );
    return document.toJson();
  }

  /// Serializes [fullConfiguration] as JSON with [indent] spaces per level.
  ///
  /// This does not run native validation or start a connection. The result may
  /// contain server credentials and should not be logged.
  String getFullConfiguration({int indent = 2}) {
    return JsonEncoder.withIndent(' ' * indent).convert(
      fullConfiguration,
    );
  }

  /// Mutable transport builder used when generating the primary outbound.
  ///
  /// Changes made before reading [outbound1] or [fullConfiguration] affect generated
  /// share-link profiles. Raw-JSON importers retain their own configuration instead.
  late final XrayStreamSettingsBuilder streamSettingsBuilder =
      XrayStreamSettingsBuilder(network: network);

  /// Current builder settings serialized as the Xray `streamSettings` object.
  Map<String, dynamic> get streamSetting =>
      streamSettingsBuilder.build().toJson();

  /// Populates Xray `streamSettings` from VLESS URL query parameters.
  ///
  /// Returns the transport Host-derived SNI suggestion; an explicit TLS SNI
  /// should take precedence. [transport] selects the network, while the other
  /// parameters retain the protocol-specific headers, paths, keys, mode and
  /// service name. [extra] carries XHTTP/HTTPUpgrade JSON settings.
  /// Native Core remains responsible for accepting the effective transport.
  String populateTransportSettings({
    required String transport,
    required String? headerType,
    required String? host,
    required String? path,
    required String? seed,
    required String? quicSecurity,
    required String? key,
    required String? mode,
    required String? serviceName,
    String? extra,
  }) {
    String sni = '';
    final normalizedTransport = transport.toLowerCase();
    streamSettingsBuilder.network = normalizedTransport;
    if (normalizedTransport == 'tcp') {
      final tcpHeader = <String, dynamic>{"type": "none", "request": null};
      final tcpSettings = <String, dynamic>{
        "header": tcpHeader,
        "acceptProxyProtocol": null
      };
      streamSettingsBuilder.tcpSettings = tcpSettings;
      if (headerType == 'http') {
        tcpHeader['type'] = 'http';
        if (host != "" || path != "") {
          final request = {
            "path": path == null ? ["/"] : path.split(","),
            "headers": {
              "Host": host == null ? "" : host.split(","),
              "User-Agent": [
                "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/53.0.2785.109 Mobile/14A456 Safari/601.1.46",
              ],
              "Accept-Encoding": [
                "gzip, deflate",
              ],
              "Connection": [
                "keep-alive",
              ],
              "Pragma": "no-cache",
            },
            "version": "1.1",
            "method": "GET",
          };
          tcpHeader['request'] = request;
          final headers = request['headers'] as Map<String, dynamic>;
          final hosts = headers['Host'] as List;
          sni = hosts.isNotEmpty ? hosts.first as String : sni;
        }
      } else {
        tcpHeader['type'] = 'none';
        sni = host != "" ? host ?? '' : '';
      }
    } else if (normalizedTransport == 'raw') {
      final rawHeader = <String, dynamic>{"type": headerType ?? "none"};
      streamSettingsBuilder.rawSettings = {
        "header": rawHeader,
        "acceptProxyProtocol": null,
      };
      sni = host != "" ? host ?? '' : '';
    } else if (normalizedTransport == 'kcp' || normalizedTransport == 'mkcp') {
      streamSettingsBuilder.network = 'kcp';
      streamSettingsBuilder.kcpSettings = {
        "mtu": 1350,
        "tti": 50,
        "uplinkCapacity": 12,
        "downlinkCapacity": 100,
        "congestion": false,
        "readBufferSize": 1,
        "writeBufferSize": 1,
        "header": {
          "type": headerType ?? "none",
        },
        "seed": (seed == null || seed == '') ? null : seed,
      };
    } else if (normalizedTransport == 'ws' ||
        normalizedTransport == 'websocket') {
      streamSettingsBuilder.network = 'ws';
      final wsHeaders = {"Host": host ?? ""};
      final wsSettings = {
        "path": path ?? ['/'],
        "headers": wsHeaders,
        "maxEarlyData": null,
        "useBrowserForwarding": null,
        "acceptProxyProtocol": null,
      };
      streamSettingsBuilder.wsSettings = wsSettings;
      sni = wsHeaders['Host'] as String;
    } else if (normalizedTransport == 'h2' || normalizedTransport == 'http') {
      streamSettingsBuilder.network = 'h2';
      final h2Settings = {
        "host": host?.split(",") ?? "",
        "path": path ?? ['/'],
      };
      streamSettingsBuilder.h2Settings = h2Settings;
      final hosts = h2Settings['host'];
      sni = hosts is List && hosts.isNotEmpty ? hosts.first as String : sni;
    } else if (normalizedTransport == 'quic') {
      streamSettingsBuilder.quicSettings = {
        "security": quicSecurity ?? 'none',
        "key": key ?? '',
        "header": {"type": headerType ?? "none"},
      };
    } else if (normalizedTransport == 'grpc') {
      streamSettingsBuilder.grpcSettings = {
        "serviceName": serviceName ?? "",
        "multiMode": mode == "multi",
      };
      sni = host ?? "";
    } else if (normalizedTransport == 'xhttp') {
      // XHTTP links often rely on server-specific knobs in `extra`. Preserving
      // them is required for compatibility. Measure an allowed destination
      // through the connected runtime to check the actual network path.
      streamSettingsBuilder.network = 'xhttp';
      final xhttpExtra = decodeXhttpExtra(extra);
      streamSettingsBuilder.xhttpSettings = {
        "host": host ?? "",
        "mode": mode ?? "auto",
        "path": emptyToDefault(path, "/"),
        if (xhttpExtra != null) "extra": xhttpExtra,
      };
      sni = host ?? "";
    } else if (normalizedTransport == 'httpupgrade' ||
        normalizedTransport == 'http_upgrade') {
      streamSettingsBuilder.network = 'httpupgrade';
      final httpupgradeExtra = decodeXhttpExtra(extra);
      streamSettingsBuilder.httpupgradeSettings = {
        "path": emptyToDefault(path, "/"),
        "host": host ?? "",
        "headers": _stringMap(httpupgradeExtra?['headers']),
        "acceptProxyProtocol": null,
      };
      sni = host ?? "";
    }
    return sni;
  }

  /// Returns [fallback] when [value] is null or empty; otherwise returns [value].
  String emptyToDefault(String? value, String fallback) {
    return value == null || value.isEmpty ? fallback : value;
  }

  /// Decodes the XHTTP `extra` JSON object from URL query parameters.
  ///
  /// Some subscriptions double-encode this field, so decoding is attempted a
  /// few times before parsing JSON. Invalid data is dropped instead of emitting
  /// malformed Xray config, which would hide the actual transport failure.
  Map<String, dynamic>? decodeXhttpExtra(String? extra) {
    if (extra == null || extra.isEmpty) {
      return null;
    }

    String candidate = extra;
    for (var i = 0; i < 3; i++) {
      try {
        final decoded = Uri.decodeComponent(candidate);
        if (decoded == candidate) {
          break;
        }
        candidate = decoded;
      } catch (_) {
        break;
      }
    }

    try {
      final decoded = jsonDecode(candidate);
      return decoded is Map<String, dynamic> ? decoded : null;
    } catch (_) {
      return null;
    }
  }

  Map<String, dynamic>? _stringMap(Object? value) {
    if (value is! Map) {
      return null;
    }
    final result = <String, dynamic>{};
    value.forEach((key, item) {
      final text = item?.toString();
      if (text != null && text.isNotEmpty) {
        result[key.toString()] = text;
      }
    });
    return result.isEmpty ? null : result;
  }

  /// Updates the transport builder from TLS/Reality share-link settings.
  ///
  /// [streamSecurity] selects the `tls` or `reality` settings object. [sni] keeps
  /// the configured server identity; [alpns] is a comma-separated ALPN list.
  /// [publicKey], [shortId] and [spiderX] are Reality parameters. Optional
  /// [pinnedPeerCertSha256] and [verifyPeerCertByName] retain explicit verification
  /// settings. [allowInsecure] is accepted for compatibility but is not emitted
  /// as a certificate-verification bypass.
  void populateTlsSettings({
    required String? streamSecurity,
    required bool allowInsecure,
    required String? sni,
    required String? fingerprint,
    required String? alpns,
    required String? publicKey,
    required String? shortId,
    required String? spiderX,
    String? pinnedPeerCertSha256,
    String? verifyPeerCertByName,
  }) {
    streamSettingsBuilder.security = streamSecurity ?? '';
    Map<String, dynamic> tlsSetting = {
      "serverName": sni,
      "alpn": alpns == '' ? null : alpns?.split(','),
      "minVersion": null,
      "maxVersion": null,
      "preferServerCipherSuites": null,
      "cipherSuites": null,
      "fingerprint": fingerprint,
      "certificates": null,
      "disableSystemRoot": null,
      "enableSessionResumption": null,
      "show": false,
      "publicKey": publicKey,
      "shortId": shortId,
      "spiderX": spiderX,
      "pinnedPeerCertSha256": _emptyToNull(pinnedPeerCertSha256),
      "verifyPeerCertByName": _emptyToNull(verifyPeerCertByName),
    };
    if (streamSecurity == 'tls') {
      streamSettingsBuilder.realitySettings = null;
      streamSettingsBuilder.tlsSettings = tlsSetting;
    } else if (streamSecurity == 'reality') {
      streamSettingsBuilder.tlsSettings = null;
      streamSettingsBuilder.realitySettings = tlsSetting;
    }
  }

  String? _emptyToNull(String? value) {
    if (value == null || value.isEmpty) {
      return null;
    }
    return value;
  }

  /// Returns the legacy typed-generator cleanup of [params].
  ///
  /// This removes absent values and normalizes known aliases. For full imported
  /// profiles use `sanitizeXrayJson(..., preserveStructure: true)` to retain
  /// explicit nulls and empty containers.
  dynamic removeNulls(dynamic params) {
    return sanitizeXrayJson(params);
  }

  /// Builds the `proxy` outbound from [protocol], its [settings] and the current
  /// [streamSettingsBuilder], with mux disabled.
  ///
  /// The returned JSON can contain credentials. Native Core validates protocol
  /// and transport compatibility when the configuration is prepared.
  Map<String, dynamic> buildProxyOutbound({
    required String protocol,
    required Map<String, dynamic> settings,
  }) {
    return XrayOutbound.proxy(
      protocol: protocol,
      settings: settings,
      streamSettings: streamSettingsBuilder.build(),
    ).toJson();
  }

  XrayStreamSettings? _streamSettingsFromOutbound(Map<String, dynamic> json) {
    final value = json['streamSettings'];
    if (value is XrayStreamSettings) {
      return value;
    }
    if (value is Map<String, dynamic>) {
      return XrayStreamSettings(
        network: value['network'] as String? ?? network,
        security: value['security'] as String? ?? '',
        rawSettings: (value['rawSettings'] as Map?)?.cast<String, dynamic>(),
        tcpSettings: (value['tcpSettings'] as Map?)?.cast<String, dynamic>(),
        kcpSettings: (value['kcpSettings'] as Map?)?.cast<String, dynamic>(),
        wsSettings: (value['wsSettings'] as Map?)?.cast<String, dynamic>(),
        httpSettings: (value['httpSettings'] as Map?)?.cast<String, dynamic>(),
        h2Settings: (value['h2Setting'] as Map?)?.cast<String, dynamic>(),
        tlsSettings: (value['tlsSettings'] as Map?)?.cast<String, dynamic>(),
        quicSettings: (value['quicSettings'] as Map?)?.cast<String, dynamic>(),
        realitySettings:
            (value['realitySettings'] as Map?)?.cast<String, dynamic>(),
        grpcSettings: (value['grpcSettings'] as Map?)?.cast<String, dynamic>(),
        xhttpSettings:
            (value['xhttpSettings'] as Map?)?.cast<String, dynamic>(),
        httpupgradeSettings:
            (value['httpupgradeSettings'] as Map?)?.cast<String, dynamic>(),
        hysteriaSettings:
            (value['hysteriaSettings'] as Map?)?.cast<String, dynamic>(),
        dsSettings: (value['dsSettings'] as Map?)?.cast<String, dynamic>(),
        sockopt: (value['sockopt'] as Map?)?.cast<String, dynamic>(),
      );
    }
    return null;
  }
}
