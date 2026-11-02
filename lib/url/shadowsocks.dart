import 'dart:convert';

import 'package:flutter_vless/url/url.dart';

/// Shadowsocks links with plain or base64-encoded method/password values.
class ShadowSocksURL extends FlutterVlessURL {
  /// Parses a lowercase `ss://` link, including legacy full-base64 authorities.
  ///
  /// Optional query parameters populate transport/TLS settings. Invalid URI or
  /// scheme throws [ArgumentError]. Final cipher and transport support are
  /// validated by the selected native Core.
  ShadowSocksURL({required super.url}) {
    if (!url.startsWith('ss://')) {
      throw ArgumentError('url is invalid');
    }
    final temp = Uri.tryParse(url);
    if (temp == null) {
      throw ArgumentError('url is invalid');
    }
    uri = temp;
    _address = uri.host;
    _port = uri.hasPort ? uri.port : null;

    if (uri.userInfo.isNotEmpty) {
      _parseMethodPassword(_decodeUserInfo(uri.userInfo));
    } else {
      _parseLegacyFullBase64();
    }

    if (uri.queryParameters.isNotEmpty) {
      var sni = super.populateTransportSettings(
        transport: uri.queryParameters['type'] ?? "tcp",
        headerType: uri.queryParameters['headerType'],
        host: uri.queryParameters["host"],
        path: uri.queryParameters["path"],
        seed: uri.queryParameters["seed"],
        quicSecurity: uri.queryParameters["quicSecurity"],
        key: uri.queryParameters["key"],
        mode: uri.queryParameters["mode"],
        serviceName: uri.queryParameters["serviceName"],
        extra: uri.queryParameters["extra"],
      );
      super.populateTlsSettings(
        streamSecurity: uri.queryParameters['security'] ?? '',
        allowInsecure: allowInsecure,
        sni: uri.queryParameters["sni"] ?? sni,
        fingerprint: streamSettingsBuilder.tlsFingerprint,
        alpns: uri.queryParameters['alpn'],
        publicKey: null,
        shortId: null,
        spiderX: null,
        pinnedPeerCertSha256: uri.queryParameters["pcs"] ??
            uri.queryParameters["pinnedPeerCertSha256"],
        verifyPeerCertByName: uri.queryParameters["vcn"] ??
            uri.queryParameters["verifyPeerCertByName"],
      );
    }
  }

  @override
  String get address => _address ?? uri.host;

  @override
  int get port => _port ?? (uri.hasPort ? uri.port : super.port);

  @override
  String get remark => Uri.decodeFull(uri.fragment.replaceAll('+', '%20'));

  /// Parsed source URI, including its credential-bearing authority and query.
  ///
  /// Do not log this value without redacting private fields.
  late final Uri uri;

  String? _address;

  int? _port;

  /// Parsed Shadowsocks encryption method; defaults to `none` if not provided.
  String method = "none";

  /// Parsed Shadowsocks password, retained for outbound generation.
  ///
  /// This is a credential; do not include it in diagnostics or logs.
  String password = "";

  String _decodeUserInfo(String value) {
    final decoded = _tryDecodeBase64(value);
    if (decoded != null) {
      return decoded;
    }
    return Uri.decodeComponent(value);
  }

  String? _tryDecodeBase64(String value) {
    var raw = Uri.decodeComponent(value);
    if (raw.length % 4 > 0) {
      raw += "=" * (4 - raw.length % 4);
    }
    try {
      return utf8.decode(base64Decode(raw));
    } catch (_) {
      return null;
    }
  }

  void _parseMethodPassword(String value) {
    final separator = value.indexOf(':');
    if (separator <= 0) {
      return;
    }
    method = value.substring(0, separator);
    password = value.substring(separator + 1);
  }

  void _parseLegacyFullBase64() {
    final fragmentStart = url.indexOf('#');
    final queryStart = url.indexOf('?');
    final end = [
      if (fragmentStart > -1) fragmentStart,
      if (queryStart > -1) queryStart,
    ].fold<int>(
        url.length, (current, index) => index < current ? index : current);
    final encoded = url.substring('ss://'.length, end);
    final decoded = _tryDecodeBase64(encoded);
    if (decoded == null) {
      return;
    }

    final authoritySeparator = decoded.lastIndexOf('@');
    if (authoritySeparator <= 0 || authoritySeparator == decoded.length - 1) {
      return;
    }
    _parseMethodPassword(decoded.substring(0, authoritySeparator));
    _parseHostPort(decoded.substring(authoritySeparator + 1));
  }

  void _parseHostPort(String value) {
    final portSeparator = value.lastIndexOf(':');
    if (portSeparator <= 0 || portSeparator == value.length - 1) {
      _address = value;
      return;
    }
    _address = value.substring(0, portSeparator);
    _port = int.tryParse(value.substring(portSeparator + 1)) ?? _port;
  }

  @override
  Map<String, dynamic> get outbound1 => buildProxyOutbound(
        protocol: "shadowsocks",
        settings: {
          "vnext": null,
          "servers": [
            {
              "address": address,
              "method": method,
              "ota": false,
              "password": password,
              "port": port,
              "level": level,
              "email": null,
              "flow": null,
              "ivCheck": null,
              "users": null
            }
          ],
          "response": null,
          "network": null,
          "address": null,
          "port": null,
          "domainStrategy": null,
          "redirect": null,
          "userLevel": null,
          "inboundTag": null,
          "secretKey": null,
          "peers": null
        },
      );
}
