import 'dart:convert';

import 'package:flutter_vless/url/url.dart';

/// SOCKS share links with optional plain or base64-encoded credentials.
class SocksURL extends FlutterVlessURL {
  /// Parses a lowercase `socks://` URI, including legacy full-base64 authorities.
  ///
  /// The server port defaults to 443 when no valid explicit port is available.
  /// Invalid URI or scheme throws [ArgumentError]. Native Core performs final
  /// configuration and server validation.
  SocksURL({required super.url}) {
    if (!url.startsWith('socks://')) {
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
      _parseUserPassword(_decodeUserInfo(uri.userInfo));
    } else {
      _parseLegacyFullBase64();
    }
  }

  /// Parsed SOCKS username, or null when the authority supplies none.
  String? username;

  /// Parsed SOCKS password, or null when no password was supplied.
  ///
  /// This is a credential; do not include it in diagnostics or logs.
  String? password;

  /// Parsed source URI, including its credential-bearing authority and query.
  ///
  /// Do not log this value without redacting private fields.
  late final Uri uri;

  String? _address;

  int? _port;

  @override
  String get address => _address ?? uri.host;

  @override
  int get port => _port ?? (uri.hasPort ? uri.port : super.port);

  @override
  String get remark => Uri.decodeFull(uri.fragment.replaceAll('+', '%20'));

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

  void _parseUserPassword(String value) {
    final separator = value.indexOf(':');
    if (separator < 0) {
      username = value.isEmpty ? null : value;
      password = null;
      return;
    }
    username = value.substring(0, separator);
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
    final encoded = url.substring('socks://'.length, end);
    final decoded = _tryDecodeBase64(encoded);
    if (decoded == null) {
      username = null;
      password = null;
      return;
    }

    final authoritySeparator = decoded.lastIndexOf('@');
    if (authoritySeparator > 0 && authoritySeparator < decoded.length - 1) {
      _parseUserPassword(decoded.substring(0, authoritySeparator));
      _parseHostPort(decoded.substring(authoritySeparator + 1));
    } else {
      _parseHostPort(decoded);
    }
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
        protocol: "socks",
        settings: {
          "servers": [
            {
              "address": address,
              "level": level,
              "method": "chacha20-poly1305",
              "ota": false,
              "password": "",
              "port": port,
              "users": [
                {"level": level, "user": username, "pass": password}
              ]
            }
          ]
        },
      );
}
