import 'package:flutter_vless/url/url.dart';

/// Hysteria 2 share links using `hysteria2://` or `hy2://`.
class Hysteria2URL extends FlutterVlessURL {
  /// Parses a lowercase Hysteria 2 link into a version-2 Hysteria outbound.
  ///
  /// Retains authentication, server identity and supported query parameters.
  /// Invalid URI or scheme throws [ArgumentError]. Import support does not
  /// establish that the selected native backend can run the transport.
  Hysteria2URL({required super.url}) {
    if (!url.startsWith('hysteria2://') && !url.startsWith('hy2://')) {
      throw ArgumentError('url is invalid');
    }
    final temp = Uri.tryParse(url);
    if (temp == null) {
      throw ArgumentError('url is invalid');
    }
    uri = temp;

    streamSettingsBuilder.network = 'hysteria';
    streamSettingsBuilder.hysteriaSettings = {
      'version': 2,
      'auth': auth,
      if (udpIdleTimeout != null) 'udpIdleTimeout': udpIdleTimeout,
    };
    populateTlsSettings(
      streamSecurity: 'tls',
      allowInsecure: _boolQuery('insecure') ??
          _boolQuery('allowInsecure') ??
          _boolQuery('skip-cert-verify') ??
          false,
      sni: uri.queryParameters['sni'] ??
          uri.queryParameters['peer'] ??
          uri.queryParameters['serverName'] ??
          address,
      fingerprint: uri.queryParameters['fp'],
      alpns: uri.queryParameters['alpn'],
      publicKey: null,
      shortId: null,
      spiderX: null,
      pinnedPeerCertSha256: uri.queryParameters['pcs'] ??
          uri.queryParameters['pinnedPeerCertSha256'],
      verifyPeerCertByName: uri.queryParameters['vcn'] ??
          uri.queryParameters['verifyPeerCertByName'],
    );
  }

  /// Parsed source URI, including its credential-bearing authority and query.
  ///
  /// Do not log this value without redacting private fields.
  late final Uri uri;

  @override
  String get address => uri.host;

  @override
  int get port => uri.hasPort ? uri.port : super.port;

  /// Percent-decoded Hysteria authentication value from the URI authority.
  String get auth => Uri.decodeComponent(uri.userInfo);

  /// Optional integer UDP idle timeout from either supported query spelling.
  ///
  /// Returns null when the link omits the value or it is not an integer.
  int? get udpIdleTimeout =>
      int.tryParse(uri.queryParameters['udpIdleTimeout'] ??
          uri.queryParameters['udp-idle-timeout'] ??
          '');

  @override
  String get remark => Uri.decodeFull(uri.fragment.replaceAll('+', '%20'));

  @override
  Map<String, dynamic> get outbound1 => {
        'tag': 'proxy',
        'protocol': 'hysteria',
        'settings': {
          'version': 2,
          'address': address,
          'port': port,
        },
        'streamSettings': streamSettingsBuilder.build().toJson(),
      };

  bool? _boolQuery(String key) {
    final value = uri.queryParameters[key];
    if (value == null || value.isEmpty) {
      return null;
    }
    final normalized = value.toLowerCase();
    return normalized == '1' || normalized == 'true';
  }
}
