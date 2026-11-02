import 'dart:convert';

import 'package:flutter_vless/url/url.dart';

/// Base64-encoded VMess JSON share links.
class VmessURL extends FlutterVlessURL {
  /// Decodes the JSON payload of a lowercase `vmess://` link.
  ///
  /// Invalid scheme, base64 or JSON throws [ArgumentError]. Required VMess field
  /// types must match the share-link format; malformed types can also throw
  /// [TypeError]. This is not a native Core check.
  VmessURL({required super.url}) {
    if (!url.startsWith('vmess://')) {
      throw ArgumentError('url is invalid');
    }
    String raw = url.substring(8);
    if (raw.length % 4 > 0) {
      raw += "=" * (4 - raw.length % 4);
    }
    try {
      rawConfig = jsonDecode(utf8.decode(base64Decode(raw)));
    } catch (_) {
      throw ArgumentError('url is invalid');
    }
    var sni = super.populateTransportSettings(
      transport: rawConfig['net'],
      headerType: rawConfig['type'],
      host: rawConfig['host'],
      path: rawConfig['path'],
      seed: rawConfig['path'],
      quicSecurity: rawConfig['host'],
      key: rawConfig['path'],
      mode: rawConfig['type'],
      serviceName: rawConfig['path'],
      extra: rawConfig['extra'],
    );
    String? fingerprint = (rawConfig['fp'] != null && rawConfig['fp'] != '')
        ? rawConfig['fp']
        : streamSettingsBuilder.tlsFingerprint;
    final configuredSni = rawConfig['sni'] as String?;
    super.populateTlsSettings(
      streamSecurity: rawConfig['tls'],
      allowInsecure: allowInsecure,
      sni: configuredSni == null || configuredSni.isEmpty ? sni : configuredSni,
      fingerprint: fingerprint,
      alpns: rawConfig['alpn'],
      publicKey: null,
      shortId: null,
      spiderX: null,
      pinnedPeerCertSha256:
          rawConfig['pcs'] ?? rawConfig['pinnedPeerCertSha256'],
      verifyPeerCertByName:
          rawConfig['vcn'] ?? rawConfig['verifyPeerCertByName'],
    );
  }
  /// Decoded VMess share-link document, including its client credentials.
  ///
  /// This map is retained by the parser; editing it affects generated settings.
  late final Map<String, dynamic> rawConfig;

  @override
  String get remark => rawConfig['ps'] ?? '';

  @override
  String get address => rawConfig['add'] ?? '';

  @override
  int get port => int.tryParse(rawConfig['port'].toString()) ?? super.port;

  @override
  Map<String, dynamic> get outbound1 => buildProxyOutbound(
        protocol: "vmess",
        settings: {
          "vnext": [
            {
              "address": address,
              "port": port,
              "users": [
                {
                  "id": rawConfig['id'] ?? '',
                  "alterId": int.tryParse(rawConfig['aid'].toString()) ?? 0,
                  "security": (rawConfig['scy']?.isEmpty ?? true)
                      ? security
                      : rawConfig['scy'],
                  "level": level,
                  "encryption": "",
                  "flow": ""
                }
              ]
            }
          ],
          "servers": null,
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
