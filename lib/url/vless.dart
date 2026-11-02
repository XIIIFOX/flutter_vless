import 'package:flutter_vless/url/url.dart';

/// VLESS links, including TLS, Reality and configured transport parameters.
class VlessURL extends FlutterVlessURL {
  /// Parses a lowercase `vless://` link and builds its transport settings.
  ///
  /// Throws [ArgumentError] when the URI or scheme is invalid. Successful parsing
  /// does not prove that credentials, encryption or a remote server are usable.
  VlessURL({required super.url}) {
    if (!url.startsWith('vless://')) {
      throw ArgumentError('url is invalid');
    }
    final temp = Uri.tryParse(url);
    if (temp == null) {
      throw ArgumentError('url is invalid');
    }
    uri = temp;
    // VLESS transports share the same URL surface, but XHTTP uses `extra` for
    // important server-side flow-control settings. Keep the raw query value
    // attached to transport parsing so the generated Xray JSON can preserve it.
    var sni = super.populateTransportSettings(
      transport: uri.queryParameters["type"] ?? "tcp",
      headerType: uri.queryParameters["headerType"],
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
      streamSecurity: uri.queryParameters["security"] ?? "",
      allowInsecure: allowInsecure,
      sni: uri.queryParameters["sni"] ?? sni,
      fingerprint:
          uri.queryParameters["fp"] ?? streamSettingsBuilder.tlsFingerprint,
      alpns: uri.queryParameters["alpn"],
      publicKey: uri.queryParameters["pbk"] ?? "",
      shortId: uri.queryParameters["sid"] ?? "",
      spiderX: uri.queryParameters["spx"] ?? "",
      pinnedPeerCertSha256: uri.queryParameters["pcs"] ??
          uri.queryParameters["pinnedPeerCertSha256"],
      verifyPeerCertByName: uri.queryParameters["vcn"] ??
          uri.queryParameters["verifyPeerCertByName"],
    );
  }

  @override
  String get address => uri.host;

  @override
  int get port => uri.hasPort ? uri.port : super.port;

  @override
  String get remark => Uri.decodeFull(uri.fragment.replaceAll('+', '%20'));

  /// Parsed source URI, including its credential-bearing authority and query.
  ///
  /// Do not log this value without redacting private fields.
  late final Uri uri;

  /// Xray VLESS Encryption value for this user.
  ///
  /// Modern Xray supports post-quantum VLESS Encryption values such as
  /// `mlkem768x25519plus.native.1rtt...`. That value is the client half of a
  /// key pair generated with `xray vlessenc` and must match the server-side
  /// `decryption` setting. It is not derivable from UUID, host, path, XHTTP
  /// mode, or any other normal share-link field.
  ///
  /// This is why a bare `vless://...?type=xhttp&security=none` link can import
  /// cleanly but still fail on-device with only SOCKS CONNECT success and no
  /// HTTP bytes. If a subscription or JSON config provides `encryption`, pass it
  /// through exactly. If the URL omits it, the only safe default is Xray's
  /// legacy `"none"`.
  String get encryption => uri.queryParameters["encryption"] ?? "none";

  @override
  Map<String, dynamic> get outbound1 => buildProxyOutbound(
        protocol: "vless",
        settings: {
          "vnext": [
            {
              "address": address,
              "port": port,
              "users": [
                {
                  "id": Uri.decodeComponent(uri.userInfo),
                  "alterId": null,
                  "security": security,
                  "level": level,
                  "encryption": encryption,
                  "flow": uri.queryParameters["flow"] ?? "",
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
