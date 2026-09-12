import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/url/hysteria2.dart';
import 'package:flutter_vless/url/shadowsocks.dart';
import 'package:flutter_vless/url/socks.dart';
import 'package:flutter_vless/url/trojan.dart';
import 'package:flutter_vless/url/vmess.dart';

import 'xray_config_test_utils.dart';

void main() {
  group('P0 supported protocol URL parsing', () {
    test('generates VMess WS/TLS outbound from a share link', () {
      final link = vmessLink({
        'v': '2',
        'ps': 'VMess WS TLS',
        'add': 'vmess.example.com',
        'port': '443',
        'id': '11111111-1111-1111-1111-111111111111',
        'aid': '0',
        'scy': 'auto',
        'net': 'ws',
        'type': 'none',
        'host': 'front.example.com',
        'path': '/ray',
        'tls': 'tls',
        'fp': 'chrome',
        'alpn': 'h2,http/1.1',
      });

      final parsed = FlutterVless.parseFromURL(link);
      final config = decodedConfig(parsed);
      final user = firstVnextUser(config);
      final stream = streamSettings(config);
      final ws = stream['wsSettings'] as Map<String, dynamic>;
      final tls = stream['tlsSettings'] as Map<String, dynamic>;

      expect(parsed, isA<VmessURL>());
      expect(parsed.remark, 'VMess WS TLS');
      expect(firstVnextServer(config)['address'], 'vmess.example.com');
      expect(firstVnextServer(config)['port'], 443);
      expect(user['id'], '11111111-1111-1111-1111-111111111111');
      expect(user['alterId'], 0);
      expect(user['security'], 'auto');
      expect(stream['network'], 'ws');
      expect(stream['security'], 'tls');
      expect(ws['path'], '/ray');
      expect(ws['headers'], {'Host': 'front.example.com'});
      expect(tls['serverName'], 'front.example.com');
      expect(tls['fingerprint'], 'chrome');
      expect(tls['alpn'], ['h2', 'http/1.1']);
    });

    test('generates Trojan gRPC/TLS outbound from a share link', () {
      const link =
          'trojan://secret@example.com:443?security=tls&type=grpc&serviceName=edge&mode=multi&sni=tls.example.com&alpn=h2,http/1.1&flow=xtls-rprx-vision#Trojan%20TLS';

      final parsed = FlutterVless.parseFromURL(link);
      final config = decodedConfig(parsed);
      final server = firstOutboundServer(config);
      final stream = streamSettings(config);
      final grpc = stream['grpcSettings'] as Map<String, dynamic>;
      final tls = stream['tlsSettings'] as Map<String, dynamic>;

      expect(parsed, isA<TrojanURL>());
      expect(parsed.remark, 'Trojan TLS');
      expect(server['address'], 'example.com');
      expect(server['port'], 443);
      expect(server['password'], 'secret');
      expect(server['flow'], 'xtls-rprx-vision');
      expect(stream['network'], 'grpc');
      expect(stream['security'], 'tls');
      expect(grpc, {'serviceName': 'edge', 'multiMode': true});
      expect(tls['serverName'], 'tls.example.com');
      expect(tls['alpn'], ['h2', 'http/1.1']);
    });

    test('generates Shadowsocks outbound from SIP002 base64 user info', () {
      final userInfo = base64UrlNoPadding('aes-128-gcm:p@ss:word');
      final link = 'ss://$userInfo@ss.example.com:8388#SS%20SIP002';

      final parsed = FlutterVless.parseFromURL(link);
      final config = decodedConfig(parsed);
      final server = firstOutboundServer(config);

      expect(parsed, isA<ShadowSocksURL>());
      expect(parsed.remark, 'SS SIP002');
      expect(server['address'], 'ss.example.com');
      expect(server['port'], 8388);
      expect(server['method'], 'aes-128-gcm');
      expect(server['password'], 'p@ss:word');
    });

    test('generates Socks outbound from partial base64 user info', () {
      final userInfo = base64UrlNoPadding('user:pass:with:colon');
      final link = 'socks://$userInfo@socks.example.com:1080#SOCKS';

      final parsed = FlutterVless.parseFromURL(link);
      final config = decodedConfig(parsed);
      final server = firstOutboundServer(config);
      final user =
          (server['users'] as List<dynamic>).first as Map<String, dynamic>;

      expect(parsed, isA<SocksURL>());
      expect(parsed.remark, 'SOCKS');
      expect(server['address'], 'socks.example.com');
      expect(server['port'], 1080);
      expect(user['user'], 'user');
      expect(user['pass'], 'pass:with:colon');
    });

    test('generates VLESS HTTPUpgrade outbound from a share link', () {
      const link =
          'vless://11111111-1111-1111-1111-111111111111@upgrade.example.com:443?type=httpupgrade&host=edge.example.com&path=/upgrade&security=tls&sni=edge.example.com#HTTPUpgrade';

      final parsed = FlutterVless.parseFromURL(link);
      final config = decodedConfig(parsed);
      final stream = streamSettings(config);
      final httpupgrade = stream['httpupgradeSettings'] as Map<String, dynamic>;

      expect(stream['network'], 'httpupgrade');
      expect(stream['security'], 'tls');
      expect(httpupgrade['host'], 'edge.example.com');
      expect(httpupgrade['path'], '/upgrade');
    });

    test('generates VLESS raw outbound from the modern transport name', () {
      const link =
          'vless://11111111-1111-1111-1111-111111111111@raw.example.com:443?type=raw&headerType=none&security=none#Raw';

      final parsed = FlutterVless.parseFromURL(link);
      final config = decodedConfig(parsed);
      final stream = streamSettings(config);
      final raw = stream['rawSettings'] as Map<String, dynamic>;

      expect(stream['network'], 'raw');
      expect(raw['header'], {'type': 'none'});
    });

    test('generates Hysteria2 outbound from a share link', () {
      const link =
          'hysteria2://secret@hy2.example.com:443?sni=edge.example.com&alpn=h3&insecure=1&pcs=e8e2d387fdbffeb38e9c9065cf30a97ee23c0e3d32ee6f78ffae40966befccc9&vcn=edge.example.com&udpIdleTimeout=120#HY2';

      final parsed = FlutterVless.parseFromURL(link);
      final config = decodedConfig(parsed);
      final outbound = proxyOutbound(config);
      final stream = streamSettings(config);
      final tls = stream['tlsSettings'] as Map<String, dynamic>;
      final hysteria = stream['hysteriaSettings'] as Map<String, dynamic>;

      expect(parsed, isA<Hysteria2URL>());
      expect(outbound['protocol'], 'hysteria');
      expect(outbound['settings'], {
        'version': 2,
        'address': 'hy2.example.com',
        'port': 443,
      });
      expect(stream['network'], 'hysteria');
      expect(stream['security'], 'tls');
      expect(tls['serverName'], 'edge.example.com');
      expect(tls['alpn'], ['h3']);
      expect(tls.containsKey('allowInsecure'), isFalse);
      expect(
        tls['pinnedPeerCertSha256'],
        'e8e2d387fdbffeb38e9c9065cf30a97ee23c0e3d32ee6f78ffae40966befccc9',
      );
      expect(tls['verifyPeerCertByName'], 'edge.example.com');
      expect(hysteria['auth'], 'secret');
      expect(hysteria['udpIdleTimeout'], 120);
    });
  });

  group('P1 compatibility URL forms', () {
    test('reads legacy full-base64 Shadowsocks links', () {
      final encoded =
          base64UrlNoPadding('chacha20-ietf-poly1305:secret@192.0.2.10:9000');
      final parsed = FlutterVless.parseFromURL('ss://$encoded#Legacy%20SS');
      final config = decodedConfig(parsed);
      final server = firstOutboundServer(config);

      expect(parsed.remark, 'Legacy SS');
      expect(server['address'], '192.0.2.10');
      expect(server['port'], 9000);
      expect(server['method'], 'chacha20-ietf-poly1305');
      expect(server['password'], 'secret');
    });

    test('reads plain Socks user-info links used by Happ docs', () {
      const link = 'socks://user:p%40ss@socks.example.com:443#Plain%20SOCKS';
      final parsed = FlutterVless.parseFromURL(link);
      final config = decodedConfig(parsed);
      final server = firstOutboundServer(config);
      final user =
          (server['users'] as List<dynamic>).first as Map<String, dynamic>;

      expect(parsed.remark, 'Plain SOCKS');
      expect(server['address'], 'socks.example.com');
      expect(server['port'], 443);
      expect(user['user'], 'user');
      expect(user['pass'], 'p@ss');
    });

    test('reads legacy full-base64 Socks links', () {
      final encoded = base64UrlNoPadding('user:secret@127.0.0.1:1080');
      final parsed = FlutterVless.parseFromURL('socks://$encoded#Legacy');
      final config = decodedConfig(parsed);
      final server = firstOutboundServer(config);
      final user =
          (server['users'] as List<dynamic>).first as Map<String, dynamic>;

      expect(parsed.remark, 'Legacy');
      expect(server['address'], '127.0.0.1');
      expect(server['port'], 1080);
      expect(user['user'], 'user');
      expect(user['pass'], 'secret');
    });

    test('rejects unknown share link schemes', () {
      expect(
        () => FlutterVless.parseFromURL('tuic://example.com:443'),
        throwsArgumentError,
      );
    });
  });
}
