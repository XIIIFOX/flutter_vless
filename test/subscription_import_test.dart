import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';

import 'xray_config_test_utils.dart';

const visionSeedEncryption =
    'mlkem768x25519plus.native.1rtt.100-500-2000.75-0-100.80-0-5000.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';

void main() {
  group('P0 subscription imports', () {
    test('imports base64 share-link lists without dropping VLESS Encryption',
        () {
      final subscription = base64Encode(utf8.encode([
        'vless://22222222-2222-4222-8222-222222222222@example.com:2043?type=xhttp&host=storage.example.com&path=/my-bucket&mode=stream-up&security=none&encryption=$visionSeedEncryption#XHTTP',
        'ss://YWVzLTEyOC1nY206cGFzcw@example.org:8388#SS',
      ].join('\n')));

      final profiles = FlutterVless.parseMany(subscription);
      final xhttpConfig = decodedConfig(profiles.first);
      final ssConfig = decodedConfig(profiles.last);

      expect(profiles, hasLength(2));
      expect(firstVnextUser(xhttpConfig)['encryption'], visionSeedEncryption);
      expect(streamSettings(xhttpConfig)['network'], 'xhttp');
      expect(proxyOutbound(ssConfig)['protocol'], 'shadowsocks');
    });

    test('imports Clash YAML VLESS XHTTP/none profiles', () {
      final profiles = FlutterVless.parseMany('''
proxies:
  - name: Clash XHTTP
    type: vless
    server: clash.example.com
    port: 2043
    uuid: 22222222-2222-4222-8222-222222222222
    network: xhttp
    security: none
    encryption: $visionSeedEncryption
    xhttp-opts:
      host: storage.example.com
      path: /my-bucket
      mode: stream-up
  - name: Unsupported TUIC
    type: tuic
    server: ignored.example.com
    port: 443
''');
      final config = decodedConfig(profiles.single);
      final xhttp =
          streamSettings(config)['xhttpSettings'] as Map<String, dynamic>;

      expect(firstVnextUser(config)['encryption'], visionSeedEncryption);
      expect(xhttp['host'], 'storage.example.com');
      expect(xhttp['path'], '/my-bucket');
      expect(xhttp['mode'], 'stream-up');
    });

    test('imports sing-box JSON VLESS and skips non-Xray-only outbounds', () {
      final profiles = FlutterVless.parseMany(jsonEncode({
        'outbounds': [
          {
            'type': 'selector',
            'tag': 'proxy',
            'outbounds': ['xhttp']
          },
          {
            'type': 'vless',
            'tag': 'xhttp',
            'server': 'sing-box.example.com',
            'server_port': 2043,
            'uuid': '22222222-2222-4222-8222-222222222222',
            'encryption': visionSeedEncryption,
            'transport': {
              'type': 'xhttp',
              'host': 'storage.example.com',
              'path': '/my-bucket',
              'mode': 'stream-up',
            },
            'tls': {'enabled': false}
          },
          {
            'type': 'hysteria2',
            'tag': 'unsupported',
            'server': 'ignored.example.com',
            'server_port': 443,
          },
        ]
      }));
      final config = decodedConfig(profiles.single);

      expect(firstVnextUser(config)['encryption'], visionSeedEncryption);
      expect(streamSettings(config)['security'], 'none');
      expect(streamSettings(config)['network'], 'xhttp');
    });

    test('imports sing-box JSON Shadowsocks outbounds', () {
      final profiles = FlutterVless.parseMany(jsonEncode({
        'outbounds': [
          {
            'type': 'shadowsocks',
            'tag': 'ss',
            'server': 'ss.example.com',
            'server_port': 8388,
            'method': '2022-blake3-aes-128-gcm',
            'password': 'secret',
          }
        ]
      }));
      final outbound = proxyOutbound(decodedConfig(profiles.single));
      final server = (outbound['settings'] as Map<String, dynamic>)['servers']
          [0] as Map<String, dynamic>;

      expect(outbound['protocol'], 'shadowsocks');
      expect(server['address'], 'ss.example.com');
      expect(server['method'], '2022-blake3-aes-128-gcm');
      expect(server['password'], 'secret');
    });

    test('imports sing-box JSON VLESS HTTPUpgrade transport', () {
      final profiles = FlutterVless.parseMany(jsonEncode({
        'outbounds': [
          {
            'type': 'vless',
            'tag': 'httpupgrade',
            'server': 'upgrade.example.com',
            'server_port': 443,
            'uuid': '22222222-2222-4222-8222-222222222222',
            'transport': {
              'type': 'httpupgrade',
              'host': 'edge.example.com',
              'path': '/upgrade',
              'headers': {
                'Host': 'edge.example.com',
                'X-Forwarded-For': '203.0.113.7',
              },
            },
            'tls': {
              'enabled': true,
              'server_name': 'edge.example.com',
            }
          }
        ]
      }));
      final stream = streamSettings(decodedConfig(profiles.single));
      final httpupgrade = stream['httpupgradeSettings'] as Map<String, dynamic>;

      expect(stream['network'], 'httpupgrade');
      expect(stream['security'], 'tls');
      expect(httpupgrade['host'], 'edge.example.com');
      expect(httpupgrade['path'], '/upgrade');
      expect(httpupgrade['headers'], {'X-Forwarded-For': '203.0.113.7'});
    });

    test('imports Clash YAML HTTP and HTTPS proxy profiles', () {
      final profiles = FlutterVless.parseMany('''
proxies:
  - name: HTTP
    type: http
    server: proxy.example.com
    port: 8080
    username: alice
    password: secret
    headers:
      X-Proxy-Region: ru-central
  - name: HTTPS
    type: https
    server: secure-proxy.example.com
    port: 8443
    username: bob
    password: hunter2
    sni: edge.example.com
    alpn:
      - h2
      - http/1.1
    client-fingerprint: chrome
    headers:
      X-Proxy-Region: eu-west
''');

      final httpConfig = decodedConfig(profiles.first);
      final http = proxyOutbound(httpConfig);
      final httpSettings = http['settings'] as Map<String, dynamic>;
      final httpsConfig = decodedConfig(profiles.last);
      final https = proxyOutbound(httpsConfig);
      final httpsSettings = https['settings'] as Map<String, dynamic>;
      final stream = streamSettings(httpsConfig);
      final tls = stream['tlsSettings'] as Map<String, dynamic>;

      expect(profiles, hasLength(2));
      expect(http['protocol'], 'http');
      expect(http.containsKey('streamSettings'), isFalse);
      expect(httpSettings['address'], 'proxy.example.com');
      expect(httpSettings['port'], 8080);
      expect(httpSettings['user'], 'alice');
      expect(httpSettings['pass'], 'secret');
      expect(httpSettings['headers'], {'X-Proxy-Region': 'ru-central'});
      expect(https['protocol'], 'http');
      expect(httpsSettings['address'], 'secure-proxy.example.com');
      expect(httpsSettings['port'], 8443);
      expect(httpsSettings['user'], 'bob');
      expect(httpsSettings['pass'], 'hunter2');
      expect(httpsSettings['headers'], {'X-Proxy-Region': 'eu-west'});
      expect(stream['network'], 'raw');
      expect(stream['security'], 'tls');
      expect(tls['serverName'], 'edge.example.com');
      expect(tls['alpn'], ['h2', 'http/1.1']);
      expect(tls['fingerprint'], 'chrome');
    });

    test('imports Clash YAML WireGuard and Hysteria2 profiles', () {
      final profiles = FlutterVless.parseMany('''
proxies:
  - name: WG
    type: wireguard
    server: wg.example.com
    port: 51820
    ip: 172.16.0.2/32
    private-key: private-key
    public-key: public-key
    pre-shared-key: psk
    reserved: [1, 2, 3]
    mtu: 1280
    workers: 2
    allowed-ips:
      - 0.0.0.0/0
      - ::/0
    domain-strategy: prefer_ipv6
    no-kernel-tun: true
  - name: HY2
    type: hysteria2
    server: hy2.example.com
    port: 443
    password: secret
    sni: edge.example.com
    alpn:
      - h3
    skip-cert-verify: true
    pinned-peer-cert-sha256: e8e2d387fdbffeb38e9c9065cf30a97ee23c0e3d32ee6f78ffae40966befccc9
    verify-peer-cert-by-name: edge.example.com
    udp-idle-timeout: 120
''');

      final wg = proxyOutbound(decodedConfig(profiles.first));
      final wgSettings = wg['settings'] as Map<String, dynamic>;
      final wgPeer =
          (wgSettings['peers'] as List<dynamic>).first as Map<String, dynamic>;
      final hy2Config = decodedConfig(profiles.last);
      final hy2 = proxyOutbound(hy2Config);
      final stream = streamSettings(hy2Config);
      final tls = stream['tlsSettings'] as Map<String, dynamic>;
      final hysteria = stream['hysteriaSettings'] as Map<String, dynamic>;

      expect(profiles, hasLength(2));
      expect(wg['protocol'], 'wireguard');
      expect(wgSettings['secretKey'], 'private-key');
      expect(wgSettings['address'], ['172.16.0.2/32']);
      expect(wgSettings['reserved'], 'AQID');
      expect(wgSettings['domainStrategy'], 'ForceIPv6v4');
      expect(wgSettings['noKernelTun'], isTrue);
      expect(wgPeer['endpoint'], 'wg.example.com:51820');
      expect(wgPeer['publicKey'], 'public-key');
      expect(wgPeer['preSharedKey'], 'psk');
      expect(wgPeer['allowedIPs'], ['0.0.0.0/0', '::/0']);
      expect(hy2['protocol'], 'hysteria');
      expect(hy2['settings'], {
        'version': 2,
        'address': 'hy2.example.com',
        'port': 443,
      });
      expect(stream['network'], 'hysteria');
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

    test('imports sing-box JSON WireGuard and Hysteria2 profiles', () {
      final profiles = FlutterVless.parseMany(jsonEncode({
        'outbounds': [
          {
            'type': 'wireguard',
            'tag': 'wg',
            'server': 'wg.example.com',
            'server_port': 51820,
            'local_address': ['172.16.0.2/32'],
            'private_key': 'private-key',
            'peer_public_key': 'public-key',
            'pre_shared_key': 'psk',
            'reserved': 'AQID',
            'mtu': 1280,
            'workers': 2,
            'domain_strategy': 'ipv4_only',
            'allowed_ips': ['0.0.0.0/0'],
          },
          {
            'type': 'hysteria2',
            'tag': 'hy2',
            'server': 'hy2.example.com',
            'server_port': 443,
            'password': 'secret',
            'udp_idle_timeout': 90,
            'tls': {
              'enabled': true,
              'server_name': 'edge.example.com',
              'insecure': false,
              'pinned_peer_cert_sha256':
                  'f8e2d387fdbffeb38e9c9065cf30a97ee23c0e3d32ee6f78ffae40966befccc9',
              'verify_peer_cert_by_name': 'edge.example.com',
              'alpn': ['h3'],
              'utls': {'fingerprint': 'chrome'},
            }
          },
        ]
      }));

      final wg = proxyOutbound(decodedConfig(profiles.first));
      final wgSettings = wg['settings'] as Map<String, dynamic>;
      final hy2Config = decodedConfig(profiles.last);
      final stream = streamSettings(hy2Config);
      final tls = stream['tlsSettings'] as Map<String, dynamic>;
      final hysteria = stream['hysteriaSettings'] as Map<String, dynamic>;

      expect(profiles, hasLength(2));
      expect(wg['protocol'], 'wireguard');
      expect(wgSettings['domainStrategy'], 'ForceIPv4');
      expect(wgSettings['reserved'], 'AQID');
      expect(stream['network'], 'hysteria');
      expect(tls['serverName'], 'edge.example.com');
      expect(tls.containsKey('allowInsecure'), isFalse);
      expect(
        tls['pinnedPeerCertSha256'],
        'f8e2d387fdbffeb38e9c9065cf30a97ee23c0e3d32ee6f78ffae40966befccc9',
      );
      expect(tls['verifyPeerCertByName'], 'edge.example.com');
      expect(tls['fingerprint'], 'chrome');
      expect(hysteria['auth'], 'secret');
      expect(hysteria['udpIdleTimeout'], 90);
    });

    test('imports sing-box JSON HTTP proxy and skips custom path variants', () {
      final profiles = FlutterVless.parseMany(jsonEncode({
        'outbounds': [
          {
            'type': 'http',
            'tag': 'http',
            'server': 'proxy.example.com',
            'server_port': 8080,
            'username': 'alice',
            'password': 'secret',
            'headers': {
              'X-Proxy-Region': 'ru-central',
            }
          },
          {
            'type': 'http',
            'tag': 'https',
            'server': 'secure-proxy.example.com',
            'server_port': 8443,
            'username': 'bob',
            'password': 'hunter2',
            'tls': {
              'enabled': true,
              'server_name': 'edge.example.com',
              'alpn': ['h2'],
              'utls': {'fingerprint': 'chrome'},
            }
          },
          {
            'type': 'http',
            'tag': 'unsupported-path',
            'server': 'ignored.example.com',
            'server_port': 8081,
            'path': '/proxy'
          },
        ]
      }));

      final httpConfig = decodedConfig(profiles.first);
      final http = proxyOutbound(httpConfig);
      final httpSettings = http['settings'] as Map<String, dynamic>;
      final httpsConfig = decodedConfig(profiles.last);
      final https = proxyOutbound(httpsConfig);
      final stream = streamSettings(httpsConfig);
      final tls = stream['tlsSettings'] as Map<String, dynamic>;

      expect(profiles, hasLength(2));
      expect(http['protocol'], 'http');
      expect(http.containsKey('streamSettings'), isFalse);
      expect(httpSettings['address'], 'proxy.example.com');
      expect(httpSettings['port'], 8080);
      expect(httpSettings['user'], 'alice');
      expect(httpSettings['pass'], 'secret');
      expect(httpSettings['headers'], {'X-Proxy-Region': 'ru-central'});
      expect(https['protocol'], 'http');
      expect(stream['network'], 'raw');
      expect(stream['security'], 'tls');
      expect(tls['serverName'], 'edge.example.com');
      expect(tls['alpn'], ['h2']);
      expect(tls['fingerprint'], 'chrome');
    });
  });
}
