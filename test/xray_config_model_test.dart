import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/url/xray_config_model.dart';
import 'package:flutter_vless/url/vless.dart';

void main() {
  group('P0 typed Xray config generation', () {
    test('default sanitizer keeps typed model empty-value cleanup', () {
      final source = {
        'settings': <String, dynamic>{},
        'null': null,
        'items': [null, <String, dynamic>{}, <dynamic>[], 'keep'],
        'streamSettings': {
          'network': 'XHTTP',
          'xHTTPSettings': <String, dynamic>{},
          'tlsSettings': {'allowInsecure': false},
        },
      };
      expect(sanitizeXrayJson(source), {
        'items': ['keep'],
        'streamSettings': {'network': 'xhttp'},
      });
      expect(source['settings'], isEmpty);
      expect((source['items'] as List).first, isNull);
      expect((source['streamSettings'] as Map)['xHTTPSettings'], isEmpty);
    });

    test('returns a fresh sanitized configuration snapshot', () {
      const link =
          'vless://00000000-0000-0000-0000-000000000000@example.com:443?type=tcp&security=none#Snapshot';
      final parsed = VlessURL(url: link);

      final first = parsed.fullConfiguration;
      final firstInbound =
          (first['inbounds'] as List).first as Map<String, dynamic>;
      firstInbound['port'] = 1;

      final second = parsed.fullConfiguration;
      final secondInbound =
          (second['inbounds'] as List).first as Map<String, dynamic>;

      expect(secondInbound['port'], 10807);
      expect(
        parsed.getFullConfiguration(),
        contains('"protocol": "vless"'),
      );
    });

    test('validates required document sections before producing JSON', () {
      final document = XrayConfigDocument(
        log: const XrayLog(),
        inbounds: [],
        outbounds: [XrayOutbound.blackhole()],
        routing: const XrayRouting(),
      );

      expect(document.toJson, throwsStateError);
    });

    test('universal parser still exposes a Map-compatible public config', () {
      const link =
          'vless://00000000-0000-0000-0000-000000000000@example.com:443?type=ws&host=front.example&path=/ray&security=tls#Typed';
      final parsed = FlutterVless.parseFromURL(link);

      final config = parsed.fullConfiguration;
      final outbounds = config['outbounds'] as List<dynamic>;
      final proxy = outbounds.first as Map<String, dynamic>;
      final stream = proxy['streamSettings'] as Map<String, dynamic>;

      expect(config['routing'], {'domainStrategy': 'AsIs'});
      expect(proxy['protocol'], 'vless');
      expect(stream['network'], 'ws');
      expect(stream['security'], 'tls');
      expect(stream.containsKey('tcpSettings'), isFalse);
    });
  });
}
