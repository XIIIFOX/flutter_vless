import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';

void main() {
  final corpus = jsonDecode(
          File('tool/fixtures/compatibility/ports.json').readAsStringSync())
      as List;
  for (final item in corpus.cast<Map<String, dynamic>>()) {
    test('raw full JSON port corpus: ${item['name']}', () {
      final profile = jsonEncode({
        'inbounds': [
          {'protocol': 'socks', 'listen': '127.0.0.1', 'port': item['value']}
        ],
        'outbounds': [
          {'protocol': 'freedom'}
        ],
      });
      if (item['dartSyntaxValid'] ?? item['invalid'] != true) {
        final parsed = FlutterVless.parse(profile);
        final inputs =
            jsonDecode(parsed.getFullConfiguration())['inbounds'] as List;
        expect(inputs.single['port'], item['value']);
      } else {
        expect(() => FlutterVless.parse(profile), throwsArgumentError);
      }
    });
  }
}
