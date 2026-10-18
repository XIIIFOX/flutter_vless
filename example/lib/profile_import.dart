import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/url/xray_json.dart';

/// Keep full Xray JSON intact; share links use the existing protocol parser.
({String config, String? remark}) importProfile(String input) {
  final text = input.trim();
  if (text.startsWith('{') ||
      text.startsWith('[') ||
      text.startsWith('//') ||
      text.startsWith('/*') ||
      text.startsWith('#')) {
    final decoded = decodeXrayJson(text);
    if (decoded is Map<String, dynamic>) {
      final titles = ['remarks', 'remark', 'ps']
          .map((key) => decoded[key])
          .whereType<String>()
          .where((value) => value.isNotEmpty);
      return (config: text, remark: titles.firstOrNull);
    }
    if (decoded is! List || decoded.isEmpty) {
      throw const FormatException(
        'An Xray configuration must be a JSON object',
      );
    }
    // Subscription arrays keep the existing parser's first-profile behavior.
  }
  final parsed = FlutterVless.parse(text);
  return (config: parsed.getFullConfiguration(), remark: parsed.remark);
}
