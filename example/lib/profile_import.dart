import 'dart:convert';
import 'package:flutter_vless/flutter_vless.dart';

/// Keep full Xray JSON intact; share links use the existing protocol parser.
({String config, String? remark}) importProfile(String input) {
  final text = input.trim();
  if (text.startsWith('{') || text.startsWith('[')) {
    final decoded = jsonDecode(text);
    if (decoded is! Map<String, dynamic>) {
      throw const FormatException(
        'An Xray configuration must be a JSON object',
      );
    }
    return (
      config: text,
      remark: decoded['remarks'] is String
          ? decoded['remarks'] as String
          : null,
    );
  }
  final parsed = FlutterVless.parse(text);
  return (config: parsed.getFullConfiguration(), remark: parsed.remark);
}
