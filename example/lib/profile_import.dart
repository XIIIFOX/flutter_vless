import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/url/xray_json.dart';

/// Keep full Xray JSON intact; share links use the existing protocol parser.
///
/// Leading comments can belong to either JSON or a subscription list. Inspect
/// the first payload token before choosing the JSON path. Multi-profile
/// subscriptions retain the example's existing first-supported-profile policy.
({String config, String? remark}) importProfile(String input) {
  final text = input.trim();
  if (_startsWithJsonDocument(text)) {
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

// Classify only leading trivia; decodeXrayJson still owns JSON validation and
// preserves the original document, including comments inside quoted strings.
bool _startsWithJsonDocument(String text) {
  var offset = 0;
  while (offset < text.length) {
    final char = text.codeUnitAt(offset);
    if (char == 32 || char == 9 || char == 10 || char == 13) {
      offset++;
      continue;
    }
    if (char == 35 || text.startsWith('//', offset)) {
      final newline = text.indexOf('\n', offset);
      if (newline < 0) return false;
      offset = newline + 1;
      continue;
    }
    if (text.startsWith('/*', offset)) {
      offset += 2;
      var star = false;
      var closed = false;
      while (offset < text.length) {
        final next = text.codeUnitAt(offset++);
        if (star && next == 47) {
          closed = true;
          break;
        }
        // The Core-style decoder retains the star state across LF.
        if (next == 42) {
          star = true;
        } else if (next != 10) {
          star = false;
        }
      }
      if (!closed) {
        throw const FormatException('Unterminated leading comment');
      }
      continue;
    }
    return char == 123 || char == 91;
  }
  return false;
}
