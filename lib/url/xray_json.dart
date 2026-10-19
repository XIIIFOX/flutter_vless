import 'dart:convert';

/// Go's struct-field matching against ASCII Xray schema names. Dictionary
/// keys are caller data and must never be normalized using this helper.
String foldXraySchemaField(String key) => String.fromCharCodes(key.runes.map(
      (rune) => switch (rune) {
        >= 0x41 && <= 0x5a => rune + 0x20,
        0x017f => 0x73,
        0x212a => 0x6b,
        _ => rune,
      },
    ));

/// Read one inspected schema field without changing the imported document.
/// Native adapters also reject ambiguous aliases before adding private state.
Object? readXraySchemaField(Map<String, dynamic> object, String field) {
  final wanted = foldXraySchemaField(field);
  Object? value;
  var present = false;
  for (final entry in object.entries) {
    if (foldXraySchemaField(entry.key) != wanted) continue;
    if (present) {
      throw ArgumentError('Xray config has conflicting aliases for "$field"');
    }
    present = true;
    value = entry.value;
  }
  return value;
}

/// Decode one Xray document (or subscription array) with Core-style comments.
///
/// Xray's local-file reader removes //, /* */ and # comments outside strings.
/// Newlines in comments are retained, including within numeric tokens. Unlike
/// its streaming decoder, this API rejects trailing documents/data explicitly;
/// they must not silently disappear. One leading UTF-8 BOM is a portable import
/// extension; native Core always receives ordinary JSON after normalization.
Object? decodeXrayJson(String input) {
  final source = input.startsWith('\uFEFF') ? input.substring(1) : input;
  final output = StringBuffer();
  var quote = 0;
  var escaped = false;
  var lineComment = false;
  var blockComment = false;
  var blockStar = false;
  for (var i = 0; i < source.length; i++) {
    final char = source.codeUnitAt(i);
    final next = i + 1 < source.length ? source.codeUnitAt(i + 1) : -1;
    if (lineComment) {
      if (char == 10) {
        lineComment = false;
        output.writeCharCode(char);
      }
      continue;
    }
    if (blockComment) {
      if (blockStar) {
        if (char == 47) {
          blockComment = false;
          blockStar = false;
        } else if (char == 10) {
          // Core retains the star state across LF, including *\n/.
          output.writeCharCode(char);
        } else if (char != 42) {
          blockStar = false;
        }
      } else if (char == 42) {
        blockStar = true;
      } else if (char == 10) {
        output.writeCharCode(char);
      }
      continue;
    }
    if (quote != 0) {
      output.writeCharCode(char);
      if (escaped) {
        escaped = false;
      } else if (char == 92) {
        escaped = true;
      } else if (char == quote) {
        quote = 0;
      }
      continue;
    }
    if (char == 34 || char == 39) {
      // Single quotes stay intact; the JSON decoder rejects JSON5 syntax.
      quote = char;
    } else if (char == 35 || (char == 47 && next == 47)) {
      lineComment = true;
      if (char == 47) i++;
      continue;
    } else if (char == 47 && next == 42) {
      blockComment = true;
      i++;
      continue;
    }
    output.writeCharCode(char);
  }
  return jsonDecode(output.toString());
}
