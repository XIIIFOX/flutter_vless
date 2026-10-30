import 'package:flutter_vless/url/xray_json.dart';

/// Early checks for pinned Core 26.10.29's GeoDAT updater. Core remains the
/// authority for cron syntax, native file resolution and the 256 MiB response cap.
/// This validator never downloads, reads files or rewrites caller fields.
abstract final class XrayGeodataUpdate {
  static void validate(Map<String, dynamic> config) {
    final value = readXraySchemaField(config, 'geodata');
    if (value == null) return;
    if (value is! Map<String, dynamic>) {
      throw ArgumentError('Xray geodata must be a JSON object');
    }
    final cron = readXraySchemaField(value, 'cron');
    if (cron != null && cron is! String) {
      throw ArgumentError('Xray geodata cron must be a string');
    }
    if (cron == '') {
      throw ArgumentError(
          'Xray geodata cron must not be empty; omit it to disable scheduling');
    }
    final outbound = readXraySchemaField(value, 'outbound');
    if (outbound != null && outbound is! String) {
      throw ArgumentError('Xray geodata outbound must be a string');
    }
    final rawAssets = readXraySchemaField(value, 'assets');
    if (rawAssets != null && rawAssets is! List) {
      throw ArgumentError('Xray geodata assets must be an array');
    }
    final assets = rawAssets as List? ?? const [];
    final active = cron is String && cron.isNotEmpty;
    if (active && assets.length > 100) {
      throw ArgumentError('Xray geodata supports at most 100 assets');
    }
    if (active) {
      final delay = _constantDelayNanoseconds(cron);
      if (delay != null && delay < BigInt.from(60000000000)) {
        throw ArgumentError(
            'Xray geodata interval must be at least one minute');
      }
    }
    for (var index = 0; index < assets.length; index++) {
      final asset = assets[index];
      if (asset is! Map<String, dynamic>) {
        throw ArgumentError(
            'Xray geodata asset at index $index must be an object');
      }
      final url = readXraySchemaField(asset, 'url');
      final uri = url is String ? Uri.tryParse(url) : null;
      // Build validates URLs even when cron is absent/empty. Do not include
      // URLs or local file values in exceptions or diagnostic reports.
      if (uri == null ||
          uri.scheme != 'https' ||
          !uri.hasAuthority ||
          uri.host.isEmpty) {
        throw ArgumentError(
            'Xray geodata asset at index $index requires an HTTPS URL');
      }
      final file = readXraySchemaField(asset, 'file');
      if (file != null && file is! String) {
        throw ArgumentError(
            'Xray geodata asset at index $index has an invalid file type');
      }
      if (active && (file is! String || !file.toLowerCase().endsWith('.dat'))) {
        throw ArgumentError(
            'Xray geodata asset at index $index requires a .dat file');
      }
    }
  }

  // Recognize Go duration values only. Unknown cron grammar/overflow is left
  // to Core instead of duplicating robfig/cron or rejecting future syntax.
  static BigInt? _constantDelayNanoseconds(String cron) {
    if (!cron.startsWith('@every ')) return null;
    var input = cron.substring(7);
    if (input.length > 256)
      return null; // Bound optional early parsing; Core owns the complete grammar.
    var negative = false;
    if (input.startsWith('-') || input.startsWith('+')) {
      negative = input.startsWith('-');
      input = input.substring(1);
    }
    if (input == '0') return BigInt.zero;
    final pattern =
        RegExp(r'([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(ns|us|µs|μs|ms|s|m|h)');
    const scales = {
      'ns': 1,
      'us': 1000,
      'µs': 1000,
      'μs': 1000,
      'ms': 1000000,
      's': 1000000000,
      'm': 60000000000,
      'h': 3600000000000
    };
    var offset = 0;
    var total = BigInt.zero;
    for (final match in pattern.allMatches(input)) {
      if (match.start != offset) return null;
      final parts = match[1]!.split('.');
      final scale = BigInt.from(scales[match[2]]!);
      total += BigInt.parse(parts.first.isEmpty ? '0' : parts.first) * scale;
      if (parts.length == 2 && parts[1].isNotEmpty) {
        total += BigInt.parse(parts[1]) *
            scale ~/
            BigInt.from(10).pow(parts[1].length);
      }
      offset = match.end;
    }
    if (offset == 0 ||
        offset != input.length ||
        total > (BigInt.one << 63) - (negative ? BigInt.zero : BigInt.one)) {
      return null;
    }
    return negative ? -total : total;
  }
}
