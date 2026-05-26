import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Chrome extension manifest key matches native host dev origin', () {
    final manifest = jsonDecode(
      File('extensions/browser/chrome/manifest.json').readAsStringSync(),
    ) as Map<String, dynamic>;
    final nativeManifest = jsonDecode(
      File(
        'native_hosts/flutter_vless_native_host/manifests/dev.tfox.flutter_vless.chrome.json',
      ).readAsStringSync(),
    ) as Map<String, dynamic>;

    final extensionId = _extensionIdFromKey(manifest['key'] as String);
    expect(extensionId, 'pnknppmnnjjoajkpelpnccddodhheefb');
    expect(
      nativeManifest['allowed_origins'],
      contains('chrome-extension://$extensionId/'),
    );
  });
}

String _extensionIdFromKey(String key) {
  final tempDir = Directory.systemTemp.createTempSync('extension_key_');
  try {
    final input = File('${tempDir.path}/key.der')
      ..writeAsBytesSync(base64Decode(key));
    final result = Process.runSync(
      'openssl',
      ['dgst', '-sha256', '-binary', input.path],
      stdoutEncoding: null,
    );
    if (result.exitCode != 0) {
      throw StateError(result.stderr.toString());
    }
    final hash = result.stdout as List<int>;
    final buffer = StringBuffer();
    for (final byte in hash.take(16)) {
      buffer
        ..write(String.fromCharCode(97 + (byte >> 4)))
        ..write(String.fromCharCode(97 + (byte & 0x0f)));
    }
    return buffer.toString();
  } finally {
    tempDir.deleteSync(recursive: true);
  }
}
