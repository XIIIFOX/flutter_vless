import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

Future<void> main() async {
  final bridge = NativeMessagingBridge();
  await bridge.run();
}

class NativeMessagingBridge {
  final List<int> _buffer = <int>[];

  Future<void> run() async {
    await for (final chunk in stdin) {
      _buffer.addAll(chunk);
      while (_buffer.length >= 4) {
        final length = _readLength(_buffer);
        if (_buffer.length < 4 + length) {
          break;
        }
        final payload = _buffer.sublist(4, 4 + length);
        _buffer.removeRange(0, 4 + length);
        await _handlePayload(payload);
      }
    }
  }

  Future<void> _handlePayload(List<int> payload) async {
    try {
      final decoded = jsonDecode(utf8.decode(payload));
      if (decoded is! Map<String, dynamic>) {
        throw const FormatException('Native message must be a JSON object.');
      }
      final response = await CompanionClient().send(decoded);
      _writeMessage({'ok': true, 'response': response});
    } catch (error) {
      _writeMessage({'ok': false, 'error': error.toString()});
    }
  }

  int _readLength(List<int> bytes) {
    final data = ByteData.sublistView(
      Uint8List.fromList(bytes.take(4).toList()),
    );
    return data.getUint32(0, Endian.little);
  }

  void _writeMessage(Map<String, Object?> message) {
    final payload = utf8.encode(jsonEncode(message));
    final length = ByteData(4)..setUint32(0, payload.length, Endian.little);
    stdout.add(length.buffer.asUint8List());
    stdout.add(payload);
  }
}

class CompanionClient {
  Future<Map<String, dynamic>> send(Map<String, dynamic> message) async {
    final state = await _readState();
    final type = message['type']?.toString() ?? 'status';
    final route = switch (type) {
      'hello' => ('GET', '/status'),
      'status' => ('GET', '/status'),
      'getProxyEndpoint' => ('GET', '/proxy-endpoint'),
      'importProfile' => ('POST', '/import'),
      'connect' => ('POST', '/connect'),
      'disconnect' => ('POST', '/disconnect'),
      'delay' => ('POST', '/delay'),
      _ => throw ArgumentError('Unsupported command: $type'),
    };

    final origin = state['origin']?.toString();
    final token = state['token']?.toString();
    if (origin == null || origin.isEmpty || token == null || token.isEmpty) {
      throw StateError('Companion state file is missing origin or token.');
    }

    final client = HttpClient();
    try {
      final uri = Uri.parse('$origin${route.$2}');
      final request = await client.openUrl(route.$1, uri);
      request.headers
        ..set(HttpHeaders.authorizationHeader, 'Bearer $token')
        ..contentType = ContentType.json;
      if (route.$1 == 'POST') {
        request.write(jsonEncode(message));
      }
      final response = await request.close();
      final text = await utf8.decoder.bind(response).join();
      final decoded = text.isEmpty ? <String, dynamic>{} : jsonDecode(text);
      if (decoded is! Map<String, dynamic>) {
        throw const FormatException(
          'Companion response must be a JSON object.',
        );
      }
      if (response.statusCode >= 400) {
        throw StateError(decoded['error'] ?? 'Companion request failed.');
      }
      return decoded;
    } finally {
      client.close(force: true);
    }
  }

  Future<Map<String, dynamic>> _readState() async {
    final file = File(_statePath);
    if (!await file.exists()) {
      throw StateError('Flutter Vless Companion is not running.');
    }
    final decoded = jsonDecode(await file.readAsString());
    if (decoded is Map<String, dynamic>) {
      return decoded;
    }
    throw const FormatException('Companion state file is invalid.');
  }

  String get _statePath {
    final base = Platform.isWindows
        ? Platform.environment['APPDATA'] ??
              Platform.environment['USERPROFILE'] ??
              Directory.current.path
        : Platform.environment['HOME'] ?? Directory.current.path;
    final directory = Platform.isWindows
        ? '$base\\flutter_vless'
        : '$base/.flutter_vless';
    return '$directory${Platform.pathSeparator}companion_state.json';
  }
}
