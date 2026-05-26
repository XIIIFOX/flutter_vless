import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'companion_controller.dart';

class CompanionStateFile {
  static String get path {
    final base = Platform.isWindows
        ? Platform.environment['APPDATA'] ??
            Platform.environment['USERPROFILE'] ??
            Directory.current.path
        : Platform.environment['HOME'] ?? Directory.current.path;
    final directory = Platform.isWindows
        ? Directory('$base\\flutter_vless')
        : Directory('$base/.flutter_vless');
    return '${directory.path}${Platform.pathSeparator}companion_state.json';
  }

  static Future<void> write(
    Map<String, Object?> state, {
    String? pathOverride,
  }) async {
    final file = File(pathOverride ?? path);
    await file.parent.create(recursive: true);
    await file.writeAsString(const JsonEncoder.withIndent('  ').convert(state));
  }

  static Future<void> delete({String? pathOverride}) async {
    final file = File(pathOverride ?? path);
    if (await file.exists()) {
      await file.delete();
    }
  }
}

class LocalApiServer {
  LocalApiServer({
    required this.controller,
    this.preferredPort = 18443,
    this.stateFilePath,
  });

  final CompanionController controller;
  final int preferredPort;
  final String? stateFilePath;
  final String token = _makeToken();
  HttpServer? _server;

  int get port => _server?.port ?? 0;
  String get origin => 'http://127.0.0.1:$port';

  Future<void> start() async {
    try {
      _server = await HttpServer.bind(
        InternetAddress.loopbackIPv4,
        preferredPort,
      );
    } on SocketException {
      _server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    }

    await CompanionStateFile.write(
      {
        'origin': origin,
        'host': '127.0.0.1',
        'port': port,
        'token': token,
        'pid': pid,
        'updatedAt': DateTime.now().toIso8601String(),
      },
      pathOverride: stateFilePath,
    );

    _server!.listen(_handleRequest);
  }

  Future<void> dispose() async {
    await CompanionStateFile.delete(pathOverride: stateFilePath);
    await _server?.close(force: true);
  }

  Future<void> _handleRequest(HttpRequest request) async {
    _setCorsHeaders(request.response);
    if (request.method == 'OPTIONS') {
      request.response.statusCode = HttpStatus.noContent;
      await request.response.close();
      return;
    }

    try {
      if (request.uri.path == '/health') {
        await _sendJson(request.response, {
          'ok': true,
          'authRequired': true,
          'origin': origin,
        });
        return;
      }

      if (!_isAuthorized(request)) {
        request.response.statusCode = HttpStatus.unauthorized;
        await _sendJson(request.response, {'error': 'Unauthorized'});
        return;
      }

      switch ((request.method, request.uri.path)) {
        case ('GET', '/status'):
          await _sendJson(request.response, controller.toStatusJson());
        case ('GET', '/proxy-endpoint'):
          await _sendJson(request.response, controller.proxyEndpoint.toJson());
        case ('POST', '/import'):
          final body = await _readJsonBody(request);
          final profile = await controller.importProfile(
            body['input']?.toString() ?? '',
          );
          await _sendJson(request.response, {'profile': profile.toJson()});
        case ('POST', '/connect'):
          final body = await _readJsonBody(request);
          await controller.connect(
            profileId: body['profileId']?.toString(),
            input: body['input']?.toString(),
            config: body['config']?.toString(),
            remark: body['remark']?.toString(),
            setSystemProxy: body['setSystemProxy'] == true,
          );
          await _sendJson(request.response, controller.toStatusJson());
        case ('POST', '/disconnect'):
          await controller.disconnect();
          await _sendJson(request.response, controller.toStatusJson());
        case ('POST', '/delay'):
          final body = await _readJsonBody(request);
          final delay = await controller.delay(
            url: body['url']?.toString() ?? 'https://google.com/generate_204',
          );
          await _sendJson(request.response, {'delay': delay});
        default:
          request.response.statusCode = HttpStatus.notFound;
          await _sendJson(request.response, {'error': 'Not found'});
      }
    } catch (error) {
      request.response.statusCode = HttpStatus.badRequest;
      await _sendJson(request.response, {'error': error.toString()});
    }
  }

  bool _isAuthorized(HttpRequest request) {
    final header = request.headers.value(HttpHeaders.authorizationHeader);
    return header == 'Bearer $token';
  }

  Future<Map<String, dynamic>> _readJsonBody(HttpRequest request) async {
    final text = await utf8.decoder.bind(request).join();
    if (text.trim().isEmpty) {
      return <String, dynamic>{};
    }
    final decoded = jsonDecode(text);
    if (decoded is Map<String, dynamic>) {
      return decoded;
    }
    throw const FormatException('JSON body must be an object.');
  }

  Future<void> _sendJson(
    HttpResponse response,
    Map<String, Object?> payload,
  ) async {
    response.headers.contentType = ContentType.json;
    response.write(jsonEncode(payload));
    await response.close();
  }

  void _setCorsHeaders(HttpResponse response) {
    response.headers
      ..set(HttpHeaders.accessControlAllowOriginHeader, '*')
      ..set(HttpHeaders.accessControlAllowMethodsHeader, 'GET, POST, OPTIONS')
      ..set(
        HttpHeaders.accessControlAllowHeadersHeader,
        'authorization, content-type',
      );
  }

  static String _makeToken() {
    final random = Random.secure();
    final bytes = List<int>.generate(32, (_) => random.nextInt(256));
    return base64UrlEncode(bytes).replaceAll('=', '');
  }
}
