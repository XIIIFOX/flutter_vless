import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/widgets.dart';
import 'package:flutter_vless/flutter_vless.dart';

const _ioTimeout = Duration(seconds: 6);
const _maximumResponseBytes = 4096;

/// The Windows Actions driver copies this entry point into a fresh Flutter app.
/// All network destinations and receipt paths come from the runner's fixtures.
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const SizedBox.shrink());

  final result = <String, Object?>{'success': false};
  String? receiptPath;
  try {
    _check(Platform.isWindows, 'The consumer smoke fixture requires Windows');
    final file = Platform.environment['FLUTTER_VLESS_CONSUMER_PLAN'];
    _check(file != null && file.isNotEmpty, 'The consumer plan is missing');
    final plan =
        jsonDecode(await File(file!).readAsString()) as Map<String, dynamic>;
    receiptPath = plan['receipt'] as String;
    result['mode'] = plan['mode'];
    await _runPlan(plan, result);
    result['success'] = true;
  } catch (error, stack) {
    result['error'] = error.toString();
    stderr.writeln('Windows consumer smoke failed: $error\n$stack');
  } finally {
    if (receiptPath != null) {
      await _writeReceipt(receiptPath, result);
    }
  }
  exit(result['success'] == true ? 0 : 1);
}

Future<void> _runPlan(
  Map<String, dynamic> plan,
  Map<String, Object?> result,
) async {
  final mode = plan['mode'];
  _check(mode == 'proxy' || mode == 'vpn', 'Invalid mode');
  final proxy = mode == 'proxy';
  final socksPort = _port(plan['socks_port']);
  final public = plan['https'] as Map<String, dynamic>;
  final host = public['host'] as String;
  final address = _ipv4(public['address']);
  final uri = Uri(
    scheme: 'https',
    host: host,
    port: _port(public['port'] ?? 443),
    path: public['path'] as String,
  );
  final activePath = plan['active_receipt'] as String;
  final continuePath = plan['continue'] as String;
  final restoredPath = plan['restored_receipt'] as String;
  final finishPath = plan['finish'] as String;
  final fixtureRoutes = plan['routes'] as List<dynamic>;
  _check(fixtureRoutes.length >= 2, 'At least two route controls are required');

  result['phase'] = 'baseline';
  result['baseline_https_status'] = await _publicHttps(uri, address);

  final events = _StatusEvents();
  result['states'] = events.transitions;
  final plugin = FlutterVless(
    onStatusChanged: events.record,
    options: const VlessOptions(reconnect: ReconnectOptions(enabled: false)),
  );
  result['phase'] = 'initializeVless';
  await plugin.initializeVless().timeout(const Duration(seconds: 10));
  if (!proxy) {
    result['phase'] = 'requestPermission';
    final elevated = await plugin.requestPermission().timeout(_ioTimeout);
    result['administrator'] = elevated;
    _check(elevated, 'The VPN app process is not elevated');
  }
  result['phase'] = 'getCoreVersion';
  result['core_version'] = await plugin.getCoreVersion().timeout(_ioTimeout);

  final observedRoutes = <Map<String, Object?>>[];
  result['routes'] = observedRoutes;
  try {
    result['phase'] = 'startVless';
    final start = Stopwatch()..start();
    events.connectWatch = start;
    await plugin
        .startVless(
          remark: 'Flutter Vless clean Windows consumer smoke',
          config: jsonEncode(plan['config']),
          proxyOnly: proxy,
        )
        .timeout(const Duration(seconds: 60));
    result['start_accepted_ms'] = start.elapsedMilliseconds;
    result['phase'] = 'wait_connected_event';
    result['start_to_connected_ms'] =
        await events.connected.future.timeout(const Duration(seconds: 10));

    result['phase'] = 'https';
    final active = await _publicHttps(
      uri,
      address,
      socksPort: proxy ? socksPort : null,
    );
    result['start_to_first_https_ms'] = start.elapsedMilliseconds;
    result['active_https_status'] = active;

    result['phase'] = 'routing';
    for (final row in fixtureRoutes.cast<Map<String, dynamic>>()) {
      final fixtureHost = row['host'] as String;
      final expected = row['expected_body'] as String;
      final route = await _routeHttp(
        fixtureHost,
        _ipv4(row['address']),
        _port(row['port']),
        socksPort: proxy ? socksPort : null,
      );
      observedRoutes.add({
        'host': fixtureHost,
        'expected': expected,
        'actual': route,
      });
      _check(route == expected, 'Unexpected route marker for $fixtureHost');
    }
    _check(
      events.current == VlessConnectionState.connected,
      'The runtime disconnected during traffic checks',
    );
    result['phase'] = 'active_hold';
    await _writeReceipt(activePath, {...result, 'success': true});
    await _waitForContinuation(File(continuePath));
    _check(
      events.current == VlessConnectionState.connected,
      'The runtime disconnected while the host verified routing state',
    );
  } catch (error) {
    result['live_error'] = error.toString();
    rethrow;
  } finally {
    final stop = Stopwatch()..start();
    events.stopWatch = stop;
    await plugin.stopVless().timeout(const Duration(seconds: 25));
    result['stop_to_disconnected_ms'] =
        await events.disconnected.future.timeout(const Duration(seconds: 10));
    result['stop_ms'] = stop.elapsedMilliseconds;
    result['disconnected'] =
        events.current == VlessConnectionState.disconnected;
  }

  result['phase'] = 'restored';
  _check(result['disconnected'] == true, 'Stop did not leave DISCONNECTED');
  result['post_stop_https_status'] = await _publicHttps(uri, address);
  await _writeReceipt(restoredPath, {...result, 'success': true});
  await _waitForContinuation(File(finishPath));
}

final class _StatusEvents {
  final transitions = <String>[];
  final connected = Completer<int>();
  final disconnected = Completer<int>();
  Stopwatch? connectWatch;
  Stopwatch? stopWatch;
  VlessConnectionState? current;

  void record(VlessStatus status) {
    final next = status.connectionState;
    if (current != next && transitions.length < 16) {
      transitions.add(next.wireName);
    }
    current = next;
    final starting = connectWatch;
    final stopping = stopWatch;
    if (current == VlessConnectionState.connected &&
        starting != null &&
        !connected.isCompleted) {
      connected.complete(starting.elapsedMilliseconds);
    } else if (current == VlessConnectionState.disconnected &&
        stopping != null &&
        !disconnected.isCompleted) {
      disconnected.complete(stopping.elapsedMilliseconds);
    }
  }
}

Future<int> _publicHttps(
  Uri uri,
  InternetAddress remote, {
  int? socksPort,
}) async {
  Socket? pendingSocket;
  Future<Socket> open() async {
    final socket = await Socket.connect(
      socksPort == null ? remote : InternetAddress.loopbackIPv4,
      socksPort ?? uri.port,
      timeout: _ioTimeout,
    );
    pendingSocket = socket;
    try {
      if (socksPort != null) {
        final reader = _SocketReader(socket);
        try {
          await _socksConnect(socket, reader, remote, uri.port);
          _check(reader.isEmpty, 'SOCKS sent unexpected data before TLS');
          final tls = await SecureSocket.secure(socket, host: uri.host)
              .timeout(_ioTimeout);
          pendingSocket = tls;
          return tls;
        } finally {
          await reader.cancel();
        }
      }
      final tls =
          await SecureSocket.secure(socket, host: uri.host).timeout(_ioTimeout);
      pendingSocket = tls;
      return tls;
    } catch (_) {
      socket.destroy();
      rethrow;
    }
  }

  final client = HttpClient()..connectionTimeout = _ioTimeout;
  client.findProxy = (_) => 'DIRECT';
  client.connectionFactory = (_, __, ___) async =>
      ConnectionTask.fromSocket(open(), () => pendingSocket?.destroy());
  try {
    final request = await client.getUrl(uri).timeout(_ioTimeout);
    request.followRedirects = false;
    request.headers.set(HttpHeaders.connectionHeader, 'close');
    final response = await request.close().timeout(_ioTimeout);
    _check(response.statusCode == HttpStatus.ok,
        'Public HTTPS did not return 200');
    final body = BytesBuilder(copy: false);
    await for (final chunk in response.timeout(_ioTimeout)) {
      body.add(chunk);
      _check(body.length <= 64, 'Public HTTPS returned an oversized IP body');
    }
    _check(
      InternetAddress.tryParse(ascii.decode(body.takeBytes()).trim()) != null,
      'Public HTTPS did not return an IP address',
    );
    return response.statusCode;
  } finally {
    client.close(force: true);
    pendingSocket?.destroy();
  }
}

Future<String> _routeHttp(
  String host,
  InternetAddress remote,
  int port, {
  int? socksPort,
}) async {
  final socket = await Socket.connect(
    socksPort == null ? remote : InternetAddress.loopbackIPv4,
    socksPort ?? port,
    timeout: _ioTimeout,
  );
  final reader = _SocketReader(socket);
  try {
    if (socksPort != null) await _socksConnect(socket, reader, host, port);
    socket.add(ascii
        .encode('GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n'));
    await socket.flush().timeout(_ioTimeout);
    final response = ascii.decode(await reader.readToEnd());
    final separator = response.indexOf('\r\n\r\n');
    _check(separator >= 0 && RegExp(r'^HTTP/1\.[01] 200\b').hasMatch(response),
        'The controlled route did not return HTTP 200');
    return response.substring(separator + 4).trim();
  } finally {
    socket.destroy();
    await reader.cancel();
  }
}

Future<void> _socksConnect(
  Socket socket,
  _SocketReader reader,
  Object remote,
  int port,
) async {
  socket.add([5, 1, 0]);
  await socket.flush().timeout(_ioTimeout);
  final method = await reader.readExactly(2);
  _check(
      method[0] == 5 && method[1] == 0, 'Local SOCKS rejected the test client');

  final target = remote is InternetAddress
      ? [1, ...remote.rawAddress]
      : [3, ascii.encode(remote as String).length, ...ascii.encode(remote)];
  socket.add([5, 1, 0, ...target, port >> 8, port & 0xff]);
  await socket.flush().timeout(_ioTimeout);
  final reply = await reader.readExactly(4);
  _check(reply[0] == 5 && reply[1] == 0 && reply[2] == 0,
      'Local SOCKS did not establish the test route');
  final length = switch (reply[3]) {
    1 => 4,
    3 => (await reader.readExactly(1)).single,
    4 => 16,
    _ => throw StateError('Invalid SOCKS reply address type'),
  };
  await reader.readExactly(length + 2);
}

final class _SocketReader {
  _SocketReader(Socket socket) : _iterator = StreamIterator(socket);

  final StreamIterator<Uint8List> _iterator;
  final _pending = <int>[];

  bool get isEmpty => _pending.isEmpty;

  Future<List<int>> readExactly(int size) async {
    while (_pending.length < size) {
      _check(await _iterator.moveNext().timeout(_ioTimeout),
          'Socket closed during SOCKS handshake');
      _pending.addAll(_iterator.current);
    }
    final result = _pending.sublist(0, size);
    _pending.removeRange(0, size);
    return result;
  }

  Future<List<int>> readToEnd() async {
    final data = BytesBuilder(copy: false)..add(_pending);
    _pending.clear();
    while (await _iterator.moveNext().timeout(_ioTimeout)) {
      data.add(_iterator.current);
      _check(data.length <= _maximumResponseBytes,
          'Controlled response is oversized');
    }
    return data.takeBytes();
  }

  Future<void> cancel() => _iterator.cancel();
}

Future<void> _waitForContinuation(File signal) async {
  final hold = Stopwatch()..start();
  while (!await signal.exists()) {
    _check(hold.elapsed < const Duration(seconds: 35),
        'The host did not verify the active mode within 20 seconds');
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
}

Future<void> _writeReceipt(String path, Map<String, Object?> result) async {
  final temporary = File('$path.partial');
  await temporary.writeAsString(jsonEncode(result), flush: true);
  await temporary.rename(path);
}

InternetAddress _ipv4(Object? value) {
  final address = InternetAddress.tryParse(value as String);
  _check(address?.type == InternetAddressType.IPv4,
      'Expected a pinned IPv4 endpoint');
  return address!;
}

int _port(Object? value) {
  _check(value is int && value > 0 && value <= 65535, 'Invalid fixture port');
  return value as int;
}

void _check(bool passed, String reason) {
  if (!passed) throw StateError(reason);
}
