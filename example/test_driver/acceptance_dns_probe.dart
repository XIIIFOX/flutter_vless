// Development acceptance only: never used by the product entrypoint or resolver.
import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

typedef AcceptanceDnsSocketFactory = Future<RawDatagramSocket> Function();
typedef AcceptanceDnsProbeRunner = Future<Map<String, Object>> Function();

Future<Map<String, Object>> runAcceptanceDnsProbe({
  AcceptanceDnsSocketFactory? socketFactory,
  int Function()? requestId,
}) async {
  final bind =
      socketFactory ??
      () => RawDatagramSocket.bind(
        InternetAddress.anyIPv4,
        0,
        reuseAddress: false,
        reusePort: false,
      );
  final random = requestId == null ? Random.secure() : null;
  final nextId = requestId ?? () => random!.nextInt(65536);
  final results = <Map<String, Object>>[];
  int? previousId;
  for (final type in [1, 28]) {
    final watch = Stopwatch()..start();
    Map<String, Object> result;
    try {
      var id = nextId() & 0xffff;
      if (id == previousId) id = (id + 1) & 0xffff;
      previousId = id;
      final reply = await _exchange(_query(id, type), bind);
      if (reply.address.address != '10.0.85.53' || reply.port != 53) {
        throw const _InvalidResponse('peer');
      }
      result = _parse(reply.data, id, type);
    } on TimeoutException {
      result = {'status': 'timeout', 'answerCount': 0, 'addressCount': 0};
    } on _InvalidResponse catch (error) {
      result = {
        'status': error.reason == 'truncated'
            ? 'truncated'
            : 'invalid_response',
        'reason': error.reason,
        'answerCount': 0,
        'addressCount': 0,
      };
    } catch (_) {
      result = {'status': 'io_error', 'answerCount': 0, 'addressCount': 0};
    }
    results.add({
      'queryType': type == 1 ? 'A' : 'AAAA',
      ...result,
      'durationMs': watch.elapsedMilliseconds,
    });
  }
  return {'version': 1, 'probe': 'managed_dns', 'results': results};
}

Future<Datagram> _exchange(
  Uint8List query,
  AcceptanceDnsSocketFactory bind,
) async {
  final pending = Completer<Datagram>();
  RawDatagramSocket? socket;
  StreamSubscription<RawSocketEvent>? subscription;
  var finished = false;
  var sent = false;
  Datagram? earlyReply;
  void fail() {
    if (!pending.isCompleted) pending.completeError(const _SocketFailure());
  }

  // One deadline also covers bind. A late bind result is still closed below.
  final timer = Timer(const Duration(seconds: 4), () {
    if (!pending.isCompleted) {
      pending.completeError(TimeoutException('deadline'));
    }
  });
  try {
    unawaited(
      bind()
          .then<void>((owned) {
            if (finished) {
              owned.close();
              return;
            }
            socket = owned;
            owned.writeEventsEnabled = false;
            subscription = owned.listen(
              (event) {
                try {
                  if (event == RawSocketEvent.read) {
                    // Ignore unrelated replies without extending the original deadline.
                    // Bound each event's work so traffic cannot starve stop/timer events.
                    var bytesRead = 0;
                    for (
                      var count = 0;
                      count < 8 && bytesRead < 16384;
                      count++
                    ) {
                      final reply = owned.receive();
                      if (reply == null || pending.isCompleted) return;
                      bytesRead += reply.data.length;
                      if (reply.address.address != '10.0.85.53' ||
                          reply.port != 53 ||
                          reply.data.length < 2 ||
                          reply.data[0] != query[0] ||
                          reply.data[1] != query[1]) {
                        continue;
                      }
                      if (sent) {
                        pending.complete(reply);
                      } else {
                        earlyReply ??= reply;
                      }
                      return;
                    }
                  } else if (event == RawSocketEvent.closed) {
                    fail();
                  }
                } catch (_) {
                  fail();
                }
              },
              onError: (_) => fail(),
              onDone: fail,
            );
            if (owned.send(query, InternetAddress('10.0.85.53'), 53) !=
                query.length) {
              fail();
              return;
            }
            sent = true;
            if (earlyReply != null && !pending.isCompleted) {
              pending.complete(earlyReply);
            }
          })
          .catchError((Object _) => fail()),
    );
    return await pending.future;
  } finally {
    finished = true;
    timer.cancel();
    socket?.close();
    final cancel = subscription?.cancel();
    if (cancel != null) unawaited(cancel.catchError((Object _) {}));
  }
}

Uint8List _query(int id, int type) => Uint8List.fromList([
  id >> 8,
  id & 255,
  1,
  0,
  0,
  1,
  0,
  0,
  0,
  0,
  0,
  0,
  4,
  116,
  102,
  111,
  120,
  3,
  100,
  101,
  118,
  0,
  0,
  type,
  0,
  1,
]);

Map<String, Object> _parse(Uint8List bytes, int id, int type) {
  if (bytes.length < 12 || bytes.length > 4096) {
    throw const _InvalidResponse('bounds');
  }
  final reader = _Reader(bytes);
  if (reader.word() != id) throw const _InvalidResponse('id');
  final flags = reader.word();
  if (flags & 0x0200 != 0) throw const _InvalidResponse('truncated');
  if (flags & 0x8000 == 0 || flags & 0x7840 != 0) {
    throw const _InvalidResponse('header');
  }
  final questions = reader.word();
  final answers = reader.word();
  final authority = reader.word();
  final additional = reader.word();
  if (questions != 1 || answers > 64 || authority + additional > 64) {
    throw const _InvalidResponse('bounds');
  }
  if (reader.name() != 'tfox.dev' ||
      reader.word() != type ||
      reader.word() != 1) {
    throw const _InvalidResponse('question');
  }
  final aliases = <String, String>{};
  final addresses = <(String, Uint8List)>[];
  var extendedRcode = 0;
  var hasOpt = false;
  for (var index = 0; index < answers + authority + additional; index++) {
    final owner = reader.name();
    final recordType = reader.word();
    final recordClass = reader.word();
    final ttl = reader.word() * 65536 + reader.word();
    final length = reader.word();
    final end = reader.position + length;
    if (end > bytes.length) throw const _InvalidResponse('bounds');
    if (index < answers) {
      if (recordClass != 1) throw const _InvalidResponse('answer');
      if (recordType == 5) {
        final target = reader.name();
        if (target.isEmpty ||
            aliases.containsKey(owner) ||
            reader.position != end) {
          throw const _InvalidResponse('answer');
        }
        aliases[owner] = target;
      } else if (recordType == type && length == (type == 1 ? 4 : 16)) {
        addresses.add((
          owner,
          Uint8List.sublistView(bytes, reader.position, end),
        ));
      } else {
        throw const _InvalidResponse('answer');
      }
    } else if (recordType == 41) {
      if (index < answers + authority || owner.isNotEmpty || hasOpt) {
        throw const _InvalidResponse('answer');
      }
      hasOpt = true;
      extendedRcode = (ttl >> 24) & 255;
    }
    reader.position = end;
  }
  if (reader.position != bytes.length) throw const _InvalidResponse('bounds');
  final chain = <String>{'tfox.dev'};
  var terminal = 'tfox.dev';
  while (aliases.containsKey(terminal)) {
    terminal = aliases[terminal]!;
    if (!chain.add(terminal) || chain.length > 17) {
      throw const _InvalidResponse('answer');
    }
  }
  if (aliases.keys.any((owner) => !chain.contains(owner)) ||
      addresses.any((entry) => entry.$1 != terminal)) {
    throw const _InvalidResponse('answer');
  }
  final rcode = (extendedRcode << 4) | (flags & 15);
  final count = addresses.map((entry) => entry.$2.join(',')).toSet().length;
  return {
    'status': rcode != 0 ? 'dns_error' : (count == 0 ? 'nodata' : 'answer'),
    'rcode': rcode,
    'answerCount': answers,
    'addressCount': count,
    if (type == 1)
      // A diagnostic expectation, never resolver configuration or a fallback.
      'expectedPublicAddressMatch':
          rcode == 0 &&
          addresses.any(
            (entry) =>
                entry.$2.length == 4 &&
                entry.$2[0] == 45 &&
                entry.$2[1] == 130 &&
                entry.$2[2] == 145 &&
                entry.$2[3] == 120,
          ),
  };
}

class _Reader {
  _Reader(this.bytes);
  final Uint8List bytes;
  int position = 0;

  int word() {
    if (position + 2 > bytes.length) throw const _InvalidResponse('bounds');
    final value = bytes[position] * 256 + bytes[position + 1];
    position += 2;
    return value;
  }

  String name() {
    var cursor = position;
    int? next;
    var expanded = 0;
    final labels = <String>[];
    final visited = <int>{};
    while (true) {
      if (cursor >= bytes.length ||
          !visited.add(cursor) ||
          visited.length > 128) {
        throw const _InvalidResponse('bounds');
      }
      final length = bytes[cursor++];
      if (length == 0) {
        position = next ?? cursor;
        return labels.join('.');
      }
      if (length & 0xc0 == 0xc0) {
        if (cursor >= bytes.length) throw const _InvalidResponse('bounds');
        final target = (length & 0x3f) * 256 + bytes[cursor++];
        if (target >= cursor - 2) throw const _InvalidResponse('bounds');
        next ??= cursor;
        cursor = target;
        continue;
      }
      if (length > 63 || cursor + length > bytes.length) {
        throw const _InvalidResponse('bounds');
      }
      final label = bytes.sublist(cursor, cursor + length);
      if (label.any((byte) => byte < 33 || byte > 126 || byte == 46)) {
        throw const _InvalidResponse('bounds');
      }
      expanded += length + 1;
      if (expanded > 254) throw const _InvalidResponse('bounds');
      labels.add(String.fromCharCodes(label).toLowerCase());
      cursor += length;
    }
  }
}

class _InvalidResponse implements Exception {
  const _InvalidResponse(this.reason);
  final String reason;
}

class _SocketFailure implements Exception {
  const _SocketFailure();
}
