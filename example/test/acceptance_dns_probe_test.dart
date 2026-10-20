import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

import '../test_driver/acceptance_dns_probe.dart';
import '../test_driver/live_main.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('only the exact live request invokes the DNS probe', () async {
    var calls = 0;
    Future<Map<String, Object>> probe() async {
      calls++;
      return {'version': 1, 'probe': 'managed_dns', 'results': <Object>[]};
    }

    for (final request in [
      null,
      'other',
      'acceptance-dns-probe ',
      'acceptance-DNS-probe',
      'acceptance-dns-probe?tfox.dev',
    ]) {
      expect(
        await handleLiveAcceptanceRequest(request, dnsProbe: probe),
        'acceptance-unsupported',
      );
    }
    expect(calls, 0);
    final result = await handleLiveAcceptanceRequest(
      'acceptance-dns-probe',
      dnsProbe: probe,
    );
    expect(calls, 1, reason: 'The exact dev-only request must reach the probe');
    expect(
      result,
      jsonEncode({'version': 1, 'probe': 'managed_dns', 'results': <Object>[]}),
    );
  });

  test('A and AAAA use fixed VIP once and close both owned sockets', () async {
    final sockets = <_Socket>[];
    Future<RawDatagramSocket> bind() async {
      final socket = _Socket((socket, packet, peer, port) {
        expect(peer.address, '10.0.85.53');
        expect(port, 53);
        expect(packet.sublist(12), [
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
          sockets.length == 1 ? 1 : 28,
          0,
          1,
        ]);
        socket.reply(
          _response(
            packet,
            address: sockets.length == 1 ? [45, 130, 145, 120] : null,
          ),
        );
      });
      sockets.add(socket);
      return socket;
    }

    final output = await runAcceptanceDnsProbe(
      socketFactory: bind,
      requestId: () => 0x1234,
    );
    final results = output['results']! as List;
    expect(
      results,
      hasLength(2),
      reason: 'Both fixed questions need a bounded result',
    );
    if (results.length != 2) return;
    expect((results[0] as Map)['status'], 'answer');
    expect((results[0] as Map)['expectedPublicAddressMatch'], true);
    expect((results[1] as Map)['status'], 'nodata');
    expect(sockets, hasLength(2));
    expect(
      sockets.every((socket) => socket.closed && socket.sent.length == 1),
      isTrue,
    );
    expect(
      sockets[0].sent.single.sublist(0, 2),
      isNot(sockets[1].sent.single.sublist(0, 2)),
    );
    final encoded = jsonEncode(output);
    expect(encoded, isNot(contains('45.130.145.120')));
    expect(encoded, isNot(contains('tfox.dev')));
  });

  test(
    'unexpected addresses remain counts and never become output text',
    () async {
      final (result, sockets) = await _firstReply(
        (query) => _response(query, address: [203, 0, 113, 9]),
      );
      expect(result['status'], 'answer');
      expect(result['rcode'], 0);
      expect(result['answerCount'], 1);
      expect(result['addressCount'], 1);
      expect(result['expectedPublicAddressMatch'], false);
      expect(jsonEncode(result), isNot(contains('203.0.113.9')));
      expect(sockets.every((socket) => socket.closed), true);
    },
  );

  test(
    'AAAA answers are validated without publishing their addresses',
    () async {
      final sockets = <_Socket>[];
      final output = await runAcceptanceDnsProbe(
        socketFactory: () async {
          final socket = _Socket((socket, query, _, _) {
            socket.reply(
              _response(
                query,
                address: sockets.length == 2
                    ? [0x20, 1, 0x0d, 0xb8, ...List.filled(11, 0), 9]
                    : null,
              ),
            );
          });
          sockets.add(socket);
          return socket;
        },
        requestId: () => 9,
      );
      final result = (output['results']! as List)[1] as Map;
      expect(result['queryType'], 'AAAA');
      expect(result['status'], 'answer');
      expect(result['addressCount'], 1);
      expect(result.containsKey('expectedPublicAddressMatch'), false);
      expect(jsonEncode(output), isNot(contains('2001:')));
    },
  );

  test('a bounded CNAME chain can own the expected A answer', () async {
    final (result, _) = await _firstReply(
      (query) => _records(query, [
        _record('tfox.dev', 5, _name('alias.invalid')),
        _record('alias.invalid', 1, [45, 130, 145, 120]),
      ]),
    );
    expect(result['status'], 'answer');
    expect(result['answerCount'], 2);
    expect(result['addressCount'], 1);
    expect(result['expectedPublicAddressMatch'], true);
    expect(jsonEncode(result), isNot(contains('alias.invalid')));
  });

  test(
    'valid negative and extended RCODE remain DNS errors, not timeouts',
    () async {
      final (negative, _) = await _firstReply(
        (query) => _response(query, rcode: 3),
      );
      expect(negative['status'], 'dns_error');
      expect(negative['rcode'], 3);
      expect(negative['addressCount'], 0);
      final (extended, _) = await _firstReply((query) {
        final packet = _response(query).toList();
        packet[11] = 1;
        packet.addAll([0, 0, 41, 16, 0, 1, 0, 0, 0, 0, 0]);
        return Uint8List.fromList(packet);
      });
      expect(extended['status'], 'dns_error');
      expect(extended['rcode'], 16);
    },
  );

  test(
    'matching malformed packets fail closed with bounded metadata',
    () async {
      final cases = <String, Uint8List Function(Uint8List)>{
        'QR': (q) => _response(q)..[2] = 1,
        'opcode': (q) => _response(q)..[2] = 0x89,
        'question count': (q) => _response(q)..[5] = 2,
        'record count': (q) => _response(q)..[7] = 65,
        'question name': (q) => _response(q)..[16] = 121,
        'question type': (q) => _response(q)..[23] = 28,
        'question class': (q) => _response(q)..[25] = 3,
        'short header': (q) => Uint8List.fromList(q.take(2).toList()),
        'oversized packet': (q) =>
            Uint8List.fromList([...q.take(2), ...List.filled(4095, 0)]),
        'trailing data': (q) => Uint8List.fromList([..._response(q), 0]),
        'short A': (q) => _response(q, address: [45, 130, 145]),
        'wrong answer type': (q) =>
            _response(q, address: [45, 130, 145, 120])..[29] = 16,
        'compression cycle': (q) =>
            _response(q, address: [45, 130, 145, 120])..[27] = 26,
        'truncated RDATA': (q) => Uint8List.fromList(
          _response(q, address: [45, 130, 145, 120]).take(40).toList(),
        ),
        'unrelated answer owner': (q) => _records(q, [
          _record('other.invalid', 1, [45, 130, 145, 120]),
        ]),
        'CNAME cycle': (q) =>
            _records(q, [_record('tfox.dev', 5, _name('tfox.dev'))]),
      };
      for (final entry in cases.entries) {
        final (result, sockets) = await _firstReply(entry.value);
        expect(result['status'], 'invalid_response', reason: entry.key);
        expect(result['addressCount'], 0, reason: entry.key);
        expect(
          sockets.every((socket) => socket.closed && socket.sent.length == 1),
          true,
          reason: entry.key,
        );
        expect((result['durationMs']! as int), greaterThanOrEqualTo(0));
      }
    },
  );

  test('TC is explicitly inconclusive and never starts TCP fallback', () async {
    final (result, sockets) = await _firstReply(
      (q) => _response(q)..[2] = 0x83,
    );
    expect(result['status'], 'truncated');
    expect(result['reason'], 'truncated');
    expect(result.containsKey('rcode'), false);
    expect(sockets, hasLength(2));
    expect(sockets.every((socket) => socket.sent.length == 1), true);
  });

  test('wrong peer, port and ID are ignored without resending', () async {
    final sockets = <_Socket>[];
    final output = await runAcceptanceDnsProbe(
      socketFactory: () async {
        final socket = _Socket((socket, query, _, _) {
          socket.reply(_response(query), peer: '203.0.113.9');
          socket.reply(_response(query), port: 54);
          socket.reply(_response(query)..[0] ^= 1);
          socket.reply(_response(query));
        });
        sockets.add(socket);
        return socket;
      },
      requestId: () => 12,
    );
    expect((output['results']! as List).map((r) => (r as Map)['status']), [
      'nodata',
      'nodata',
    ]);
    expect(
      sockets.every((socket) => socket.sent.length == 1 && socket.closed),
      true,
    );
  });

  test('partial send is an IO failure even if an early reply exists', () async {
    final sockets = <_Socket>[];
    final output = await runAcceptanceDnsProbe(
      socketFactory: () async {
        final socket = _Socket(
          (socket, query, _, _) => socket.reply(_response(query)),
        )..sendCount = 0;
        sockets.add(socket);
        return socket;
      },
      requestId: () => 12,
    );
    expect((output['results']! as List).map((r) => (r as Map)['status']), [
      'io_error',
      'io_error',
    ]);
    expect(sockets.every((socket) => socket.closed), true);
  });

  test('bind and receive errors never expose exception text', () async {
    var binds = 0;
    final sockets = <_Socket>[];
    final output = await runAcceptanceDnsProbe(
      socketFactory: () async {
        if (binds++ == 0) throw StateError('private-error-canary');
        final socket = _Socket((socket, _, _, _) {
          socket.error(StateError('private-error-canary'));
        });
        sockets.add(socket);
        return socket;
      },
      requestId: () => 12,
    );
    expect((output['results']! as List).map((r) => (r as Map)['status']), [
      'io_error',
      'io_error',
    ]);
    expect(jsonEncode(output), isNot(contains('canary')));
    expect(sockets.single.closed, true);
  });

  test('live handler suppresses an unexpected probe error', () async {
    final text = await handleLiveAcceptanceRequest(
      'acceptance-dns-probe',
      dnsProbe: () async => throw StateError('private-error-canary'),
    );
    expect(jsonDecode(text), {
      'version': 1,
      'probe': 'managed_dns',
      'status': 'unavailable',
      'results': [],
    });
    expect(text, isNot(contains('canary')));
  });

  testWidgets(
    'both questions have one four-second deadline and close on timeout',
    (tester) async {
      final sockets = <_Socket>[];
      final pending = runAcceptanceDnsProbe(
        socketFactory: () async {
          final socket = _Socket((_, _, _, _) {});
          sockets.add(socket);
          return socket;
        },
        requestId: () => 1,
      );
      await tester.pump();
      await tester.pump(const Duration(seconds: 4));
      await tester.pump();
      await tester.pump(const Duration(seconds: 4));
      final output = await pending;
      expect((output['results']! as List).map((r) => (r as Map)['status']), [
        'timeout',
        'timeout',
      ]);
      expect(
        sockets.every((socket) => socket.closed && socket.sent.length == 1),
        true,
      );
    },
  );

  testWidgets('a throwing receive callback becomes a closed IO result', (
    tester,
  ) async {
    final sockets = <_Socket>[];
    final uncaught = <Type>[];
    late Future<Map<String, Object>> pending;
    runZonedGuarded(() {
      pending = runAcceptanceDnsProbe(
        socketFactory: () async {
          final socket = _Socket((socket, query, _, _) {
            if (sockets.length == 1) {
              socket.receiveOverride = () => throw StateError('private-canary');
              socket.readEvent();
            } else {
              socket.reply(_response(query));
            }
          });
          sockets.add(socket);
          return socket;
        },
        requestId: () => 1,
      );
    }, (Object error, _) => uncaught.add(error.runtimeType));
    await tester.pump();
    await tester.pump(const Duration(seconds: 4));
    final output = await pending;
    expect(
      uncaught,
      isEmpty,
      reason: 'Stream listener failures must not escape the diagnostic',
    );
    expect((output['results']! as List).map((r) => (r as Map)['status']), [
      'io_error',
      'nodata',
    ]);
    expect(sockets.every((socket) => socket.closed), true);
  });

  testWidgets('late successful bind is closed without sending after timeout', (
    tester,
  ) async {
    final binding = Completer<RawDatagramSocket>();
    final late = _Socket((_, _, _, _) {});
    var calls = 0;
    final pending = runAcceptanceDnsProbe(
      socketFactory: () {
        if (calls++ == 0) return binding.future;
        return Future.value(_Socket((s, q, _, _) => s.reply(_response(q))));
      },
      requestId: () => 1,
    );
    await tester.pump();
    await tester.pump(const Duration(seconds: 4));
    final output = await pending;
    expect((output['results']! as List).map((r) => (r as Map)['status']), [
      'timeout',
      'nodata',
    ]);
    binding.complete(late);
    await tester.pump();
    expect(late.closed, true);
    expect(late.sent, isEmpty);
  });

  testWidgets('wrong ID near deadline does not reset it', (tester) async {
    final sockets = <_Socket>[];
    final pending = runAcceptanceDnsProbe(
      socketFactory: () async {
        final socket = _Socket((socket, query, _, _) {
          if (sockets.length == 1) {
            Timer(
              const Duration(seconds: 3),
              () => socket.reply(_response(query)..[0] ^= 1),
            );
          } else {
            socket.reply(_response(query));
          }
        });
        sockets.add(socket);
        return socket;
      },
      requestId: () => 1,
    );
    await tester.pump();
    await tester.pump(const Duration(seconds: 3));
    expect(sockets, hasLength(1));
    await tester.pump(const Duration(seconds: 1));
    final output = await pending;
    expect((output['results']! as List).map((r) => (r as Map)['status']), [
      'timeout',
      'nodata',
    ]);
    expect(sockets.first.sent, hasLength(1));
    expect(sockets.first.closed, true);
  });

  testWidgets('a read event drains at most eight unrelated datagrams', (
    tester,
  ) async {
    final sockets = <_Socket>[];
    final pending = runAcceptanceDnsProbe(
      socketFactory: () async {
        final socket = _Socket((socket, query, _, _) {
          if (sockets.length == 1) {
            socket.receiveOverride = () => Datagram(
              Uint8List.fromList([255, 255]),
              InternetAddress('10.0.85.53'),
              53,
            );
            socket.readEvent();
          } else {
            socket.reply(_response(query));
          }
        });
        sockets.add(socket);
        return socket;
      },
      requestId: () => 1,
    );
    await tester.pump();
    expect(sockets.first.received, 8);
    await tester.pump(const Duration(seconds: 4));
    expect(((await pending)['results']! as List).first['status'], 'timeout');
    expect(sockets.first.closed, true);
  });
}

typedef _Send =
    void Function(
      _Socket socket,
      Uint8List packet,
      InternetAddress peer,
      int port,
    );

class _Socket extends Stream<RawSocketEvent> implements RawDatagramSocket {
  _Socket(this.onSend);
  final _Send onSend;
  final _events = StreamController<RawSocketEvent>(sync: true);
  final _datagrams = <Datagram>[];
  final sent = <Uint8List>[];
  bool closed = false;
  int? sendCount;
  int received = 0;
  Datagram? Function()? receiveOverride;
  @override
  bool writeEventsEnabled = true;

  void reply(Uint8List packet, {String peer = '10.0.85.53', int port = 53}) {
    _datagrams.add(Datagram(packet, InternetAddress(peer), port));
    _events.add(RawSocketEvent.read);
  }

  void readEvent() => _events.add(RawSocketEvent.read);
  void error(Object error) => _events.addError(error);

  @override
  int send(List<int> buffer, InternetAddress address, int port) {
    final packet = Uint8List.fromList(buffer);
    sent.add(packet);
    onSend(this, packet, address, port);
    return sendCount ?? buffer.length;
  }

  @override
  Datagram? receive() {
    received++;
    return receiveOverride?.call() ??
        (_datagrams.isEmpty ? null : _datagrams.removeAt(0));
  }

  @override
  void close() {
    if (closed) return;
    closed = true;
    unawaited(_events.close());
  }

  @override
  StreamSubscription<RawSocketEvent> listen(
    void Function(RawSocketEvent event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) => _events.stream.listen(
    onData,
    onError: onError,
    onDone: onDone,
    cancelOnError: cancelOnError,
  );

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

Uint8List _response(Uint8List query, {List<int>? address, int rcode = 0}) {
  final bytes = query.toList();
  bytes[2] = 0x81;
  bytes[3] = 0x80 | rcode;
  bytes[6] = 0;
  bytes[7] = address == null ? 0 : 1;
  if (address != null) {
    bytes.addAll([
      0xc0,
      0x0c,
      query[query.length - 4],
      query[query.length - 3],
      0,
      1,
      0,
      0,
      0,
      60,
      0,
      address.length,
      ...address,
    ]);
  }
  return Uint8List.fromList(bytes);
}

Future<(Map<String, Object>, List<_Socket>)> _firstReply(
  Uint8List Function(Uint8List) first,
) async {
  final sockets = <_Socket>[];
  final output = await runAcceptanceDnsProbe(
    socketFactory: () async {
      final socket = _Socket((socket, query, _, _) {
        socket.reply(sockets.length == 1 ? first(query) : _response(query));
      });
      sockets.add(socket);
      return socket;
    },
    requestId: () => 0x1234,
  );
  return (
    ((output['results']! as List).first as Map).cast<String, Object>(),
    sockets,
  );
}

List<int> _name(String name) => [
  for (final label in name.split('.')) ...[label.length, ...label.codeUnits],
  0,
];

List<int> _record(String owner, int type, List<int> data) => [
  ..._name(owner),
  0,
  type,
  0,
  1,
  0,
  0,
  0,
  60,
  data.length >> 8,
  data.length & 255,
  ...data,
];

Uint8List _records(Uint8List query, List<List<int>> records) {
  final bytes = _response(query).toList();
  bytes[7] = records.length;
  bytes.addAll(records.expand((record) => record));
  return Uint8List.fromList(bytes);
}
