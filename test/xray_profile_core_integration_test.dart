import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';

void main() {
  // Supply trusted, unpacked Core executables explicitly for real-wire tests.
  for (final (version, variable) in [
    ('26.10.31', 'XRAY_PROFILE_TEST_OLD_CORE'),
    ('26.11.9', 'XRAY_PROFILE_TEST_NEW_CORE'),
  ]) {
    final executable = Platform.environment[variable];
    test('explicit new Freedom field has a Core version guard on $version',
        () async {
      final port = await _unusedPort();
      final target = await _Peer.start('unblocked', Duration.zero);
      addTearDown(target.close);
      final original = XrayProfile.fromJson('''
        {
          "inbounds": [{"listen": "127.0.0.1", "protocol": "http", "port": $port}],
          "outbounds": [{
            "protocol": "freedom",
            "settings": {"finalRules": [{"action": "block", "blockDelay": 5}]}
          }]
        }
      ''');
      final rule = CorePath.root
          .key('outbounds')
          .index(0)
          .key('settings')
          .key('finalRules')
          .index(0);
      final updated = original.edit((draft) {
        draft.removeRaw(rule.key('blockDelay'));
        draft.setRaw(rule.key('delay'), 0);
        draft.setRaw(rule.key('logLevel'), 'warning');
      });
      final guarded =
          updated.edit((draft) => draft.requireCoreAtLeast('26.11.9'));
      final temp = await Directory.systemTemp.createTemp('xray-version-test-');
      try {
        final config = File('${temp.path}/config.json');
        await config.writeAsString(updated.toCoreJson());
        final unguarded = await Process.run(
            executable!, ['run', '-test', '-config', config.path]);
        expect(unguarded.exitCode, 0, reason: '${unguarded.stdout}');
        await config.writeAsString(guarded.toCoreJson());
        final tested = await Process.run(
            executable, ['run', '-test', '-config', config.path]);
        if (version == '26.11.9') {
          expect(tested.exitCode, 0, reason: '${tested.stdout}');
        } else {
          expect(tested.exitCode, isNot(0));
          expect('${tested.stdout}${tested.stderr}',
              contains('26.11.9 or higher'));
        }
      } finally {
        await temp.delete(recursive: true);
      }
      await _withCore(executable, port, updated, (client) async {
        final request = _query(
            client, Uri.parse('http://127.0.0.1:${target.port}/traffic'));
        if (version == '26.11.9') {
          expect(await request, isNull, reason: 'delay: 0 closes the flow');
        } else {
          await expectLater(request, throwsA(isA<TimeoutException>()));
        }
      });
    },
        skip: executable == null
            ? 'Set $variable to run Core version tests'
            : false);

    test('generated routes and probes work on Core $version', () async {
      final cli = executable!;
      final release = await Process.run(cli, ['version']);
      expect(release.stdout, startsWith('Xray $version '));
      final fast = await _Peer.start('fast', const Duration(milliseconds: 15));
      final slow = await _Peer.start('slow', const Duration(milliseconds: 180));
      final direct = await _Peer.start('direct', Duration.zero);
      addTearDown(fast.close);
      addTearDown(slow.close);
      addTearDown(direct.close);

      final port = await _unusedPort();
      final probeUrl = Uri.parse('http://127.0.0.1:9/probe');
      final httpProbe = HealthProbe.http(
        probeUrl,
        interval: const Duration(milliseconds: 220),
        enableConcurrency: true,
      );
      final burstProbe = HealthProbe.burst(probeUrl, sampling: 1);
      for (final (strategy, probe) in [
        (const BalanceStrategy.leastPing(), httpProbe),
        (const BalanceStrategy.roundRobin(), null),
        (
          BalanceStrategy.leastLoad(
            expected: 1,
            maxRtt: const Duration(milliseconds: 100),
          ),
          burstProbe
        ),
      ]) {
        final burst = identical(probe, burstProbe);
        fast.healthy = burst;
        slow.healthy = burst;
        final profile = XrayProfile.build((draft) {
          final first = draft.addNode(fast.outbound());
          final second = draft.addNode(slow.outbound());
          final group = draft.addGroup(
            nodes: [first, second],
            strategy: strategy,
            fallback: probe == null ? null : const GroupFallback.block(),
          );
          if (probe != null) draft.setHealthProbe(probe);
          draft.addRule(RouteRule.domains(
            ['full:localhost'],
            to: const RouteTarget.direct(),
          ));
          draft.setDefaultRoute(RouteTarget.group(group));
          draft.setRaw(CorePath.root.key('inbounds'), [
            {'listen': '127.0.0.1', 'port': port, 'protocol': 'http'},
          ]);
        });
        await _withCore(cli, port, profile, (client) async {
          final grouped = Uri.parse('http://group.invalid/traffic');
          final directUri =
              Uri.parse('http://localhost:${direct.port}/traffic');
          expect(await _query(client, directUri), 'direct');
          if (burst) {
            await _until(client, grouped, 'fast');
            return;
          }
          if (probe == null) {
            expect({
              await _query(client, grouped),
              await _query(client, grouped),
            }, {
              'fast',
              'slow'
            });
            return;
          }
          expect(await _query(client, grouped), isNull);
          fast.healthy = true;
          slow.healthy = true;
          await _until(client, grouped, 'fast');
          fast.healthy = false;
          await _until(client, grouped, 'slow');
          slow.healthy = false;
          await _until(client, grouped, null);
          expect(await _query(client, directUri), 'direct');
          fast.healthy = true;
          await _until(client, grouped, 'fast');
        });
      }
    },
        skip: executable == null
            ? 'Set $variable to run Core traffic tests'
            : false);
  }
}

Future<int> _unusedPort() async {
  final socket = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = socket.port;
  await socket.close();
  return port;
}

Future<void> _withCore(String binary, int port, XrayProfile profile,
    Future<void> Function(HttpClient client) test) async {
  final temp = await Directory.systemTemp.createTemp('xray-profile-test-');
  final config = await File('${temp.path}/config.json')
      .writeAsString(profile.toCoreJson());
  final process = await Process.start(binary, ['run', '-config', config.path]);
  final stdout = process.stdout.drain<void>();
  final stderr = process.stderr.drain<void>();
  final client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 1)
    ..findProxy = (_) => 'PROXY 127.0.0.1:$port';
  try {
    final deadline = DateTime.now().add(const Duration(seconds: 5));
    while (true) {
      try {
        final socket = await Socket.connect(InternetAddress.loopbackIPv4, port);
        socket.destroy();
        break;
      } on SocketException {
        if (DateTime.now().isAfter(deadline)) rethrow;
        await Future<void>.delayed(const Duration(milliseconds: 25));
      }
    }
    await test(client);
  } finally {
    client.close(force: true);
    process.kill();
    try {
      await process.exitCode.timeout(const Duration(seconds: 3));
    } on TimeoutException {
      process.kill(ProcessSignal.sigkill);
      await process.exitCode;
    }
    await Future.wait([stdout, stderr]);
    await temp.delete(recursive: true);
  }
}

Future<String?> _query(HttpClient client, Uri uri) async {
  try {
    final request = await client.getUrl(uri);
    request.persistentConnection = false;
    final response = await request.close().timeout(const Duration(seconds: 2));
    final bytes = await response.expand((bytes) => bytes).toList();
    return response.statusCode == 200 ? String.fromCharCodes(bytes) : null;
  } on HttpException {
    return null;
  } on SocketException {
    return null;
  }
}

Future<void> _until(HttpClient client, Uri uri, String? expected) async {
  final deadline = DateTime.now().add(const Duration(seconds: 5));
  while (true) {
    final actual = await _query(client, uri);
    if (actual == expected) return;
    expect(actual, isNot('direct'));
    if (DateTime.now().isAfter(deadline)) {
      expect(actual, expected);
    }
    await Future<void>.delayed(const Duration(milliseconds: 70));
  }
}

final class _Peer {
  _Peer(this.server, this.label, this.latency);

  static Future<_Peer> start(String label, Duration latency) async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final peer = _Peer(server, label, latency);
    server.listen(peer.respond);
    return peer;
  }

  final HttpServer server;
  final String label;
  final Duration latency;
  bool healthy = false;
  int get port => server.port;

  ProxyNode outbound() => ProxyNode.fromMap({
        'protocol': 'freedom',
        'settings': {'redirect': '127.0.0.1:$port'},
      });

  Future<void> respond(HttpRequest request) async {
    if (request.uri.path == '/probe') {
      if (!healthy) {
        (await request.response.detachSocket(writeHeaders: false)).destroy();
        return;
      }
      await Future<void>.delayed(latency);
      request.response.statusCode = HttpStatus.noContent;
    } else {
      request.response.write(label);
    }
    await request.response.close();
  }

  Future<void> close() => server.close(force: true);
}
