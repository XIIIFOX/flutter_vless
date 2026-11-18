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

    test('typed Freedom and GeoDAT configurations on Core $version', () async {
      final base = XrayProfile.build((draft) {
        final node = draft.addNode(ProxyNode.fromMap({'protocol': 'freedom'}));
        draft.setFreedomFinalRules(node, [
          XrayFreedomFinalRule.allow(
            destinationCidrs: [XrayCidr.parse('192.0.2.0/24')],
            destinationPorts: [XrayPortRange.single(443)],
            networks: {XrayRouteNetwork.tcp},
          ),
          XrayFreedomFinalRule.block(),
        ]);
        draft.setGeoDataSchedule(
            XrayGeoDataSchedule.every(const Duration(hours: 12), assets: []));
      });
      final withImmediateBlock = base.edit((draft) {
        draft.setFreedomFinalRules(draft.nodeAt(0), [
          XrayFreedomFinalRule.block(
            delay: XrayFreedomBlockDelay.fixed(Duration.zero),
            logLevel: XrayFreedomLogLevel.none,
          ),
        ]);
      });
      final temp =
          await Directory.systemTemp.createTemp('xray-typed-services-');
      try {
        final config = File('${temp.path}/profile.json');
        Future<ProcessResult> check(XrayProfile profile) async {
          await config.writeAsString(profile.toCoreJson());
          return Process.run(
              executable!, ['run', '-test', '-config', config.path]);
        }

        final compatible = await check(base);
        expect(compatible.exitCode, 0, reason: '${compatible.stdout}');
        final guarded = await check(withImmediateBlock);
        if (version == '26.11.9') {
          expect(guarded.exitCode, 0, reason: '${guarded.stdout}');
        } else {
          expect(guarded.exitCode, isNot(0));
          expect('${guarded.stdout}${guarded.stderr}',
              contains('26.11.9 or higher'));
        }
      } finally {
        await temp.delete(recursive: true);
      }
    },
        skip: executable == null
            ? 'Set $variable to run Core version tests'
            : false);

    test('typed split DNS and combined route conditions work on Core $version',
        () async {
      const splitHost = 'corp.split-fixture.invalid';
      const refusedHost = 'refused.$splitHost';
      const defaultHost = 'public.split-fixture.invalid';
      final primaryDns = await _LoopDns.start();
      final splitDns = await _LoopDns.start(refuse: refusedHost);
      addTearDown(primaryDns.close);
      addTearDown(splitDns.close);

      final ipv4 = await _Peer.start('split-ipv4', Duration.zero);
      final ipv6 = await _Peer.start('default-ipv6', Duration.zero);
      final fallback = await _Peer.start('route-fallback', Duration.zero);
      addTearDown(ipv4.close);
      addTearDown(ipv6.close);
      addTearDown(fallback.close);
      final port = await _unusedPort();
      final profile = XrayProfile.build((draft) {
        const primaryTag = 'default-dns';
        const splitTag = 'corp-dns';
        final ipv4Target = RouteTarget.node(draft.addNode(ipv4.outbound()));
        final ipv6Target = RouteTarget.node(draft.addNode(ipv6.outbound()));
        final fallbackTarget =
            RouteTarget.node(draft.addNode(fallback.outbound()));
        draft.setDnsOptions(const XrayDnsOptions(disableFallbackIfMatch: true));
        draft.addDnsServer(XrayDnsServer.udp(
          '127.0.0.1',
          port: primaryDns.port,
          tag: primaryTag,
          queryStrategy: XrayDnsQueryStrategy.useIpv6,
        ));
        draft.addDnsServer(XrayDnsServer.udp(
          '127.0.0.1',
          port: splitDns.port,
          tag: splitTag,
          domains: ['domain:$splitHost'],
          queryStrategy: XrayDnsQueryStrategy.useIpv4,
          skipFallback: true,
        ));
        draft.addDnsServer(XrayDnsServer.doh(
          Uri.parse('https://127.0.0.1:1/dns-query'),
          domains: ['full:unused.split-fixture.invalid'],
          skipFallback: true,
          finalQuery: true,
        ));
        draft.setRoutingDomainStrategy(XrayRoutingDomainStrategy.ipOnDemand);
        draft.addRule(RouteRule.match(
          to: const RouteTarget.direct(),
          inboundTags: [primaryTag, splitTag],
          networks: {XrayRouteNetwork.udp},
        ));
        draft.addRule(RouteRule.match(
          to: ipv4Target,
          destinationCidrs: [XrayCidr.parse('127.0.0.0/8')],
          destinationPorts: [XrayPortRange.range(18001, 18002)],
          networks: {XrayRouteNetwork.tcp},
        ));
        draft.addRule(RouteRule.match(
          to: ipv6Target,
          destinationCidrs: [XrayCidr.parse('::1/128')],
          destinationPorts: [XrayPortRange.single(18001)],
          networks: {XrayRouteNetwork.tcp},
        ));
        draft.setDefaultRoute(fallbackTarget);
        draft.setRaw(CorePath.root.key('inbounds'), [
          {'listen': '127.0.0.1', 'port': port, 'protocol': 'http'},
        ]);
      });
      Uri url(String host, [int destinationPort = 18001]) => Uri(
          scheme: 'http', host: host, port: destinationPort, path: '/traffic');
      await _withCore(executable!, port, profile, (client) async {
        expect(await _query(client, url(splitHost)), ipv4.label);
        expect(await _query(client, url(splitHost, 18002)), ipv4.label);
        expect(await _query(client, url(splitHost, 18003)), fallback.label);
        expect(await _query(client, url(defaultHost)), ipv6.label);
        expect(await _query(client, url(refusedHost)), fallback.label);

        expect(splitDns.questions[splitHost], {1});
        expect(splitDns.questions[refusedHost], {1});
        expect(splitDns.questions, isNot(contains(defaultHost)));
        expect(primaryDns.questions[defaultHost], {28});
        expect(primaryDns.questions, isNot(contains(splitHost)));
        expect(primaryDns.questions, isNot(contains(refusedHost)));
      });
    },
        skip: executable == null
            ? 'Set $variable to run loopback DNS and routing tests'
            : false);

    if (version == '26.11.9') {
      test('34-node round-robin routes on Core $version', () async {
        final peers = <_Peer>[];
        for (var index = 0; index < 34; index++) {
          final peer = await _Peer.start('node-$index', Duration.zero,
              address: index.isEven
                  ? InternetAddress.loopbackIPv4
                  : InternetAddress.loopbackIPv6);
          peers.add(peer);
          addTearDown(peer.close);
        }
        final direct = await _Peer.start('direct', Duration.zero);
        addTearDown(direct.close);
        final first = Uri.http('first.example.invalid', '/traffic');
        final second = Uri.http('second.example.invalid', '/traffic');
        final labels = peers.map((peer) => peer.label).toSet();

        for (final bypass in <Uri?>[null, first, second]) {
          final port = await _unusedPort();
          final profile = XrayProfile.build((draft) {
            final group = draft.addGroup(
              nodes:
                  peers.map((peer) => draft.addNode(peer.outbound())).toList(),
              strategy: const BalanceStrategy.roundRobin(),
            );
            if (bypass != null) {
              final directNode = draft.addNode(direct.outbound());
              draft.addRule(RouteRule.domains(
                ['full:${bypass.host}'],
                to: RouteTarget.node(directNode),
              ));
            }
            draft.setDefaultRoute(RouteTarget.group(group));
            draft.setRaw(CorePath.root.key('inbounds'), [
              {'listen': '127.0.0.1', 'port': port, 'protocol': 'http'},
            ]);
          });
          await _withCore(executable!, port, profile, (client) async {
            if (bypass == null) {
              final exits = <String?>{
                for (var index = 0; index < peers.length; index++)
                  await _query(client, index.isEven ? first : second),
              };
              expect(exits, labels);
            } else {
              final grouped = bypass == first ? second : first;
              for (var index = 0; index < 3; index++) {
                expect(await _query(client, bypass), direct.label);
                expect(await _query(client, grouped), isIn(labels));
              }
            }
          });
        }
      },
          skip: executable == null
              ? 'Set $variable to run the 34-node traffic test'
              : false);
    }
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

final class _LoopDns {
  _LoopDns(this._socket, this._refuse);

  static Future<_LoopDns> start({String? refuse}) async {
    final socket =
        await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
    final resolver = _LoopDns(socket, refuse);
    resolver._subscription = socket.listen((event) {
      if (event == RawSocketEvent.read) {
        final packet = socket.receive();
        if (packet != null) resolver._reply(packet);
      }
    });
    return resolver;
  }

  final RawDatagramSocket _socket;
  final String? _refuse;
  late final StreamSubscription<RawSocketEvent> _subscription;
  final questions = <String, Set<int>>{};

  int get port => _socket.port;

  void _reply(Datagram packet) {
    final data = packet.data;
    if (data.length < 17 || data[4] != 0 || data[5] != 1) return;
    var index = 12;
    final labels = <String>[];
    while (index < data.length && data[index] != 0) {
      final length = data[index++];
      if (length > 63 || index + length >= data.length) return;
      labels.add(String.fromCharCodes(data, index, index + length));
      index += length;
    }
    if (index + 5 > data.length) return;
    final host = labels.join('.');
    final type = (data[index + 1] << 8) | data[index + 2];
    questions.putIfAbsent(host, () => {}).add(type);
    final answer = switch (type) {
      1 => InternetAddress.loopbackIPv4.rawAddress,
      28 => InternetAddress.loopbackIPv6.rawAddress,
      _ => const <int>[],
    };
    final refused = host == _refuse;
    final hasAnswer = !refused && answer.isNotEmpty;
    _socket.send([
      data[0],
      data[1],
      0x81,
      refused ? 0x85 : 0x80,
      0,
      1,
      0,
      hasAnswer ? 1 : 0,
      0,
      0,
      0,
      0,
      ...data.sublist(12, index + 5),
      if (hasAnswer) ...[
        0xc0,
        0x0c,
        0,
        type,
        0,
        1,
        0,
        0,
        0,
        10,
        0,
        answer.length,
        ...answer,
      ],
    ], packet.address, packet.port);
  }

  Future<void> close() async {
    _socket.close();
    await _subscription.cancel();
  }
}

final class _Peer {
  _Peer(this.server, this.label, this.latency);

  static Future<_Peer> start(String label, Duration latency,
      {InternetAddress? address}) async {
    final server =
        await HttpServer.bind(address ?? InternetAddress.loopbackIPv4, 0);
    final peer = _Peer(server, label, latency);
    server.listen(peer.respond);
    return peer;
  }

  final HttpServer server;
  final String label;
  final Duration latency;
  bool healthy = false;
  int get port => server.port;

  ProxyNode outbound() {
    final redirect = Uri(host: server.address.address, port: port).authority;
    return ProxyNode.fromMap({
      'protocol': 'freedom',
      'settings': {'redirect': redirect},
    });
  }

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
