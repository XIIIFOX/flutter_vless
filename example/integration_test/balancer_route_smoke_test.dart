import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless_example/balancer_example.dart';
import 'package:flutter_vless_example/routing_config.dart';
import 'package:integration_test/integration_test.dart';

const _fixturePath = String.fromEnvironment('BALANCER_SMOKE_INPUT_FILE');
const _case = String.fromEnvironment(
  'BALANCER_SMOKE_CASE',
  defaultValue: 'all',
);
const _expectedNodes = int.fromEnvironment('BALANCER_SMOKE_EXPECTED_NODES');
const _maxConnectMs = int.fromEnvironment('BALANCER_SMOKE_MAX_CONNECT_MS');
const _requireProxyIpv6 = bool.fromEnvironment(
  'BALANCER_SMOKE_REQUIRE_IPV6',
  defaultValue: true,
);
const _requireDirectIpv6 = bool.fromEnvironment(
  'BALANCER_SMOKE_REQUIRE_DIRECT_IPV6',
);

// Use the page's own IP endpoint. An HTML IP page can require JavaScript or
// respond with an anti-bot challenge instead of the address.
const _firstEcho = String.fromEnvironment(
  'BALANCER_SMOKE_FIRST_ECHO',
  defaultValue: 'https://tfox.dev/ip/api',
);
const _secondEcho = String.fromEnvironment(
  'BALANCER_SMOKE_SECOND_ECHO',
  defaultValue: 'https://api.ipify.org/',
);
const _ipv6Echo = String.fromEnvironment(
  'BALANCER_SMOKE_IPV6_ECHO',
  defaultValue: 'https://api6.ipify.org/',
);

enum _RouteCase { roundRobin, firstDirect, secondDirect }

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('fresh subscription startup, balance and domain routing', (
    _,
  ) async {
    expect(
      Platform.isIOS ||
          Platform.isMacOS ||
          Platform.isAndroid ||
          Platform.isWindows,
      isTrue,
      reason: 'Run this test on an actual supported VPN target.',
    );
    final input = await _readFixture();
    final echo = [_echoUri(_firstEcho), _echoUri(_secondEcho)];
    final ipv6 = _echoUri(_ipv6Echo);
    expect(
      {echo[0].host, echo[1].host, ipv6.host}.length,
      3,
      reason: 'Use distinct echo hosts so routing can distinguish them.',
    );
    final cases = _case == 'all'
        ? _RouteCase.values
        : [_RouteCase.values.byName(_case)];

    final monitor = _ConnectionMonitor();
    final plugin = FlutterVless(onStatusChanged: monitor.update);
    await _bounded(
      'VPN initialization',
      () => plugin.initializeVless(
        providerBundleIdentifier: 'dev.tfox.flutterXrayExample',
        groupIdentifier: 'group.dev.tfox.flutterXray',
      ),
      const Duration(seconds: 15),
    );
    final permission = await _bounded(
      'VPN permission',
      plugin.requestPermission,
      const Duration(seconds: 60),
    );
    expect(
      permission,
      isTrue,
      reason:
          'Authorize VPN on the dedicated target. Windows requires elevation.',
    );

    // Android broadcasts status changes but may not send an initial state.
    if (!Platform.isAndroid) {
      await _bounded(
        'Initial VPN status',
        () => monitor.initial.future,
        const Duration(seconds: 10),
      );
    }
    for (final route in cases) {
      expect(
        monitor.state == VlessConnectionState.disconnected ||
            (Platform.isAndroid && monitor.state == null),
        isTrue,
        reason: 'Use a dedicated target with the Example VPN disconnected.',
      );
      await _checkCase(plugin, monitor, input, route, echo, ipv6);
    }
  }, timeout: const Timeout(Duration(minutes: 8)));
}

Future<void> _checkCase(
  FlutterVless plugin,
  _ConnectionMonitor monitor,
  String input,
  _RouteCase route,
  List<Uri> echo,
  Uri ipv6,
) async {
  final baseline = await Future.wait(echo.map(_readAddress));
  expect(
    baseline.every((address) => address != null),
    isTrue,
    reason: 'Both HTTPS controls must report an IP with the VPN stopped.',
  );
  final ipv6Baseline = await _readAddress(
    ipv6,
    family: InternetAddressType.IPv6,
  );
  if (_requireDirectIpv6) {
    expect(
      ipv6Baseline != null,
      isTrue,
      reason: 'This run requires a working untunneled IPv6 baseline.',
    );
  }

  final imported = _importShareList(input);
  final nodes = _countNodes(imported);
  expect(
    nodes,
    greaterThanOrEqualTo(2),
    reason: 'The fixture needs two unique nodes.',
  );
  if (_expectedNodes > 0) expect(nodes, _expectedNodes);
  final directIndex = switch (route) {
    _RouteCase.roundRobin => null,
    _RouteCase.firstDirect => 0,
    _RouteCase.secondDirect => 1,
  };
  final directIpv6 = ipv6Baseline != null && route == _RouteCase.firstDirect;
  final config = routingConfig(
    config: imported,
    selectedSites: [
      if (directIndex != null) 'full:${echo[directIndex].host}',
      if (directIpv6) 'full:${ipv6.host}',
    ],
  );

  final startedAt = DateTime.now().toUtc();
  final watch = Stopwatch()..start();
  final firstStatus = monitor.begin();
  final receipt = <String, Object?>{
    'case': route.name,
    'nodes': nodes,
    'directIpv6Baseline': ipv6Baseline != null,
  };
  try {
    await _bounded(
      'First Connect',
      () => plugin.startVless(
        remark: 'Balancer integration test',
        config: config,
      ),
      const Duration(seconds: 35),
    );
    final state = await _bounded(
      'First Connect status',
      () => firstStatus,
      const Duration(seconds: 35),
    );
    watch.stop();
    receipt['connectMs'] = watch.elapsedMilliseconds;
    receipt['connectionState'] = state.wireName;
    receipt['endpointPlanMs'] = await _endpointPlanMs(plugin, startedAt);
    expect(state, VlessConnectionState.connected);
    if (_maxConnectMs > 0) {
      expect(watch.elapsedMilliseconds, lessThanOrEqualTo(_maxConnectMs));
    }

    final primaryExits = <String>{};
    for (var i = 0; i < echo.length; i++) {
      final direct = directIndex == i;
      // One client/connection per sample. A reused HTTPS connection does not
      // exercise another round-robin choice.
      final samples = route == _RouteCase.roundRobin && i == 0 ? 4 : 2;
      for (var sample = 0; sample < samples; sample++) {
        final address = await _readAddress(echo[i], family: baseline[i]!.type);
        expect(address != null, isTrue, reason: 'An HTTPS echo failed.');
        expect(
          _sameAddress(address!, baseline[i]!),
          direct,
          reason: 'Echo ${i + 1} did not use the configured route.',
        );
        if (i == 0) primaryExits.add(address.rawAddress.join(','));
      }
    }
    receipt['distinctFirstEchoExits'] = primaryExits.length;
    if (route == _RouteCase.roundRobin) {
      expect(
        primaryExits.length,
        greaterThan(1),
        reason: 'Provide nodes that expose at least two observable egress IPs.',
      );
    }

    final ipv6Address = await _readAddress(
      ipv6,
      family: InternetAddressType.IPv6,
    );
    receipt['ipv6Route'] = directIpv6 ? 'direct' : 'balancer';
    receipt['ipv6Echo'] = ipv6Address == null ? 'unavailable' : 'reachable';
    if (directIpv6 || _requireProxyIpv6) {
      expect(
        ipv6Address != null,
        isTrue,
        reason: 'The configured route did not reach the IPv6-only echo.',
      );
    }
    if (ipv6Address != null && ipv6Baseline != null) {
      expect(
        _sameAddress(ipv6Address, ipv6Baseline),
        directIpv6,
        reason: 'The IPv6 echo did not use the configured route.',
      );
    }
  } finally {
    try {
      await _bounded('VPN stop', plugin.stopVless, const Duration(seconds: 20));
      await _bounded(
        'VPN disconnected status',
        monitor.waitForDisconnect,
        const Duration(seconds: 15),
      );
      receipt['stop'] = 'disconnected';
    } finally {
      // Only counts, status and timings. Never log the subscription, receipt
      // addresses, or the native diagnostic snapshot.
      // ignore: avoid_print
      print('BALANCER_ROUTE_SMOKE ${jsonEncode(receipt)}');
    }
  }
}

String _importShareList(String input) {
  final links = const LineSplitter()
      .convert(input)
      .where((line) => line.trim().isNotEmpty);
  final shareLink = RegExp(r'^[a-zA-Z][a-zA-Z0-9+.-]*://');
  if (links.length < 2 ||
      links.any((line) => !shareLink.hasMatch(line.trim()))) {
    fail('Supply the decoded subscription body with one share link per line.');
  }
  try {
    return importBalancerProfile(input).config;
  } on Object {
    fail('The Example importer could not read the share-list fixture.');
  }
}

int _countNodes(String config) {
  final decoded = jsonDecode(config) as Map<String, dynamic>;
  final routing = decoded['routing'] as Map<String, dynamic>?;
  final balancers = routing?['balancers'] as List<dynamic>?;
  final group = balancers?.singleOrNull as Map<String, dynamic>?;
  final strategy = group?['strategy'] as Map<String, dynamic>?;
  expect(
    strategy?['type'],
    'roundRobin',
    reason: 'The Example must generate a roundRobin group.',
  );
  final selectors = (group?['selector'] as List<dynamic>? ?? const [])
      .whereType<String>()
      .toSet();
  return selectors.length;
}

class _ConnectionMonitor {
  VlessConnectionState? state;
  final initial = Completer<VlessConnectionState>();
  Completer<VlessConnectionState>? _attempt;
  bool _sawConnecting = false;

  Future<VlessConnectionState> begin() {
    _sawConnecting = false;
    final attempt = Completer<VlessConnectionState>();
    _attempt = attempt;
    return attempt.future;
  }

  void update(VlessStatus status) {
    final value = status.connectionState;
    state = value;
    if (!initial.isCompleted) initial.complete(value);
    final attempt = _attempt;
    if (attempt == null || attempt.isCompleted) return;
    if (value == VlessConnectionState.connecting) _sawConnecting = true;
    if (value == VlessConnectionState.connected ||
        (_sawConnecting && value == VlessConnectionState.disconnected)) {
      attempt.complete(value);
    }
  }

  Future<void> waitForDisconnect() async {
    final stopDeadline = Stopwatch()..start();
    while (state != VlessConnectionState.disconnected &&
        stopDeadline.elapsed < const Duration(seconds: 14)) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    expect(state, VlessConnectionState.disconnected);
  }
}

Future<String> _readFixture() async {
  const name = 'balancer-smoke.input';
  final path = _fixturePath.isNotEmpty
      ? _fixturePath
      : switch (Platform.operatingSystem) {
          'ios' ||
          'macos' => '${Directory.systemTemp.parent.path}/Documents/$name',
          'android' =>
            '/data/data/com.example.flutter_vless_example/files/$name',
          _ => '${Directory.current.path}${Platform.pathSeparator}$name',
        };
  final file = File(path);
  return _bounded('Read private fixture on the target', () async {
    expect(await file.length(), inInclusiveRange(1, 1024 * 1024));
    return file.readAsString();
  }, const Duration(seconds: 5));
}

Uri _echoUri(String value) {
  final uri = Uri.tryParse(value);
  if (uri == null ||
      uri.scheme != 'https' ||
      uri.host.isEmpty ||
      uri.userInfo.isNotEmpty ||
      uri.hasFragment) {
    fail('An IP echo must be an HTTPS URL without userinfo or a fragment.');
  }
  return uri;
}

Future<InternetAddress?> _readAddress(
  Uri uri, {
  InternetAddressType? family,
}) async {
  final client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 6)
    ..findProxy = (_) => 'DIRECT';
  try {
    return await (() async {
      final request = await client.getUrl(uri);
      request.followRedirects = false;
      request.persistentConnection = false;
      request.headers.set(HttpHeaders.cacheControlHeader, 'no-cache, no-store');
      final response = await request.close();
      if (response.statusCode != HttpStatus.ok) return null;
      final bytes = <int>[];
      await for (final chunk in response) {
        if (chunk.length > 8192 - bytes.length) return null;
        bytes.addAll(chunk);
      }
      final body = utf8.decode(bytes).trim();
      final Object? value = body.startsWith('{')
          ? (jsonDecode(body) as Map)['ip']
          : body;
      final address = value is String ? InternetAddress.tryParse(value) : null;
      return family == null || address?.type == family ? address : null;
    })().timeout(const Duration(seconds: 8));
  } on Exception {
    return null;
  } finally {
    client.close(force: true);
  }
}

bool _sameAddress(InternetAddress a, InternetAddress b) =>
    a.type == b.type && a.address == b.address;

Future<int?> _endpointPlanMs(FlutterVless plugin, DateTime startedAt) async {
  final cutoff = startedAt.millisecondsSinceEpoch ~/ 1000;
  final event = RegExp(
    r'^(\S+) Startup timing phase=endpoint-plan elapsedMs=(\d+) generation=\d+ current=true$',
  );
  try {
    final snapshot = await plugin.getProviderDebugSnapshot().timeout(
      const Duration(seconds: 4),
    );
    int? elapsed;
    for (final line in const LineSplitter().convert(snapshot)) {
      final match = event.firstMatch(line.trim());
      if (match == null) continue;
      final date = DateTime.tryParse(match[1]!);
      if (date != null && date.millisecondsSinceEpoch ~/ 1000 >= cutoff) {
        elapsed = int.tryParse(match[2]!);
      }
    }
    return elapsed;
  } on Exception {
    return null;
  }
}

Future<T> _bounded<T>(
  String stage,
  Future<T> Function() operation,
  Duration timeout,
) async {
  try {
    return await operation().timeout(timeout);
  } on TimeoutException {
    fail('$stage timed out.');
  } on Object {
    fail('$stage failed.');
  }
}
