import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('flutter_vless');
  const config =
      '{"inbounds":[{"tag":"caller","protocol":"socks","port":10808}],'
      '"outbounds":[{"tag":"blocked","protocol":"blackhole"},'
      '{"tag":"chosen-proxy","protocol":"freedom"}]}';
  late List<MethodCall> calls;
  Map<String, bool>? capabilities;

  setUp(() {
    calls = [];
    capabilities = {'vpnRouting': true};
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return call.method == 'getSecurityCapabilities' ? capabilities : null;
    });
  });
  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('per-session source zero and non-first default cross the public API',
      () async {
    await FlutterVless(onStatusChanged: (_) {}).startVless(
      remark: 'Routing',
      config: config,
      vpnRouting: const VpnRoutingOptions(
          sourceInboundIndex: 0, defaultOutboundTag: 'chosen-proxy'),
    );
    expect(
        calls.map((c) => c.method), ['getSecurityCapabilities', 'startVless']);
    expect(calls.last.arguments['vpn_routing'],
        {'sourceInboundIndex': 0, 'defaultOutboundTag': 'chosen-proxy'});
    expect(calls.last.arguments['config'], config);
  });

  test(
      'null routing keeps the ordinary wire contract without a capability call',
      () async {
    capabilities = null;
    await FlutterVless(onStatusChanged: (_) {})
        .startVless(remark: 'Ordinary', config: config);
    expect(calls.single.method, 'startVless');
    expect(calls.single.arguments.containsKey('vpn_routing'), isFalse);
  });

  test('an explicit empty option still requests the native routing factory',
      () async {
    await FlutterVless(onStatusChanged: (_) {}).startVless(
        remark: 'Default routing',
        config: config,
        vpnRouting: const VpnRoutingOptions());
    expect(
        calls.map((c) => c.method), ['getSecurityCapabilities', 'startVless']);
    expect(calls.last.arguments['vpn_routing'], isEmpty);
  });

  test('older backends cannot silently ignore a requested routing policy',
      () async {
    for (final support in [null, false]) {
      calls.clear();
      capabilities = support == null ? null : {'vpnRouting': support};
      await expectLater(
          FlutterVless(onStatusChanged: (_) {}).startVless(
              remark: 'Unsupported',
              config: config,
              vpnRouting: const VpnRoutingOptions(sourceInboundIndex: 0)),
          throwsUnsupportedError);
      expect(calls.map((c) => c.method), ['getSecurityCapabilities']);
    }
  });

  test('proxy-only routing requests fail before native calls', () async {
    await expectLater(
        FlutterVless(onStatusChanged: (_) {}).startVless(
            remark: 'Wrong mode',
            config: config,
            proxyOnly: true,
            vpnRouting: const VpnRoutingOptions()),
        throwsArgumentError);
    expect(calls, isEmpty);
  });

  test('invalid source indices fail before capability or start', () async {
    for (final index in [-1, 2147483648]) {
      await expectLater(
          FlutterVless(onStatusChanged: (_) {}).startVless(
              remark: 'Bad index',
              config: config,
              vpnRouting: VpnRoutingOptions(sourceInboundIndex: index)),
          throwsArgumentError);
    }
    expect(calls, isEmpty);
  });

  test('tag strings and independent option maps preserve exact values', () {
    const tag = ' e\u0301/\u212a\u0000 ';
    const routing = VpnRoutingOptions(defaultOutboundTag: tag);
    final first = routing.toMap();
    first['defaultOutboundTag'] = 'changed';
    expect(routing.toMap(), {'defaultOutboundTag': tag});
    expect(routing.toString(), 'VpnRoutingOptions(<private>)');
    expect(const VpnRoutingOptions().toMap(), isEmpty);
    expect(const VpnRoutingOptions(defaultOutboundTag: '').toMap(),
        {'defaultOutboundTag': ''});
  });

  test('invalid option serialization is refused independently of the facade',
      () {
    expect(() => const VpnRoutingOptions(sourceInboundIndex: -1).toMap(),
        throwsArgumentError);
  });

  test('caller JSON cannot turn on native routing policy', () async {
    capabilities = null;
    await FlutterVless(onStatusChanged: (_) {}).startVless(
        remark: 'Untrusted JSON',
        config: '{"nativeRoutingSpec":{"sourceInboundIndex":0},'
            '"outbounds":[{"protocol":"freedom"}]}');
    expect(calls.single.method, 'startVless');
    expect(calls.single.arguments.containsKey('vpn_routing'), isFalse);
  });
}
