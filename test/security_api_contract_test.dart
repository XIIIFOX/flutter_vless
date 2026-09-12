import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/url/xray_config_model.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('flutter_vless');
  const events = MethodChannel('flutter_vless/status');
  const config = '{"outbounds":[{"protocol":"freedom"}]}';
  late List<MethodCall> calls;
  Map<String, bool>? capabilities;

  setUp(() {
    calls = [];
    capabilities = {'iosKeychainReference': true, 'androidProxyDns': true};
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return call.method == 'getSecurityCapabilities' ? capabilities : null;
    });
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(events, (_) async => null);
  });
  tearDown(() {
    for (final c in [channel, events]) {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(c, null);
    }
  });

  test('shared Keychain group crosses the complete public API', () async {
    await FlutterVless(onStatusChanged: (_) {}).initializeVless(
      keychainAccessGroup: 'TEAM.dev.example.tunnel',
    );
    expect(calls.map((c) => c.method),
        ['getSecurityCapabilities', 'initializeVless']);
    expect(
        calls.last.arguments['keychainAccessGroup'], 'TEAM.dev.example.tunnel');
  });

  test('proxy DNS opt-in and selected outbound reach native unchanged',
      () async {
    await FlutterVless(onStatusChanged: (_) {}).startVless(
      remark: 'DNS',
      config: config,
      androidDnsPolicy: AndroidDnsPolicy.proxy,
      androidDnsProxyOutboundTag: 'chosen-proxy',
    );
    expect(calls.last.arguments['android_dns_policy'], 'proxy');
    expect(
        calls.last.arguments['android_dns_proxy_outbound_tag'], 'chosen-proxy');
  });

  test('unsupported guarantees fail before native startup or initialization',
      () async {
    capabilities = null;
    final api = FlutterVless(onStatusChanged: (_) {});
    await expectLater(
        api.startVless(
            remark: 'DNS',
            config: config,
            androidDnsPolicy: AndroidDnsPolicy.proxy),
        throwsUnsupportedError);
    await expectLater(api.initializeVless(keychainAccessGroup: 'TEAM.group'),
        throwsUnsupportedError);
    expect(calls.every((c) => c.method == 'getSecurityCapabilities'), isTrue);
  });

  test('legacy defaults do not request unsupported native capabilities',
      () async {
    capabilities = null;
    await FlutterVless(onStatusChanged: (_) {})
        .startVless(remark: 'old', config: config);
    expect(calls.single.method, 'startVless');
    expect(calls.single.arguments.containsKey('android_dns_policy'), isFalse);
  });

  test('invalid DNS mode combinations fail without native mutation', () async {
    final api = FlutterVless(onStatusChanged: (_) {});
    await expectLater(
        api.startVless(
            remark: 'bad', config: config, androidDnsProxyOutboundTag: 'proxy'),
        throwsArgumentError);
    await expectLater(
        api.startVless(
            remark: 'bad',
            config: config,
            proxyOnly: true,
            androidDnsPolicy: AndroidDnsPolicy.proxy),
        throwsArgumentError);
    expect(calls, isEmpty);
  });

  test('explicit SOCKS credentials serialize without affecting remote users',
      () {
    final inbound =
        XrayInbound.localSocksTunnel(username: 'local', password: 'secret');
    expect(inbound.settings['auth'], 'password');
    expect(inbound.settings['accounts'], [
      {'user': 'local', 'pass': 'secret'}
    ]);
    expect(() => XrayInbound.localSocksTunnel(username: 'local'),
        throwsArgumentError);
    expect(
        () => XrayInbound.localSocksTunnel(username: 'local', password: '\n'),
        throwsArgumentError);
    final parsed = FlutterVless.parseFromURL(
        'socks://remote:remote-password@127.0.0.1:1080#test');
    final first = parsed.getFullConfiguration();
    expect(parsed.getFullConfiguration(), first);
    expect(jsonDecode(first)['inbounds'][0]['settings']['auth'], 'noauth');
    expect(first, contains('remote-password'));
    expect(first, isNot(contains('"pass": "secret"')));
  });
}
