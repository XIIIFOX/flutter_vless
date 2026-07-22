import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless_android/flutter_vless_android.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('flutter_vless');
  const statusChannel = MethodChannel('flutter_vless/status');
  late List<MethodCall> calls;

  void installHandlers({Object? Function(MethodCall call)? respond}) {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return respond?.call(call);
    });
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(statusChannel, (_) async => null);
  }

  setUp(() {
    calls = [];
    installHandlers();
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(statusChannel, null);
  });

  test('P0 startVless forwards Android VPN/tun2socks arguments unchanged',
      () async {
    const config = '{"outbounds":[]}';
    final plugin = FlutterVlessAndroid();

    await plugin.startVless(
      remark: 'Android XHTTP none',
      config: config,
      blockedApps: ['com.browser.blocked'],
      bypassSubnets: ['192.168.0.0/16'],
      proxyOnly: false,
      notificationDisconnectButtonName: 'DISCONNECT',
    );

    expect(calls, hasLength(1));
    expect(calls.single.method, 'startVless');
    expect(calls.single.arguments, {
      'remark': 'Android XHTTP none',
      'config': config,
      'blocked_apps': ['com.browser.blocked'],
      'bypass_subnets': ['192.168.0.0/16'],
      'proxy_only': false,
      'notificationDisconnectButtonName': 'DISCONNECT',
    });
  });

  test('P0 startVless forwards Android proxy-only mode unchanged', () async {
    const config = '{"outbounds":[]}';
    final plugin = FlutterVlessAndroid();

    await plugin.startVless(
      remark: 'Android proxy only',
      config: config,
      proxyOnly: true,
      notificationDisconnectButtonName: 'DISCONNECT',
    );

    expect(calls, hasLength(1));
    expect(calls.single.method, 'startVless');
    expect(calls.single.arguments, containsPair('proxy_only', true));
    expect(calls.single.arguments, containsPair('config', config));
  });

  test('P0 initializeVless forwards notification icon settings', () async {
    final plugin = FlutterVlessAndroid();

    await plugin.initializeVless(
      onStatusChanged: (_) {},
      notificationIconResourceType: 'drawable',
      notificationIconResourceName: 'ic_vpn',
      providerBundleIdentifier: '',
      groupIdentifier: '',
    );

    expect(calls, hasLength(1));
    expect(calls.single.method, 'initializeVless');
    expect(calls.single.arguments, {
      'notificationIconResourceType': 'drawable',
      'notificationIconResourceName': 'ic_vpn',
      'providerBundleIdentifier': '',
      'groupIdentifier': '',
    });
  });

  test('P1 delay, permission, stop, and version calls use flutter_vless',
      () async {
    installHandlers(respond: (call) {
      switch (call.method) {
        case 'requestPermission':
          return null;
        case 'getServerDelay':
          return 91;
        case 'getConnectedServerDelay':
          return 42;
        case 'getCoreVersion':
          return 'Xray 26.7.11';
      }
      return null;
    });
    final plugin = FlutterVlessAndroid();

    expect(await plugin.requestPermission(), isFalse);
    expect(
      await plugin.getServerDelay(
        config: '{"outbounds":[]}',
        url: 'https://example.com/generate_204',
      ),
      91,
    );
    expect(
      await plugin.getConnectedServerDelay('https://example.com/generate_204'),
      42,
    );
    expect(await plugin.getCoreVersion(), 'Xray 26.7.11');
    await plugin.stopVless();

    expect(calls.map((call) => call.method), [
      'requestPermission',
      'getServerDelay',
      'getConnectedServerDelay',
      'getCoreVersion',
      'stopVless',
    ]);
    expect(calls[1].arguments, {
      'config': '{"outbounds":[]}',
      'url': 'https://example.com/generate_204',
    });
    expect(calls[2].arguments, {'url': 'https://example.com/generate_204'});
  });
}
