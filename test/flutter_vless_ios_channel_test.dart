import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless_ios.dart';

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

  test('P0 startVless forwards packet-tunnel arguments unchanged', () async {
    const config = '{"outbounds":[]}';
    final plugin = FlutterVlessIOS();

    await plugin.startVless(
      remark: 'XHTTP none',
      config: config,
      blockedApps: ['com.example.blocked'],
      bypassSubnets: ['10.0.0.0/8'],
      proxyOnly: true,
      notificationDisconnectButtonName: 'STOP',
    );

    expect(calls, hasLength(1));
    expect(calls.single.method, 'startVless');
    expect(calls.single.arguments, {
      'remark': 'XHTTP none',
      'config': config,
      'blocked_apps': ['com.example.blocked'],
      'bypass_subnets': ['10.0.0.0/8'],
      'proxy_only': true,
      'notificationDisconnectButtonName': 'STOP',
    });
  });

  test('P0 startVless forwards an iOS geo asset directory', () async {
    const config = '{"outbounds":[]}';
    final plugin = FlutterVlessIOS();

    await plugin.startVless(
      remark: 'Geo routing',
      config: config,
      notificationDisconnectButtonName: 'STOP',
      geoAssetsDirectory:
          '/private/var/mobile/Containers/Shared/AppGroup/example/geodata',
    );

    expect(calls.single.arguments, {
      'remark': 'Geo routing',
      'config': config,
      'blocked_apps': null,
      'bypass_subnets': null,
      'proxy_only': false,
      'notificationDisconnectButtonName': 'STOP',
      'geo_assets_directory':
          '/private/var/mobile/Containers/Shared/AppGroup/example/geodata',
    });
  });

  test('P0 initializeVless sends iOS provider and app group identifiers',
      () async {
    final plugin = FlutterVlessIOS();

    await plugin.initializeVless(
      onStatusChanged: (_) {},
      notificationIconResourceType: 'mipmap',
      notificationIconResourceName: 'ic_launcher',
      providerBundleIdentifier: 'dev.tfox.flutterXrayExample',
      groupIdentifier: 'group.dev.tfox.flutterXray',
    );

    expect(calls, hasLength(1));
    expect(calls.single.method, 'initializeVless');
    expect(calls.single.arguments, {
      'notificationIconResourceType': 'mipmap',
      'notificationIconResourceName': 'ic_launcher',
      'providerBundleIdentifier': 'dev.tfox.flutterXrayExample',
      'groupIdentifier': 'group.dev.tfox.flutterXray',
    });
  });

  test('P1 delay and permission methods use the shared flutter_vless channel',
      () async {
    installHandlers(respond: (call) {
      switch (call.method) {
        case 'requestPermission':
          return true;
        case 'getServerDelay':
          return 123;
        case 'getConnectedServerDelay':
          return 45;
        case 'getCoreVersion':
          return 'Xray 26.7.28';
      }
      return null;
    });
    final plugin = FlutterVlessIOS();

    expect(await plugin.requestPermission(), isTrue);
    expect(
      await plugin.getServerDelay(
        config: '{"outbounds":[]}',
        url: 'https://example.com/generate_204',
      ),
      123,
    );
    expect(
      await plugin.getConnectedServerDelay('https://example.com/generate_204'),
      45,
    );
    expect(await plugin.getCoreVersion(), 'Xray 26.7.28');

    expect(calls.map((call) => call.method), [
      'requestPermission',
      'getServerDelay',
      'getConnectedServerDelay',
      'getCoreVersion',
    ]);
    expect(calls[1].arguments, {
      'config': '{"outbounds":[]}',
      'url': 'https://example.com/generate_204',
    });
    expect(calls[2].arguments, {'url': 'https://example.com/generate_204'});
  });

  test('P1 getServerDelay forwards an iOS geo asset directory', () async {
    installHandlers(respond: (call) => 123);
    final plugin = FlutterVlessIOS();

    await plugin.getServerDelay(
      config: '{"outbounds":[]}',
      url: 'https://example.com/generate_204',
      geoAssetsDirectory: '/private/app-group/geodata',
    );

    expect(calls.single.arguments, {
      'config': '{"outbounds":[]}',
      'url': 'https://example.com/generate_204',
      'geo_assets_directory': '/private/app-group/geodata',
    });
  });
}
