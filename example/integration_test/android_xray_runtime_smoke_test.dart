import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Android Xray runtime reports v26.7.11', (tester) async {
    if (!Platform.isAndroid) {
      return;
    }

    final vless = FlutterVless(onStatusChanged: (_) {});
    await vless.initializeVless();

    final version = await vless.getCoreVersion();
    // ignore: avoid_print
    print('ANDROID_XRAY_CORE_VERSION=$version');

    expect(version, contains('26.7.11'));
    expect(version.toLowerCase(), isNot(contains('not found')));
    expect(version.toLowerCase(), isNot(startsWith('error:')));
  });

  testWidgets('Android Xray starts with packaged geo assets', (tester) async {
    if (!Platform.isAndroid) {
      return;
    }

    final connected = Completer<void>();
    final vless = FlutterVless(
      onStatusChanged: (status) {
        if (status.connectionState == VlessConnectionState.connected &&
            !connected.isCompleted) {
          connected.complete();
        }
      },
    );
    await vless.initializeVless();

    final config = jsonEncode({
      'log': {'loglevel': 'warning'},
      'routing': {
        'domainStrategy': 'IPIfNonMatch',
        'rules': [
          {
            'type': 'field',
            'domain': ['geosite:category-ads-all'],
            'outboundTag': 'blocked',
          },
          {
            'type': 'field',
            'ip': ['geoip:private'],
            'outboundTag': 'direct',
          },
        ],
      },
      'outbounds': [
        {
          'protocol': 'freedom',
          'tag': 'direct',
          'settings': {},
        },
        {
          'protocol': 'blackhole',
          'tag': 'blocked',
          'settings': {},
        },
      ],
    });

    try {
      await vless.startVless(
        remark: 'Android geo asset smoke',
        config: config,
        proxyOnly: true,
      );

      await connected.future.timeout(const Duration(seconds: 8));
    } finally {
      await vless.stopVless();
    }
  });
}
