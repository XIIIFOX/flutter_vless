import 'dart:io' show Platform;

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless/flutter_vless.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Embedded Xray core reports v26.7.11', (tester) async {
    if (!(Platform.isAndroid || Platform.isIOS || Platform.isMacOS)) {
      return;
    }

    final vless = FlutterVless(onStatusChanged: (_) {});
    await vless.initializeVless(
      notificationIconResourceType: 'mipmap',
      notificationIconResourceName: 'ic_launcher',
      providerBundleIdentifier: 'dev.tfox.flutterXrayExample',
      groupIdentifier: 'group.dev.tfox.flutterXray',
    );

    final version = await vless.getCoreVersion();
    // ignore: avoid_print
    print('XRAY_CORE_VERSION=$version');

    expect(version, contains('26.7.11'));
    expect(version.toLowerCase(), isNot(contains('not found')));
    expect(version.toLowerCase(), isNot(startsWith('error:')));
  });
}
