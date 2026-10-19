// Development-only entrypoint for live UI acceptance tests against real native VPNs.
// No mocked channels, profile injection or production entrypoint changes.
import 'package:flutter/services.dart';
import 'package:flutter_driver/driver_extension.dart';

import 'package:flutter_vless_example/main.dart' as example;

Future<void> main() async {
  enableFlutterDriverExtension(handler: handleLiveAcceptanceRequest);
  await example.main();
}

Future<String> handleLiveAcceptanceRequest(String? request) async {
  if (request == 'acceptance-full-stop') {
    try {
      const channel = MethodChannel('flutter_vless');
      await channel
          .invokeMethod<void>('stopVless')
          .timeout(const Duration(seconds: 30));
      return 'acceptance-vpn-stopped';
    } catch (_) {
      return 'acceptance-error';
    }
  }
  if (request != 'acceptance-stop-core') return 'acceptance-unsupported';
  try {
    const channel = MethodChannel('dev.tfox.flutterXrayExample/acceptance');
    final response = await channel
        .invokeMethod<String>('stopCore')
        .timeout(const Duration(seconds: 12));
    return response == 'acceptance-core-stopped'
        ? 'acceptance-core-stopped'
        : 'acceptance-error';
  } catch (_) {
    return 'acceptance-error';
  }
}
