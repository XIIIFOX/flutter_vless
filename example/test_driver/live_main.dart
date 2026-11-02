// Development-only entrypoint for live UI acceptance tests against real native VPNs.
// No mocked channels, profile injection or production entrypoint changes.
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_driver/driver_extension.dart';

import 'package:flutter_vless_example/main.dart' as example;
import 'package:flutter_vless_example/options_storage.dart';

import 'acceptance_dns_probe.dart';
import 'acceptance_web_probe.dart';
import 'acceptance_connection_probe.dart';
import 'import_contract_probe.dart';

Future<void> main() async {
  enableFlutterDriverExtension(handler: handleLiveAcceptanceRequest);
  WidgetsFlutterBinding.ensureInitialized();
  final options = await ExampleOptionsStorage.load();
  runApp(_AcceptanceApp(app: example.MyApp(options: options)));
}

class _AcceptanceApp extends StatelessWidget {
  const _AcceptanceApp({required this.app});
  final example.MyApp app;

  @override
  Widget build(BuildContext context) {
    final normal = app.build(context) as MaterialApp;
    return MaterialApp(
      debugShowCheckedModeBanner: normal.debugShowCheckedModeBanner,
      title: normal.title,
      theme: normal.theme,
      home: Builder(
        builder: (context) => AcceptanceWebOverlay(child: normal.home!),
      ),
    );
  }
}

Future<String> handleLiveAcceptanceRequest(
  String? request, {
  AcceptanceDnsProbeRunner? dnsProbe,
  AcceptanceNamedDnsProbeRunner? namedDnsProbe,
}) async {
  const connectedTargets = {
    'acceptance-connected-delay-2ip': '2ip',
    'acceptance-connected-delay-tfox': 'tfox',
  };
  final target = connectedTargets[request];
  if (target != null) {
    if (kReleaseMode) return 'acceptance-unsupported';
    return jsonEncode(await runAcceptanceConnectedProbe(target));
  }
  if (request == 'acceptance-network-inventory' ||
      request == 'acceptance-import-contract') {
    if (kReleaseMode) return 'acceptance-unsupported';
    if (!await acceptanceConnectionProbeAdmitted()) {
      return 'acceptance-unavailable';
    }
    try {
      return jsonEncode(
        request == 'acceptance-network-inventory'
            ? await runAcceptanceNetworkInventory()
            : await runAcceptanceImportContract(),
      );
    } catch (_) {
      return 'acceptance-unavailable';
    }
  }
  if (request == 'acceptance-own-view-snapshot') {
    if (kReleaseMode) return 'acceptance-unsupported';
    return captureAcceptanceOwnView();
  }
  if (request == 'acceptance-owned-manager-safety') {
    if (kReleaseMode) return 'acceptance-unsupported';
    return captureAcceptanceOwnedManagerSafety();
  }
  if (request == 'acceptance-dns-probe' ||
      request == 'acceptance-dns-probe-1cfresh') {
    final domain = request == 'acceptance-dns-probe-1cfresh'
        ? '1cfresh.com'
        : 'tfox.dev';
    if (kReleaseMode) return 'acceptance-unsupported';
    try {
      final result = domain == 'tfox.dev'
          ? await (dnsProbe ?? runAcceptanceDnsProbe)()
          : await (namedDnsProbe ??
                ((domain) =>
                    runAcceptanceDnsProbe(queryDomain: domain)))(domain);
      return jsonEncode(result);
    } catch (_) {
      return jsonEncode({
        'version': 1,
        'probe': 'managed_dns',
        'status': 'unavailable',
        if (domain != 'tfox.dev') 'queryDomain': domain,
        'results': <Object>[],
      });
    }
  }
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
