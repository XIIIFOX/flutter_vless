import 'dart:convert';

import 'package:flutter_vless/flutter_vless.dart';
import 'package:flutter_vless/url/xray_config.dart';
import 'package:flutter_vless/url/xray_json.dart';

import 'main.dart' show runExample;
import 'profile_import.dart';

Future<void> main() {
  const name = String.fromEnvironment(
    'BALANCER_STRATEGY',
    defaultValue: 'roundRobin',
  );
  return runExample(
    title: 'Flutter Vless — Balancer',
    profileImporter: (input) {
      final strategy = ExampleBalanceStrategy.values
          .where((value) => value.name == name)
          .firstOrNull;
      if (strategy == null) {
        throw const FormatException(
          'BALANCER_STRATEGY must be random, roundRobin, leastPing, or leastLoad.',
        );
      }
      return importBalancerInput(
        input,
        strategy: strategy,
        probeUrl: Uri.tryParse(
          const String.fromEnvironment('BALANCER_PROBE_URL'),
        ),
      );
    },
  );
}

enum ExampleBalanceStrategy { random, roundRobin, leastPing, leastLoad }

/// Downloads a pasted HTTPS subscription or imports the clipboard payload.
Future<ImportedProfile> importBalancerInput(
  String input, {
  ExampleBalanceStrategy strategy = ExampleBalanceStrategy.roundRobin,
  Uri? probeUrl,
  Future<List<FlutterVlessURL>> Function(Uri) fetch =
      FlutterVless.fetchSubscription,
}) async {
  final text = input.trim();
  final url = subscriptionUrl(text);
  if (url != null) {
    return _balanceProfiles(await fetch(url), strategy, probeUrl);
  }
  return importBalancerProfile(text, strategy: strategy, probeUrl: probeUrl);
}

/// Builds a balancer from separate proxies in a share-link subscription.
/// A standalone complete JSON profile retains its original routing and DNS.
ImportedProfile importBalancerProfile(
  String input, {
  ExampleBalanceStrategy strategy = ExampleBalanceStrategy.roundRobin,
  Uri? probeUrl,
}) {
  final text = input.trim();
  if (startsWithJsonDocument(text) && decodeXrayJson(text) is Map) {
    return importProfile(text);
  }
  final List<FlutterVlessURL> profiles;
  try {
    profiles = FlutterVless.parseMany(text);
  } catch (_) {
    throw const FormatException(
      'The subscription contains no usable profiles.',
    );
  }
  return _balanceProfiles(profiles, strategy, probeUrl);
}

ImportedProfile _balanceProfiles(
  List<FlutterVlessURL> profiles,
  ExampleBalanceStrategy strategy,
  Uri? probeUrl,
) {
  if (profiles.length == 1) {
    return importedProfile(profiles.single);
  }
  if (profiles.isEmpty) {
    throw const FormatException(
      'The subscription contains no usable profiles.',
    );
  }
  if (profiles.any((profile) => profile is XrayJsonConfig)) {
    throw const FormatException(
      'Use a share-link list to balance separate profiles with their own configuration.',
    );
  }
  final proxies = <String, ProxyNode>{};
  for (final profile in profiles) {
    final outbound = Map<String, dynamic>.of(profile.outbound1)..remove('tag');
    proxies.putIfAbsent(
      jsonEncode(outbound),
      () => ProxyNode.fromMap(outbound),
    );
  }
  if (proxies.length < 2) {
    throw const FormatException(
      'The balancer needs at least two distinct proxies.',
    );
  }

  final balance = switch (strategy) {
    ExampleBalanceStrategy.random => const BalanceStrategy.random(),
    ExampleBalanceStrategy.roundRobin => const BalanceStrategy.roundRobin(),
    ExampleBalanceStrategy.leastPing => const BalanceStrategy.leastPing(),
    ExampleBalanceStrategy.leastLoad => BalanceStrategy.leastLoad(expected: 1),
  };
  final measured =
      strategy == ExampleBalanceStrategy.leastPing ||
      strategy == ExampleBalanceStrategy.leastLoad;
  final probe = probeUrl;
  if (measured &&
      (probe == null ||
          (probe.scheme != 'http' && probe.scheme != 'https') ||
          probe.host.isEmpty)) {
    throw const FormatException(
      'The selected strategy needs an HTTP(S) BALANCER_PROBE_URL.',
    );
  }

  final profile = XrayProfile.build((draft) {
    final nodes = proxies.values.map(draft.addNode).toList();
    final group = draft.addGroup(
      nodes: nodes,
      strategy: balance,
      fallback: measured ? const GroupFallback.block() : null,
    );
    if (measured) {
      draft.setHealthProbe(
        strategy == ExampleBalanceStrategy.leastLoad
            ? HealthProbe.burst(
                probe!,
                interval: const Duration(seconds: 10),
                sampling: 3,
              )
            : HealthProbe.http(
                probe!,
                interval: const Duration(seconds: 5),
                enableConcurrency: true,
              ),
      );
    }
    // The existing domain editor uses this tag for user-selected direct routes.
    draft.addNode(ProxyNode.fromMap({'tag': 'direct', 'protocol': 'freedom'}));
    draft.setDefaultRoute(RouteTarget.group(group));
  });
  return (
    config: profile.toCoreJson(indent: '  '),
    remark: 'Balancer · ${strategy.name} · ${proxies.length} nodes',
    balancedNodeCount: proxies.length,
  );
}
