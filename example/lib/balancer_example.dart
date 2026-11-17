import 'dart:convert';

import 'package:flutter_vless/flutter_vless.dart';

import 'main.dart' show runExample;
import 'profile_import.dart';

Future<void> main() {
  const name = String.fromEnvironment(
    'BALANCER_STRATEGY',
    defaultValue: 'roundRobin',
  );
  return runExample(
    profileImporter: (input) {
      final strategy = ExampleBalanceStrategy.values
          .where((value) => value.name == name)
          .firstOrNull;
      if (strategy == null) {
        throw const FormatException(
          'BALANCER_STRATEGY must be random, roundRobin, leastPing, or leastLoad.',
        );
      }
      return importBalancerProfile(
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

/// Builds a balancer from plain share links pasted one per line.
/// Single profiles and other input formats use the standard Example importer.
({String config, String? remark}) importBalancerProfile(
  String input, {
  ExampleBalanceStrategy strategy = ExampleBalanceStrategy.roundRobin,
  Uri? probeUrl,
}) {
  final links = const LineSplitter()
      .convert(input)
      .map((line) => line.trim())
      .where((line) => line.isNotEmpty)
      .toList();
  if (links.length < 2 ||
      !RegExp(r'^[a-zA-Z][a-zA-Z0-9+.-]*://').hasMatch(links.first)) {
    return importProfile(input);
  }
  final distinctLinks = links.toSet();
  if (distinctLinks.length < 2) {
    throw const FormatException('Paste at least two distinct share links.');
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
    final nodes = <NodeRef>[];
    for (final (index, link) in distinctLinks.indexed) {
      try {
        nodes.add(draft.addNode(ProxyNode.fromLink(link)));
      } catch (_) {
        // Some protocol parsers attach the source link to the exception.
        throw FormatException('Invalid share link at position ${index + 1}.');
      }
    }
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
    remark: 'Balancer · ${strategy.name} · ${distinctLinks.length} nodes',
  );
}
