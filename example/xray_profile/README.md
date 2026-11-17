# Build and edit Xray profiles

Use the existing `FlutterVless` controller to start the generated profile.
Initialize the controller and request VPN permission as in the main example.

```dart
import 'package:flutter_vless/flutter_vless.dart';

XrayProfile buildProfile(String firstLink, String secondLink, Uri probeUrl) {
  return XrayProfile.build((draft) {
    final first = draft.addNode(ProxyNode.fromLink(firstLink));
    final second = draft.addNode(ProxyNode.fromLink(secondLink));
    final group = draft.addGroup(
      nodes: [first, second],
      strategy: BalanceStrategy.leastPing(),
      fallback: GroupFallback.block(),
    );
    draft.setHealthProbe(HealthProbe.http(probeUrl));
    draft.addRule(RouteRule.domains(
      ['domain:example.org'],
      to: RouteTarget.direct(),
    ));
    draft.setDefaultRoute(RouteTarget.group(group));
  });
}

Future<void> connect(FlutterVless controller, XrayProfile profile) {
  return controller.startVless(
    remark: 'Low latency',
    config: profile.toCoreJson(),
  );
}
```

The domain rule is evaluated before the final TCP/UDP rule. Use an HTTP(S)
probe URL you control. The group blocks matching new connections until Core
finds a candidate, and again when all candidates are unavailable. System
protection and protected DNS retain their respective platform policies.

For distribution without probing, use `BalanceStrategy.roundRobin()` and
omit the probe and fallback. Use `proxyOnly: true` on the existing start call
to run with the local listener and without an OS VPN session.

## Add a field introduced in Core 26.11.9

This example assumes the imported profile already has a Freedom outbound as
its first outbound and a block rule as its first final rule.

```dart
final original = XrayProfile.fromJson(importedJson);
final rule = CorePath.root
    .key('outbounds').index(0)
    .key('settings').key('finalRules').index(0);

final updated = original.edit((draft) {
  draft.removeRaw(rule.key('blockDelay'));
  draft.setRaw(rule.key('delay'), 0);
  draft.setRaw(rule.key('logLevel'), 'warning');
  draft.requireCoreAtLeast('26.11.9');
});
```

The imported profile remains available for a separate connection. Its
unknown fields and array order survive the edit. Use `toCoreMap()` to
inspect a separate copy in memory. Profile JSON can contain credentials.
