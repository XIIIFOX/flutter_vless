# Build and edit Xray profiles

## Run the balancer in Example

From the repository's `example` directory, run the balancer entry point on a
device with the [usual Example setup](../README.md).

```sh
flutter run -t lib/balancer_example.dart
```

Copy two or more working share links, one per line. In Example, tap
**Import (clipboard)**, inspect the generated JSON, and tap **Connect**.
The default `roundRobin` distributes new connections across the group.
Choose `random` with `--dart-define=BALANCER_STRATEGY=random`.

For latency-based selection, supply a probe endpoint you control that returns
HTTP 204. Keep your share links in the clipboard.

```sh
flutter run -t lib/balancer_example.dart \
  --dart-define=BALANCER_STRATEGY=leastPing \
  --dart-define=BALANCER_PROBE_URL=https://your-probe.example/204
```

Use `leastLoad` in the same command for Burst Observatory. These two strategies
block grouped connections while no node is eligible. To test split routing,
add a domain in the existing routing editor. Its traffic uses the direct
outbound ahead of the final group rule. The platform's DNS policy continues to
apply. Single profiles and full JSON can still use the regular import path.

## Verify first connection and split routing

Use a test subscription with 34 distinct supported nodes. Keep its URL and
credentials outside the repository.

1. With Example disconnected, record the IPv4 results from tfox.dev and
   ipify and check the IPv6-only ipify endpoint. Keep the addresses in memory
   for comparison.
2. Import the subscription anew for each case. In VPN Mode, time one Connect
   from the button press to **CONNECTED**. On Apple platforms, also record
   the current endpoint plan time from **VPN Diagnostics**. Compare builds
   using the same device, Core version, network and subscription.
3. With no domain bypass, open fresh HTTPS connections to the two IP sites.
   Verify that the public exit differs from the baseline and that repeated
   requests use different exits. On iOS, check the recorded node selections
   during the active session.
4. Run both split-routing cases. Bypass tfox.dev and keep ipify on the
   balancer, then swap the rules. The bypassed site must see the baseline IP.
   The other site must see an exit from the group.
5. Check the IPv6-only endpoint through the tunnel and record whether the
   device could reach it before connecting. For IPv6 acceptance, use a
   test network and nodes that support IPv6 end to end.
6. Disconnect after each case and verify that the test tunnel stopped.
   Keep timings, address families and equality results in reports.

The [live integration test](../integration_test/balancer_route_smoke_test.dart)
runs these cases using a private file with the decoded subscription, one share
link per line. Place `balancer-smoke.input` in the Example app's Documents
directory on Apple platforms or its private files directory on Android. On
Windows, pass the target's absolute file path as
`--dart-define=BALANCER_SMOKE_INPUT_FILE=...`.

From `example`, run:

```sh
flutter drive -d <target> \
  --driver=test_driver/integration_test.dart \
  --target=integration_test/balancer_route_smoke_test.dart \
  --dart-define=BALANCER_SMOKE_EXPECTED_NODES=34
```

Use a signed VPN build on Apple platforms and an elevated native Windows
session with its VPN runtime installed. Pass
`--dart-define=BALANCER_SMOKE_REQUIRE_IPV6=false` for an explicit IPv4-only
run when the test network lacks IPv6. The
`balancer-smoke` Actions scope uses isolated Core peers on macOS and Windows,
including IPv6 peers, and exercises the macOS DNS preparation scheduler.

## Compose a profile in Dart

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
