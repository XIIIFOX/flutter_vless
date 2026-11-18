# Examples

These examples focus on the Dart API. Platform setup still has to be completed
before VPN/tunnel mode can work.

- [Run the Example app](../example/README.md) for clipboard import, routing, VPN,
  proxy mode and diagnostics.
- [Balance connections across several servers](#5-balance-connections-across-several-servers)
  with an HTTPS subscription or multiple share links.
- [Build a typed profile](../example/xray_profile/README.md#compose-a-profile-in-dart)
  or [edit a copy using exact Core fields](../example/xray_profile/README.md#add-a-field-introduced-in-core-26119).

## 1. Proxy-Only Start

Use proxy-only mode when you want local Xray proxy behavior without installing a
system VPN route.

```dart
import 'package:flutter/foundation.dart';
import 'package:flutter_vless/flutter_vless.dart';

final flutterVless = FlutterVless(
  onStatusChanged: (status) {
    debugPrint('state=${status.connectionState.name}');
  },
);

Future<void> startProxyOnly(String link) async {
  final parsed = FlutterVless.parse(link);

  await flutterVless.initializeVless();

  await flutterVless.startVless(
    remark: parsed.remark,
    config: parsed.getFullConfiguration(),
    proxyOnly: true,
  );
}
```

## 2. VPN Or Packet Tunnel Start

Use VPN/tunnel mode when the app should route system traffic through the native
VPN or Packet Tunnel path.

```dart
Future<void> startTunnel(String link) async {
  final parsed = FlutterVless.parse(link);

  await flutterVless.initializeVless(
    providerBundleIdentifier: 'com.example.myapp',
    groupIdentifier: 'group.com.example.myapp',
  );

  final allowed = await flutterVless.requestPermission();
  if (!allowed) {
    return;
  }

  await flutterVless.startVless(
    remark: parsed.remark,
    config: parsed.getFullConfiguration(),
  );
}
```

Notes:

- Android can use `blockedApps` for per-app VPN exclusions.
- iOS and macOS require Network Extension and App Group setup.
- macOS/Windows accept IPv4 `bypassSubnets` as Core direct rules. For iOS, use
  Xray routing rules; non-empty `bypassSubnets` are rejected.
- Windows tunnel behavior may require elevated permissions.

## 3. Import A Subscription

Use `parseMany()` when the input can contain more than one profile.

```dart
Future<List<String>> importSubscription(String subscriptionText) async {
  final profiles = FlutterVless.parseMany(subscriptionText);

  return profiles.map((profile) {
    return profile.getFullConfiguration();
  }).toList();
}
```

`parseMany()` supports base64 share-link lists, Clash YAML, sing-box JSON, and
raw payloads containing supported Xray-compatible protocols.

For an HTTPS subscription URL, fetch the profiles before choosing one. This
keeps the display name and connection config together in each result:

```dart
final profiles = await FlutterVless.fetchSubscription(subscriptionUrl);
final choices = [
  for (final profile in profiles)
    (label: profile.remark, config: profile.getFullConfiguration()),
];
```

Pass the selected choice's `label` and `config` to `startVless()`.

## 4. Custom Routing

Build a profile from one proxy share link. Add a domain rule before setting
the default route, then serialize the profile for startup.

```dart
Future<void> startWithCustomRouting(String link) async {
  final profile = XrayProfile.build((draft) {
    final node = draft.addNode(ProxyNode.fromLink(link));
    draft.addRule(RouteRule.domains(
      ['domain:example.org'],
      to: RouteTarget.direct(),
    ));
    draft.setDefaultRoute(RouteTarget.node(node));
  });

  await flutterVless.startVless(
    remark: 'Domain routing',
    config: profile.toCoreJson(),
    proxyOnly: true,
  );
}
```

See the [configuration guide](configuration.md) for full JSON and platform
preparation details.

## 5. Balance Connections Across Several Servers

Use a balancer when several proxy nodes can handle the same traffic. This
example sends `example.org` directly and rotates other new connections through
the group with `roundRobin`.

```dart
XrayProfile buildBalancedProfile(List<String> shareLinks) {
  return XrayProfile.build((draft) {
    final nodes = shareLinks
        .map((link) => draft.addNode(ProxyNode.fromLink(link)))
        .toList();
    final group = draft.addGroup(
      nodes: nodes,
      strategy: BalanceStrategy.roundRobin(),
    );
    draft.addRule(RouteRule.domains(
      ['domain:example.org'],
      to: RouteTarget.direct(),
    ));
    draft.setDefaultRoute(RouteTarget.group(group));
  });
}
```

Pass `profile.toCoreJson()` to `startVless()` just as in the routing example.
For a runnable test, start the separate entry point from `example/`:

```sh
flutter run -t lib/balancer_example.dart
```

Import an HTTPS subscription URL or paste two or more working share links,
one per line. Check the node count in **Configuration (JSON)**. To see which
node Core selected, enable **Record balancer selections** before connecting in
VPN mode and open **VPN Diagnostics** after generating traffic. The history is
available with compatible Core builds and shows session-local node numbers.
A browser can reuse one connection for several requests.

See the [balancer guide](../example/xray_profile/README.md#run-the-balancer-in-example)
for `leastPing`, `leastLoad`, and the two-way split-routing check.

## 6. Edit A Copy Of An Imported Profile

Keep the imported profile so the user can restore it. This example edits one
field in a profile that already defines a `dns` object:

```dart
final original = XrayProfile.fromJson(importedJson);
final edited = original.edit((draft) {
  draft.setRaw(CorePath.root.key('dns').key('queryStrategy'), 'UseIPv4');
});

final configuration = edited.toCoreJson();
```

This changes the address family Xray requests when resolving names. Other DNS
settings and routing rules are preserved in the edited copy. Use
`original.toCoreJson()` to restore the imported profile.
