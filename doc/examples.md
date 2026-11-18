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

## 7. Check A Profile Before Connecting

Read the installed Core's capabilities and check the profile before offering
Connect. This works before `initializeVless()` and leaves the active session
untouched.

```dart
Future<VlessProfileValidation> checkSavedProfile(XrayProfile profile) async {
  final capabilities = await flutterVless.getCoreCapabilities();
  if (!capabilities.profileValidation) {
    return const VlessProfileValidation(VlessProfileValidationStatus.unsupported);
  }
  return flutterVless.validateProfile(profile);
}
```

Use `validateProfileJson(text)` to check pasted JSON or JSONC before importing
it. The result carries a stable status and may identify a rejected entry by
section and index. You can use `xdrive`, `geoDataUpdates`, and
`balancerSelections` to show controls only when the installed Core supports
them.

The check covers the authored Core configuration and supported file references.
VPN permissions, tunnel setup, and network reachability are checked separately
when connecting. A profile that sets Core `env` values reports `unsupported`
because inspection leaves the process environment intact. On Apple, validation
uses the app's current GeoDAT lookup context. A custom `geoAssetsDirectory`
reports `unsupported` because changing that context could affect an active
session.

## 8. Split DNS And Match IP Networks

Keep a general resolver first and give a specific domain its own resolver.
Xray combines a rule’s CIDR, port, and network conditions. In this example,
TCP traffic to the private network on port 443 goes directly, the same UDP
traffic is blocked, and other traffic uses the proxy.

```dart
XrayProfile buildSplitProfile(String link) {
  return XrayProfile.build((draft) {
    final proxy = draft.addNode(ProxyNode.fromLink(link));
    draft.setDnsOptions(const XrayDnsOptions(disableFallbackIfMatch: true));
    draft.addDnsServer(XrayDnsServer.udp('1.1.1.1'));
    draft.addDnsServer(XrayDnsServer.doh(
      Uri.parse('https://1.0.0.1/dns-query'),
      domains: ['domain:example.org'],
      skipFallback: true,
    ));

    draft.setRoutingDomainStrategy(XrayRoutingDomainStrategy.ipOnDemand);
    final privateNetworks = [
      XrayCidr.parse('192.168.0.0/16'),
      XrayCidr.parse('fd00::/8'),
    ];
    final httpsPorts = [XrayPortRange.single(443)];
    draft.addRule(RouteRule.match(
      destinationCidrs: privateNetworks,
      destinationPorts: httpsPorts,
      networks: {XrayRouteNetwork.tcp},
      to: const RouteTarget.direct(),
    ));
    draft.addRule(RouteRule.match(
      destinationCidrs: privateNetworks,
      destinationPorts: httpsPorts,
      networks: {XrayRouteNetwork.udp},
      to: const RouteTarget.block(),
    ));
    draft.setDefaultRoute(RouteTarget.node(proxy));
  });
}
```

Rules match in order. `ipOnDemand` also lets Xray check named destinations
against CIDRs before a catch-all rule. Use a DNS server's `tag` with
`RouteRule.match(inboundTags: …)` when its queries need a specific outbound.

## 9. Refresh A Subscription And Keep Local Edits

Store the selected node's ID in the subscription state. The refresh reads the
same feed and returns a new state with its latest order.

```dart
var subscription = XraySubscription.fromProfiles(
  await FlutterVless.fetchSubscription(subscriptionUrl),
);
final id = subscription.nodes.first.id;
subscription = subscription.select(id).editProfile(id, (draft) {
  draft.setDnsOptions(const XrayDnsOptions(
    queryStrategy: XrayDnsQueryStrategy.useIpv4,
  ));
});

final refresh = await FlutterVless.refreshSubscription(
  subscriptionUrl,
  subscription,
);
subscription = refresh.subscription;
final profileToConnect = subscription.selectedNode?.profile;
```

Inspect `removedNodes` for removed or ambiguous matches. That list includes
their local profiles. `conflictedNodeIds` identifies nodes with edits on both
sides to the same value. Arrays such as outbounds are reconciled as a unit.
When both sides change one array, the effective profile keeps the local array
and `sourceProfile` holds the latest provider value. Use `resetProfile(id)` to
restore that node's source configuration. Pass a stable provider ID through
`fromProfiles(sourceId: …)` when your data supplies one.

## 10. Set Freedom Final Rules

Apply rules in order on a Freedom outbound. This example closes UDP traffic to
port 443 when it reaches that outbound, with per-destination logging disabled.
Other traffic follows Core's remaining policy for the outbound.

```dart
final profile = XrayProfile.build((draft) {
  final direct = draft.addNode(ProxyNode.fromMap({'protocol': 'freedom'}));
  draft.setFreedomFinalRules(direct, [
    XrayFreedomFinalRule.block(
      destinationPorts: [XrayPortRange.single(443)],
      networks: {XrayRouteNetwork.udp},
      delay: XrayFreedomBlockDelay.fixed(Duration.zero),
      logLevel: XrayFreedomLogLevel.none,
    ),
  ]);
});
```

Setting the delay or log level adds a minimum Core version of 26.11.9.

## 11. Schedule GeoDAT Updates

Check the native capability before offering scheduled updates. This example
checks a profile that reloads its installed datasets every 24 hours.

```dart
final capabilities = await flutterVless.getCoreCapabilities();
if (capabilities.geoDataUpdates) {
  final updated = original.edit((draft) {
    draft.setGeoDataSchedule(
      XrayGeoDataSchedule.every(const Duration(hours: 24), assets: []),
    );
  });
  final check = await flutterVless.validateProfile(updated);
}
```

Use `XrayGeoDataSchedule.cron('0 3 * * *')` for a calendar schedule.
To download updates, add a dataset to `assets`:

```dart
final geosite = XrayGeoDataAsset(
  url: Uri.parse(
    'https://github.com/XTLS/Xray-rules-dat/releases/latest/download/geosite.dat.gz',
  ),
  file: 'geosite.dat',
);
```

Pass a writable directory with the existing `.dat` targets as
`geoAssetsDirectory` to `startVless()`. Apple checks this download setup at
startup. Standalone validation of that setup returns `unsupported`.
