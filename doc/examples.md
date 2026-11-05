# Examples

These examples focus on the Dart API. Platform setup still has to be completed
before VPN/tunnel mode can work.

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

## 4. Custom Routing

Edit and serialize one `fullConfiguration` document before startup. Re-reading
the getter for a share link generates another document.

```dart
import 'dart:convert';

Future<void> startWithCustomRouting(String link) async {
  final parsed = FlutterVless.parse(link);

  final document = parsed.fullConfiguration;
  final inbounds = (document['inbounds'] as List).cast<Map<String, dynamic>>();
  inbounds.first['port'] = 10890;
  inbounds.first['listen'] = '127.0.0.1';
  final routing = document['routing'] as Map<String, dynamic>;
  routing['domainStrategy'] = 'AsIs';
  routing['rules'] = [
    {
      'type': 'field',
      'domain': ['domain:example.org'],
      'outboundTag': 'direct',
    },
  ];

  await flutterVless.startVless(
    remark: parsed.remark,
    config: jsonEncode(document),
    proxyOnly: true,
  );
}
```

For deeper config work, pair this with `configuration.md` and the platform guide
for the target operating system.

