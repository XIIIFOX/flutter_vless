# flutter_vless

**Flutter plugin to run VLESS/VMESS as a local proxy and VPN on Android and iOS.**

Provides fine-grained routing for domains, sites, and apps, with built-in status tracking, delay testing, and extended configuration options.

## Table of contents

- [Key Features](#key-features)
- [Quick Start (TL;DR)](#quick-start-tldr)
- [Requirements](#requirements)
- [Installation](#installation)
- [Platform setup (step-by-step)](#platform-setup-step-by-step)
  - [iOS](#ios)
  - [Android](#android)
- [Usage examples](#usage-examples)
  - [URL parser](#url-parser-)
  - [Edit configuration](#edit-configuration)
  - [Start / stop FlutterVless](#start--stop-fluttervless)
- [Contributing / Contact / License](#contributing--contact--license)


---

## Key features
- Supports iOS and Android out of the box, with routing and similar features available
- Run flutter_vless as a local proxy or using the VPN mode (Network Extension / VpnService).
- Parse VLESS/VMESS share links and generate ready-to-run configurations.
- Measure server delay (ping) for a configuration.
- Edit configuration (ports, DNS, routing, etc.).

---


## Quick Start (TL;DR)

1. Install the package (see [Installation](#installation)).
2. Complete platform setup (iOS / Android).
3. Initialize the plugin and start flutter_vless from your app.

- [Simple vless client written in flutter](https://github.com/XIIIFOX/flutter_vless/blob/master/example/lib/main.dart)

Minimal copy‑paste example:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_vless/flutter_vless.dart';

void main() => runApp(const MyApp());

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  late final FlutterVless _flutterVless;

  @override
  void initState() {
    super.initState();
    _flutterVless = FlutterVless(onStatusChanged: (status) {
      print('VLESS status: $status');
    });
    _init();
  }

  Future<void> _init() async {
    await _flutterVless.initializeVless(
      providerBundleIdentifier: 'com.example.myapp.VPNProvider',
      groupIdentifier: 'group.com.example.myapp',
    );
  }

  Future<void> _startFromShareLink(String shareLink) async {
    final FlutterVlessURL parser = FlutterVless.parseFromURL(shareLink);
    final String config = parser.getFullConfiguration();

    final int delayMs = await _flutterVless.getServerDelay(config: config);
    print('Server delay: ${delayMs}ms');

    final bool allowed = await _flutterVless.requestPermission();
    if (!allowed) return;

    await _flutterVless.startVless(
      remark: parser.remark,
      config: config,
    );
  }

  Future<void> _stop() async {
    await _flutterVless.stopVless();
  }

  @override
  Widget build(BuildContext context) => Container();
}
```

---

## Requirements

- Flutter SDK (the minimum supported version used by the package).
- Android: recommended `minSdkVersion` >= 23; set `targetSdkVersion` to a recent API.
- iOS: `iOS Deployment Target` >= 13.0 (may vary depending on Network Extension usage).
- Running VPN mode on iOS requires Network Extension and a provisioning profile that allows it.

---

## Installation

### From pub.dev

```yaml
dependencies:
  flutter_vless: replace_with_current_plugin_version
```

### From Git

```yaml
dependencies:
  flutter_vless:
    git:
      url: https://github.com/XIIIFOX/flutter_vless.git
      ref: main
```

### Local development

```yaml
dependencies:
  flutter_vless:
    path: ../flutter_vless
```

Then run:

```bash
flutter pub get
```

---

## Platform setup (step-by-step)

Follow the platform steps below — without these the plugin cannot run VPN/Network Extension.

### iOS
[Setup for IOS](./IOS_SETUP.md)

### Android

1.  Add the attribute android:extractNativeLibs="true" to the <application> tag in your AndroidManifest.xml.

```xml
<application
    android:name=".MyApplication"
    android:label="@string/app_name"
    android:icon="@mipmap/ic_launcher"
    android:extractNativeLibs="true">
    ...
</application>

```

2. Set minSdkVersion to >= 23. Ensure your `minSdkVersion` and `targetSdkVersion` match plugin and Play Store requirements.

> Google Play note: apps that modify network traffic may require a privacy policy and additional disclosure in the store listing.

---

## Usage examples


### URL parser

```dart
import 'package:flutter_vless/flutter_vless.dart';

final String link = 'vmess://...'; // or vless://, trojan:// etc.
FlutterVlessURL parsed = FlutterVless.parseFromURL(link);
print('Remark: ${parsed.remark}');
final String config = parsed.getFullConfiguration();
print('Config JSON: $config');
```

### Edit Configuration

An example of how we work with routing through configuration is available in our example.

``` dart
// Change listening port
parsed.inbound['port'] = 10890;
// Change listening host
parsed.inbound['listen'] = '0.0.0.0';
// Change dns
parsed.dns = {
    "servers": ["1.1.1.1"]
};
// and ...
```


### Start / Stop FlutterVless

```dart
final flutterVless = FlutterVless(onStatusChanged: (status) => print(status));

await flutterVless.initializeVless(
  providerBundleIdentifier: 'com.example.myapp.VPNProvider',
  groupIdentifier: 'group.com.example.myapp',
);

if (await flutterVless.requestPermission()) {
  await flutterVless.startVless(
    remark: 'My server',
    config: newConfig,
    blockedApps: null, // list of package names
    bypassSubnets: FlutterVless.defaultBypassSubnets(),
    proxyOnly: false,
  );
}

await flutterVless.stopVless();
```


---


## FAQ / common issues

**Q: The VPN permission is granted but the VPN doesn’t start.** A: Check that `providerBundleIdentifier` and `groupIdentifier` match the values in Xcode, and that the provisioning profile allows Network Extensions.

**Q: My Play Store submission was rejected.** A: Ensure your app includes a clear privacy policy and a disclosure about VPN/proxy usage in the store listing.

**Q: ****\`\`**** shows very high latency.** A: Verify DNS, server address, and network reachability. Try from a different network or device to exclude local network issues.

---

## Contributing / Contact / License

[Contributing](./CONTRIBUTING.md)

[License](./LICENSE)

### Contact
  - [Telegram](https://t.me/ley_dey)
  - By email - 13fox.comp@gmail.com

### Donation
BTC:

bc1qeqlrphnwmpt2qsfz7uk8wnv62vyq9ef6lansh4

ETH:

0x49F7af0D7Afc7e174b086e24DA5A8649586e23d1

USDT TRC20: 

TTUe9Ca3S83LTJ2r6e7B7XguNvru2MoAmb

USDT TON:

UQBot8FUuYpyW8cjq306-qiEqnpfNjTHxhC1dk_6XDcJ5a1J



All rights reserved.
