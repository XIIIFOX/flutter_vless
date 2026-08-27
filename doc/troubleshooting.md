# Troubleshooting

This guide is intentionally practical. Use it when the app compiles but the connection does not behave the way you expect.

## VPN Permission Is Granted, But Traffic Does Not Flow

Check:

- `providerBundleIdentifier` matches the base app bundle id, not the extension id
- `groupIdentifier` matches the App Group used by the native target
- the platform setup guide has been followed completely
- the platform actually supports the mode you are trying to use

## The Connection Starts, But Browsing Is Stalled

Common causes:

- DNS is misconfigured
- the server route loops back into the tunnel
- the wrong platform guide was followed
- a proxy-only example was copied into a VPN flow, or vice versa

On macOS Packet Tunnel, do not treat `Delay` or Xray's internal SOCKS checks as
complete proof that browser traffic can flow. A healthy macOS VPN run should
also show app-side raw TCP probes through the selected `utun` route and growing
download counters. If `raw-http-ip-literal-bound-utun*` fails with
`No route to host`, inspect the Packet Tunnel route model before changing the
Xray config.

## `parse()` Fails On A Link

Check whether the input really is one of the supported formats:

- `vmess://`
- `vless://`
- `trojan://`
- `ss://`
- `socks://`
- `hysteria2://`
- `hy2://`
- raw Xray JSON
- base64 subscription text
- Clash YAML
- sing-box JSON

If the input is a subscription payload, try `FlutterVless.parseMany()` first so you can see every supported profile.

## `startVless()` Rejects My Config Before Native Code

That usually means the JSON is structurally invalid, not just unsupported by the
server.

Check:

- the config is a JSON object, not an array
- `outbounds` exists and is not empty
- each outbound has a `protocol`
- if you are building configs manually, use the typed helpers in
  `lib/url/xray_config_model.dart`

## Android Specific

- confirm Gradle `packaging.jniLibs.useLegacyPackaging = true` is set when extracted native executables are required
- confirm `minSdkVersion` is high enough
- confirm the app resolves the current Maven runtime AAR, which includes emulator ABIs
- confirm `blockedApps` is only used where the platform backend supports it

## iOS And macOS Specific

- use a real device for tunnel validation
- confirm the Packet Tunnel target is signed
- confirm the App Group is shared between the app and the extension
- for macOS, read the packet tunnel architecture note before changing routing or DNS
- for macOS `1.1.6`, keep explicit Packet Tunnel DNS enabled and DNS host-route
  exclusions disabled unless a real smoke test proves another route model

## macOS Build Fails During Xcode Or SwiftPM Resolution

For the bundled example, run from the repository example directory:

```bash
cd flutter_vless/example
flutter clean
rm -rf macos/Flutter/ephemeral macos/Pods macos/Podfile.lock
flutter pub get
../tool/prepare_apple_swiftpm.sh
flutter run -d macos
```

If Xcode reports `unknown 'PinsStorage' version '3'`, delete the generated
`macos/Runner.xcworkspace/xcshareddata/swiftpm/Package.resolved` file and rerun
the prepare script. The repository does not require this generated file.

If a new app reports that `flutter-vless-macos` requires macOS 13.0 while the
generated target supports 10.15, run:

```bash
dart run flutter_vless:setup_macos_vpn --prepare-only
```

If CocoaPods fallback reports `no such module 'CXRay'`, clean `macos/Pods`,
`macos/Podfile.lock`, and `macos/Flutter/ephemeral`, then run `flutter pub get`
again so CocoaPods regenerates the pod settings.

If Xcode prints `DVTPortal` or `Your session has expired`, that is an Apple
account/signing issue rather than a SwiftPM package issue. Open Xcode Settings,
sign in again, then select your Apple Team for both `Runner` and `XrayTunnel`
in `example/macos/Runner.xcworkspace`.

## Windows Specific

- confirm `xray.exe` is available where the plugin expects it
- confirm the current process has enough permissions for system routing changes
- confirm proxy-only and VPN mode are not being mixed up

## When In Doubt

Use the bundled example app, then compare its behavior with the docs. The example is often the quickest way to see whether the problem is in your app code or in platform setup.
