# Options and system controls (1.1.7)

Construct `FlutterVless(options: ...)`, then initialize it. `VlessOptions.fromMap(options.toMap())` restores validated non-secret settings for application-owned persistence. Existing callers remain compatible. Native options require the matching 1.1.7 source packages; older backends reject custom options explicitly. This development revision does not publish Dart packages. Use the repository's local dependency overrides when testing it.

```dart
final vpn = FlutterVless(
  onStatusChanged: (status) { /* update the application */ },
  options: const VlessOptions(
    notification: NotificationOptions(
      iconResourceType: 'drawable',
      iconResourceName: 'vpn_notification',
      buttonLabel: 'Open app',
      action: VlessNotificationAction.openApp,
    ),
    quickAccess: QuickAccessOptions(
      enabled: true,
      label: 'My VPN',
      action: VlessSystemAction.toggle,
      requireUnlock: true,
      appleSymbol: 'shield',
    ),
    reconnect: ReconnectOptions(
      initialDelay: Duration(seconds: 1),
      maxDelay: Duration(seconds: 30),
      maxAttempts: 5, // 0 = unlimited
    ),
    protection: ProtectionOptions(killSwitch: KillSwitchPolicy.required),
    diagnostics: DiagnosticsOptions(maxBytes: 64 * 1024, maxLines: 150),
  ),
);
await vpn.initializeVless(
  providerBundleIdentifier: 'com.example.app',
  groupIdentifier: 'group.com.example.app',
);
final capabilities = await vpn.getCapabilities();
// Start a real VPN profile once before using its native quick control.
```

Bundle any referenced Android resource before using this sample. `NotificationOptions` customizes Android's required foreground notification. Supported button actions are `disconnect`, `openApp`, and `none`. The latter hides the action button, not the mandatory foreground notification. Explicit legacy initialization icon arguments and `notificationDisconnectButtonName` override their corresponding options.

`QuickTileOptions` is an alias for `QuickAccessOptions`. Fixed native actions work independently of Dart callbacks. Flutter widgets, executable callbacks and arbitrary image URLs cannot be serialized into system UI. Use Android drawable/mipmap resource names, an Apple SF Symbol, or an absolute Windows `.ico` path. Windows defaults to the application icon. Labels are limited to 80 UTF-16 units; resource names and symbols to 128; labels cannot contain control characters. A missing Android drawable uses the bundled tile icon.

| Platform | Quick access | Lifetime and setup |
| --- | --- | --- |
| Android 7+ | Quick Settings Tile | Native daemon; does not need a Flutter engine. Profile encrypted with Android Keystore in no-backup storage. |
| Android 13+ | `requestAddQuickTile()` system dialog | Requires an attached foreground Activity and enabled quick access. Earlier versions use the system tile editor. |
| iOS/iPadOS 18+ | Control Center WidgetKit control | Host extension, App Group and signing required. The current template opens the app to execute the native intent. |
| macOS 13+ | Menu bar | Default macOS surface; requires the app process. Profile remains in the scoped Keychain/system VPN configuration. |
| macOS 26+ | Control Center WidgetKit control | Optional `controlCenter` surface, host extension and Xcode 26+ required. Current template opens the app. |
| Windows | Notification area/system tray | Requires the app process. Last accepted VPN configuration remains in memory only. |

`getCapabilities()` reports the loaded backend's implementation, available surfaces, extension setup, custom native retry support, On Demand, Kill Switch and Android's current Always-on/lockdown state. Proxy-only sessions do not become quick VPN profiles. Unsupported surfaces and required protection features fail initialization or connection explicitly instead of silently degrading.

`requireUnlock` asks Android to unlock before the action. The Apple Control Widget uses LocalAuthentication before changing the VPN when enabled; cancellation performs no action. Opening an app can itself require the OS to unlock even when this option is false. Desktop menu/tray interaction already requires an accessible desktop session.

`clearQuickAccessProfile()` forgets only the native quick-access authorization/configuration, leaving an active VPN alone. Reopening/reinitializing the application does not recover the forgotten profile; connect explicitly from the application again. Disabling quick access removes the retained quick profile/authorization. A manual Stop retains the quick profile for a later explicit toggle, but disarms automatic restart. On Apple, the system VPN profile and its Keychain entry remain because an active/system-managed session may still use them.

## Recovery and protection

`ReconnectOptions` governs the plugin's native worker recovery. Delay doubles after consecutive failed attempts, bounded by `maxDelay`; a healthy connection resets it. `initialDelay` is at least 100 ms; `maxDelay` is between the initial delay and 10 minutes; attempts are 0–1000. Disabling retries or exhausting them retains the active capture/protection until explicit Stop. It does not disable Xray's own per-connection transport retry behavior.

Session recovery/protection and Android notification settings are snapshots: apply them with the next explicit connection. Quick-control presentation and diagnostics can be configured again during initialization. Apple owns scheduling after termination of the complete Network Extension; the custom schedule governs workers inside a surviving extension.

`KillSwitchPolicy.required` and `platformDefault` both preserve mandatory protection in VPN mode. There is no option to silently weaken it. Proxy-only mode does not capture system traffic. Ordinary Android VPN capture cannot survive the death of the entire VPN process by itself; enable OS Always-on with “Block connections without VPN” for that OS-level guarantee. Apple cannot promise continuous capture after the entire provider is terminated. Windows retains its owned WFP barrier until explicit Stop, including after a crash.

`ProtectionOptions.onDemand` is Apple-specific. `platformDefault` enables On Demand when reconnect is enabled; `disabled` disables OS relaunch while keeping worker retry settings separate. Explicit `enabled` requires Auto Reconnect. On Demand is not an un-disableable VPN: explicit system/app disconnect disarms it.

Android Always-on and lockdown are selected by the user/device owner in system VPN settings. `AlwaysOnMode.system` respects that policy; `requireEnabled` additionally rejects a VPN connection until the OS mode is enabled (Android 10+ state query). While OS Always-on/lockdown is active, library Stop returns `ALWAYS_ON_MANAGED`; disable that system setting first. Quick Tile/notification actions direct the user to the app rather than pretending to disable OS policy. Apple Always On applies to managed IKEv2 deployments and is unavailable for this custom Xray Packet Tunnel; Windows does not expose Android's mode through this plugin.

`DiagnosticsOptions` only bounds existing privacy-filtered diagnostics. Disabling collection clears its own retained buffers; raw Xray output, credentials, configuration and imported log destinations remain prohibited. Bounds are 4096–131072 bytes and 1–300 lines; returned snapshots may have stricter existing platform limits.

## Apple Control Widget setup

Configure the ordinary Packet Tunnel first. The controls target is separate from the VPN extension and links only the lightweight `flutter-vless-controls` SwiftPM product, without embedding another Xray runtime.

```sh
dart run flutter_vless:setup_apple_controls \
  --project-dir . --platform ios \
  --bundle-id com.example.app --group-id group.com.example.app \
  --team-id YOUR_TEAM
# For macOS use --platform macos after setup_macos_vpn.
```

Requires macOS and the Ruby `xcodeproj` gem (included with CocoaPods; otherwise `gem install xcodeproj`). The idempotent generator creates `VlessControls`, embeds it in Runner, adds the shared intent source to both targets, and configures App Group/signing metadata and Face ID usage text. Its deployment minimum is iOS 18/macOS 26; the main app may keep its earlier minimum. Enable App Groups and Network Extensions for the controls App ID in your developer signing configuration too. Add the control from the system's Control Center editor; an app cannot silently insert it. `controlCenterExtensionConfigured` reports the generated host declaration, not a successful physical-device signing/install check.

The example uses Flutter 3.44+ and saves all five Options blocks in application preferences and restores them before its first plugin initialization. This matters because a Control Center intent can cold-launch the app. VPN links/configuration are excluded from these preferences.

The templates are under `templates/apple_controls`; generated examples are in `example/ios/VlessControls` and `example/macos/VlessControls`. Keep both target memberships and the extension's `FLUTTER_VLESS_WIDGET_EXTENSION` compilation condition. The extension never changes VPN preferences itself: the intent executes in Runner, verifies the saved profile identity/reference and confirms On Demand persistence before disconnecting.

## Verification and next device phase

Automated coverage includes Dart validation/wire compatibility, Kotlin/Swift/C++ field parsing and retry policies, protected stop/error paths, native diagnostic bounds, Apple generator idempotency, example UI, and native Android SystemUI tile stop/cold reconnect without Flutter. Windows native tests and application/runtime builds run in GitHub Actions. macOS validation is compilation and isolated injected-preferences tests: never activate a second VPN on the development Mac.

Before release, use the actual signed iPhone and supplied VPN links to verify Control Center insertion, lock/authentication cancellation, stop/reconnect with the app closed, Xray 26.10.17 connection stability, direct/proxy routing and DNS behavior. Repeat Quick Tile/notification checks on the physical Android device. Verify tray interaction on a Windows desktop. Simulator/compiler results do not establish these physical-device checks. No links were supplied for this phase yet.

The Android tile work takes the idea of [PR #21](https://github.com/XIIIFOX/flutter_vless/pull/21); that pull request is not merged. The implementation uses the current native lifecycle and protected profile storage.

Platform references: [Android tiles](https://developer.android.com/develop/ui/views/quicksettings-tiles), [Apple controls](https://developer.apple.com/documentation/widgetkit/controls-collection), [Windows notification area](https://learn.microsoft.com/en-us/windows/win32/shell/notification-area).
