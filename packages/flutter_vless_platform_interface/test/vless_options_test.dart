import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_vless_platform_interface/flutter_vless_platform_interface.dart';

void main() {
  test('defaults retain protection and opt out of system controls', () {
    const value = VlessOptions();
    expect(value.isDefault, isTrue);
    expect(value.quickAccess.enabled, isFalse);
    expect(value.reconnect.enabled, isTrue);
    expect(value.protection.killSwitch, KillSwitchPolicy.required);
    expect(value.protection.alwaysOn, AlwaysOnMode.system);
    expect(value.toMap()['version'], 1);
  });
  test('all five options blocks serialize every public field', () {
    const value = VlessOptions(
      notification: NotificationOptions(
          iconResourceType: 'drawable',
          iconResourceName: 'vpn_notice',
          buttonLabel: 'Open',
          action: VlessNotificationAction.openApp),
      quickAccess: QuickTileOptions(
          enabled: true,
          surface: QuickAccessSurface.quickTile,
          label: 'Private network',
          action: VlessSystemAction.openApp,
          requireUnlock: false,
          androidIconResourceName: 'vpn_tile',
          appleSymbol: 'lock.shield',
          windowsIconPath: r'C:\app\vpn.ico'),
      reconnect: ReconnectOptions(
          enabled: false,
          initialDelay: Duration(milliseconds: 500),
          maxDelay: Duration(seconds: 15),
          maxAttempts: 4),
      protection: ProtectionOptions(
          killSwitch: KillSwitchPolicy.platformDefault,
          onDemand: OnDemandMode.disabled,
          alwaysOn: AlwaysOnMode.requireEnabled),
      diagnostics:
          DiagnosticsOptions(enabled: false, maxBytes: 8192, maxLines: 20),
    );
    expect(value.isDefault, isFalse);
    expect(value.toMap(), {
      'version': 1,
      'notification': {
        'iconResourceType': 'drawable',
        'iconResourceName': 'vpn_notice',
        'buttonLabel': 'Open',
        'action': 'openApp'
      },
      'quickAccess': {
        'enabled': true,
        'surface': 'quickTile',
        'label': 'Private network',
        'action': 'openApp',
        'requireUnlock': false,
        'androidIconResourceName': 'vpn_tile',
        'appleSymbol': 'lock.shield',
        'windowsIconPath': r'C:\app\vpn.ico'
      },
      'reconnect': {
        'enabled': false,
        'initialDelayMs': 500,
        'maxDelayMs': 15000,
        'maxAttempts': 4
      },
      'protection': {
        'killSwitch': 'platformDefault',
        'onDemand': 'disabled',
        'alwaysOn': 'requireEnabled'
      },
      'diagnostics': {'enabled': false, 'maxBytes': 8192, 'maxLines': 20},
    });
  });
  test('all actions and placements retain stable wire names', () {
    for (final action in VlessNotificationAction.values) {
      expect(
          NotificationOptions(action: action).toMap()['action'], action.name);
    }
    for (final surface in QuickAccessSurface.values) {
      for (final action in VlessSystemAction.values) {
        expect(QuickAccessOptions(surface: surface, action: action).toMap(),
            containsPair('surface', surface.name));
        expect(QuickAccessOptions(action: action).toMap(),
            containsPair('action', action.name));
      }
    }
    for (final mode in OnDemandMode.values) {
      expect(ProtectionOptions(onDemand: mode).toMap()['onDemand'], mode.name);
    }
    for (final mode in AlwaysOnMode.values) {
      expect(ProtectionOptions(alwaysOn: mode).toMap()['alwaysOn'], mode.name);
    }
    for (final mode in KillSwitchPolicy.values) {
      expect(
          ProtectionOptions(killSwitch: mode).toMap()['killSwitch'], mode.name);
    }
  });
  final invalid = <String, VlessOptions>{
    'resource type': const VlessOptions(
        notification: NotificationOptions(iconResourceType: 'raw')),
    'notification resource': const VlessOptions(
        notification: NotificationOptions(iconResourceName: '../icon')),
    'tile resource': const VlessOptions(
        quickAccess: QuickAccessOptions(androidIconResourceName: 'a/b')),
    'empty label':
        const VlessOptions(quickAccess: QuickAccessOptions(label: ' ')),
    'button controls': const VlessOptions(
        notification: NotificationOptions(buttonLabel: 'Stop\nNow')),
    'symbol controls': const VlessOptions(
        quickAccess: QuickAccessOptions(appleSymbol: '\u0000')),
    'relative icon': const VlessOptions(
        quickAccess: QuickAccessOptions(windowsIconPath: 'vpn.ico')),
    'wrong icon type': const VlessOptions(
        quickAccess: QuickAccessOptions(windowsIconPath: r'C:\vpn.png')),
    'short retry': const VlessOptions(
        reconnect: ReconnectOptions(initialDelay: Duration(milliseconds: 99))),
    'inverted backoff': const VlessOptions(
        reconnect: ReconnectOptions(
            initialDelay: Duration(seconds: 20),
            maxDelay: Duration(seconds: 1))),
    'unbounded delay': const VlessOptions(
        reconnect: ReconnectOptions(maxDelay: Duration(hours: 1))),
    'negative attempts':
        const VlessOptions(reconnect: ReconnectOptions(maxAttempts: -1)),
    'attempt ceiling':
        const VlessOptions(reconnect: ReconnectOptions(maxAttempts: 1001)),
    'contradictory recovery': const VlessOptions(
        reconnect: ReconnectOptions(enabled: false),
        protection: ProtectionOptions(onDemand: OnDemandMode.enabled)),
    'small diagnostics':
        const VlessOptions(diagnostics: DiagnosticsOptions(maxBytes: 4095)),
    'large diagnostics':
        const VlessOptions(diagnostics: DiagnosticsOptions(maxBytes: 131073)),
    'zero lines':
        const VlessOptions(diagnostics: DiagnosticsOptions(maxLines: 0)),
    'many lines':
        const VlessOptions(diagnostics: DiagnosticsOptions(maxLines: 301)),
  };
  for (final entry in invalid.entries) {
    test('reject ${entry.key} before a platform action', () {
      expect(entry.value.validate, throwsArgumentError);
      expect(entry.value.toMap, throwsArgumentError);
    });
  }
  test(
      'capabilities tolerate older and unknown fields without fabricating support',
      () {
    final value = VlessCapabilities.fromMap({
      'optionsVersion': 1,
      'quickAccessSurfaces': ['quickTile', 'futureSurface'],
      'requestAddQuickTile': true,
      'controlCenterExtensionConfigured': true,
      'customReconnectBackoff': true,
      'onDemand': true,
      'alwaysOn': true,
      'alwaysOnEnabled': true,
      'lockdownEnabled': true,
      'killSwitch': true,
    });
    expect(value.optionsVersion, 1);
    expect(value.quickAccessSurfaces, [QuickAccessSurface.quickTile]);
    expect(
        value.requestAddQuickTile &&
            value.controlCenterExtensionConfigured &&
            value.customReconnectBackoff &&
            value.onDemand &&
            value.alwaysOn &&
            value.alwaysOnEnabled &&
            value.lockdownEnabled &&
            value.killSwitch,
        isTrue);
    expect(() => value.quickAccessSurfaces.add(QuickAccessSurface.menuBar),
        throwsUnsupportedError);
    expect(VlessCapabilities.fromMap({'onDemand': 'true'}).onDemand, isFalse);
    expect(VlessCapabilities.fromMap({}).optionsVersion, 0);
  });
}
