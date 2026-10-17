/// Native actions remain available when the Flutter UI is not running.
enum VlessSystemAction { toggle, openApp }

/// Action on the Android foreground notification's optional button.
enum VlessNotificationAction { disconnect, openApp, none }

/// Where to expose a quick VPN control.
enum QuickAccessSurface {
  platformDefault,
  quickTile,
  menuBar,
  systemTray,
  controlCenter
}

/// Apple controls the timing of Network Extension on-demand reconnection.
enum OnDemandMode { platformDefault, enabled, disabled }

/// System always-on is configured by the device owner, never silently enabled.
enum AlwaysOnMode { system, requireEnabled }

/// Neither policy permits the plugin to silently weaken its VPN protection.
enum KillSwitchPolicy { platformDefault, required }

/// Presentation of the Android foreground notification.
///
/// Icons are application drawable/mipmap resources, not Flutter widgets.
/// Other operating systems do not create an Android-style foreground notice.
class NotificationOptions {
  const NotificationOptions({
    this.iconResourceType = 'mipmap',
    this.iconResourceName = 'ic_launcher',
    this.buttonLabel = 'DISCONNECT',
    this.action = VlessNotificationAction.disconnect,
  });

  final String iconResourceType;
  final String iconResourceName;
  final String buttonLabel;
  final VlessNotificationAction action;

  Map<String, Object?> toMap() => {
        'iconResourceType': iconResourceType,
        'iconResourceName': iconResourceName,
        'buttonLabel': buttonLabel,
        'action': action.name,
      };
}

/// A native VPN toggle: Android tile, desktop menu/tray, or Apple control.
///
/// Disabled by default. Apple Control Center needs a host Widget extension.
/// Desktop menu/tray controls require the application process to remain alive.
class QuickAccessOptions {
  const QuickAccessOptions({
    this.enabled = false,
    this.surface = QuickAccessSurface.platformDefault,
    this.label = 'VPN',
    this.action = VlessSystemAction.toggle,
    this.requireUnlock = true,
    this.androidIconResourceName = 'flutter_vless_ic_quick_tile',
    this.appleSymbol = 'network',
    this.windowsIconPath,
  });

  final bool enabled;
  final QuickAccessSurface surface;
  final String label;
  final VlessSystemAction action;
  final bool requireUnlock;
  final String androidIconResourceName;
  final String appleSymbol;

  /// Optional absolute path to a Windows .ico image. Null uses the app icon.
  final String? windowsIconPath;

  Map<String, Object?> toMap() => {
        'enabled': enabled,
        'surface': surface.name,
        'label': label,
        'action': action.name,
        'requireUnlock': requireUnlock,
        'androidIconResourceName': androidIconResourceName,
        'appleSymbol': appleSymbol,
        if (windowsIconPath != null) 'windowsIconPath': windowsIconPath,
      };
}

/// Android-friendly spelling of the cross-platform quick-access settings.
typedef QuickTileOptions = QuickAccessOptions;

/// Recovery after an unexpected runtime failure or physical network change.
///
/// An explicit Stop always disarms recovery. Disabling automatic recovery does
/// not release a captured VPN interface or its traffic protection.
/// Apple Network Extension owns its retry schedule; custom timing/attempt
/// limits must be checked against [VlessCapabilities.customReconnectBackoff].
class ReconnectOptions {
  const ReconnectOptions({
    this.enabled = true,
    this.initialDelay = const Duration(seconds: 1),
    this.maxDelay = const Duration(seconds: 60),
    this.maxAttempts = 0,
  });

  final bool enabled;
  final Duration initialDelay;
  final Duration maxDelay;

  /// Zero means unlimited retries.
  final int maxAttempts;

  bool get hasCustomSchedule =>
      initialDelay != const Duration(seconds: 1) ||
      maxDelay != const Duration(seconds: 60) ||
      maxAttempts != 0;

  Map<String, Object?> toMap() => {
        'enabled': enabled,
        'initialDelayMs': initialDelay.inMilliseconds,
        'maxDelayMs': maxDelay.inMilliseconds,
        'maxAttempts': maxAttempts,
      };
}

/// Requested protection guarantees, distinct from automatic reconnection.
class ProtectionOptions {
  const ProtectionOptions({
    this.killSwitch = KillSwitchPolicy.required,
    this.onDemand = OnDemandMode.platformDefault,
    this.alwaysOn = AlwaysOnMode.system,
  });

  final KillSwitchPolicy killSwitch;
  final OnDemandMode onDemand;
  final AlwaysOnMode alwaysOn;

  Map<String, Object?> toMap() => {
        'killSwitch': killSwitch.name,
        'onDemand': onDemand.name,
        'alwaysOn': alwaysOn.name,
      };
}

/// Bounds for privacy-filtered diagnostics. Raw Xray credentials/configuration
/// logging cannot be enabled through these options.
class DiagnosticsOptions {
  const DiagnosticsOptions({
    this.enabled = true,
    this.maxBytes = 128 * 1024,
    this.maxLines = 300,
  });

  final bool enabled;
  final int maxBytes;
  final int maxLines;

  Map<String, Object?> toMap() => {
        'enabled': enabled,
        'maxBytes': maxBytes,
        'maxLines': maxLines,
      };
}

/// Immutable instance settings. Server configuration remains on startVless.
class VlessOptions {
  const VlessOptions({
    this.notification = const NotificationOptions(),
    this.quickAccess = const QuickAccessOptions(),
    this.reconnect = const ReconnectOptions(),
    this.protection = const ProtectionOptions(),
    this.diagnostics = const DiagnosticsOptions(),
  });

  /// Restores non-secret settings saved with [toMap]. Unknown fields are ignored;
  /// malformed values and unsupported schema versions fail before native calls.
  factory VlessOptions.fromMap(Map<String, Object?> map) {
    Never invalid(String key) =>
        throw ArgumentError.value(key, 'options', 'Invalid saved option');
    Map<String, Object?> section(String key) {
      if (!map.containsKey(key)) return const {};
      final value = map[key];
      if (value is! Map) invalid(key);
      return Map<String, Object?>.from(value);
    }

    String text(Map<String, Object?> values, String key, String fallback) {
      if (!values.containsKey(key)) return fallback;
      final value = values[key];
      if (value is! String) invalid(key);
      return value;
    }

    bool flag(Map<String, Object?> values, String key, bool fallback) {
      if (!values.containsKey(key)) return fallback;
      final value = values[key];
      if (value is! bool) invalid(key);
      return value;
    }

    int number(Map<String, Object?> values, String key, int fallback) {
      if (!values.containsKey(key)) return fallback;
      final value = values[key];
      if (value is! num ||
          !value.isFinite ||
          value < -1000000000 ||
          value > 1000000000 ||
          value != value.toInt()) {
        invalid(key);
      }
      return value.toInt();
    }

    if (number(map, 'version', 1) != 1) invalid('version');
    final n = section('notification'),
        q = section('quickAccess'),
        r = section('reconnect'),
        p = section('protection'),
        d = section('diagnostics');
    final path = q['windowsIconPath'];
    if (path != null && path is! String) invalid('windowsIconPath');
    final result = VlessOptions(
      notification: NotificationOptions(
          iconResourceType: text(n, 'iconResourceType', 'mipmap'),
          iconResourceName: text(n, 'iconResourceName', 'ic_launcher'),
          buttonLabel: text(n, 'buttonLabel', 'DISCONNECT'),
          action: VlessNotificationAction.values
              .byName(text(n, 'action', 'disconnect'))),
      quickAccess: QuickAccessOptions(
          enabled: flag(q, 'enabled', false),
          surface: QuickAccessSurface.values
              .byName(text(q, 'surface', 'platformDefault')),
          label: text(q, 'label', 'VPN'),
          action: VlessSystemAction.values.byName(text(q, 'action', 'toggle')),
          requireUnlock: flag(q, 'requireUnlock', true),
          androidIconResourceName:
              text(q, 'androidIconResourceName', 'flutter_vless_ic_quick_tile'),
          appleSymbol: text(q, 'appleSymbol', 'network'),
          windowsIconPath: path as String?),
      reconnect: ReconnectOptions(
          enabled: flag(r, 'enabled', true),
          initialDelay:
              Duration(milliseconds: number(r, 'initialDelayMs', 1000)),
          maxDelay: Duration(milliseconds: number(r, 'maxDelayMs', 60000)),
          maxAttempts: number(r, 'maxAttempts', 0)),
      protection: ProtectionOptions(
          killSwitch:
              KillSwitchPolicy.values.byName(text(p, 'killSwitch', 'required')),
          onDemand: OnDemandMode.values
              .byName(text(p, 'onDemand', 'platformDefault')),
          alwaysOn: AlwaysOnMode.values.byName(text(p, 'alwaysOn', 'system'))),
      diagnostics: DiagnosticsOptions(
          enabled: flag(d, 'enabled', true),
          maxBytes: number(d, 'maxBytes', 131072),
          maxLines: number(d, 'maxLines', 300)),
    );
    result.validate();
    return result;
  }

  final NotificationOptions notification;
  final QuickAccessOptions quickAccess;
  final ReconnectOptions reconnect;
  final ProtectionOptions protection;
  final DiagnosticsOptions diagnostics;

  void validate() {
    void text(String value, String name, int max) {
      if (value.trim().isEmpty ||
          value.length > max ||
          value.contains(RegExp(r'[\x00-\x1f\x7f]'))) {
        throw ArgumentError.value(value, name, 'Invalid native UI text');
      }
    }

    void resource(String value, String name) {
      if (value.length > 128 ||
          value.contains(RegExp(r'[\x00-\x1f\x7f]')) ||
          !RegExp(r'^[a-zA-Z_][a-zA-Z0-9_]*$').hasMatch(value)) {
        throw ArgumentError.value(
            value, name, 'Expected an Android resource name');
      }
    }

    if (!['mipmap', 'drawable'].contains(notification.iconResourceType)) {
      throw ArgumentError.value(
          notification.iconResourceType, 'iconResourceType');
    }
    resource(notification.iconResourceName, 'iconResourceName');
    resource(quickAccess.androidIconResourceName, 'androidIconResourceName');
    text(notification.buttonLabel, 'buttonLabel', 80);
    text(quickAccess.label, 'quickAccess.label', 80);
    text(quickAccess.appleSymbol, 'appleSymbol', 128);
    final path = quickAccess.windowsIconPath;
    if (path != null &&
        (!RegExp(r'^(?:[a-zA-Z]:[\\/]|\\\\)').hasMatch(path) ||
            !path.toLowerCase().endsWith('.ico') ||
            path.contains('\u0000'))) {
      throw ArgumentError.value(
          path, 'windowsIconPath', 'Expected an absolute .ico path');
    }
    final initial = reconnect.initialDelay.inMilliseconds;
    final maximum = reconnect.maxDelay.inMilliseconds;
    if (initial < 100 ||
        maximum < initial ||
        maximum > 600000 ||
        reconnect.maxAttempts < 0 ||
        reconnect.maxAttempts > 1000) {
      throw ArgumentError('Invalid reconnect timing or attempt limit');
    }
    if (!reconnect.enabled && protection.onDemand == OnDemandMode.enabled) {
      throw ArgumentError('On Demand requires automatic reconnect');
    }
    if (diagnostics.maxBytes < 4096 ||
        diagnostics.maxBytes > 128 * 1024 ||
        diagnostics.maxLines < 1 ||
        diagnostics.maxLines > 300) {
      throw ArgumentError('Diagnostics limits exceed the supported bounds');
    }
  }

  Map<String, Object?> toMap() {
    validate();
    return {
      'version': 1,
      'notification': notification.toMap(),
      'quickAccess': quickAccess.toMap(),
      'reconnect': reconnect.toMap(),
      'protection': protection.toMap(),
      'diagnostics': diagnostics.toMap(),
    };
  }

  bool get isDefault =>
      notification.iconResourceType == 'mipmap' &&
      notification.iconResourceName == 'ic_launcher' &&
      notification.buttonLabel == 'DISCONNECT' &&
      notification.action == VlessNotificationAction.disconnect &&
      !quickAccess.enabled &&
      reconnect.enabled &&
      !reconnect.hasCustomSchedule &&
      protection.killSwitch == KillSwitchPolicy.required &&
      protection.onDemand == OnDemandMode.platformDefault &&
      protection.alwaysOn == AlwaysOnMode.system &&
      diagnostics.enabled &&
      diagnostics.maxBytes == 128 * 1024 &&
      diagnostics.maxLines == 300;
}

/// Features implemented by the loaded native backend, not just by the OS.
class VlessCapabilities {
  const VlessCapabilities({
    this.optionsVersion = 0,
    this.quickAccessSurfaces = const [],
    this.requestAddQuickTile = false,
    this.controlCenterExtensionConfigured = false,
    this.customReconnectBackoff = false,
    this.onDemand = false,
    this.alwaysOn = false,
    this.alwaysOnEnabled = false,
    this.lockdownEnabled = false,
    this.killSwitch = false,
  });

  final int optionsVersion;
  final List<QuickAccessSurface> quickAccessSurfaces;
  final bool requestAddQuickTile;
  final bool controlCenterExtensionConfigured;
  final bool customReconnectBackoff;
  final bool onDemand;
  final bool alwaysOn;
  final bool alwaysOnEnabled;
  final bool lockdownEnabled;
  final bool killSwitch;

  factory VlessCapabilities.fromMap(Map<Object?, Object?> map) {
    final rawSurfaces = map['quickAccessSurfaces'];
    return VlessCapabilities(
      optionsVersion:
          map['optionsVersion'] is int ? map['optionsVersion'] as int : 0,
      quickAccessSurfaces: List.unmodifiable(QuickAccessSurface.values.where(
          (surface) =>
              rawSurfaces is List && rawSurfaces.contains(surface.name))),
      requestAddQuickTile: map['requestAddQuickTile'] == true,
      controlCenterExtensionConfigured:
          map['controlCenterExtensionConfigured'] == true,
      customReconnectBackoff: map['customReconnectBackoff'] == true,
      onDemand: map['onDemand'] == true,
      alwaysOn: map['alwaysOn'] == true,
      alwaysOnEnabled: map['alwaysOnEnabled'] == true,
      lockdownEnabled: map['lockdownEnabled'] == true,
      killSwitch: map['killSwitch'] == true,
    );
  }
}

enum QuickTileAddResult { added, alreadyAdded, declined, unsupported }
