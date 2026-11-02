/// Native actions remain available when the Flutter UI is not running.
enum VlessSystemAction {
  /// Toggle the saved, authorized VPN profile; explicit Stop disarms recovery.
  toggle,

  /// Open the host application without toggling the VPN.
  openApp
}

/// Action on the Android foreground notification's optional button.
enum VlessNotificationAction {
  /// Stop the session, subject to Android system Always-on restrictions.
  disconnect,

  /// Open the application without stopping the session.
  openApp,

  /// Omit the optional action button.
  none
}

/// Where to expose a quick VPN control.
enum QuickAccessSurface {
  /// Use the platform's default tile, menu bar, tray or iOS Control Center.
  platformDefault,

  /// Android Quick Settings tile; unsupported on other operating systems.
  quickTile,

  /// macOS menu-bar control, available while the application process runs.
  menuBar,

  /// Windows notification-area control, available while the application runs.
  systemTray,

  /// Apple Control Center control supplied by a configured host extension.
  controlCenter
}

/// Apple controls the timing of Network Extension on-demand reconnection.
enum OnDemandMode {
  /// Enable Apple On Demand when automatic reconnect is enabled.
  platformDefault,

  /// Request Apple On Demand; requires [ReconnectOptions.enabled].
  enabled,

  /// Disable OS relaunch while leaving worker retry settings independent.
  disabled
}

/// System always-on is configured by the device owner, never silently enabled.
enum AlwaysOnMode {
  /// Respect the device owner's existing Android Always-on setting.
  system,

  /// Require Android Always-on to be enabled; never change the OS setting.
  requireEnabled
}

/// Neither policy permits the plugin to silently weaken its VPN protection.
enum KillSwitchPolicy {
  /// Retain the platform adapter's mandatory VPN protection.
  platformDefault,

  /// Require the native backend to provide its supported VPN protection.
  required
}

/// Presentation of the Android foreground notification.
///
/// Icons are application drawable/mipmap resources, not Flutter widgets.
/// Other operating systems do not create an Android-style foreground notice.
class NotificationOptions {
  /// Creates Android notification settings; validate through [VlessOptions].
  const NotificationOptions({
    this.iconResourceType = 'mipmap',
    this.iconResourceName = 'ic_launcher',
    this.buttonLabel = 'DISCONNECT',
    this.action = VlessNotificationAction.disconnect,
  });

  /// Android resource directory: `mipmap` (default) or `drawable`.
  final String iconResourceType;
  /// Android resource name without an extension; defaults to `ic_launcher`.
  final String iconResourceName;
  /// Nonempty button text, at most 80 UTF-16 code units; defaults to `DISCONNECT`.
  final String buttonLabel;
  /// Optional notification-button behavior; defaults to disconnecting.
  final VlessNotificationAction action;

  /// Encodes this section for [VlessOptions.toMap].
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
  /// Creates disabled-by-default quick access; native support is capability-gated.
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

  /// Whether native quick access is authorized; defaults to false.
  final bool enabled;
  /// Requested control surface; unsupported explicit choices fail initialization.
  final QuickAccessSurface surface;
  /// Nonempty control label, at most 80 UTF-16 code units; defaults to `VPN`.
  final String label;
  /// Action performed by the control; defaults to toggling the saved VPN.
  final VlessSystemAction action;
  /// Require Android unlock or Apple local authentication before the action.
  ///
  /// Defaults to true. Cancellation performs no action; desktop controls already
  /// require access to the active desktop session.
  final bool requireUnlock;
  /// Android drawable name for the tile; excludes a path or file extension.
  final String androidIconResourceName;
  /// Nonempty SF Symbols name, at most 128 UTF-16 code units; defaults to `network`.
  final String appleSymbol;

  /// Optional absolute path to a Windows .ico image. Null uses the app icon.
  final String? windowsIconPath;

  /// Encodes this section without storing a VPN configuration or credentials.
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
/// Settings govern native workers while their service/provider survives. Apple
/// owns OS relaunch timing after the whole Network Extension terminates.
/// Check custom worker timing/attempt support with
/// [VlessCapabilities.customReconnectBackoff].
class ReconnectOptions {
  /// Creates worker recovery settings with one-second initial backoff.
  const ReconnectOptions({
    this.enabled = true,
    this.initialDelay = const Duration(seconds: 1),
    this.maxDelay = const Duration(seconds: 60),
    this.maxAttempts = 0,
  });

  /// Allow native worker retries after failure; defaults to true.
  final bool enabled;
  /// Initial retry delay, at least 100 ms; defaults to one second.
  final Duration initialDelay;
  /// Backoff ceiling, from [initialDelay] to ten minutes; defaults to 60 seconds.
  final Duration maxDelay;

  /// Retry limit from 0 to 1000; zero (the default) means unlimited retries.
  final int maxAttempts;

  /// Whether timing or attempts differ from the default native retry schedule.
  bool get hasCustomSchedule =>
      initialDelay != const Duration(seconds: 1) ||
      maxDelay != const Duration(seconds: 60) ||
      maxAttempts != 0;

  /// Encodes retry durations as milliseconds for the native adapter.
  Map<String, Object?> toMap() => {
        'enabled': enabled,
        'initialDelayMs': initialDelay.inMilliseconds,
        'maxDelayMs': maxDelay.inMilliseconds,
        'maxAttempts': maxAttempts,
      };
}

/// Requested protection guarantees, distinct from automatic reconnection.
class ProtectionOptions {
  /// Creates mandatory VPN protection with platform-default On Demand.
  const ProtectionOptions({
    this.killSwitch = KillSwitchPolicy.required,
    this.onDemand = OnDemandMode.platformDefault,
    this.alwaysOn = AlwaysOnMode.system,
  });

  /// Required protection policy; neither value enables an unprotected fallback.
  final KillSwitchPolicy killSwitch;
  /// Apple OS relaunch policy; explicit enablement requires automatic reconnect.
  final OnDemandMode onDemand;
  /// Android OS Always-on requirement; the plugin never enables it itself.
  final AlwaysOnMode alwaysOn;

  /// Encodes requested protection policies; availability is checked natively.
  Map<String, Object?> toMap() => {
        'killSwitch': killSwitch.name,
        'onDemand': onDemand.name,
        'alwaysOn': alwaysOn.name,
      };
}

/// Bounds for privacy-filtered diagnostics. Raw Xray credentials/configuration
/// logging cannot be enabled through these options.
class DiagnosticsOptions {
  /// Creates bounded diagnostic collection, enabled by default.
  const DiagnosticsOptions({
    this.enabled = true,
    this.maxBytes = 128 * 1024,
    this.maxLines = 300,
  });

  /// Collect bounded diagnostics; disabling also clears retained native buffers.
  final bool enabled;
  /// Byte limit from 4096 to 131072; defaults to 131072 (128 KiB).
  final int maxBytes;
  /// Line limit from 1 to 300; defaults to 300. Native snapshots may be smaller.
  final int maxLines;

  /// Encodes collection limits without enabling raw configuration logging.
  Map<String, Object?> toMap() => {
        'enabled': enabled,
        'maxBytes': maxBytes,
        'maxLines': maxLines,
      };
}

/// Immutable instance settings. Server configuration remains on startVless.
class VlessOptions {
  /// Creates native settings for initialization; server JSON is supplied on Start.
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

  /// Android foreground-notification presentation and action.
  final NotificationOptions notification;
  /// Native quick-control presentation and authorization.
  final QuickAccessOptions quickAccess;
  /// Worker recovery policy for the next explicit connection.
  final ReconnectOptions reconnect;
  /// Protection and OS recovery policy for the next explicit connection.
  final ProtectionOptions protection;
  /// Privacy-filtered native diagnostic collection and limits.
  final DiagnosticsOptions diagnostics;

  /// Throws [ArgumentError] for invalid text, resources, limits or policy pairs.
  ///
  /// This validates values only. Native capabilities and host extension setup
  /// are checked separately during initialization and startup.
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

  /// Validates and encodes the versioned, non-secret native settings contract.
  ///
  /// Throws [ArgumentError] when [validate] rejects a value.
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

  /// Whether settings can use the legacy native initialization contract.
  ///
  /// Presentation fields of disabled quick access do not affect this result.
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
  /// Creates a capability snapshot; defaults describe an older/unknown backend.
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

  /// Supported typed-options schema; zero means unavailable, currently one is used.
  final int optionsVersion;
  /// Control surfaces implemented by this backend and host integration.
  final List<QuickAccessSurface> quickAccessSurfaces;
  /// Whether Android can show its foreground Add Quick Tile system dialog.
  final bool requestAddQuickTile;
  /// Whether the host Apple Control Center extension is configured.
  final bool controlCenterExtensionConfigured;
  /// Whether worker retry timing and attempt limits are configurable.
  ///
  /// Apple still owns relaunch scheduling after the whole extension terminates.
  final bool customReconnectBackoff;
  /// Whether Apple-style OS On Demand policy is implemented.
  final bool onDemand;
  /// Whether the backend can inspect/enforce Android Always-on requirements.
  final bool alwaysOn;
  /// Current Android OS Always-on state for this VPN application.
  final bool alwaysOnEnabled;
  /// Current Android OS setting to block traffic outside the VPN.
  final bool lockdownEnabled;
  /// Whether mandatory traffic protection is implemented by the backend.
  ///
  /// This is a feature report, not a guarantee that capture survives an entire
  /// process/provider crash; system lockdown and platform limits still apply.
  final bool killSwitch;

  /// Decodes known native fields, ignoring unknown surfaces and using safe defaults.
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

/// Result of Android's Add Quick Tile system request.
///
/// Adding a tile does not connect the VPN or authorize a saved profile.
enum QuickTileAddResult {
  /// The user accepted adding the tile.
  added,

  /// The system reports that the tile is already present.
  alreadyAdded,

  /// The user declined or dismissed the system request.
  declined,

  /// The platform, OS version or active host cannot perform this request.
  unsupported
}
