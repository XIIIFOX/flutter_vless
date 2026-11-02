// Copyright (c) 2024-2026 13FOX Studio / tfox.dev.
// SPDX-License-Identifier: MIT

/// Normalized connection state emitted by the active VLESS/Xray backend.
///
/// Native implementations can still expose their raw state string through
/// [VlessStatus.state]. Use this enum in application UI when you need stable
/// branching that is not tied to platform-specific casing or payload shape.
enum VlessConnectionState {
  /// The platform backend reports that the session is active.
  ///
  /// On Apple VPN sessions this includes the native worker and authenticated
  /// local listener being ready. Reachability depends on the caller's routing,
  /// DNS and remote servers; measure an allowed URL separately when required.
  connected,

  /// The platform backend is starting or attaching the runtime.
  connecting,

  /// No proxy or VPN/tunnel session is active.
  disconnected,

  /// The platform backend is stopping the active session.
  disconnecting,

  /// The backend emitted a state that is not recognized by this package.
  unknown;

  /// Converts a native state value into a normalized enum value.
  static VlessConnectionState parse(Object? value) {
    final normalized = value?.toString().trim().toUpperCase();
    return switch (normalized) {
      'CONNECTED' => VlessConnectionState.connected,
      'CONNECTING' => VlessConnectionState.connecting,
      'DISCONNECTED' => VlessConnectionState.disconnected,
      'DISCONNECTING' => VlessConnectionState.disconnecting,
      _ => VlessConnectionState.unknown,
    };
  }

  /// Uppercase wire value used by native status payloads.
  String get wireName {
    return switch (this) {
      VlessConnectionState.connected => 'CONNECTED',
      VlessConnectionState.connecting => 'CONNECTING',
      VlessConnectionState.disconnected => 'DISCONNECTED',
      VlessConnectionState.disconnecting => 'DISCONNECTING',
      VlessConnectionState.unknown => 'UNKNOWN',
    };
  }
}

/// Runtime status snapshot for the current proxy or VPN/tunnel session.
///
/// Platform implementations may send status events as legacy positional lists
/// or as maps. [VlessStatus.fromEvent] accepts both shapes and converts them
/// into this stable Dart model.
class VlessStatus {
  /// Number of seconds reported by the native runtime since session start.
  final int duration;

  /// Current upload speed reported by the native runtime.
  final int uploadSpeed;

  /// Current download speed reported by the native runtime.
  final int downloadSpeed;

  /// Total uploaded bytes reported by the native runtime.
  final int upload;

  /// Total downloaded bytes reported by the native runtime.
  final int download;

  /// Raw state string emitted by the platform backend.
  final String state;

  /// Normalized state parsed from [state].
  final VlessConnectionState connectionState;

  /// Creates a status snapshot.
  ///
  /// When [connectionState] is omitted, it is derived from [state].
  VlessStatus({
    this.duration = 0,
    this.uploadSpeed = 0,
    this.downloadSpeed = 0,
    this.upload = 0,
    this.download = 0,
    this.state = "DISCONNECTED",
    VlessConnectionState? connectionState,
  }) : connectionState = connectionState ?? VlessConnectionState.parse(state);

  /// Parses a map status payload from a native platform implementation.
  ///
  /// Both camelCase and snake_case speed keys are accepted for compatibility
  /// with older platform packages.
  factory VlessStatus.fromMap(Map<Object?, Object?> map) {
    final state = _readString(map, const ['state', 'status']) ??
        VlessConnectionState.disconnected.wireName;
    return VlessStatus(
      duration: _readInt(map, const ['duration']),
      uploadSpeed: _readInt(map, const ['uploadSpeed', 'upload_speed']),
      downloadSpeed: _readInt(map, const ['downloadSpeed', 'download_speed']),
      upload: _readInt(map, const ['upload']),
      download: _readInt(map, const ['download']),
      state: state,
    );
  }

  /// Parses the legacy positional EventChannel payload.
  ///
  /// Expected order: duration, upload speed, download speed, upload total,
  /// download total, and state.
  factory VlessStatus.fromList(List<Object?> values) {
    return VlessStatus(
      duration: _parseInt(_valueAt(values, 0)),
      uploadSpeed: _parseInt(_valueAt(values, 1)),
      downloadSpeed: _parseInt(_valueAt(values, 2)),
      upload: _parseInt(_valueAt(values, 3)),
      download: _parseInt(_valueAt(values, 4)),
      state: _valueAt(values, 5)?.toString() ??
          VlessConnectionState.disconnected.wireName,
    );
  }

  /// Parses any supported status event payload.
  ///
  /// Throws a [FormatException] when [event] is not a [VlessStatus], map, or
  /// positional list payload.
  factory VlessStatus.fromEvent(Object? event) {
    if (event is VlessStatus) {
      return event;
    }
    if (event is Map<Object?, Object?>) {
      return VlessStatus.fromMap(event);
    }
    if (event is List<Object?>) {
      return VlessStatus.fromList(event);
    }
    throw FormatException('Unsupported VLESS status payload: $event');
  }

  /// Attempts to parse [event] and returns `null` for unsupported shapes.
  static VlessStatus? tryParse(Object? event) {
    try {
      return VlessStatus.fromEvent(event);
    } on FormatException {
      return null;
    }
  }

  /// Converts this status to the stable map shape used in tests and logs.
  Map<String, Object> toMap() => {
        'duration': duration,
        'uploadSpeed': uploadSpeed,
        'downloadSpeed': downloadSpeed,
        'upload': upload,
        'download': download,
        'state': state,
      };

  @override
  String toString() {
    return 'VlessStatus('
        'duration: $duration, '
        'uploadSpeed: $uploadSpeed, '
        'downloadSpeed: $downloadSpeed, '
        'upload: $upload, '
        'download: $download, '
        'state: $state'
        ')';
  }

  @override
  bool operator ==(Object other) {
    return other is VlessStatus &&
        other.duration == duration &&
        other.uploadSpeed == uploadSpeed &&
        other.downloadSpeed == downloadSpeed &&
        other.upload == upload &&
        other.download == download &&
        other.state == state &&
        other.connectionState == connectionState;
  }

  @override
  int get hashCode => Object.hash(
        duration,
        uploadSpeed,
        downloadSpeed,
        upload,
        download,
        state,
        connectionState,
      );

  static Object? _valueAt(List<Object?> values, int index) {
    return index < values.length ? values[index] : null;
  }

  static int _readInt(Map<Object?, Object?> map, List<String> keys) {
    for (final key in keys) {
      if (map.containsKey(key)) {
        return _parseInt(map[key]);
      }
    }
    return 0;
  }

  static String? _readString(Map<Object?, Object?> map, List<String> keys) {
    for (final key in keys) {
      final value = map[key];
      if (value != null) {
        return value.toString();
      }
    }
    return null;
  }

  static int _parseInt(Object? value) {
    if (value is int) {
      return value;
    }
    if (value is num) {
      return value.toInt();
    }
    if (value is String) {
      return int.tryParse(value) ?? 0;
    }
    return 0;
  }
}
