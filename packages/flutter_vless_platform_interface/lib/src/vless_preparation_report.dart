/// The configuration boundary covered by a native preparation report.
enum VlessPreparationScope {
  /// The backend did not provide a supported report.
  unavailable,

  /// Checked in the host process; a VPN provider may prepare it further.
  host,

  /// Checked after preparation of the configuration used by the native runtime.
  runtimeFinal
}

/// A Core check is separate from socket readiness or a working connection.
enum VlessCoreCheck {
  /// The backend cannot report whether Core validation ran.
  unavailable,

  /// Preparation was reported without running Core validation.
  notRun,

  /// Core accepted the configuration at the reported preparation boundary.
  passed,

  /// Core rejected the configuration at the reported preparation boundary.
  failed
}

/// Instrumented edits to typed Xray fields. Unknown/opaque user data is never
/// compared or included in this list.
enum VlessPreparationChange {
  /// Relative TLS certificate/key references were bound to the supplied directory.
  certificateRefsBound('certificate_refs_bound'),

  /// A session-owned authenticated local input was added.
  privateListenerAdded('private_listener_added'),

  /// Private system-DNS forwarding rules were added.
  systemDnsGuardAdded('system_dns_guard_added'),

  /// The native adapter applied its restricted runtime logging policy.
  privateLoggingApplied('private_logging_applied'),

  /// Core-style port environment references were resolved.
  portEnvironmentBound('port_environment_bound'),

  /// Core-style address environment references were resolved.
  addressEnvironmentBound('address_environment_bound'),

  /// A legacy TLS `allowInsecure` override was removed from a typed TLS owner.
  tlsOverrideRemoved('tls_override_removed'),

  /// A supported legacy transport/settings alias was normalized.
  streamAliasNormalized('stream_alias_normalized');

  const VlessPreparationChange(this.wireName);

  /// Stable code used in native replies and [VlessPreparationReport.toMap].
  final String wireName;
}

/// A value-only, per-start report. It contains no configuration values, names,
/// addresses, paths or configuration fingerprints. A successful Core check
/// does not assert that the session has connected or can reach the internet.
///
/// [changes] covers the instrumented operations at [scope], plus shared Dart
/// compatibility edits. It is not a general diff or a list of all Core defaults.
final class VlessPreparationReport {
  /// Creates a report with an immutable, deduplicated set of [changes].
  VlessPreparationReport({
    required this.scope,
    required this.coreCheck,
    Iterable<VlessPreparationChange> changes = const [],
  }) : changes = Set.unmodifiable(changes);

  /// Creates the explicit result for older or uninstrumented backends.
  const VlessPreparationReport.unavailable()
      : scope = VlessPreparationScope.unavailable,
        coreCheck = VlessCoreCheck.unavailable,
        changes = const {};

  /// Native preparation boundary represented by this report.
  final VlessPreparationScope scope;

  /// Core validation result, independent of connection or Internet readiness.
  final VlessCoreCheck coreCheck;

  /// Instrumented edits at [scope], including shared Dart compatibility edits.
  final Set<VlessPreparationChange> changes;

  /// Decode only this closed contract; never retain arbitrary native fields.
  ///
  /// [reply] is a native Start reply containing a version-1 `preparationReport`
  /// object, rather than the report object alone.
  /// Invalid or unsupported replies produce [VlessPreparationReport.unavailable].
  /// Unknown change codes are ignored for forward compatibility.
  factory VlessPreparationReport.fromNativeReply(Object? reply) {
    const unavailable = VlessPreparationReport.unavailable();
    if (reply is! Map) return unavailable;
    final report = reply['preparationReport'];
    if (report is! Map || report['version'] is! int || report['version'] != 1) {
      return unavailable;
    }
    final scope = _named(VlessPreparationScope.values, report['scope']);
    final check = _named(VlessCoreCheck.values, report['coreCheck']);
    final changes = report['changes'];
    if (scope == null ||
        check == null ||
        changes is! List ||
        changes.any((value) => value is! String) ||
        (scope == VlessPreparationScope.unavailable &&
            check != VlessCoreCheck.unavailable)) {
      return unavailable;
    }
    return VlessPreparationReport(
      scope: scope,
      coreCheck: check,
      changes: VlessPreparationChange.values
          .where((value) => changes.contains(value.wireName)),
    );
  }

  /// Returns a new report with [additional] changes, preserving this report.
  VlessPreparationReport withChanges(
          Iterable<VlessPreparationChange> additional) =>
      VlessPreparationReport(
          scope: scope,
          coreCheck: coreCheck,
          changes: {...changes, ...additional});

  /// Encodes the versioned report using enum-order change codes.
  Map<String, Object> toMap() => {
        'version': 1,
        'scope': scope.name,
        'coreCheck': coreCheck.name,
        'changes': [
          for (final value in VlessPreparationChange.values)
            if (changes.contains(value)) value.wireName,
        ],
      };
}

T? _named<T extends Enum>(List<T> values, Object? name) {
  for (final value in values) {
    if (value.name == name) return value;
  }
  return null;
}

/// Safe native failure location. Core stdout/stderr and arbitrary native
/// exception messages are deliberately outside this contract.
final class VlessConfigurationFailure {
  VlessConfigurationFailure._(this.stage, this.section, this.index);

  /// Recognized native failure stages; arbitrary error strings are rejected.
  static const stages = {
    'prepare',
    'core-check',
    'persist',
    'start',
    'privacy',
    'decode',
    'build',
    'internal',
    'environment-policy',
    'active-session',
    'port-environment',
    'certificate-assets',
    'routing',
    'capability',
  };

  /// Closed failure stage identifying preparation, validation or startup work.
  final String stage;

  /// Qualified `inbounds` or `outbounds` location, or null when unavailable.
  final String? section;

  /// Zero-based entry index at the native failure boundary, if qualified.
  ///
  /// A final-runtime index can refer to an adapter-generated entry.
  final int? index;

  /// Reads safe native exception details, returning null for an unknown stage.
  ///
  /// Pass the channel exception's `details` map as [details].
  /// Invalid section/index pairs are omitted; raw messages and other fields are
  /// never retained. Legacy port failures map `inboundIndex` to `inbounds`.
  static VlessConfigurationFailure? fromDetails(Object? details) {
    if (details is! Map || !stages.contains(details['stage'])) return null;
    final portLocation = details['stage'] == 'port-environment' &&
        !details.containsKey('section');
    final section = portLocation ? 'inbounds' : details['section'];
    final index = portLocation ? details['inboundIndex'] : details['index'];
    final located = (section == 'inbounds' || section == 'outbounds') &&
        index is int &&
        index >= 0 &&
        index <= 2147483647;
    return VlessConfigurationFailure._(details['stage'] as String,
        located ? section as String : null, located ? index : null);
  }

  /// Encodes only the validated stage and optional section/index location.
  Map<String, Object> toMap() => {
        'stage': stage,
        if (section != null) 'section': section!,
        if (index != null) 'index': index!,
      };
}
