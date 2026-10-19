/// The configuration boundary covered by a native preparation report.
enum VlessPreparationScope { unavailable, host, runtimeFinal }

/// A Core check is separate from socket readiness or a working connection.
enum VlessCoreCheck { unavailable, notRun, passed, failed }

/// Instrumented edits to typed Xray fields. Unknown/opaque user data is never
/// compared or included in this list.
enum VlessPreparationChange {
  certificateRefsBound('certificate_refs_bound'),
  privateListenerAdded('private_listener_added'),
  systemDnsGuardAdded('system_dns_guard_added'),
  privateLoggingApplied('private_logging_applied'),
  portEnvironmentBound('port_environment_bound'),
  addressEnvironmentBound('address_environment_bound'),
  tlsOverrideRemoved('tls_override_removed'),
  streamAliasNormalized('stream_alias_normalized');

  const VlessPreparationChange(this.wireName);
  final String wireName;
}

/// A value-only, per-start report. It contains no configuration values, names,
/// addresses, paths or configuration fingerprints. A successful Core check
/// does not assert that the session has connected or can reach the internet.
///
/// [changes] covers the instrumented operations at [scope], plus shared Dart
/// compatibility edits. It is not a general diff or a list of all Core defaults.
final class VlessPreparationReport {
  VlessPreparationReport({
    required this.scope,
    required this.coreCheck,
    Iterable<VlessPreparationChange> changes = const [],
  }) : changes = Set.unmodifiable(changes);

  const VlessPreparationReport.unavailable()
      : scope = VlessPreparationScope.unavailable,
        coreCheck = VlessCoreCheck.unavailable,
        changes = const {};

  final VlessPreparationScope scope;
  final VlessCoreCheck coreCheck;
  final Set<VlessPreparationChange> changes;

  /// Decode only this closed contract; never retain arbitrary native fields.
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

  VlessPreparationReport withChanges(
          Iterable<VlessPreparationChange> additional) =>
      VlessPreparationReport(
          scope: scope,
          coreCheck: coreCheck,
          changes: {...changes, ...additional});

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

  final String stage;
  final String? section;
  final int? index;

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

  Map<String, Object> toMap() => {
        'stage': stage,
        if (section != null) 'section': section!,
        if (index != null) 'index': index!,
      };
}
