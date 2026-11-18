/// Features of the Core installed for the current backend.
///
/// Older and custom backends report only the capabilities they can verify.
/// A version alone cannot advertise a feature that needs a native bridge.
final class VlessCoreCapabilities {
  /// Creates a conservative capability snapshot.
  const VlessCoreCapabilities({
    this.coreVersion,
    this.profileValidation = false,
    this.vpnRouting = false,
    this.geoDataUpdates = false,
    this.xdrive = false,
    this.balancerSelections = false,
  });

  /// Core version in `major.minor.patch` format when the backend can report it.
  final String? coreVersion;

  /// Whether the backend can check a profile without connecting.
  final bool profileValidation;

  /// Whether the Core supports the plugin's native VPN routing bridge.
  final bool vpnRouting;

  /// Whether managed GeoDAT updates follow the lifetime of the VPN or proxy.
  final bool geoDataUpdates;

  /// Whether managed XDRIVE storage and workers follow the session lifetime.
  final bool xdrive;

  /// Whether the Core can record private balancer selections.
  final bool balancerSelections;

  static final _version =
      RegExp(r'^(?:Xray )?v?(\d{1,9}\.\d{1,9}\.\d{1,9})(?:\s|$)');

  /// Decodes known capability fields and discards the Core's banner text.
  factory VlessCoreCapabilities.fromNativeReply(Object? reply) {
    if (reply is! Map) return const VlessCoreCapabilities();
    final version = reply['coreVersion'];
    return VlessCoreCapabilities(
      coreVersion: version is String && version.length <= 512
          ? _version.firstMatch(version)?.group(1)
          : null,
      profileValidation: reply['profileValidation'] == true,
      vpnRouting: reply['vpnRouting'] == true,
      geoDataUpdates: reply['geoDataUpdates'] == true,
      xdrive: reply['xdrive'] == true,
      balancerSelections: reply['balancerSelections'] == true,
    );
  }
}

/// Outcome of inspecting one authored profile without opening a connection.
enum VlessProfileValidationStatus {
  /// The installed Core accepted the prepared configuration.
  valid,

  /// The input, its file references or the Core configuration were rejected.
  invalid,

  /// A required capability is absent on the installed backend or Core.
  unsupported,

  /// The backend did not produce a usable check result.
  unavailable,
}

/// Where an invalid profile was rejected.
enum VlessProfileValidationStage {
  /// Decode, normalization or asset preparation failed.
  prepare,

  /// The private input for the Core check could not be written.
  persist,

  /// The installed Core rejected the configuration.
  coreCheck,
}

/// Authored list that contains a rejected entry.
enum VlessProfileSection {
  /// An entry in `inbounds`.
  inbounds,

  /// An entry in `outbounds`.
  outbounds,
}

/// A private, value-only result. No profile values or native messages are kept.
final class VlessProfileValidation {
  /// Creates an inspection result with an optional closed failure location.
  const VlessProfileValidation(this.status,
      {this.stage, this.section, this.index});

  /// Whether profile inspection succeeded, failed or was unavailable.
  final VlessProfileValidationStatus status;

  /// Optional rejection stage for an invalid profile.
  final VlessProfileValidationStage? stage;

  /// List containing the rejected entry, when the backend identifies one.
  final VlessProfileSection? section;

  /// Zero-based index of the rejected entry in [section].
  final int? index;

  /// Decodes the closed wire contract. Unknown replies cannot report success.
  factory VlessProfileValidation.fromNativeReply(Object? reply) {
    const unavailable =
        VlessProfileValidation(VlessProfileValidationStatus.unavailable);
    if (reply is! Map) return unavailable;
    final status =
        _enumByName(VlessProfileValidationStatus.values, reply['status']);
    if (status == null) return unavailable;
    if (status != VlessProfileValidationStatus.invalid) {
      return VlessProfileValidation(status);
    }
    final stage =
        _enumByName(VlessProfileValidationStage.values, reply['stage']);
    final section = _enumByName(VlessProfileSection.values, reply['section']);
    final index = reply['index'];
    final hasLocation =
        section != null && index is int && index >= 0 && index <= 2147483647;
    return VlessProfileValidation(status,
        stage: stage,
        section: hasLocation ? section : null,
        index: hasLocation ? index : null);
  }
}

T? _enumByName<T extends Enum>(List<T> values, Object? name) {
  for (final value in values) {
    if (value.name == name) return value;
  }
  return null;
}
