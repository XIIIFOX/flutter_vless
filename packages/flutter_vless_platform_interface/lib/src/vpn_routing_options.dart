/// Routing choices for one VPN session, separate from the supplied Xray JSON.
///
/// These require a native runtime built with VPN routing support. Unsupported
/// runtimes reject the request before replacing the current session. Omit this
/// option to retain the ordinary adapter path.
class VpnRoutingOptions {
  const VpnRoutingOptions({this.sourceInboundIndex, this.defaultOutboundTag});

  /// An index into the ORIGINAL configuration's `inbounds` array, starting at
  /// zero. VPN traffic uses that input's inbound-tag context without editing its
  /// listener, accounts or rules. Null retains the private adapter's context.
  final int? sourceInboundIndex;

  /// The exact outbound tag used when the caller's routing rules have no match.
  /// Existing matching rules, balancers and chains retain their behavior.
  /// Null or empty keeps Core's ordinary default outbound selection.
  final String? defaultOutboundTag;

  void validate() {
    final index = sourceInboundIndex;
    if (index != null && (index < 0 || index > 2147483647)) {
      throw ArgumentError(
          'sourceInboundIndex must be a non-negative 32-bit index.');
    }
  }

  /// A fresh selection-only map. Runtime credentials and generated metadata
  /// belong to the native session and are never part of this option.
  Map<String, Object?> toMap() {
    validate();
    return {
      if (sourceInboundIndex != null) 'sourceInboundIndex': sourceInboundIndex,
      if (defaultOutboundTag != null) 'defaultOutboundTag': defaultOutboundTag,
    };
  }

  @override
  String toString() => 'VpnRoutingOptions(<private>)';
}
