/// One session-local selection made by Xray for a new balanced connection.
///
/// The only recorded values are ordinals. The selection carries no names,
/// addresses, timestamps, credentials, or traffic data.
final class BalancerSelection {
  /// Creates a selection from one-based ordinals.
  const BalancerSelection({
    required this.sequence,
    required this.group,
    required this.node,
  });

  /// Order in which the current runtime recorded the selection.
  final int sequence;

  /// The balancer's one-based position in the runtime configuration.
  final int group;

  /// The selected outbound's one-based position in the runtime configuration.
  final int node;
}
