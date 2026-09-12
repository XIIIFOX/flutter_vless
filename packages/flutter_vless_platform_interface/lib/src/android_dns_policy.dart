/// How Android handles the system resolver advertised by the VPN.
enum AndroidDnsPolicy {
  /// Preserve the routing and DNS semantics of the supplied Xray config.
  config,

  /// Route virtual system DNS over TCP through the selected proxy outbound.
  proxy,
}
