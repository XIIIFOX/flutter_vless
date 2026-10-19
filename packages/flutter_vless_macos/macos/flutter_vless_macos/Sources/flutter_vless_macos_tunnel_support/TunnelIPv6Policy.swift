import Foundation
import NetworkExtension
import Darwin
import flutter_vless_macos_privacy

/// Capture IPv6 through the same Core routing policy as IPv4. The underlay
/// bootstrap remains separate from the logical destination address family.
public enum TunnelIPv6Policy {
    public static let address = "fd00:198:18::1"
    public static let blockTag = "flutter-vless-ipv6-block"

    public static func networkSettings(proxyAddresses: [String]) -> NEIPv6Settings {
        let settings = NEIPv6Settings(addresses: [address], networkPrefixLengths: [64])
        settings.includedRoutes = [NEIPv6Route.default()]
        settings.excludedRoutes = proxyAddresses.filter { value in
            var address = in6_addr()
            return value.withCString { inet_pton(AF_INET6, $0, &address) } == 1
        }.map { NEIPv6Route(destinationAddress: $0, networkPrefixLength: 128) }
        return settings
    }

    static func apply(to config: inout [String: Any], managedInboundTag: String? = nil) -> Bool {
        // FakeDNS virtual pools require their own qualified packet mapping.
        guard !config.keys.contains(where: { XrayJSONField.matches($0, "fakeDns") }) else { return false }
        // Keep literal targets while using the sniffed RouteTarget for caller
        // domain rules. Do not insert a library IPv6 routing override.
        if var inbounds = config["inbounds"] as? [[String: Any]] {
            for index in inbounds.indices {
                if let managedInboundTag, inbounds[index]["tag"] as? String != managedInboundTag { continue }
                let proto = (inbounds[index]["protocol"] as? String ?? "").lowercased()
                guard proto == "socks" || proto == "http" else { continue }
                var sniffing = inbounds[index]["sniffing"] as? [String: Any] ?? [:]
                sniffing["routeOnly"] = true
                inbounds[index]["sniffing"] = sniffing
            }
            config["inbounds"] = inbounds
        }
        return true
    }
}
