import Foundation
import NetworkExtension
import Darwin

/// Capture IPv6 and reject it at Xray until a dual-stack packet path has been
/// measured on device. Omitting NEIPv6Settings does not disable physical IPv6.
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

    static func apply(to config: inout [String: Any]) -> Bool {
        // FakeDNS can replace Target even with routeOnly enabled. Its virtual
        // address pools are incompatible with this literal-IP block policy.
        guard !config.keys.contains(where: { $0.lowercased() == "fakedns" }) else { return false }
        var outbounds = config["outbounds"] as? [[String: Any]] ?? []
        guard !outbounds.contains(where: { ($0["tag"] as? String) == blockTag }) else { return false }
        outbounds.append(["tag": blockTag, "protocol": "blackhole"])
        config["outbounds"] = outbounds
        var routing = config["routing"] as? [String: Any] ?? [:]
        var rules = routing["rules"] as? [[String: Any]] ?? []
        rules.insert(["type": "field", "ip": ["::/0"], "outboundTag": blockTag], at: 0)
        routing["rules"] = rules
        config["routing"] = routing
        // Xray's IP matcher reads Target; with routeOnly=false sniffing replaces
        // it with a domain and an IPv6 literal can bypass the block. RouteTarget
        // still carries the sniffed name for existing domain routing rules.
        if var inbounds = config["inbounds"] as? [[String: Any]] {
            for index in inbounds.indices {
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
