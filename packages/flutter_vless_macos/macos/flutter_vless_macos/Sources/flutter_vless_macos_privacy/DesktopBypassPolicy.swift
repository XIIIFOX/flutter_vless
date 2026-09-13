import Foundation
import Darwin

public enum DesktopTunnelError: Error, LocalizedError {
    case configurationInUse
    public var errorDescription: String? { "Stop the current VPN before replacing its configuration" }
}

/// Preserve explicit IPv4 bypass CIDRs inside Xray instead of weakening the
/// NetworkExtension include-all policy. DNS and IPv6 rules are prepended later.
public enum DesktopBypassPolicy {
    @discardableResult
    public static func validate(_ cidrs: [String]) throws -> [String] {
        for cidr in cidrs {
            let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
            var address = in_addr()
            guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix),
                  String(parts[0]).withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else {
                throw NSError(domain: "flutter_vless.routing", code: 1, userInfo: [NSLocalizedDescriptionKey:
                    "VPN bypassSubnets must contain IPv4 CIDRs; IPv6 remains blocked by traffic protection."])
            }
        }
        return cidrs
    }

    public static func apply(to data: Data, cidrs: [String]) throws -> Data {
        try validate(cidrs)
        if cidrs.isEmpty { return data }
        var config = try LocalProxyAccessPolicy.normalizedConfig(configData: data)
        guard var outbounds = config["outbounds"] as? [[String: Any]] else {
            throw LocalProxyAccessError.malformedConfiguration
        }
        var tag = "flutter-vless-subnet-direct"
        let tags = Set(outbounds.compactMap { $0["tag"] as? String })
        while tags.contains(tag) { tag += "-" }
        outbounds.append(["tag": tag, "protocol": "freedom", "settings": ["domainStrategy": "ForceIPv4"]])
        config["outbounds"] = outbounds
        guard config["routing"] == nil || config["routing"] is [String: Any] else {
            throw LocalProxyAccessError.malformedConfiguration
        }
        var routing = config["routing"] as? [String: Any] ?? [:]
        guard routing["rules"] == nil || routing["rules"] is [[String: Any]] else {
            throw LocalProxyAccessError.malformedConfiguration
        }
        var rules = routing["rules"] as? [[String: Any]] ?? []
        rules.insert(["type": "field", "ip": cidrs, "outboundTag": tag], at: 0)
        routing["rules"] = rules
        config["routing"] = routing
        return try JSONSerialization.data(withJSONObject: config)
    }
}
