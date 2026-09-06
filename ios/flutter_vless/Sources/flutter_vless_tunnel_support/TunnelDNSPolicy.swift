import Foundation
import Darwin

/// Packet-tunnel DNS must reach the selected proxy even when it only carries TCP.
/// Bootstrap resolution runs before NetworkExtension installs any routes. Keep
/// endpoint names intact (HTTP Host, TLS SNI and XHTTP depend on them), and pin
/// their transport lookup through Xray's hosts map instead of the OS resolver.
public enum TunnelDNSPolicy {
    public static let virtualServer = "198.18.0.2"
    private static let relayTag = "flutter-vless-system-dns"
    private static let upstreamTag = "flutter-vless-dns-upstream"
    private static let proxyTag = "flutter-vless-dns-proxy"
    private static let endpointProtocols: Set<String> = [
        "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria", "wireguard"
    ]

    static func apply(
        to config: inout [String: Any],
        resolveIPv4: (String) -> String?
    ) -> [String]? {
        guard var outbounds = config["outbounds"] as? [[String: Any]],
              let primary = outbounds.firstIndex(where: {
                  ($0["tag"] as? String) == "proxy" && endpointProtocols.contains(($0["protocol"] as? String ?? "").lowercased())
              }) ?? outbounds.firstIndex(where: {
                  endpointProtocols.contains(($0["protocol"] as? String ?? "").lowercased())
              }) else { return nil }
        let tags = outbounds.compactMap { $0["tag"] as? String }
        let inboundTags = (config["inbounds"] as? [[String: Any]] ?? []).compactMap { $0["tag"] as? String }
        guard Set(tags).count == tags.count,
              Set(tags + inboundTags).isDisjoint(with: [relayTag, upstreamTag, proxyTag]) else { return nil }
        if (outbounds[primary]["tag"] as? String ?? "").isEmpty {
            outbounds[primary]["tag"] = proxyTag
        }
        let selectedTag = outbounds[primary]["tag"] as! String
        var hosts: [String: String] = [:]
        var addresses = Set<String>()
        for index in outbounds.indices {
            let proto = (outbounds[index]["protocol"] as? String ?? "").lowercased()
            guard endpointProtocols.contains(proto) else { continue }
            guard let settings = outbounds[index]["settings"] as? [String: Any] else { return nil }
            let entries: [[String: Any]]
            if proto == "wireguard" {
                entries = settings["peers"] as? [[String: Any]] ?? []
            } else if settings["address"] is String {
                entries = [settings]
            } else {
                let legacyKey = proto == "vless" || proto == "vmess" ? "vnext" : "servers"
                entries = settings[legacyKey] as? [[String: Any]] ?? []
            }
            guard !entries.isEmpty else { return nil }
            for entry in entries {
                guard let host = (entry["address"] as? String)
                    ?? endpointHost(entry["endpoint"] as? String), !host.isEmpty else { return nil }
                if isLiteral(host) {
                    addresses.insert(host)
                } else {
                    guard let ip = hosts[hostKey(host)] ?? resolveIPv4(host), isLiteral(ip) else { return nil }
                    hosts[hostKey(host)] = ip
                    addresses.insert(ip)
                }
            }
            var stream = outbounds[index]["streamSettings"] as? [String: Any] ?? [:]
            guard prepareStream(&stream, hosts: &hosts, addresses: &addresses, resolveIPv4: resolveIPv4) else { return nil }
            outbounds[index]["streamSettings"] = stream
        }
        outbounds.append([
            "tag": relayTag,
            "protocol": "dns",
            "settings": [
                "rewriteNetwork": "tcp", "rewriteAddress": "1.1.1.1", "rewritePort": 53,
                // In DNS outbound vocabulary this means relay through its
                // dialer, which proxySettings below chains to the proxy.
                "rules": [["action": "direct"]]
            ],
            "proxySettings": ["tag": selectedTag]
        ])
        config["outbounds"] = outbounds
        // The sample owns system DNS, as before. Never use tcp+local/local or
        // an OS-resolver fallback once the tunnel routes have been installed.
        config["dns"] = [
            "hosts": hosts, "servers": ["tcp://1.1.1.1"], "tag": upstreamTag,
            "queryStrategy": "UseIPv4", "disableFallback": true
        ]
        var routing = config["routing"] as? [String: Any] ?? [:]
        var rules = routing["rules"] as? [[String: Any]] ?? []
        rules.insert(contentsOf: [
            ["type": "field", "inboundTag": [upstreamTag], "outboundTag": selectedTag],
            ["type": "field", "ip": [virtualServer + "/32"], "port": "53",
             "network": "tcp,udp", "outboundTag": relayTag]
        ], at: 0)
        routing["rules"] = rules
        config["routing"] = routing
        return addresses.sorted()
    }

    /// Explicit bypasses remain supported except those which take the virtual
    /// system resolver off the protected path (including an equal /32 route).
    public static func allowsRouteExclusions(_ cidrs: [String]) -> Bool {
        let dns: UInt32 = 0xc6120002
        return !cidrs.contains { cidr in
            let parts = cidr.split(separator: "/")
            guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix) else { return false }
            var address = in_addr()
            guard String(parts[0]).withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else { return false }
            let mask: UInt32 = prefix == 0 ? 0 : UInt32.max << (32 - prefix)
            return UInt32(bigEndian: address.s_addr) & mask == dns & mask
        }
    }

    private static func prepareStream(
        _ stream: inout [String: Any], hosts: inout [String: String],
        addresses: inout Set<String>, resolveIPv4: (String) -> String?
    ) -> Bool {
        var sockopt = stream["sockopt"] as? [String: Any] ?? [:]
        // SRV/TXT overrides use the system resolver independently of hosts.
        guard (sockopt["addressPortStrategy"] as? String ?? "none").lowercased() == "none" else { return false }
        sockopt["domainStrategy"] = "ForceIP"
        stream["sockopt"] = sockopt
        if let host = stream["address"] as? String, !host.isEmpty {
            if isLiteral(host) {
                addresses.insert(host)
            } else {
                guard let ip = hosts[hostKey(host)] ?? resolveIPv4(host), isLiteral(ip) else { return false }
                hosts[hostKey(host)] = ip
                addresses.insert(ip)
            }
        }
        for key in ["xhttpSettings", "xHTTPSettings", "splithttpSettings", "splitHTTPSettings"] {
            guard var settings = stream[key] as? [String: Any] else { continue }
            // Xray extra replaces the outer download settings entirely.
            if settings["extra"] == nil, var download = settings["downloadSettings"] as? [String: Any] {
                guard prepareStream(&download, hosts: &hosts, addresses: &addresses, resolveIPv4: resolveIPv4) else { return false }
                settings["downloadSettings"] = download
            }
            if var extra = settings["extra"] as? [String: Any],
               var download = extra["downloadSettings"] as? [String: Any] {
                guard prepareStream(&download, hosts: &hosts, addresses: &addresses, resolveIPv4: resolveIPv4) else { return false }
                extra["downloadSettings"] = download
                settings["extra"] = extra
            }
            stream[key] = settings
        }
        return true
    }

    private static func isLiteral(_ value: String) -> Bool {
        var v4 = in_addr()
        var v6 = in6_addr()
        return value.withCString { inet_pton(AF_INET, $0, &v4) } == 1
            || value.withCString { inet_pton(AF_INET6, $0, &v6) } == 1
    }

    private static func endpointHost(_ endpoint: String?) -> String? {
        guard let endpoint, let colon = endpoint.lastIndex(of: ":"),
              let port = Int(endpoint[endpoint.index(after: colon)...]), (1...65535).contains(port) else { return nil }
        let host = String(endpoint[..<colon])
        if host.hasPrefix("["), host.hasSuffix("]") {
            let literal = String(host.dropFirst().dropLast())
            return isLiteral(literal) ? literal : nil
        }
        return host.contains(":") || host.isEmpty ? nil : host
    }

    private static func hostKey(_ host: String) -> String {
        // Xray LookupIP removes the terminal root label before hosts matching.
        (host.hasSuffix(".") ? String(host.dropLast()) : host).lowercased()
    }
}
