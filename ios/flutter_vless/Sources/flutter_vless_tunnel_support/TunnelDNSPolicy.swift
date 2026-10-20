import Foundation
import CoreFoundation
import Darwin
import flutter_vless_privacy

/// System A and AAAA queries use the caller's Core DNS client. Transport bootstrap pins
/// live in private, closed routing branches rather than the caller's hosts map.
public enum TunnelDNSPolicy {
    public static let virtualServer = "10.0.85.53"
    private static let endpointProtocols: Set<String> = [
        "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria", "masque", "wireguard"
    ]
    private struct Endpoint { let host: String; let port: Int }

    // Core aliases change policy roles, not caller protocol text. Internal
    // DNS/loopback handlers have no physical server endpoint to bootstrap.
    static func protocolRole(_ value: Any?) -> String {
        switch (value as? String ?? "").lowercased() {
        case "direct": return "freedom"
        case "block": return "blackhole"
        case let value: return value
        }
    }

    static func primaryEndpointIndex(in outbounds: [[String: Any]]) -> Int? {
        outbounds.firstIndex { ($0["tag"] as? String) == "proxy" && endpointProtocols.contains(protocolRole($0["protocol"])) }
            ?? outbounds.firstIndex { endpointProtocols.contains(protocolRole($0["protocol"])) }
    }

    static func effectiveTransport(in stream: [String: Any]) -> String {
        // method is a pointer in Core: explicit null leaves network effective.
        ((stream["method"] as? String) ?? (stream["network"] as? String) ?? "tcp").lowercased()
    }

    /// Bind schema-selected transport, logical handler and caller DNS Address values.
    /// Keep user-map keys and opaque strings; never publish a partial edit.
    @discardableResult
    static func bindEndpointEnvironment(to config: inout [String: Any], environment: [String: String]) throws -> Bool {
        try XrayAddressEnvironment.bind(to: &config, environment: environment)
    }

    static func apply(to config: inout [String: Any], managedInboundTag: String,
                      generatedRuleCount: ((Int) -> Void)? = nil,
                      environmentSnapshot: XrayEnvironmentSnapshot = .capture(),
                      resolveIPv4: (String) -> String?) -> [String]? {
        // Admission is transactional: a failed bootstrap must not partially
        // rewrite a caller dictionary which might be retried.
        guard var output = TunnelConfigKeys.normalize(config) else { return nil }
        do { try XrayAddressEnvironment.bind(to: &output, environmentSnapshot: environmentSnapshot) }
        catch { return nil }
        guard TunnelFakeDNSPolicy.active(in: output) != nil else { return nil }
        guard var outbounds = output["outbounds"] as? [[String: Any]], !outbounds.isEmpty else { return nil }
        let primary = primaryEndpointIndex(in: outbounds)
        let tags = outbounds.compactMap { $0["tag"] as? String }.filter { !$0.isEmpty }
        guard Set(tags).count == tags.count else { return nil }
        var allocator = XrayServiceTags(configuration: output)
        let relay = allocator.next("flutter-vless-system-dns")
        let denied = allocator.next("flutter-vless-bootstrap-block")
        if let primary, (outbounds[primary]["tag"] as? String ?? "").isEmpty {
            outbounds[primary]["tag"] = allocator.next("flutter-vless-dns-proxy")
        }
        let selected = primary.flatMap { outbounds[$0]["tag"] as? String }
        var privateRules: [[String: Any]] = []
        var generated: [[String: Any]] = []
        var resolved: [String: String] = [:]
        var addresses = Set<String>()
        guard output["dns"] == nil || output["dns"] is NSNull || output["dns"] is [String: Any] else { return nil }
        var dns = output["dns"] as? [String: Any] ?? [:]
        guard prepareDNS(&dns, allocator: &allocator, selected: selected, rules: &privateRules) else { return nil }

        // A caller dialer chain carries a logical destination. Pin only the
        // named handler's physical endpoint, never that logical destination.
        var chains: [String: [String]] = [:]
        for outbound in outbounds {
            if let name = outbound["tag"] as? String {
                chains[name] = outboundChains(outbound)
            }
        }
        let available = Set(outbounds.compactMap { $0["tag"] as? String })
        func validChain(_ next: String, visited: Set<String>) -> Bool {
            guard available.contains(next), !visited.contains(next) else { return false }
            return (chains[next] ?? []).allSatisfy { validChain($0, visited: visited.union([next])) }
        }
        for outbound in outbounds {
            let name = outbound["tag"] as? String ?? ""
            for next in outboundChains(outbound) {
                guard validChain(next, visited: name.isEmpty ? [] : [name]) else { return nil }
            }
        }
        for index in outbounds.indices {
            let proto = protocolRole(outbounds[index]["protocol"])
            var stream = outbounds[index]["streamSettings"] as? [String: Any] ?? [:]
            if proto == "freedom" {
                var settings = outbounds[index]["settings"] as? [String: Any] ?? [:]
                settings["domainStrategy"] = "ForceIPv4"
                settings.removeValue(forKey: "targetStrategy")
                outbounds[index]["settings"] = settings
                var sockopt = stream["sockopt"] as? [String: Any] ?? [:]
                guard inactiveAddressPortStrategy(sockopt["addressPortStrategy"]) else { return nil }
                // A direct named DoH target with an exact caller hosts entry
                // must consult Core, never the OS resolver inside the tunnel.
                sockopt["domainStrategy"] = (sockopt["dialerProxy"] as? String ?? "").isEmpty ? "ForceIPv4" : "AsIs"
                stream["sockopt"] = sockopt
                outbounds[index]["streamSettings"] = stream
                continue
            }
            guard endpointProtocols.contains(proto), var settings = outbounds[index]["settings"] as? [String: Any] else { continue }
            if proto == "wireguard" {
                guard (((stream["sockopt"] as? [String: Any])?["dialerProxy"] as? String) ?? "").isEmpty else { return nil }
                guard var peers = settings["peers"] as? [[String: Any]], !peers.isEmpty else { return nil }
                for peer in peers.indices {
                    guard let target = endpoint(peers[peer]["endpoint"] as? String),
                          let ip = pin(target.host, resolved: &resolved, addresses: &addresses, resolver: resolveIPv4) else { return nil }
                    // WireGuard resolves peers before DialSystem. Its identity
                    // is the public key, so pin its address at this boundary.
                    peers[peer]["endpoint"] = (ip.contains(":") ? "[\(ip)]" : ip) + ":\(target.port)"
                }
                settings["peers"] = peers
                outbounds[index]["settings"] = settings
                continue
            }
            let entries: [[String: Any]]
            if settings["address"] is String { entries = [settings] }
            else { entries = settings[proto == "vless" || proto == "vmess" ? "vnext" : "servers"] as? [[String: Any]] ?? [] }
            guard !entries.isEmpty else { return nil }
            var endpoints: [Endpoint] = []
            for entry in entries {
                guard let raw = entry["address"] as? String, let port = port(entry["port"]) else { return nil }
                let host = LocalProxyAccessPolicy.coreAddressText(raw)
                guard !host.isEmpty else { return nil }
                endpoints.append(Endpoint(host: host, port: port))
            }
            guard prepareStream(&stream, endpoints: endpoints, sendThrough: outbounds[index]["sendThrough"], allocator: &allocator, denied: denied,
                                generated: &generated, rules: &privateRules, resolved: &resolved,
                                addresses: &addresses, resolver: resolveIPv4) else { return nil }
            outbounds[index]["streamSettings"] = stream
        }
        outbounds.append(contentsOf: generated)
        if !generated.isEmpty { outbounds.append(["tag": denied, "protocol": "blackhole"]) }
        outbounds.append(["tag": relay, "protocol": "dns", "settings": ["rules": [
            ["action": "hijack", "qType": "1"],
            ["action": "hijack", "qType": "28"],
            ["action": "return", "rCode": 5]
        ]]])
        privateRules.insert(["type": "field", "inboundTag": [managedInboundTag], "ip": [virtualServer + "/32"],
                             "port": "53", "network": "tcp,udp", "outboundTag": relay], at: 0)
        var routing = output["routing"] as? [String: Any] ?? [:]
        routing["rules"] = privateRules + (routing["rules"] as? [[String: Any]] ?? [])
        output["routing"] = routing
        output["dns"] = dns
        output["outbounds"] = outbounds
        config = output
        generatedRuleCount?(privateRules.count)
        return addresses.sorted()
    }

    private static func prepareDNS(_ dns: inout [String: Any], allocator: inout XrayServiceTags,
                                   selected: String?, rules: inout [[String: Any]]) -> Bool {
        // Read aliases without normalizing caller DNS maps or nested fields.
        func field(_ object: [String: Any], _ name: String) -> Any? {
            object.first { XrayJSONField.matches($0.key, name) }?.value
        }
        func unambiguous(_ object: [String: Any], _ names: [String]) -> Bool {
            names.allSatisfy { name in object.keys.filter { XrayJSONField.matches($0, name) }.count <= 1 }
        }
        guard unambiguous(dns, ["servers", "hosts", "tag", "queryStrategy", "useSystemHosts", "script"]),
              (field(dns, "script") as? String ?? "").isEmpty,
              !systemStrategy(field(dns, "queryStrategy")) else { return false }
        let hosts = field(dns, "hosts") as? [String: Any] ?? [:]
        func staticIP(_ host: String) -> Bool {
            func domainLower(_ value: String) -> String {
                value.replacingOccurrences(of: "İ", with: "i", options: .literal).lowercased()
            }
            func visit(_ query: String, remaining: Int) -> Bool {
                let keys = hosts.keys.filter { key in
                    // Rule prefixes are case-sensitive; map keys retain their
                    // terminal dot. Only the initial query trims its FQDN dot.
                    let domain = key.hasPrefix("full:") ? String(key.dropFirst(5)) : key
                    return domainLower(domain) == query
                }
                guard keys.count == 1, let value = hosts[keys[0]] else { return false }
                func address(_ raw: String) -> Bool {
                    let parsed = LocalProxyAccessPolicy.coreAddressText(raw)
                    if isLiteral(parsed) { return true }
                    // Core StaticHosts.Lookup unwraps at most five aliases.
                    // Prove a numeric leaf without querying native/OS DNS.
                    // New alias admission is ASCII-only: Swift canonical equality
                    // and contextual case mapping must not invent a Core match.
                    return remaining > 0 && !parsed.isEmpty && !parsed.hasPrefix("#")
                        && parsed.utf8.allSatisfy({ $0 < 0x80 })
                        && visit(domainLower(parsed), remaining: remaining - 1)
                }
                if let scalar = value as? String { return address(scalar) }
                if let values = value as? [String], !values.isEmpty {
                    if values.count == 1 { return address(values[0]) }
                    // Keep mixed or ambiguous replacements outside admission.
                    return values.allSatisfy { isLiteral(LocalProxyAccessPolicy.coreAddressText($0)) }
                }
                return false
            }
            return visit(domainLower(hostKey(host)), remaining: 5)
        }
        let serverKeys = dns.keys.filter { XrayJSONField.matches($0, "servers") }
        let original = serverKeys.first.flatMap { dns[$0] }
        guard original == nil || original is NSNull || original is [Any] else { return false }
        var servers = original as? [Any] ?? []
        if servers.isEmpty { servers = ["localhost"] }
        var changed = original == nil || original is NSNull || (original as? [Any])?.isEmpty == true
        for index in servers.indices {
            let originalEntry = servers[index]
            var entry: [String: Any]
            let rawAddress: String
            if let string = originalEntry as? String { entry = [:]; rawAddress = string }
            else if let object = originalEntry as? [String: Any],
                    unambiguous(object, ["address", "tag", "queryStrategy"]),
                    let value = field(object, "address") as? String { entry = object; rawAddress = value }
            else { return false }
            // Address.UnmarshalJSON parses the whole value before DNS mode
            // selection. Keep its raw text in JSON, using this view for admission.
            let address = LocalProxyAccessPolicy.coreAddressText(rawAddress)
            guard !systemStrategy(field(entry, "queryStrategy")) else { return false }
            if XrayJSONField.matches(address, "fakedns") {
                // Core's DNS relay enables FakeDNS using this same engine.
                // Preserve the sentinel and all per-server selection fields.
                continue
            } else if address.lowercased() == "localhost" || address.isEmpty {
                // Explicit remote caller DNS needs no selected proxy. Only the
                // native protected default requires a qualified detour.
                guard let selected else { return false }
                let tagValue = field(entry, "tag")
                guard tagValue == nil || tagValue is NSNull || tagValue is String else { return false }
                let addressKey = entry.keys.first { XrayJSONField.matches($0, "address") } ?? "address"
                entry[addressKey] = "tcp://1.1.1.1"
                var tag = tagValue as? String ?? ""
                if tag.isEmpty {
                    tag = allocator.next("flutter-vless-dns-upstream")
                    let tagKey = entry.keys.first { XrayJSONField.matches($0, "tag") } ?? "tag"
                    entry[tagKey] = tag
                }
                rules.append(["type": "field", "inboundTag": [tag], "ip": ["1.1.1.1/32"],
                              "port": "53", "network": "tcp", "outboundTag": selected])
                servers[index] = entry
                changed = true
            } else if isLiteral(address) {
                // Caller DNS destinations are logical Core addresses; their
                // routing remains caller-owned for both IP families.
                continue
            } else if let url = URLComponents(string: address), let scheme = url.scheme {
                // A special/unsupported DNS URL cannot become a bare-host
                // admission merely because a hosts key happens to match it.
                guard ["tcp", "https", "h2c"].contains(scheme.lowercased()), let rawHost = url.host else { return false }
                let host = LocalProxyAccessPolicy.coreAddressText(rawHost)
                guard isLiteral(host) || (!isLiteral(host) && staticIP(host)) else { return false }
                continue
            } else if staticIP(address) {
                continue
            } else { return false }
        }
        if changed { dns[serverKeys.first ?? "servers"] = servers }
        return true
    }

    private static func prepareStream(_ stream: inout [String: Any], endpoints: [Endpoint], sendThrough: Any?,
        allocator: inout XrayServiceTags, denied: String, generated: inout [[String: Any]],
        rules: inout [[String: Any]], resolved: inout [String: String], addresses: inout Set<String>,
        resolver: (String) -> String?, followDownload: Bool = true) -> Bool {
        guard stream["sockopt"] == nil || stream["sockopt"] is NSNull || stream["sockopt"] is [String: Any] else { return false }
        var sockopt = stream["sockopt"] as? [String: Any] ?? [:]
        guard sockopt["dialerProxy"] == nil || sockopt["dialerProxy"] is NSNull || sockopt["dialerProxy"] is String else { return false }
        guard inactiveAddressPortStrategy(sockopt["addressPortStrategy"]) else { return false }
        if (stream["security"] as? String)?.lowercased() == "tls",
           let tls = stream["tlsSettings"] as? [String: Any],
           tls.keys.contains(where: { XrayJSONField.matches($0, "echConfigList") && (tls[$0] as? String ?? "").contains("://") }) { return false }
        let network = effectiveTransport(in: stream)
        // XDRIVE has a separate fronting destination, not the protocol endpoint.
        guard network != "xdrive" else { return false }
        let penetrating = sockopt["penetrate"] as? Bool == true
        var physicalTargets = endpoints
        // The immediate client uses getHTTPClient, not another XHTTP Dial;
        // its nested download is inactive even with independent socket policy.
        let downloadSettings = followDownload ? effectiveDownload(in: stream) : nil
        // Core casts both immediate HTTP clients to XHTTP Config, regardless
        // of whether their socket policies are independent or inherited.
        if let download = downloadSettings,
           !["xhttp", "splithttp"].contains(effectiveTransport(in: download)) { return false }
        if penetrating, let download = downloadSettings {
            // Core replaces the child's entire socket policy with this parent
            // and dials its immediate XHTTP destination without child recursion.
            guard let raw = download["address"] as? String,
                  let p = port(download["port"]) else { return false }
            let host = LocalProxyAccessPolicy.coreAddressText(raw)
            guard !host.isEmpty else { return false }
            if (download["security"] as? String)?.lowercased() == "tls",
               let tls = download["tlsSettings"] as? [String: Any],
               tls.keys.contains(where: { XrayJSONField.matches($0, "echConfigList") && (tls[$0] as? String ?? "").contains("://") }) { return false }
            if !physicalTargets.contains(where: { $0.host == host && $0.port == p }) {
                physicalTargets.append(Endpoint(host: host, port: p))
            }
        }
        let chained = !(sockopt["dialerProxy"] as? String ?? "").isEmpty
        sockopt["domainStrategy"] = "AsIs"
        if !chained {
            var pins: [(Endpoint, String)] = []
            for target in physicalTargets {
                guard let ip = pin(target.host, resolved: &resolved, addresses: &addresses, resolver: resolver) else { return false }
                pins.append((target, ip))
            }
            if physicalTargets.contains(where: { !isLiteral($0.host) }) {
                let loop = allocator.next("flutter-vless-bootstrap-loop")
                let scope = allocator.next("flutter-vless-bootstrap-input")
                sockopt["dialerProxy"] = loop
                generated.append(["tag": loop, "protocol": "loopback", "settings": ["inboundTag": scope]])
                for (target, ip) in pins {
                    let leaf = allocator.next("flutter-vless-bootstrap-pin")
                    var physical = sockopt
                    physical.removeValue(forKey: "dialerProxy")
                    physical["domainStrategy"] = "ForceIPv4"
                    var outbound: [String: Any] = ["tag": leaf, "protocol": "freedom", "settings": ["redirect": (ip.contains(":") ? "[\(ip)]" : ip) + ":0"],
                                                  "streamSettings": ["sockopt": physical]]
                    if let sendThrough { outbound["sendThrough"] = sendThrough }
                    generated.append(outbound)
                    var rule: [String: Any] = ["type": "field", "inboundTag": [scope], "port": String(target.port), "outboundTag": leaf]
                    if isLiteral(target.host) { rule["ip"] = [target.host] }
                    else { rule["domain"] = Array(Set(["full:" + target.host, "full:" + hostKey(target.host)])).sorted() }
                    rules.append(rule)
                }
                rules.append(["type": "field", "inboundTag": [scope], "outboundTag": denied])
            }
        }
        stream["sockopt"] = sockopt
        // The child keeps its source JSON. Core applies this prepared parent
        // policy to it at runtime, including the union's closed private context.
        if penetrating { return true }
        // Only the effective XHTTP settings participate. A supplied extra
        // replaces outer downloadSettings; dormant data must not bootstrap.
        let key = stream["xhttpSettings"] is [String: Any] ? "xhttpSettings" : "splithttpSettings"
        if followDownload, ["xhttp", "splithttp"].contains(network), var settings = stream[key] as? [String: Any] {
            if let extraValue = settings["extra"] {
                var extra = extraValue as? [String: Any] ?? [:]
                if var download = extra["downloadSettings"] as? [String: Any] {
                    guard let host = download["address"] as? String, let p = port(download["port"]),
                          prepareStream(&download, endpoints: [Endpoint(host: LocalProxyAccessPolicy.coreAddressText(host), port: p)], sendThrough: sendThrough, allocator: &allocator,
                                        denied: denied, generated: &generated, rules: &rules, resolved: &resolved,
                                        addresses: &addresses, resolver: resolver, followDownload: false) else { return false }
                    extra["downloadSettings"] = download
                    settings["extra"] = extra
                }
            } else if var download = settings["downloadSettings"] as? [String: Any] {
                guard let host = download["address"] as? String, let p = port(download["port"]),
                      prepareStream(&download, endpoints: [Endpoint(host: LocalProxyAccessPolicy.coreAddressText(host), port: p)], sendThrough: sendThrough, allocator: &allocator,
                                    denied: denied, generated: &generated, rules: &rules, resolved: &resolved,
                                    addresses: &addresses, resolver: resolver, followDownload: false) else { return false }
                settings["downloadSettings"] = download
            }
            stream[key] = settings
        }
        return true
    }

    private static func outboundChains(_ outbound: [String: Any]) -> [String] {
        // Loopback.Process redispatches the link and never calls its dialer.
        // Its sender still builds normally; only these socket edges are unused.
        guard protocolRole(outbound["protocol"]) != "loopback" else { return [] }
        return streamChains(outbound["streamSettings"] as? [String: Any] ?? [:])
    }

    private static func streamChains(_ stream: [String: Any], followDownload: Bool = true) -> [String] {
        var result: [String] = []
        if let tag = (stream["sockopt"] as? [String: Any])?["dialerProxy"] as? String, !tag.isEmpty { result.append(tag) }
        // The immediate client's getHTTPClient uses its own socket settings;
        // it does not invoke another XHTTP Dial for the child's nested download.
        if followDownload, (stream["sockopt"] as? [String: Any])?["penetrate"] as? Bool != true,
           let download = effectiveDownload(in: stream) { result += streamChains(download, followDownload: false) }
        return result
    }

    private static func effectiveDownload(in stream: [String: Any]) -> [String: Any]? {
        guard ["xhttp", "splithttp"].contains(effectiveTransport(in: stream)),
              let settings = (stream["xhttpSettings"] as? [String: Any]) ?? (stream["splithttpSettings"] as? [String: Any]) else { return nil }
        let effective = settings["extra"] != nil ? (settings["extra"] as? [String: Any] ?? [:]) : settings
        return effective["downloadSettings"] as? [String: Any]
    }

    private static func pin(_ host: String, resolved: inout [String: String], addresses: inout Set<String>,
                            resolver: (String) -> String?) -> String? {
        if isLiteral(host) { addresses.insert(host); return host }
        guard let ip = resolved[hostKey(host)] ?? resolver(host), isLiteral(ip) else { return nil }
        resolved[hostKey(host)] = ip
        addresses.insert(ip)
        return ip
    }
    private static func inactiveAddressPortStrategy(_ value: Any?) -> Bool {
        guard let value, !(value is NSNull) else { return true }
        guard let strategy = value as? String else { return false }
        return strategy.isEmpty || strategy.lowercased() == "none"
    }
    private static func systemStrategy(_ value: Any?) -> Bool {
        let folded = (value as? String ?? "").lowercased().replacingOccurrences(of: "_", with: "").replacingOccurrences(of: "-", with: "")
        return ["usesys", "usesystem"].contains(folded)
    }
    private static func port(_ value: Any?) -> Int? {
        guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(),
              n.doubleValue == Double(n.intValue), (1...65535).contains(n.intValue) else { return nil }
        return n.intValue
    }
    private static func isIPv4(_ value: String) -> Bool {
        guard !value.utf8.contains(0) else { return false }
        var address = in_addr()
        return value.withCString { inet_pton(AF_INET, $0, &address) } == 1
    }
    private static func isLiteral(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.allSatisfy({
            (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) || $0 == 46 || $0 == 58
        }) else { return false }
        var address = in6_addr()
        return isIPv4(value) || value.withCString { inet_pton(AF_INET6, $0, &address) } == 1
    }
    private static func endpoint(_ value: String?) -> Endpoint? {
        guard let value, let colon = value.lastIndex(of: ":"), let p = Int(value[value.index(after: colon)...]),
              (1...65535).contains(p) else { return nil }
        var host = String(value[..<colon])
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        guard !host.isEmpty else { return nil }
        return Endpoint(host: host, port: p)
    }
    private static func hostKey(_ host: String) -> String {
        (host.hasSuffix(".") ? String(host.dropLast()) : host).lowercased()
    }

    /// Explicit bypasses remain supported except those covering the virtual DNS.
    public static func allowsRouteExclusions(_ cidrs: [String]) -> Bool {
        var virtual = in_addr()
        guard virtualServer.withCString({ inet_pton(AF_INET, $0, &virtual) }) == 1 else { return false }
        let dns = UInt32(bigEndian: virtual.s_addr)
        return !cidrs.contains { cidr in
            let parts = cidr.split(separator: "/")
            guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix) else { return false }
            var address = in_addr()
            guard String(parts[0]).withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else { return false }
            let mask: UInt32 = prefix == 0 ? 0 : UInt32.max << (32 - prefix)
            return UInt32(bigEndian: address.s_addr) & mask == dns & mask
        }
    }
}
