import Foundation
import CoreFoundation
import Darwin
import flutter_vless_privacy

/// System A and AAAA queries use the caller's Core DNS client. Transport bootstrap pins
/// live in private, closed routing branches rather than the caller's hosts map.
public enum TunnelDNSPolicy {
    public static let virtualServer = "198.18.0.2"
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
                      resolveIPv4: (String) -> String?) -> [String]? {
        // Admission is transactional: a failed bootstrap must not partially
        // rewrite a caller dictionary which might be retried.
        guard var output = TunnelConfigKeys.normalize(config) else { return nil }
        do { try bindEndpointEnvironment(to: &output, environment: ProcessInfo.processInfo.environment) }
        catch { return nil }
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
                chains[name] = streamChains(outbound["streamSettings"] as? [String: Any] ?? [:])
            }
        }
        let available = Set(outbounds.compactMap { $0["tag"] as? String })
        func validChain(_ next: String, visited: Set<String>) -> Bool {
            guard available.contains(next), !visited.contains(next) else { return false }
            return (chains[next] ?? []).allSatisfy { validChain($0, visited: visited.union([next])) }
        }
        for outbound in outbounds {
            let name = outbound["tag"] as? String ?? ""
            for next in streamChains(outbound["streamSettings"] as? [String: Any] ?? [:]) {
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
              field(dns, "useSystemHosts") as? Bool != true,
              (field(dns, "script") as? String ?? "").isEmpty,
              !systemStrategy(field(dns, "queryStrategy")) else { return false }
        let hosts = field(dns, "hosts") as? [String: Any] ?? [:]
        func staticIPv4(_ host: String) -> Bool {
            let keys = hosts.keys.filter { key in
                // Core recognizes the literal lowercase rule prefix before
                // folding only the domain body; FULL: is not a full rule.
                let domain = key.hasPrefix("full:") ? String(key.dropFirst(5)) : key
                // Go's simple lowercase maps U+0130 to ASCII i; Foundation's
                // full mapping expands it. Keep decomposed sequences distinct.
                let folded = domain.replacingOccurrences(of: "İ", with: "i", options: .literal).lowercased()
                return folded == hostKey(host)
            }
            guard keys.count == 1, let value = hosts[keys[0]] else { return false }
            if let ip = value as? String { return isDNSIPv4(LocalProxyAccessPolicy.coreAddressText(ip)) }
            if let ips = value as? [String] {
                return !ips.isEmpty && ips.allSatisfy { isDNSIPv4(LocalProxyAccessPolicy.coreAddressText($0)) }
            }
            return false
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
            guard !systemStrategy(field(entry, "queryStrategy")), address.lowercased() != "fakedns" else { return false }
            if address.lowercased() == "localhost" || address.isEmpty {
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
                guard isDNSIPv4(address) else { return false }
                continue
            } else if let url = URLComponents(string: address), let scheme = url.scheme {
                // A special/unsupported DNS URL cannot become a bare-host
                // admission merely because a hosts key happens to match it.
                guard ["tcp", "https", "h2c"].contains(scheme.lowercased()), let rawHost = url.host else { return false }
                let host = LocalProxyAccessPolicy.coreAddressText(rawHost)
                guard isDNSIPv4(host) || (!isLiteral(host) && staticIPv4(host)) else { return false }
                continue
            } else if staticIPv4(address) {
                continue
            } else { return false }
        }
        if changed { dns[serverKeys.first ?? "servers"] = servers }
        return true
    }

    private static func prepareStream(_ stream: inout [String: Any], endpoints: [Endpoint], sendThrough: Any?,
        allocator: inout XrayServiceTags, denied: String, generated: inout [[String: Any]],
        rules: inout [[String: Any]], resolved: inout [String: String], addresses: inout Set<String>,
        resolver: (String) -> String?) -> Bool {
        guard stream["sockopt"] == nil || stream["sockopt"] is NSNull || stream["sockopt"] is [String: Any] else { return false }
        var sockopt = stream["sockopt"] as? [String: Any] ?? [:]
        guard sockopt["dialerProxy"] == nil || sockopt["dialerProxy"] is NSNull || sockopt["dialerProxy"] is String else { return false }
        guard inactiveAddressPortStrategy(sockopt["addressPortStrategy"]) else { return false }
        if let tls = stream["tlsSettings"] as? [String: Any],
           tls.keys.contains(where: { XrayJSONField.matches($0, "echConfigList") && (tls[$0] as? String ?? "").contains("://") }) { return false }
        let network = effectiveTransport(in: stream)
        // XDRIVE has a separate fronting destination, not the protocol endpoint.
        guard network != "xdrive" else { return false }
        let penetrating = sockopt["penetrate"] as? Bool == true
        var physicalTargets = endpoints
        if penetrating, let download = effectiveDownload(in: stream) {
            // Core replaces the child's entire socket policy with this parent
            // and dials its immediate XHTTP destination without child recursion.
            guard ["xhttp", "splithttp"].contains(effectiveTransport(in: download)),
                  let raw = download["address"] as? String,
                  let p = port(download["port"]) else { return false }
            let host = LocalProxyAccessPolicy.coreAddressText(raw)
            guard !host.isEmpty else { return false }
            if let tls = download["tlsSettings"] as? [String: Any],
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
        if ["xhttp", "splithttp"].contains(network), var settings = stream[key] as? [String: Any] {
            if let extraValue = settings["extra"] {
                var extra = extraValue as? [String: Any] ?? [:]
                if var download = extra["downloadSettings"] as? [String: Any] {
                    guard let host = download["address"] as? String, let p = port(download["port"]),
                          prepareStream(&download, endpoints: [Endpoint(host: LocalProxyAccessPolicy.coreAddressText(host), port: p)], sendThrough: sendThrough, allocator: &allocator,
                                        denied: denied, generated: &generated, rules: &rules, resolved: &resolved,
                                        addresses: &addresses, resolver: resolver) else { return false }
                    extra["downloadSettings"] = download
                    settings["extra"] = extra
                }
            } else if var download = settings["downloadSettings"] as? [String: Any] {
                guard let host = download["address"] as? String, let p = port(download["port"]),
                      prepareStream(&download, endpoints: [Endpoint(host: LocalProxyAccessPolicy.coreAddressText(host), port: p)], sendThrough: sendThrough, allocator: &allocator,
                                    denied: denied, generated: &generated, rules: &rules, resolved: &resolved,
                                    addresses: &addresses, resolver: resolver) else { return false }
                settings["downloadSettings"] = download
            }
            stream[key] = settings
        }
        return true
    }

    private static func streamChains(_ stream: [String: Any]) -> [String] {
        var result: [String] = []
        if let tag = (stream["sockopt"] as? [String: Any])?["dialerProxy"] as? String, !tag.isEmpty { result.append(tag) }
        if (stream["sockopt"] as? [String: Any])?["penetrate"] as? Bool != true,
           let download = effectiveDownload(in: stream) { result += streamChains(download) }
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
        guard let ip = resolved[hostKey(host)] ?? resolver(host), isIPv4(ip) else { return nil }
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
        var address = in_addr()
        return value.withCString { inet_pton(AF_INET, $0, &address) } == 1
    }
    private static func isDNSIPv4(_ value: String) -> Bool {
        if isIPv4(value) { return true }
        var address = in6_addr()
        guard value.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else { return false }
        // Core folds only the exact 80 zero bits + ffff mapped prefix to IPv4.
        // This is an admission view; keep the caller's raw DNS JSON unchanged.
        return withUnsafeBytes(of: address) { bytes in
            bytes.prefix(10).allSatisfy { $0 == 0 } && bytes[10] == 0xff && bytes[11] == 0xff
        }
    }
    private static func isLiteral(_ value: String) -> Bool {
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
}
