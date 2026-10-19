import Foundation

/// Freeze only schema-selected Core Address environment references before a
/// profile crosses native processes. This layer has no Core or tunnel dependency.
public enum XrayAddressEnvironment {
    public static func bind(configData: Data,
        environment: [String: String] = ProcessInfo.processInfo.environment) throws -> Data {
        guard var config = try JSONSerialization.jsonObject(with: configData) as? [String: Any] else {
            throw LocalProxyAccessError.malformedConfiguration
        }
        guard try bind(to: &config, environment: environment) else { return configData }
        return try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])
    }

    private static let endpointProtocols: Set<String> = [
        "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria", "masque", "wireguard"
    ]

    private static func protocolRole(_ value: Any?) -> String {
        switch (value as? String ?? "").lowercased() {
        case "direct": return "freedom"
        case "block": return "blackhole"
        case let value: return value
        }
    }

    private static func effectiveTransport(in stream: [String: Any]) -> String {
        ((stream["method"] as? String) ?? (stream["network"] as? String) ?? "tcp").lowercased()
    }

    @discardableResult
    public static func bind(to config: inout [String: Any], environment: [String: String]) throws -> Bool {
        guard var output = XrayConfigKeys.normalize(config) else { throw LocalProxyAccessError.malformedConfiguration }
        var changed = false
        func bindValue(_ value: Any) throws -> Any {
            guard let raw = value as? String, raw.hasPrefix("env:") else { return value }
            let bound = try LocalProxyAccessPolicy.bindingAddressEnvironment(raw, environment: environment)
            changed = true
            return bound
        }
        func fieldKey(_ object: [String: Any], _ name: String) throws -> String? {
            let keys = object.keys.filter { XrayJSONField.matches($0, name) }
            guard keys.count <= 1 else { throw LocalProxyAccessError.malformedConfiguration }
            return keys.first
        }
        func bindField(_ object: inout [String: Any], _ name: String) throws {
            if let key = try fieldKey(object, name), let value = object[key] {
                object[key] = try bindValue(value)
            }
        }
        func bindLogicalTarget(_ settings: inout [String: Any]) throws {
            // Core selects non-null address over rewriteAddress, even when the
            // primary value is malformed. Leave that error for Core preflight;
            // never expand a dormant alias or silently fall back to it.
            if let key = try fieldKey(settings, "address"), let value = settings[key], !(value is NSNull) {
                settings[key] = try bindValue(value)
            } else { try bindField(&settings, "rewriteAddress") }
        }
        if var dns = output["dns"] as? [String: Any] {
            try bindField(&dns, "clientIp")
            if let key = try fieldKey(dns, "servers"), var servers = dns[key] as? [Any] {
                for index in servers.indices {
                    if var server = servers[index] as? [String: Any] {
                        try bindField(&server, "address")
                        try bindField(&server, "clientIp")
                        servers[index] = server
                    } else { servers[index] = try bindValue(servers[index]) }
                }
                dns[key] = servers
            }
            if let key = try fieldKey(dns, "hosts"), var hosts = dns[key] as? [String: Any] {
                // Every array element is an Address. Core itself selects the
                // first domain alias over all IPs; preserve that order intact.
                for host in Array(hosts.keys) {
                    if var values = hosts[host] as? [Any] {
                        for index in values.indices { values[index] = try bindValue(values[index]) }
                        hosts[host] = values
                    } else if let value = hosts[host] { hosts[host] = try bindValue(value) }
                }
                dns[key] = hosts
            }
            output["dns"] = dns
        }
        if var inbounds = output["inbounds"] as? [[String: Any]] {
            for index in inbounds.indices {
                guard ["dokodemo-door", "tunnel"].contains(protocolRole(inbounds[index]["protocol"])),
                      var settings = inbounds[index]["settings"] as? [String: Any] else { continue }
                try bindLogicalTarget(&settings)
                inbounds[index]["settings"] = settings
            }
            output["inbounds"] = inbounds
        }
        guard var outbounds = output["outbounds"] as? [[String: Any]] else {
            if changed { config = output }
            return changed
        }
        func bind(_ object: inout [String: Any]) throws {
            guard let raw = object["address"] as? String, raw.hasPrefix("env:") else { return }
            object["address"] = try LocalProxyAccessPolicy.bindingAddressEnvironment(raw, environment: environment)
            changed = true
        }
        func bindDownload(_ stream: inout [String: Any]) throws {
            guard ["xhttp", "splithttp"].contains(effectiveTransport(in: stream)) else { return }
            let key = stream["xhttpSettings"] is [String: Any] ? "xhttpSettings" : "splithttpSettings"
            guard var settings = stream[key] as? [String: Any] else { return }
            if let extraValue = settings["extra"] {
                guard var extra = extraValue as? [String: Any], var download = extra["downloadSettings"] as? [String: Any] else { return }
                try bind(&download)
                extra["downloadSettings"] = download
                settings["extra"] = extra
            } else if var download = settings["downloadSettings"] as? [String: Any] {
                try bind(&download)
                settings["downloadSettings"] = download
            }
            stream[key] = settings
        }
        for index in outbounds.indices {
            let proto = protocolRole(outbounds[index]["protocol"])
            guard proto != "wireguard", endpointProtocols.contains(proto) || ["freedom", "dns"].contains(proto) else { continue }
            if proto == "dns", var settings = outbounds[index]["settings"] as? [String: Any] {
                try bindLogicalTarget(&settings)
                outbounds[index]["settings"] = settings
            }
            if endpointProtocols.contains(proto), var settings = outbounds[index]["settings"] as? [String: Any] {
                if settings["address"] is String {
                    try bind(&settings)
                } else if settings["address"] == nil || settings["address"] is NSNull {
                    let listKey = ["vless", "vmess"].contains(proto) ? "vnext" : "servers"
                    if ["vless", "vmess", "trojan", "shadowsocks", "http", "socks"].contains(proto),
                       var servers = settings[listKey] as? [[String: Any]] {
                        for server in servers.indices { try bind(&servers[server]) }
                        settings[listKey] = servers
                    }
                }
                outbounds[index]["settings"] = settings
            }
            if var stream = outbounds[index]["streamSettings"] as? [String: Any] {
                try bindDownload(&stream)
                outbounds[index]["streamSettings"] = stream
            }
        }
        if changed { output["outbounds"] = outbounds; config = output }
        return changed
    }
}
