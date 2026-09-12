import Foundation

/// Go's JSON decoder matches struct fields without regard to case. Normalize
/// policy-owned fields before reading or writing them, and reject ambiguous
/// duplicates. Leave user maps (headers, credentials, DNS hosts) untouched.
enum TunnelConfigKeys {
    static func normalize(_ input: [String: Any]) -> [String: Any]? {
        var config = input
        guard fields(&config, ["inbounds", "outbounds", "routing", "dns", "log"]) else { return nil }
        if var routing = config["routing"] as? [String: Any] {
            guard fields(&routing, ["rules", "domainStrategy"]) else { return nil }
            config["routing"] = routing
        }
        for key in ["inbounds", "outbounds"] {
            guard var entries = config[key] as? [[String: Any]] else { continue }
            for index in entries.indices {
                guard fields(&entries[index], ["tag", "protocol", "settings", "streamSettings", "sniffing"]) else { return nil }
                if var sniffing = entries[index]["sniffing"] as? [String: Any] {
                    guard fields(&sniffing, ["enabled", "destOverride", "routeOnly"]) else { return nil }
                    entries[index]["sniffing"] = sniffing
                }
                if var settings = entries[index]["settings"] as? [String: Any] {
                    guard fields(&settings, ["address", "vnext", "servers", "peers"]) else { return nil }
                    for listKey in ["vnext", "servers", "peers"] {
                        guard var servers = settings[listKey] as? [[String: Any]] else { continue }
                        for server in servers.indices {
                            guard fields(&servers[server], ["address", "endpoint"]) else { return nil }
                        }
                        settings[listKey] = servers
                    }
                    entries[index]["settings"] = settings
                }
                if var stream = entries[index]["streamSettings"] as? [String: Any] {
                    guard normalizeStream(&stream) else { return nil }
                    entries[index]["streamSettings"] = stream
                }
            }
            config[key] = entries
        }
        return config
    }

    private static func normalizeStream(_ stream: inout [String: Any]) -> Bool {
        guard fields(&stream, ["address", "network", "security", "sockopt", "xhttpSettings",
                              "splithttpSettings", "httpupgradeSettings", "tlsSettings"]) else { return false }
        if var sockopt = stream["sockopt"] as? [String: Any] {
            guard fields(&sockopt, ["domainStrategy", "addressPortStrategy"]) else { return false }
            stream["sockopt"] = sockopt
        }
        for key in ["xhttpSettings", "splithttpSettings"] {
            guard var settings = stream[key] as? [String: Any] else { continue }
            guard fields(&settings, ["extra", "downloadSettings"]) else { return false }
            if var extra = settings["extra"] as? [String: Any] {
                guard fields(&extra, ["downloadSettings"]) else { return false }
                if var download = extra["downloadSettings"] as? [String: Any] {
                    guard normalizeStream(&download) else { return false }
                    extra["downloadSettings"] = download
                }
                settings["extra"] = extra
            } else if var download = settings["downloadSettings"] as? [String: Any] {
                guard normalizeStream(&download) else { return false }
                settings["downloadSettings"] = download
            }
            stream[key] = settings
        }
        return true
    }

    private static func fields(_ object: inout [String: Any], _ names: [String]) -> Bool {
        for canonical in names {
            let matches = object.keys.filter { $0.lowercased() == canonical.lowercased() }
            guard matches.count <= 1 else { return false }
            if let key = matches.first, key != canonical {
                object[canonical] = object.removeValue(forKey: key)
            }
        }
        return true
    }
}
