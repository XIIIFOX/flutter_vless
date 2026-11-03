import Foundation
import CoreFoundation

/// Mirrors the packaged Go privacy boundary so prepared JSON is safe as well.
public enum XrayPrivacyConfig {
    public static func apply(to config: inout [String: Any]) -> Bool {
        apply(to: &config, onLoggingChange: nil)
    }

    public static func apply(to config: inout [String: Any], onLoggingChange: (() -> Void)?) -> Bool {
        var loggingChanged = false
        guard fields(&config, ["log", "inbounds", "outbounds", "api", "stats", "policy"]) else { return false }
        // Keep the established defaults for an absent root. A levels-only
        // imported policy does not disable monitoring: fill only its missing
        // inbound-counter flags when the plugin owns statistics collection.
        // Explicit null/false values and caller management APIs stay intact.
        if config["stats"] == nil { config["stats"] = [String: Any]() }
        if config["policy"] == nil {
            config["policy"] = ["system": ["statsInboundUplink": true, "statsInboundDownlink": true,
                                            "statsOutboundUplink": true, "statsOutboundDownlink": true]]
        } else if config["api"] == nil, !(config["stats"] is NSNull),
                  var policy = config["policy"] as? [String: Any] {
            let keys = policy.keys.filter { XrayJSONField.matches($0, "system") }
            // Do not choose among ambiguous caller spellings or replace an
            // explicitly supplied null/malformed object before Core sees it.
            if keys.count <= 1 {
                let key = keys.first ?? "system"
                if policy[key] == nil || policy[key] is [String: Any] {
                    var system = policy[key] as? [String: Any] ?? [:]
                    let counters = ["statsInboundUplink", "statsInboundDownlink"]
                    let ambiguous = counters.contains { field in
                        system.keys.filter { XrayJSONField.matches($0, field) }.count > 1
                    }
                    if !ambiguous {
                        for field in counters
                            where !system.keys.contains(where: { XrayJSONField.matches($0, field) }) {
                            system[field] = true
                        }
                        policy[key] = system
                        config["policy"] = policy
                    }
                }
            }
        }
        guard config["log"] == nil || config["log"] is NSNull || config["log"] is [String: Any] else { return false }
        var log = config["log"] as? [String: Any] ?? [:]
        guard fields(&log, ["access", "error", "loglevel", "dnsLog"]) else { return false }
        // The replacement below also removes this known Core log field,
        // including null/empty values. Opaque log metadata is not reported.
        if log.keys.contains(where: { XrayJSONField.matches($0, "maskAddress") }) { loggingChanged = true }
        let requested = (log["loglevel"] as? String ?? "warning").lowercased()
        let level = ["error", "none"].contains(requested) ? requested : "warning"
        for (key, value): (String, Any) in [("access", "none"), ("error", "none"), ("loglevel", level), ("dnsLog", false)] {
            setPrivateValue(value, key: key, in: &log, changed: &loggingChanged)
        }
        config["log"] = ["access": "none", "error": "none", "loglevel": level, "dnsLog": false]
        for key in ["inbounds", "outbounds"] {
            guard config[key] == nil || config[key] is NSNull || config[key] is [[String: Any]] else { return false }
            guard var entries = config[key] as? [[String: Any]] else { continue }
            for index in entries.indices {
                guard fields(&entries[index], ["streamSettings"]) else { return false }
                if let value = entries[index]["streamSettings"], !(value is NSNull) {
                    guard var stream = value as? [String: Any], privateStream(&stream, changed: &loggingChanged) else { return false }
                    entries[index]["streamSettings"] = stream
                }
            }
            config[key] = entries
        }
        if loggingChanged { onLoggingChange?() }
        return true
    }

    private static func setPrivateValue(_ value: Any, key: String, in object: inout [String: Any], changed: inout Bool) {
        if let expected = value as? String {
            if object[key] as? String != expected { changed = true }
        } else if let expected = value as? Bool {
            if let actual = object[key] as? NSNumber, CFGetTypeID(actual) == CFBooleanGetTypeID(), actual.boolValue == expected {} else { changed = true }
        }
        object[key] = value
    }

    private static func privateFinalMask(_ stream: inout [String: Any], changed: inout Bool) -> Bool {
        guard fields(&stream, ["finalmask"]) else { return false }
        guard let value = stream["finalmask"], !(value is NSNull) else { return true }
        guard var mask = value as? [String: Any], fields(&mask, ["tcp", "udp", "quicParams"]) else { return false }
        if let value = mask["quicParams"], !(value is NSNull) {
            guard var params = value as? [String: Any], fields(&params, ["debug"]) else { return false }
            setPrivateValue(false, key: "debug", in: &params, changed: &changed)
            mask["quicParams"] = params
        }
        for network in ["tcp", "udp"] {
            guard let value = mask[network], !(value is NSNull) else { continue }
            guard var entries = value as? [[String: Any]] else { return false }
            for index in entries.indices {
                guard fields(&entries[index], ["type"]) else { return false }
                guard (entries[index]["type"] as? String)?.lowercased() == "realm" else { continue }
                guard fields(&entries[index], ["settings"]) else { return false }
                guard let value = entries[index]["settings"], !(value is NSNull) else { continue }
                guard var settings = value as? [String: Any], fields(&settings, ["tlsConfig"]) else { return false }
                if let value = settings["tlsConfig"], !(value is NSNull) {
                    guard var tls = value as? [String: Any], fields(&tls, ["masterKeyLog"]) else { return false }
                    setPrivateValue("", key: "masterKeyLog", in: &tls, changed: &changed)
                    settings["tlsConfig"] = tls
                }
                entries[index]["settings"] = settings
            }
            mask[network] = entries
        }
        stream["finalmask"] = mask
        return true
    }

    private static func privateStream(_ stream: inout [String: Any], changed: inout Bool) -> Bool {
        guard privateFinalMask(&stream, changed: &changed) else { return false }
        guard fields(&stream, ["tlsSettings", "realitySettings", "xhttpSettings", "splithttpSettings"]) else { return false }
        for key in ["tlsSettings", "realitySettings"] {
            guard let value = stream[key], !(value is NSNull) else { continue }
            guard var settings = value as? [String: Any], fields(&settings, ["masterKeyLog"]) else { return false }
            setPrivateValue("", key: "masterKeyLog", in: &settings, changed: &changed)
            if key == "realitySettings" {
                guard fields(&settings, ["show"]) else { return false }
                setPrivateValue(false, key: "show", in: &settings, changed: &changed)
            }
            stream[key] = settings
        }
        for key in ["xhttpSettings", "splithttpSettings"] {
            guard let value = stream[key], !(value is NSNull) else { continue }
            guard var settings = value as? [String: Any], fields(&settings, ["extra"]), privateDownloads(&settings, changed: &changed) else { return false }
            if let extra = settings["extra"], !(extra is NSNull) {
                guard var object = extra as? [String: Any], privateDownloads(&object, changed: &changed) else { return false }
                settings["extra"] = object
            }
            stream[key] = settings
        }
        return true
    }

    private static func privateDownloads(_ settings: inout [String: Any], changed: inout Bool) -> Bool {
        guard fields(&settings, ["downloadSettings"]) else { return false }
        if let value = settings["downloadSettings"], !(value is NSNull) {
            guard var stream = value as? [String: Any], privateStream(&stream, changed: &changed) else { return false }
            settings["downloadSettings"] = stream
        }
        return true
    }

    private static func fields(_ object: inout [String: Any], _ names: [String]) -> Bool {
        for name in names {
            let matches = object.keys.filter { XrayJSONField.matches($0, name) }
            guard matches.count <= 1 else { return false }
            if let key = matches.first, key != name { object[name] = object.removeValue(forKey: key) }
        }
        return true
    }
}
