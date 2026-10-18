import Foundation
import Security

/// Credentials belong to a native running session, never to an exported profile.
public struct LocalProxyCredentials: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let username: String
    public let password: String

    public init(username: String, password: String) throws {
        guard [username, password].allSatisfy({ value in
            (1...255).contains(value.utf8.count) && !value.unicodeScalars.contains { $0.value < 0x20 || $0.value == 0x7f }
        }) else { throw LocalProxyAccessError.invalidCredentials }
        self.username = username
        self.password = password
    }

    /// 128-bit username and 256-bit password from Apple's system CSPRNG.
    public static func generate() throws -> Self {
        var bytes = [UInt8](repeating: 0, count: 48)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw LocalProxyAccessError.randomGenerationFailed
        }
        return try Self(username: bytes.prefix(16).map { String(format: "%02x", $0) }.joined(),
                        password: bytes.suffix(32).map { String(format: "%02x", $0) }.joined())
    }

    public var socksAuthenticationRequest: Data {
        Data([1, UInt8(username.utf8.count)] + Array(username.utf8) + [UInt8(password.utf8.count)] + Array(password.utf8))
    }

    public var description: String { "LocalProxyCredentials(<private>)" }
    public var debugDescription: String { description }
}

public enum LocalProxyAccessError: Error, LocalizedError {
    case malformedConfiguration, ambiguousField, incompatibleInbounds, invalidCredentials, randomGenerationFailed
    case portEnvironment(Int)

    public var errorDescription: String? {
        switch self {
        case .malformedConfiguration: return "Invalid local proxy configuration"
        case .ambiguousField: return "Ambiguous local proxy configuration fields"
        case .incompatibleInbounds: return "No free port is available for the private VPN adapter."
        case .invalidCredentials: return "Local proxy credentials must contain 1–255 UTF-8 bytes without control characters"
        case .randomGenerationFailed: return "Unable to generate local proxy session credentials"
        case .portEnvironment(let index): return "Unable to resolve inbounds[\(index)].port from the application environment."
        }
    }
}

/// Reserve imported listener ports without rewriting their Core syntax.
/// Environment references belong to the native process, never the Dart host.
public enum XrayPortSpec {
    /// API.listen also binds a TCP socket. Reserve its numeric port before
    /// choosing a private adapter; Unix and dynamic port-zero listeners do not
    /// occupy a fixed TCP port. Named services remain Core/OS syntax, not errors.
    public static func apiListenerPorts(configuration: [String: Any]) -> Set<Int> {
        var ports = Set<Int>()
        for (key, value) in configuration where XrayJSONField.matches(key, "api") {
            guard let api = value as? [String: Any] else { continue }
            for (field, value) in api where XrayJSONField.matches(field, "listen") {
                guard let listen = value as? String, !listen.hasPrefix("/"), !listen.hasPrefix("@"),
                      let colon = listen.lastIndex(of: ":") else { continue }
                let digits = listen[listen.index(after: colon)...]
                guard !digits.isEmpty, digits.utf8.allSatisfy({ (48...57).contains($0) }),
                      let port = Int(digits), (1...65535).contains(port) else { continue }
                ports.insert(port)
            }
        }
        return ports
    }

    public static func reservedPorts(_ value: Any,
        environment: (String) -> String? = { ProcessInfo.processInfo.environment[$0] }) throws -> Set<Int> {
        if let number = value as? NSNumber {
            guard CFGetTypeID(number) != CFBooleanGetTypeID(),
                  !["f", "d"].contains(String(cString: number.objCType)),
                  (0...65535).contains(number.intValue) else { throw LocalProxyAccessError.malformedConfiguration }
            return number.intValue == 0 ? [] : [number.intValue]
        }
        guard let text = value as? String else { throw LocalProxyAccessError.malformedConfiguration }
        var ports = Set<Int>()
        for raw in text.split(separator: ",", omittingEmptySubsequences: false) {
            var part = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if part.isEmpty { continue } // Core ignores empty list entries.
            let fromEnvironment = part.hasPrefix("env:")
            if fromEnvironment {
                let name = String(part.dropFirst(4))
                let alternate = name.trimmingCharacters(in: .whitespacesAndNewlines).uppercased().replacingOccurrences(of: ".", with: "_")
                guard let resolved = environment(name) ?? environment(alternate) else { throw LocalProxyAccessError.malformedConfiguration }
                part = resolved
            }
            let limits = part.split(separator: "-", omittingEmptySubsequences: false)
            guard (1...2).contains(limits.count) else { throw LocalProxyAccessError.malformedConfiguration }
            func number(_ text: Substring) throws -> Int {
                guard !text.isEmpty, text.utf8.allSatisfy({ (48...57).contains($0) }),
                      fromEnvironment || limits.count == 2 || text == "0" || !text.hasPrefix("0"),
                      let result = Int(text), (0...65535).contains(result) else { throw LocalProxyAccessError.malformedConfiguration }
                return result
            }
            let first = try number(limits[0]), last = try number(limits.last!)
            // Core's PortList treats a descending range as an empty selection.
            if first <= last { ports.formUnion((first...last).filter { $0 != 0 }) }
        }
        return ports
    }
}

/// Owns only local listeners. Remote passwords, IDs, keys and user maps remain untouched.
public enum LocalProxyAccessPolicy {
    /// A Packet Tunnel is a separate process and does not inherit Runner's
    /// environment. Bind port references once before saving the immutable
    /// session, so system/control restarts use the same effective port list.
    /// The caller's source JSON remains available in its own editor/model.
    public static func bindingPortEnvironment(configData: Data,
        environment: [String: String] = ProcessInfo.processInfo.environment) throws -> Data {
        var config = try normalizedConfig(configData: configData)
        guard var inputs = config["inbounds"] as? [[String: Any]] else { return configData }
        var changed = false
        for index in inputs.indices {
            guard let value = inputs[index]["port"] as? String else { continue }
            let parts = value.split(separator: ",", omittingEmptySubsequences: false)
            guard parts.contains(where: { $0.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("env:") }) else { continue }
            do {
                _ = try XrayPortSpec.reservedPorts(value, environment: { environment[$0] })
                inputs[index]["port"] = try parts.map { raw -> String in
                    let part = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard part.hasPrefix("env:") else { return String(raw) }
                    let name = String(part.dropFirst(4))
                    let alternate = name.trimmingCharacters(in: .whitespacesAndNewlines).uppercased().replacingOccurrences(of: ".", with: "_")
                    guard let resolved = environment[name] ?? environment[alternate] else { throw LocalProxyAccessError.portEnvironment(index) }
                    // Validation above uses this same immutable environment.
                    // Canonical decimal tokens also retain env: leading-zero
                    // semantics when Core parses the resulting ordinary list.
                    return resolved.split(separator: "-", omittingEmptySubsequences: false).map { String(Int($0)!) }.joined(separator: "-")
                }.joined(separator: ",")
                changed = true
            } catch { throw LocalProxyAccessError.portEnvironment(index) }
        }
        guard changed else { return configData }
        config["inbounds"] = inputs
        return try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])
    }

    public static func normalizedConfig(configData: Data) throws -> [String: Any] {
        guard var object = try JSONSerialization.jsonObject(with: configData) as? [String: Any] else {
            throw LocalProxyAccessError.malformedConfiguration
        }
        try normalizeLocalFields(&object)
        return object
    }

    /// A latency probe starts an isolated core, so it must not bind imported listeners.
    /// A fresh tag also avoids inheriting a user's inbound-specific direct route.
    public static func applyDelayProbe(to config: inout [String: Any], port: Int,
                                       credentials: LocalProxyCredentials) throws {
        guard (1...65535).contains(port) else { throw LocalProxyAccessError.malformedConfiguration }
        try normalizeLocalFields(&config)
        var tags = XrayServiceTags(configuration: config)
        let tag = tags.next("flutter-vless-delay")
        config["inbounds"] = [["tag": tag, "listen": "127.0.0.1", "port": port, "protocol": "http",
            "settings": ["accounts": [["user": credentials.username, "pass": credentials.password]]]]]
    }

    public static let managedTagPrefix = "flutter-vless-tun"

    public static func validateVPN(configData: Data) throws {
        let object = try normalizedConfig(configData: configData)
        _ = try privatePort(configuration: object)
    }

    /// Add a private authenticated adapter without changing imported listeners.
    /// Always prepare the original profile; prepared session credentials are not
    /// persisted or fed back into this function during recovery.
    @discardableResult
    public static func applyVPN(to config: inout [String: Any], credentials: LocalProxyCredentials) throws -> Int {
        try normalizeLocalFields(&config)
        let imported = config["inbounds"] as? [[String: Any]] ?? []
        let port = try privatePort(configuration: config)
        var tags = XrayServiceTags(configuration: config)
        let tag = tags.next(managedTagPrefix)
        let managed: [String: Any] = [
            "tag": tag, "listen": "127.0.0.1", "port": port, "protocol": "socks",
            "settings": ["auth": "password", "accounts": [["user": credentials.username, "pass": credentials.password]],
                         "udp": true, "ip": "127.0.0.1"],
            "sniffing": ["enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true]
        ]
        // Providers select the first local SOCKS port from the prepared config.
        config["inbounds"] = [managed] + imported
        return port
    }

    private static func privatePort(configuration: [String: Any]) throws -> Int {
        let inbounds = configuration["inbounds"] as? [[String: Any]] ?? []
        var used = XrayPortSpec.apiListenerPorts(configuration: configuration)
        for inbound in inbounds {
            guard let proto = inbound["protocol"] as? String, !proto.isEmpty else {
                throw LocalProxyAccessError.malformedConfiguration
            }
            let listen = inbound["listen"] as? String ?? ""
            // Core ignores PortList when this input listens on a Unix socket.
            if listen.hasPrefix("/") || listen.hasPrefix("@") { continue }
            guard let value = inbound["port"] else { continue } // Unix/listener-free inputs.
            used.formUnion(try XrayPortSpec.reservedPorts(value))
        }
        guard let port = (10808...65535).first(where: { !used.contains($0) }) ?? (1024..<10808).first(where: { !used.contains($0) }) else {
            throw LocalProxyAccessError.incompatibleInbounds
        }
        return port
    }

    private static func normalizeLocalFields(_ config: inout [String: Any]) throws {
        try normalize(&config, names: ["inbounds"])
        // Temporary delay/proxyOnly runners may insert their managed listener.
        // Absence is distinct from an explicitly malformed or null value; VPN
        // validation allocates a separate private SOCKS inbound.
        guard config["inbounds"] != nil else { return }
        guard var inbounds = config["inbounds"] as? [[String: Any]] else {
            throw LocalProxyAccessError.malformedConfiguration
        }
        for index in inbounds.indices {
            try normalize(&inbounds[index], names: ["protocol", "listen", "port", "settings", "tag"])
            let proto = (inbounds[index]["protocol"] as? String)?.lowercased()
            guard proto == "socks" || proto == "http" else { continue }
            guard let value = inbounds[index]["settings"] else { continue }
            guard var settings = value as? [String: Any] else {
                throw LocalProxyAccessError.malformedConfiguration
            }
            try normalize(&settings, names: ["auth", "accounts", "udp", "ip", "users"])
            if var accounts = settings["accounts"] as? [[String: Any]] {
                for account in accounts.indices { try normalize(&accounts[account], names: ["user", "pass"]) }
                settings["accounts"] = accounts
            }
            inbounds[index]["settings"] = settings
        }
        config["inbounds"] = inbounds
    }

    private static func normalize(_ object: inout [String: Any], names: [String]) throws {
        for canonical in names {
            let keys = object.keys.filter { XrayJSONField.matches($0, canonical) }
            guard keys.count <= 1 else { throw LocalProxyAccessError.ambiguousField }
            if let key = keys.first, key != canonical { object[canonical] = object.removeValue(forKey: key) }
        }
    }
}

/// Go encoding/json uses Unicode simple folding for schema field names. Only
/// long S and Kelvin sign share a fold class with ASCII outside A–Z/a–z.
/// Do not use full Unicode folding or apply this to user dictionary keys.
public enum XrayJSONField {
    public static func matches(_ key: String, _ asciiField: String) -> Bool {
        func folded(_ scalar: Unicode.Scalar) -> UInt32 {
            switch scalar.value {
            case 65...90: return scalar.value + 32
            case 0x017f: return 115
            case 0x212a: return 107
            default: return scalar.value
            }
        }
        return key.unicodeScalars.map(folded) == asciiField.unicodeScalars.map(folded)
    }
}
