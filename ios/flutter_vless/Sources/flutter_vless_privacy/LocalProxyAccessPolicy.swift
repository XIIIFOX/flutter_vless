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

    public var errorDescription: String? {
        switch self {
        case .malformedConfiguration: return "Invalid local proxy configuration"
        case .ambiguousField: return "Ambiguous local proxy configuration fields"
        case .incompatibleInbounds: return "No free port is available for the private VPN adapter."
        case .invalidCredentials: return "Local proxy credentials must contain 1–255 UTF-8 bytes without control characters"
        case .randomGenerationFailed: return "Unable to generate local proxy session credentials"
        }
    }
}

/// Owns only local listeners. Remote passwords, IDs, keys and user maps remain untouched.
public enum LocalProxyAccessPolicy {
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
        let entries = (config["inbounds"] as? [[String: Any]] ?? []) + (config["outbounds"] as? [[String: Any]] ?? [])
        let tags = Set(entries.compactMap { $0["tag"] as? String })
        let prefix = "flutter-vless-delay"
        var tag = prefix
        var suffix = 0
        while tags.contains(tag) { suffix += 1; tag = "\(prefix)-\(suffix)" }
        config["inbounds"] = [["tag": tag, "listen": "127.0.0.1", "port": port, "protocol": "http",
            "settings": ["accounts": [["user": credentials.username, "pass": credentials.password]]]]]
    }

    public static let managedTagPrefix = "flutter-vless-tun"

    public static func validateVPN(configData: Data) throws {
        let object = try normalizedConfig(configData: configData)
        _ = try privatePort(inbounds: object["inbounds"] as? [[String: Any]] ?? [])
    }

    /// Add a private authenticated adapter without changing imported listeners.
    /// Always prepare the original profile; prepared session credentials are not
    /// persisted or fed back into this function during recovery.
    @discardableResult
    public static func applyVPN(to config: inout [String: Any], credentials: LocalProxyCredentials) throws -> Int {
        try normalizeLocalFields(&config)
        let imported = config["inbounds"] as? [[String: Any]] ?? []
        let port = try privatePort(inbounds: imported)
        let allEntries = imported + (config["outbounds"] as? [[String: Any]] ?? [])
        let tags = Set(allEntries.compactMap { $0["tag"] as? String })
        var tag = managedTagPrefix
        var suffix = 0
        while tags.contains(tag) { suffix += 1; tag = "\(managedTagPrefix)-\(suffix)" }
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

    private static func privatePort(inbounds: [[String: Any]]) throws -> Int {
        var used = Set<Int>()
        for inbound in inbounds {
            guard let proto = inbound["protocol"] as? String, !proto.isEmpty else {
                throw LocalProxyAccessError.malformedConfiguration
            }
            guard let value = inbound["port"] else { continue } // Unix/listener-free inputs.
            if let number = value as? NSNumber {
                guard CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue == Double(number.intValue),
                      (0...65535).contains(number.intValue) else { throw LocalProxyAccessError.malformedConfiguration }
                used.insert(number.intValue)
            } else if let text = value as? String {
                for part in text.split(separator: ",", omittingEmptySubsequences: false) {
                    let limits = part.trimmingCharacters(in: .whitespaces).split(separator: "-", omittingEmptySubsequences: false)
                    guard (1...2).contains(limits.count), let first = Int(limits[0]), let last = Int(limits.last!),
                          (0...65535).contains(first), (first...65535).contains(last) else {
                        throw LocalProxyAccessError.malformedConfiguration
                    }
                    used.formUnion(first...last)
                }
            } else { throw LocalProxyAccessError.malformedConfiguration }
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
