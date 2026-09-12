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
        case .incompatibleInbounds: return "VPN mode requires one loopback SOCKS inbound; additional SOCKS/HTTP inbounds and non-loopback listeners are unsupported. Use proxyOnly for a custom local proxy."
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

    public static func validateVPN(configData: Data) throws {
        var object = try normalizedConfig(configData: configData)
        _ = try managedInbound(in: &object)
    }

    @discardableResult
    public static func applyVPN(to config: inout [String: Any], credentials: LocalProxyCredentials) throws -> Int {
        let (index, port) = try managedInbound(in: &config)
        var inbounds = config["inbounds"] as! [[String: Any]]
        var settings = inbounds[index]["settings"] as? [String: Any] ?? [:]
        settings["auth"] = "password"
        settings["accounts"] = [["user": credentials.username, "pass": credentials.password]]
        settings["udp"] = true
        // Xray advertises this address in UDP ASSOCIATE replies.
        settings["ip"] = "127.0.0.1"
        inbounds[index]["listen"] = "127.0.0.1"
        inbounds[index]["settings"] = settings
        config["inbounds"] = inbounds
        return port
    }

    private static func managedInbound(in config: inout [String: Any]) throws -> (Int, Int) {
        try normalizeLocalFields(&config)
        guard let inbounds = config["inbounds"] as? [[String: Any]] else {
            throw LocalProxyAccessError.malformedConfiguration
        }
        var candidates: [Int] = []
        for index in inbounds.indices {
            guard let proto = inbounds[index]["protocol"] as? String else {
                throw LocalProxyAccessError.malformedConfiguration
            }
            guard ["socks", "http"].contains(proto.lowercased()) else { continue }
            guard proto == "socks" else { throw LocalProxyAccessError.incompatibleInbounds }
            let listen = inbounds[index]["listen"] as? String
            guard inbounds[index]["listen"] == nil || listen == "127.0.0.1" || listen == "::1" || listen == "localhost" else {
                throw LocalProxyAccessError.incompatibleInbounds
            }
            candidates.append(index)
        }
        guard candidates.count == 1, let index = candidates.first else { throw LocalProxyAccessError.incompatibleInbounds }
        guard let number = inbounds[index]["port"] as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue == Double(number.intValue), (1...65535).contains(number.intValue) else {
            throw LocalProxyAccessError.malformedConfiguration
        }
        config["inbounds"] = inbounds
        return (index, number.intValue)
    }

    private static func normalizeLocalFields(_ config: inout [String: Any]) throws {
        try normalize(&config, names: ["inbounds"])
        // Temporary delay/proxyOnly runners may insert their managed listener.
        // Absence is distinct from an explicitly malformed or null value; VPN
        // validation still requires exactly one usable SOCKS inbound below.
        guard config["inbounds"] != nil else { return }
        guard var inbounds = config["inbounds"] as? [[String: Any]] else {
            throw LocalProxyAccessError.malformedConfiguration
        }
        for index in inbounds.indices {
            try normalize(&inbounds[index], names: ["protocol", "listen", "port", "settings", "tag"])
            let proto = (inbounds[index]["protocol"] as? String)?.lowercased()
            guard proto == "socks" || proto == "http" else { continue }
            if let value = inbounds[index]["settings"], !(value is [String: Any]) {
                throw LocalProxyAccessError.malformedConfiguration
            }
            var settings = inbounds[index]["settings"] as? [String: Any] ?? [:]
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
            let keys = object.keys.filter { $0.lowercased() == canonical.lowercased() }
            guard keys.count <= 1 else { throw LocalProxyAccessError.ambiguousField }
            if let key = keys.first, key != canonical { object[canonical] = object.removeValue(forKey: key) }
        }
    }
}
