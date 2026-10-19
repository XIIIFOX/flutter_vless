import Foundation
import Security
import Darwin

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
        listenerPorts(configuration: configuration, sections: ["api"])
    }

    /// Management services share the TCP port namespace with the private adapter.
    /// Keep caller API/metrics fields intact, including Core's field aliases.
    public static func serviceListenerPorts(configuration: [String: Any]) -> Set<Int> {
        listenerPorts(configuration: configuration, sections: ["api", "metrics"])
    }

    private static func listenerPorts(configuration: [String: Any], sections: [String]) -> Set<Int> {
        var ports = Set<Int>()
        for (key, value) in configuration where sections.contains(where: { XrayJSONField.matches(key, $0) }) {
            guard let service = value as? [String: Any] else { continue }
            for (field, value) in service where XrayJSONField.matches(field, "listen") {
                guard let listen = value as? String, !listen.hasPrefix("/"), !listen.hasPrefix("@"),
                      let colon = listen.lastIndex(of: ":") else { continue }
                var digits = listen[listen.index(after: colon)...]
                // Go net.Listen accepts a single leading plus for decimal ports.
                if digits.first == "+" { digits = digits.dropFirst() }
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
    /// environment. Bind listener addresses and port references once before
    /// saving the immutable session, so system/control restarts keep their
    /// effective listener type and port list.
    /// The caller's source JSON remains available in its own editor/model.
    public static func bindingPortEnvironment(configData: Data,
        environment: [String: String] = ProcessInfo.processInfo.environment) throws -> Data {
        var config = try normalizedConfig(configData: configData)
        var changed = try bindListenerEnvironment(&config, environment: environment)
        guard var inputs = config["inbounds"] as? [[String: Any]] else { return configData }
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
        try normalize(&config, names: ["api", "metrics"])
        var tags = XrayServiceTags(configuration: config)
        let tag = tags.next("flutter-vless-delay")
        // Only this isolated measurement core omits caller-owned management
        // listeners, which may already belong to the running VPN provider.
        // Clearing listen instead would install an API/metrics outbound by tag.
        config.removeValue(forKey: "api")
        config.removeValue(forKey: "metrics")
        config["inbounds"] = [["tag": tag, "listen": "127.0.0.1", "port": port, "protocol": "http",
            "settings": ["accounts": [["user": credentials.username, "pass": credentials.password]]]]]
    }

    public static let managedTagPrefix = "flutter-vless-tun"

    public static func validateVPN(configData: Data, tcpPortAvailable: ((Int) -> Bool)? = nil) throws {
        var object = try normalizedConfig(configData: configData)
        _ = try bindListenerEnvironment(&object, environment: ProcessInfo.processInfo.environment)
        _ = try privatePort(configuration: object, tcpPortAvailable: tcpPortAvailable)
    }

    /// Add a private authenticated adapter without changing imported listeners.
    /// Always prepare the original profile; prepared session credentials are not
    /// persisted or fed back into this function during recovery.
    @discardableResult
    public static func applyVPN(to config: inout [String: Any], credentials: LocalProxyCredentials,
                                tcpPortAvailable: ((Int) -> Bool)? = nil) throws -> Int {
        try normalizeLocalFields(&config)
        _ = try bindListenerEnvironment(&config, environment: ProcessInfo.processInfo.environment)
        let imported = config["inbounds"] as? [[String: Any]] ?? []
        let port = try privatePort(configuration: config, tcpPortAvailable: tcpPortAvailable)
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

    /// Address.UnmarshalJSON performs exactly one env lookup before deciding
    /// whether listen is a Unix path or an IP. Freeze that same effective value
    /// before port allocation and cross-process profile persistence.
    private static func bindListenerEnvironment(_ config: inout [String: Any],
                                                environment: [String: String]) throws -> Bool {
        guard var inputs = config["inbounds"] as? [[String: Any]] else { return false }
        var changed = false
        for index in inputs.indices {
            guard let listen = inputs[index]["listen"] as? String, listen.hasPrefix("env:") else { continue }
            let resolved = try bindingAddressEnvironment(listen, environment: environment)
            inputs[index]["listen"] = resolved
            changed = true
        }
        if changed { config["inbounds"] = inputs }
        return changed
    }

    /// Match Core's one-time Address.UnmarshalJSON environment lookup. Keep
    /// raw expanded text so a later Core decode performs ParseAddress once.
    public static func bindingAddressEnvironment(_ raw: String,
        environment: [String: String] = ProcessInfo.processInfo.environment) throws -> String {
        guard raw.hasPrefix("env:") else { return raw }
        let name = String(raw.dropFirst(4))
        let resolved: String
        if let exact = environment[name] {
            resolved = exact // LookupEnv preserves an explicitly empty value.
        } else {
            let trimmed = name.trimmingCharacters(in: goWhitespace)
            // Swift full Unicode uppercasing can expand a scalar (ß -> SS),
            // unlike Go's simple case mapping. Keep that alias boundary
            // explicit while retaining exact Unicode environment keys.
            guard trimmed.unicodeScalars.allSatisfy({ $0.isASCII }) else {
                throw LocalProxyAccessError.malformedConfiguration
            }
            let alternate = trimmed.uppercased().replacingOccurrences(of: ".", with: "_")
            resolved = alternate.isEmpty ? "" : environment[alternate] ?? ""
        }
        // Emitting a raw env: result would perform another lookup when saved
        // JSON is decoded. Refuse it instead of changing Core's one-lookup meaning.
        guard !resolved.hasPrefix("env:") else { throw LocalProxyAccessError.malformedConfiguration }
        return resolved
    }

    /// ParseAddress strips one bracket pair before Go's whitespace trim.
    /// This classification view must not replace the caller's raw JSON value.
    public static func coreAddressText(_ raw: String) -> String {
        let unbracketed = raw.hasPrefix("[") && raw.hasSuffix("]")
            ? String(raw.dropFirst().dropLast()) : raw
        return unbracketed.trimmingCharacters(in: goWhitespace)
    }

    // strings.TrimSpace uses Go's Unicode White_Space table. Keep it explicit
    // rather than Foundation's broader character classification.
    private static let goWhitespace = CharacterSet(charactersIn:
        "\u{0009}\u{000a}\u{000b}\u{000c}\u{000d} \u{0085}\u{00a0}\u{1680}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}")

    private static func isUnixListener(_ raw: String) -> Bool {
        // ParseAddress removes one outer bracket pair before TrimSpace. This
        // view is for classification only; retain the original effective text.
        let address = coreAddressText(raw)
        return address.hasPrefix("/") || address.hasPrefix("@")
    }

    /// This is an availability check, not a retained listener or atomic handoff.
    /// Core owns the final socket and refuses a later conflicting bind.
    public static func isTCPPortAvailable(_ port: Int) -> Bool {
        guard (1...65535).contains(port) else { return false }
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(port).bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        return withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0
            }
        }
    }

    private static func privatePort(configuration: [String: Any], tcpPortAvailable: ((Int) -> Bool)? = nil) throws -> Int {
        let inbounds = configuration["inbounds"] as? [[String: Any]] ?? []
        var used = XrayPortSpec.serviceListenerPorts(configuration: configuration)
        for inbound in inbounds {
            guard let proto = inbound["protocol"] as? String, !proto.isEmpty else {
                throw LocalProxyAccessError.malformedConfiguration
            }
            let listen = inbound["listen"] as? String ?? ""
            // Core ignores PortList when this input listens on a Unix socket.
            if isUnixListener(listen) { continue }
            guard let value = inbound["port"] else { continue } // Unix/listener-free inputs.
            used.formUnion(try XrayPortSpec.reservedPorts(value))
        }
        var attempts = 0
        let candidates = sequence(first: 10808) { $0 == 65535 ? 1024 : ($0 == 10807 ? nil : $0 + 1) }
        for port in candidates where !used.contains(port) {
            guard let tcpPortAvailable else { return port }
            guard attempts < 32 else { throw LocalProxyAccessError.incompatibleInbounds }
            attempts += 1
            if tcpPortAvailable(port) { return port }
        }
        throw LocalProxyAccessError.incompatibleInbounds
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
