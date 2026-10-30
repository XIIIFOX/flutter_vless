import Foundation
import CoreFoundation

/// Finite origins of the pinned S3/Google Drive clients. Remote folders,
/// object prefixes and secrets are never interpreted as local file paths.
public enum XdriveServicePolicy {
    public struct Target: Hashable { public let host: String; public let port: Int }
    private struct Invalid: Error {}
    private static func field(_ object: [String: Any], _ name: String) throws -> Any? {
        let keys = object.keys.filter { XrayJSONField.matches($0, name) }
        guard keys.count <= 1 else { throw Invalid() }
        let value = keys.first.flatMap { object[$0] }
        return value is NSNull ? nil : value
    }
    private static func string(_ value: Any?) throws -> String? {
        guard value == nil || value is String else { throw Invalid() }
        return value as? String
    }
    private static func validName(_ value: String) -> Bool {
        !value.isEmpty && !value.unicodeScalars.contains { $0.value < 32 || $0.value == 127 || $0 == "\\" }
            && value.components(separatedBy: "/").allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
    }
    public static func active(_ stream: [String: Any]) throws -> Bool {
        (try string(field(stream, "method")) ?? string(field(stream, "network")) ?? "tcp").lowercased() == "xdrive"
    }
    public static func targets(_ stream: [String: Any]) throws -> [Target] {
        guard let settings = try field(stream, "xdriveSettings") as? [String: Any],
              let folder = try string(field(settings, "remoteFolder")), !folder.isEmpty,
              let secrets = try field(settings, "secrets") as? [String], secrets.allSatisfy({ !$0.isEmpty }) else { throw Invalid() }
        let service = try string(field(settings, "service"))
        let logical: [Target]
        switch service {
        case "google-drive", "Google Drive":
            guard secrets.count == 3 else { throw Invalid() }
            logical = [Target(host: "oauth2.googleapis.com", port: 443), Target(host: "www.googleapis.com", port: 443)]
        case "s3":
            guard (2...3).contains(secrets.count), validName(folder.hasSuffix("/") ? String(folder.dropLast()) : folder),
                  let s3 = try field(settings, "s3") as? [String: Any],
                  let endpoint = try string(field(s3, "endpoint")), let url = URLComponents(string: endpoint),
                  ["http", "https"].contains(url.scheme?.lowercased() ?? ""),
                  let authority = url.host, !authority.isEmpty, url.user == nil, url.password == nil,
                  url.query == nil, url.fragment == nil, let bucket = try string(field(s3, "bucket")),
                  validName(bucket), !bucket.contains("/") else { throw Invalid() }
            let mode = try field(s3, "pathStyle")
            if let mode { guard let number = mode as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { throw Invalid() } }
            var host = authority.hasPrefix("[") && authority.hasSuffix("]") ? String(authority.dropFirst().dropLast()) : authority
            if mode as? Bool == false {
                guard !host.contains(":"), !host.allSatisfy({ $0.isNumber || $0 == "." }),
                      bucket.allSatisfy({ "abcdefghijklmnopqrstuvwxyz0123456789-.".contains($0) }),
                      !bucket.hasPrefix("."), !bucket.hasSuffix("."), !bucket.contains("..") else { throw Invalid() }
                host = bucket + "." + host
            }
            let port = url.port ?? (url.scheme?.lowercased() == "https" ? 443 : 80)
            guard (1...65535).contains(port) else { throw Invalid() }
            logical = [Target(host: host, port: port)]
        default: throw Invalid() // template/local require a separate file/lifetime contract.
        }
        let front = try string(field(stream, "address"))
        let rawPort = try field(stream, "port")
        let frontPort: Int
        if let rawPort {
            guard let number = rawPort as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                  number.doubleValue == Double(number.intValue), (0...65535).contains(number.intValue) else { throw Invalid() }
            frontPort = number.intValue
        } else { frontPort = 0 }
        guard let front else { return logical }
        guard !front.isEmpty else { throw Invalid() }
        return Array(Set(logical.map { Target(host: front, port: frontPort == 0 ? $0.port : frontPort) }))
    }

    /// Public startup/provider gate. A custom or legacy SDK must advertise its
    /// managed-service lifetime independently of the unchanged Core version.
    static func streams(_ config: [String: Any]) throws -> [[String: Any]] {
        var result: [[String: Any]] = []
        for collection in ["inbounds", "outbounds"] {
            for item in try field(config, collection) as? [[String: Any]] ?? [] {
                if collection == "outbounds", ["loopback", "freedom", "blackhole", "dns", "wireguard"].contains(try string(field(item, "protocol"))?.lowercased() ?? "") { continue }
                if let stream = try field(item, "streamSettings") as? [String: Any], try active(stream) { result.append(stream) }
            }
        }
        return result
    }
    public static func validate(_ config: [String: Any]) throws {
        for stream in try streams(config) { _ = try targets(stream) }
    }
    public static func requiresLifetime(_ data: Data) throws -> Bool {
        guard let config = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw Invalid() }
        let active = try streams(config)
        for stream in active { _ = try targets(stream) }
        return !active.isEmpty
    }
}
