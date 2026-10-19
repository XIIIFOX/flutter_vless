import Foundation
import CoreFoundation
import Darwin
import flutter_vless_privacy

/// Qualify Core's own pools without changing the caller's engine or DNS policy.
/// Native resolver/interface/probe addresses must never be allocated as fake IPs.
enum TunnelFakeDNSPolicy {
    private struct CIDR {
        let bytes: [UInt8]
        let prefix: Int

        init?(_ text: String) {
            // Darwin accepts scoped IPv6 text; Core ParseCIDR accepts only a
            // plain numeric address and decimal prefix, without scope/whitespace.
            guard text.utf8.allSatisfy({ "0123456789abcdefABCDEF:./".utf8.contains($0) }) else { return nil }
            let parts = text.split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count == 2, !parts[1].isEmpty,
                  parts[1].utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }), let prefix = Int(parts[1]) else { return nil }
            let address = String(parts[0])
            if address.contains(".") {
                // inet_pton on Darwin also accepts zero-padded IPv4 octets;
                // Core's numeric parser rejects those, including mapped tails.
                let tail = address.split(separator: ":", omittingEmptySubsequences: false).last ?? ""
                let octets = tail.split(separator: ".", omittingEmptySubsequences: false)
                guard octets.count == 4, octets.allSatisfy({ octet in
                    !octet.isEmpty && (octet.count == 1 || octet.first != "0") &&
                    octet.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) &&
                    Int(octet).map { $0 <= 255 } == true
                }) else { return nil }
            }
            var v4 = in_addr()
            var v6 = in6_addr()
            if address.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
                guard prefix <= 32 else { return nil }
                bytes = withUnsafeBytes(of: &v4) { Array($0) }
            } else if address.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
                guard prefix <= 128 else { return nil }
                bytes = withUnsafeBytes(of: &v6) { Array($0) }
            } else { return nil }
            self.prefix = prefix
        }

        func overlaps(_ other: CIDR) -> Bool {
            guard bytes.count == other.bytes.count else { return false }
            let bits = min(prefix, other.prefix)
            for bit in 0..<bits {
                let mask = UInt8(1 << (7 - bit % 8))
                if bytes[bit / 8] & mask != other.bytes[bit / 8] & mask { return false }
            }
            return true
        }
    }

    private static let reserved = [
        "10.0.85.0/24", "26.26.26.0/30", "fd26:26:26::/126", "fd00:198:18::/64",
        // Core canonicalizes mapped IPv6 addresses to IPv4 on allocation.
        "::ffff:10.0.85.0/120", "::ffff:26.26.26.0/126"
    ].map { CIDR($0)! }

    /// nil means invalid/ambiguous; false means no active engine or sentinel.
    static func active(in config: [String: Any]) -> Bool? {
        func key(_ object: [String: Any], _ name: String) throws -> String? {
            let keys = object.keys.filter { XrayJSONField.matches($0, name) }
            guard keys.count <= 1 else { throw Invalid.configuration }
            return keys.first
        }
        do {
            let root = try key(config, "fakedns").flatMap { config[$0] }
            var active = root != nil && !(root is NSNull)
            if let root, !(root is NSNull) {
                let pools: [Any]
                if let object = root as? [String: Any] { pools = [object] }
                else if let array = root as? [Any] { pools = array }
                else { return nil }
                for value in pools {
                    guard let pool = value as? [String: Any],
                          let ipKey = try key(pool, "ipPool"), let text = pool[ipKey] as? String,
                          let cidr = CIDR(text),
                          let sizeKey = try key(pool, "poolSize"), let number = pool[sizeKey] as? NSNumber,
                          CFGetTypeID(number) != CFBooleanGetTypeID(),
                          !["f", "d"].contains(String(cString: number.objCType)),
                          let size = Int64(number.stringValue), size > 0,
                          log2(Double(size)) < Double(cidr.bytes.count * 8 - cidr.prefix),
                          !reserved.contains(where: { cidr.overlaps($0) }) else { return nil }
                }
            }
            if let dnsKey = try key(config, "dns"), let dns = config[dnsKey] as? [String: Any],
               let serversKey = try key(dns, "servers"), let servers = dns[serversKey] as? [Any] {
                for server in servers {
                    let raw: String?
                    if let string = server as? String { raw = string }
                    else if let object = server as? [String: Any] {
                        raw = try key(object, "address").flatMap { object[$0] as? String }
                    } else { raw = nil }
                    if let raw, XrayJSONField.matches(LocalProxyAccessPolicy.coreAddressText(raw), "fakedns") { active = true }
                }
            }
            return active
        } catch { return nil }
    }

    private enum Invalid: Error { case configuration }
}
