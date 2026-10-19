import Foundation

/// Reserve definitions and references before adding private runtime services.
/// A dangling user reference must not acquire a new meaning after preparation.
/// Only field names are folded; tag values remain case sensitive and unchanged.
public struct XrayServiceTags {
    private var used = Set<String>()

    // Core uses byte-prefix selectors, not exact tag references. Empty
    // selectors remain a Core-provenance boundary: naming cannot hide them.
    private var prefixes = [[UInt8]]()
    private var firstScalars = Set<UInt32>()
    private var escapeScalar: Unicode.Scalar?

    public init(configuration: Any) {
        collect(configuration)
        if let object = configuration as? [String: Any] { collectSelectors(object) }
        escapeScalar = safeScalar()
    }

    public mutating func next(_ preferred: String) -> String {
        var stem = preferred
        var candidate = stem
        var suffix = 0
        var escaped = false
        while true {
            if !escaped, prefixes.contains(where: { candidate.utf8.starts(with: $0) }), let escapeScalar {
                stem = String(escapeScalar) + preferred
                candidate = stem
                suffix = 0
                escaped = true
                continue
            }
            guard used.contains(candidate) else { break }
            suffix += 1
            candidate = "\(stem)-\(suffix)"
        }
        used.insert(candidate)
        return candidate
    }

    private func values(_ object: [String: Any], _ name: String) -> [Any] {
        object.compactMap { XrayJSONField.matches($0.key, name) ? $0.value : nil }
    }

    private mutating func collectPrefixes(_ value: Any, commaString: Bool) {
        let strings: [String]
        if commaString, let string = value as? String { strings = string.components(separatedBy: ",") }
        else { strings = (value as? [Any] ?? []).compactMap { $0 as? String } }
        for string in strings where !string.isEmpty {
            prefixes.append(Array(string.utf8))
            if let first = string.unicodeScalars.first { firstScalars.insert(first.value) }
        }
    }

    private mutating func collectSelectors(_ object: [String: Any]) {
        for routing in values(object, "routing").compactMap({ $0 as? [String: Any] }) {
            for list in values(routing, "balancers").compactMap({ $0 as? [Any] }) {
                for balancer in list.compactMap({ $0 as? [String: Any] }) {
                    for value in values(balancer, "selector") { collectPrefixes(value, commaString: true) }
                }
            }
        }
        for name in ["observatory", "burstObservatory"] {
            for observer in values(object, name).compactMap({ $0 as? [String: Any] }) {
                for value in values(observer, "subjectSelector") { collectPrefixes(value, commaString: false) }
            }
        }
    }

    private func safeScalar() -> Unicode.Scalar? {
        for scalar in "_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-".unicodeScalars {
            if !firstScalars.contains(scalar.value) { return scalar }
        }
        // At most N+1 different scalars are needed for N occupied first
        // scalars. Exhausting the finite alphabet retains exact allocation;
        // it must not reject a caller profile or loop on universal coverage.
        let limit = min(firstScalars.count + 1, 0x110000 - 0x800)
        var examined = 0
        let ranges: [ClosedRange<UInt32>] = [0xE000...0xF8FF, 0xF0000...0xFFFFD, 0x100000...0x10FFFD,
            0...0xD7FF, 0xF900...0xEFFFF, 0xFFFFE...0xFFFFF, 0x10FFFE...0x10FFFF]
        for range in ranges {
            for value in range {
                guard examined < limit else { return nil }
                examined += 1
                if !firstScalars.contains(value), let scalar = Unicode.Scalar(value) { return scalar }
            }
        }
        return nil
    }

    private mutating func collect(_ value: Any) {
        if let object = value as? [String: Any] {
            for (key, child) in object {
                if ["tag", "inboundTag", "outboundTag", "balancerTag", "dialerProxy", "fallbackTag"].contains(where: { XrayJSONField.matches(key, $0) }) {
                    if let tag = child as? String { used.insert(tag) }
                    if let tags = child as? [String] { used.formUnion(tags) }
                }
                collect(child)
            }
        } else if let array = value as? [Any] {
            for child in array { collect(child) }
        }
    }
}
