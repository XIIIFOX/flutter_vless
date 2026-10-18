import Foundation

/// Reserve definitions and references before adding private runtime services.
/// A dangling user reference must not acquire a new meaning after preparation.
/// Only field names are folded; tag values remain case sensitive and unchanged.
public struct XrayServiceTags {
    private var used = Set<String>()

    public init(configuration: Any) { collect(configuration) }

    public mutating func next(_ preferred: String) -> String {
        var candidate = preferred
        var suffix = 0
        while used.contains(candidate) {
            suffix += 1
            candidate = "\(preferred)-\(suffix)"
        }
        used.insert(candidate)
        return candidate
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
