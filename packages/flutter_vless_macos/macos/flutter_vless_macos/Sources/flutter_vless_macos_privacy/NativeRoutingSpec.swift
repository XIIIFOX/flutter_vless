import Foundation
import CoreFoundation
import CryptoKit

/// Native-only choices. This index addresses the ORIGINAL caller inbounds.
/// The preparer must separately supply its provenance-backed final mapping.
public struct NativeRoutingIntent: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    public let sourceInboundIndex: Int?
    public let defaultOutboundTag: String?

    public init(sourceInboundIndex: Int? = nil, defaultOutboundTag: String? = nil) throws {
        guard sourceInboundIndex.map({ $0 >= 0 }) ?? true else { throw NativeRoutingSpecError.invalidIntent }
        self.sourceInboundIndex = sourceInboundIndex
        self.defaultOutboundTag = defaultOutboundTag
    }

    /// Only the trusted channel/profile metadata may request the factory.
    /// An empty dictionary is an explicit request; absent/null is ordinary.
    public static func parse(_ value: Any?) throws -> NativeRoutingIntent? {
        guard let value, !(value is NSNull) else { return nil }
        guard let object = value as? [String: Any],
              Set(object.keys).isSubset(of: ["sourceInboundIndex", "defaultOutboundTag"]) else {
            throw NativeRoutingSpecError.invalidIntent
        }
        var index: Int?
        if let raw = object["sourceInboundIndex"] {
            guard let number = raw as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                  !["f", "d"].contains(String(cString: number.objCType)),
                  let integer = Int(number.stringValue), integer >= 0 else {
                throw NativeRoutingSpecError.invalidIntent
            }
            index = integer
        }
        var tag: String?
        if let raw = object["defaultOutboundTag"], !(raw is NSNull) {
            guard let string = raw as? String else { throw NativeRoutingSpecError.invalidIntent }
            tag = string
        }
        return try NativeRoutingIntent(sourceInboundIndex: index, defaultOutboundTag: tag)
    }

    /// Persist choices only. Session credentials/digests/compiled indices belong
    /// to the provider's freshly prepared envelope, never to the saved profile.
    public var dictionary: [String: Any] {
        var result: [String: Any] = [:]
        if let sourceInboundIndex { result["sourceInboundIndex"] = sourceInboundIndex }
        if let defaultOutboundTag, !defaultOutboundTag.isEmpty { result["defaultOutboundTag"] = defaultOutboundTag }
        return result
    }

    public static func == (lhs: NativeRoutingIntent, rhs: NativeRoutingIntent) -> Bool {
        lhs.sourceInboundIndex == rhs.sourceInboundIndex
            && (lhs.defaultOutboundTag ?? "").utf8.elementsEqual((rhs.defaultOutboundTag ?? "").utf8)
    }

    public var description: String { "NativeRoutingIntent(<private>)" }
    public var debugDescription: String { description }
}

/// Exact immutable arguments for one native factory call. It has no public
/// memberwise initializer and cannot be enabled by fields in the caller JSON.
public struct NativeRoutingEnvelope: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let configurationData: Data
    public let metadataData: Data
    public let sourceSHA256: String

    fileprivate init(configurationData: Data, metadataData: Data, sourceSHA256: String) {
        self.configurationData = configurationData
        self.metadataData = metadataData
        self.sourceSHA256 = sourceSHA256
    }

    public var description: String { "NativeRoutingEnvelope(<private>)" }
    public var debugDescription: String { description }
}

public enum NativeRoutingSpecError: Error, LocalizedError, Sendable {
    case invalidIntent, malformedConfiguration, invalidManagedInbound
    case invalidSourceInbound, invalidDefaultOutbound, invalidGuardRules
    case unsupportedRuntime, coreRejected

    public var errorDescription: String? {
        switch self {
        case .invalidIntent: return "Invalid native routing intent."
        case .malformedConfiguration: return "Invalid final native routing configuration."
        case .invalidManagedInbound: return "Invalid private native routing adapter."
        case .invalidSourceInbound: return "Invalid native routing source selection."
        case .invalidDefaultOutbound: return "Invalid native routing default selection."
        case .invalidGuardRules: return "Invalid native routing guard selection."
        case .unsupportedRuntime: return "Native VPN routing is unavailable in this Xray runtime."
        case .coreRejected: return "Xray rejected the final native VPN routing configuration."
        }
    }
}

public enum NativeRoutingSpec {
    public static func requireRuntime(_ capability: Int64) throws {
        guard capability == 1 else { throw NativeRoutingSpecError.unsupportedRuntime }
    }

    /// Validate selections against caller handlers before any private handler is
    /// appended. Generated bootstrap/DNS tags cannot become a caller default.
    public static func validateSource(_ data: Data, intent: NativeRoutingIntent?) throws {
        guard let intent else { return }
        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw NativeRoutingSpecError.malformedConfiguration
        }
        if let index = intent.sourceInboundIndex {
            guard let inputs = try field(root, "inbounds") as? [[String: Any]], inputs.indices.contains(index) else {
                throw NativeRoutingSpecError.invalidSourceInbound
            }
        }
        if let selected = intent.defaultOutboundTag, !selected.isEmpty {
            guard let outputs = try field(root, "outbounds") as? [[String: Any]] else {
                throw NativeRoutingSpecError.invalidDefaultOutbound
            }
            var matches = 0
            for output in outputs where try equal(tag(output), selected) { matches += 1 }
            guard matches == 1 else { throw NativeRoutingSpecError.invalidDefaultOutbound }
        }
    }

    public static func check(_ envelope: NativeRoutingEnvelope, capability: () -> Int64,
                             check: (Data, Data) -> Int64) throws {
        try requireRuntime(capability())
        guard check(envelope.configurationData, envelope.metadataData) == 0 else {
            throw NativeRoutingSpecError.coreRejected
        }
    }

    /// This creates metadata only: it never normalizes, rebuilds or runs Core.
    /// A nil trusted intent keeps the ordinary path, regardless of caller JSON.
    /// Go preflight remains authoritative for the complete compiled Core shape.
    public static func freeze(finalData: Data, managedInboundIndex: Int, managedInboundTag: String,
                              authUser: String, intent: NativeRoutingIntent?, sourceInboundFinalIndex: Int? = nil,
                              guardRuleIndices: [Int] = []) throws -> NativeRoutingEnvelope? {
        guard let intent else { return nil }
        // A real copy also isolates Data backed by externally mutable NSData.
        let frozen = finalData.withUnsafeBytes { Data($0) }
        guard let root = (try? JSONSerialization.jsonObject(with: frozen)) as? [String: Any],
              let inbounds = try field(root, "inbounds") as? [[String: Any]] else {
            throw NativeRoutingSpecError.malformedConfiguration
        }
        guard !managedInboundTag.isEmpty, !authUser.isEmpty, inbounds.indices.contains(managedInboundIndex),
              try privateInput(inbounds[managedInboundIndex], tag: managedInboundTag, user: authUser) else {
            throw NativeRoutingSpecError.invalidManagedInbound
        }
        var managedMatches = 0
        for inbound in inbounds where try equal(tag(inbound), managedInboundTag) { managedMatches += 1 }
        guard managedMatches == 1 else { throw NativeRoutingSpecError.invalidManagedInbound }

        if let original = intent.sourceInboundIndex {
            guard original >= 0, let mapped = sourceInboundFinalIndex, inbounds.indices.contains(mapped),
                  mapped != managedInboundIndex else { throw NativeRoutingSpecError.invalidSourceInbound }
        } else if sourceInboundFinalIndex != nil {
            throw NativeRoutingSpecError.invalidSourceInbound
        }

        let defaultTag = intent.defaultOutboundTag ?? ""
        if !defaultTag.isEmpty {
            guard let outbounds = try field(root, "outbounds") as? [[String: Any]] else {
                throw NativeRoutingSpecError.invalidDefaultOutbound
            }
            var matches = 0
            for outbound in outbounds where try equal(tag(outbound), defaultTag) { matches += 1 }
            guard matches == 1 else { throw NativeRoutingSpecError.invalidDefaultOutbound }
        }

        if !guardRuleIndices.isEmpty {
            guard let routing = try field(root, "routing") as? [String: Any],
                  let rules = try field(routing, "rules") as? [[String: Any]],
                  Set(guardRuleIndices).count == guardRuleIndices.count else {
                throw NativeRoutingSpecError.invalidGuardRules
            }
            for index in guardRuleIndices {
                guard rules.indices.contains(index), try guardRule(rules[index]) else {
                    throw NativeRoutingSpecError.invalidGuardRules
                }
            }
        }

        let digest = SHA256.hash(data: frozen).map { String(format: "%02x", $0) }.joined()
        var metadata: [String: Any] = ["version": 1, "source_sha256": digest,
            "managed_inbound_index": managedInboundIndex, "managed_inbound_tag": managedInboundTag,
            "auth_user": authUser, "guard_rule_indices": guardRuleIndices]
        if let mapped = sourceInboundFinalIndex { metadata["source_inbound_index"] = mapped }
        if !defaultTag.isEmpty { metadata["default_outbound_tag"] = defaultTag }
        guard let encoded = try? JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys]) else {
            throw NativeRoutingSpecError.malformedConfiguration
        }
        return NativeRoutingEnvelope(configurationData: frozen, metadataData: encoded, sourceSHA256: digest)
    }

    private static func equal(_ lhs: String, _ rhs: String) -> Bool {
        lhs.utf8.elementsEqual(rhs.utf8)
    }

    private static func field(_ object: [String: Any], _ name: String) throws -> Any? {
        let keys = object.keys.filter { XrayJSONField.matches($0, name) }
        guard keys.count <= 1 else { throw NativeRoutingSpecError.malformedConfiguration }
        return keys.first.flatMap { object[$0] }
    }

    private static func tag(_ object: [String: Any]) throws -> String {
        guard let value = try field(object, "tag"), !(value is NSNull) else { return "" }
        guard let tag = value as? String else { throw NativeRoutingSpecError.malformedConfiguration }
        return tag
    }

    private static func privateInput(_ input: [String: Any], tag expectedTag: String, user: String) throws -> Bool {
        guard try equal(tag(input), expectedTag),
              try field(input, "protocol") as? String == "socks",
              let listen = try field(input, "listen") as? String, ["127.0.0.1", "::1"].contains(listen),
              let port = try field(input, "port") as? NSNumber, CFGetTypeID(port) != CFBooleanGetTypeID(),
              port.doubleValue >= 1, port.doubleValue <= 65535, port.doubleValue.rounded() == port.doubleValue,
              let settings = try field(input, "settings") as? [String: Any],
              try field(settings, "auth") as? String == "password",
              let accounts = try field(settings, "accounts") as? [[String: Any]], accounts.count == 1,
              let accountUser = try field(accounts[0], "user") as? String, equal(accountUser, user),
              let password = try field(accounts[0], "pass") as? String, !password.isEmpty else { return false }
        return true
    }

    private static func guardRule(_ rule: [String: Any]) throws -> Bool {
        guard let target = try field(rule, "outboundTag") as? String, !target.isEmpty else { return false }
        if let value = try field(rule, "balancerTag"), !(value is NSNull) {
            guard let balancing = value as? String, balancing.isEmpty else { return false }
        }
        if let webhook = try field(rule, "webhook"), !(webhook is NSNull) { return false }
        let values: [String]
        if let list = try field(rule, "inboundTag") as? [String] { values = list }
        else if let list = try field(rule, "inboundTag") as? String { values = list.components(separatedBy: ",") }
        else { return false }
        return !values.isEmpty && values.allSatisfy { !$0.isEmpty }
    }
}
