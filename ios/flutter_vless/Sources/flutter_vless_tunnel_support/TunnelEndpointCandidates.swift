import Foundation

/// A selection witness, not proof of a Core socket's interface or reachability.
public struct TunnelEndpointPath: Equatable, Sendable {
    public let generation: UInt64
    public let interfaceIndex: UInt32
    public let interfaceName: String?
    public let supportsIPv4: Bool
    public let supportsIPv6: Bool
    public let supportsDNS: Bool

    public init(generation: UInt64, interfaceIndex: UInt32, interfaceName: String? = nil,
                supportsIPv4: Bool, supportsIPv6: Bool, supportsDNS: Bool) {
        self.generation = generation
        self.interfaceIndex = interfaceIndex
        self.interfaceName = interfaceName
        self.supportsIPv4 = supportsIPv4
        self.supportsIPv6 = supportsIPv6
        self.supportsDNS = supportsDNS
    }

    public func rebased(generation: UInt64) -> Self {
        Self(generation: generation, interfaceIndex: interfaceIndex, interfaceName: interfaceName,
             supportsIPv4: supportsIPv4, supportsIPv6: supportsIPv6, supportsDNS: supportsDNS)
    }
}

public struct TunnelEndpointCandidate: Equatable, Sendable {
    public enum Origin: Equatable, Sendable {
        case literal
        case systemNameAnswer
        case systemIPv4Translation(originalIPv4: String)
        case encryptedIPv4Answer
    }
    public enum LookupScope: Equatable, Sendable {
        case literal
        case processDefault
        case interface(index: UInt32)
    }

    public let address: TunnelEndpointAddress
    public let origin: Origin
    public let receivedAt: TimeInterval
    public let validUntil: TimeInterval?
    public let lookupScope: LookupScope

    public init(address: TunnelEndpointAddress, origin: Origin, receivedAt: TimeInterval,
                validUntil: TimeInterval? = nil, lookupScope: LookupScope? = nil) {
        self.address = address
        self.origin = origin
        self.receivedAt = receivedAt
        self.validUntil = validUntil
        self.lookupScope = lookupScope ?? (origin == .literal ? .literal : .processDefault)
    }

    /// TTL zero is usable only by the current fresh query's single attempt.
    /// It must not be cached, reused for a later retry, or turned into a timer loop.
    public var isSingleAttemptOnly: Bool { validUntil == receivedAt && origin == .systemNameAnswer }

    var isWellFormed: Bool {
        guard receivedAt.isFinite, receivedAt >= 0,
              validUntil.map({ $0.isFinite && $0 >= receivedAt }) ?? true else { return false }
        switch (origin, address.source) {
        case (.literal, .literal):
            return lookupScope == .literal && validUntil == nil
        case (.systemNameAnswer, .systemNameAnswer):
            if case .interface(let index) = lookupScope { return index != 0 }
            return lookupScope == .processDefault
        case (.encryptedIPv4Answer, .encryptedIPv4Answer):
            return address.family == .ipv4 && lookupScope == .processDefault && validUntil == nil
        case (.systemIPv4Translation(let original), .systemIPv4Translation):
            return address.family == .ipv6 && lookupScope == .processDefault && validUntil == nil &&
                TunnelEndpointAddress(text: original, source: .literal)?.family == .ipv4
        default: return false
        }
    }

    public func isUsable(on path: TunnelEndpointPath, at now: TimeInterval,
                         allowFreshZeroTTL: Bool = false) -> Bool {
        guard isWellFormed, now.isFinite, now >= receivedAt,
              (origin == .literal && address.isLoopback) || (address.family == .ipv4 ? path.supportsIPv4 : path.supportsIPv6) else { return false }
        if case .interface(let index) = lookupScope, index != path.interfaceIndex { return false }
        if let validUntil, now >= validUntil {
            return allowFreshZeroTTL && isSingleAttemptOnly
        }
        return true
    }
}

/// At most 16 distinct, canonical numeric addresses, in backend order.
public struct TunnelEndpointCandidates: Equatable, Sendable {
    public static let maximumCount = 16
    public let path: TunnelEndpointPath
    public let candidates: [TunnelEndpointCandidate]

    public init(path: TunnelEndpointPath, candidates: [TunnelEndpointCandidate]) {
        self.path = path
        var seen = Set<String>()
        self.candidates = candidates.filter { value in
            guard value.isWellFormed, seen.count < Self.maximumCount else { return false }
            return seen.insert(value.address.text).inserted
        }
    }

    public func usable(at now: TimeInterval, allowFreshZeroTTL: Bool = false) -> [TunnelEndpointCandidate] {
        candidates.filter { $0.isUsable(on: path, at: now, allowFreshZeroTTL: allowFreshZeroTTL) }
    }
}

struct TunnelEndpointDNSAnswer: Sendable {
    let hostname: String
    let text: String
    let interfaceIndex: UInt32
    let ttl: UInt32
    let added: Bool
    /// On an error callback DNS-SD leaves all answer fields undefined. The
    /// adapter supplies only this coarse category and never reads those fields.
    enum Failure: Sendable { case noRecord, timeout, serviceUnavailable, defunct, policyDenied, other }
    var failure: Failure? = nil

    static func failed(_ failure: Failure) -> Self {
        Self(hostname: "", text: "", interfaceIndex: 0, ttl: 0, added: false, failure: failure)
    }
}

/// Fixed-size, saturating counts only. Neither labels nor address/interface
/// values can enter these diagnostics, and callback bursts cannot grow storage.
struct TunnelEndpointDNSOutcomes {
    private(set) var callbacks = 0
    private(set) var noRecord = 0
    private(set) var timeout = 0
    private(set) var serviceUnavailable = 0
    private(set) var defunct = 0
    private(set) var policyDenied = 0
    private(set) var otherError = 0
    private(set) var questionRejected = 0
    private(set) var interfaceRejected = 0
    private(set) var malformed = 0
    private(set) var adds = 0
    private(set) var removes = 0
    private(set) var capacityRejected = 0

    enum Outcome { case noRecord, timeout, serviceUnavailable, defunct, policyDenied, otherError, questionRejected, interfaceRejected, malformed, adds, removes, capacityRejected }

    mutating func recordCallback() { callbacks = min(callbacks + 1, 65_535) }

    mutating func record(_ outcome: Outcome) {
        func bounded(_ value: Int) -> Int { min(value + 1, 65_535) }
        switch outcome {
        case .noRecord: noRecord = bounded(noRecord)
        case .timeout: timeout = bounded(timeout)
        case .serviceUnavailable: serviceUnavailable = bounded(serviceUnavailable)
        case .defunct: defunct = bounded(defunct)
        case .policyDenied: policyDenied = bounded(policyDenied)
        case .otherError: otherError = bounded(otherError)
        case .questionRejected: questionRejected = bounded(questionRejected)
        case .interfaceRejected: interfaceRejected = bounded(interfaceRejected)
        case .malformed: malformed = bounded(malformed)
        case .adds: adds = bounded(adds)
        case .removes: removes = bounded(removes)
        case .capacityRejected: capacityRejected = bounded(capacityRejected)
        }
    }
}

/// Pure callback accumulation; no completion on the first A / MoreComing batch.
struct TunnelEndpointDNSAccumulator {
    private let host: [UInt8]
    private let path: TunnelEndpointPath
    private var values: [TunnelEndpointCandidate] = []
    private(set) var outcomes = TunnelEndpointDNSOutcomes()

    init(host: String, path: TunnelEndpointPath) {
        self.host = Self.name(host)
        self.path = path
    }

    mutating func accept(_ answer: TunnelEndpointDNSAnswer, at now: TimeInterval) {
        outcomes.recordCallback()
        if let failure = answer.failure {
            switch failure {
            case .noRecord: outcomes.record(.noRecord)
            case .timeout: outcomes.record(.timeout)
            case .serviceUnavailable: outcomes.record(.serviceUnavailable)
            case .defunct: outcomes.record(.defunct)
            case .policyDenied: outcomes.record(.policyDenied)
            case .other: outcomes.record(.otherError)
            }
            return
        }
        let questionMatches = Self.name(answer.hostname) == host
        let interfaceMatches = path.interfaceIndex == 0 || answer.interfaceIndex == path.interfaceIndex
        // Count both reasons if an alias and interface mismatch coexist. These
        // counters may overlap; acceptance keeps exactly the original predicate.
        if !questionMatches { outcomes.record(.questionRejected) }
        if !interfaceMatches { outcomes.record(.interfaceRejected) }
        guard questionMatches, interfaceMatches else { return }
        guard let address = TunnelEndpointAddress(text: answer.text, source: .systemNameAnswer),
              now.isFinite, now >= 0 else { outcomes.record(.malformed); return }
        let existing = values.firstIndex { $0.address.text == address.text }
        if !answer.added {
            outcomes.record(.removes)
            if let existing { values.remove(at: existing) }
            return
        }
        let scope: TunnelEndpointCandidate.LookupScope = path.interfaceIndex == 0 ? .processDefault : .interface(index: path.interfaceIndex)
        let value = TunnelEndpointCandidate(address: address, origin: .systemNameAnswer,
            receivedAt: now, validUntil: now + Double(answer.ttl), lookupScope: scope)
        if let existing { values[existing] = value; outcomes.record(.adds) }
        else if values.count < TunnelEndpointCandidates.maximumCount { values.append(value); outcomes.record(.adds) }
        else { outcomes.record(.capacityRejected) }
    }

    func snapshot(at now: TimeInterval) -> [TunnelEndpointCandidate] {
        values.filter { $0.isUsable(on: path, at: now, allowFreshZeroTTL: true) }
    }

    private static func name(_ value: String) -> [UInt8] {
        var bytes = Array(value.utf8)
        if bytes.last == 46 { bytes.removeLast() }
        return bytes.map { (65...90).contains($0) ? $0 + 32 : $0 }
    }
}
