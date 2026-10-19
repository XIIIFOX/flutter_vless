import Foundation

/// A closed summary of this invocation's checked candidate, never config data.
public struct NativePreparationReport: Sendable {
    public enum Change: String, Hashable, Sendable {
        case certificateRefsBound = "certificate_refs_bound"
        case privateListenerAdded = "private_listener_added"
        case systemDNSGuardAdded = "system_dns_guard_added"
        case privateLoggingApplied = "private_logging_applied"
        case portEnvironmentBound = "port_environment_bound"
        case addressEnvironmentBound = "address_environment_bound"
    }
    public let scope: String
    public let coreCheck: String
    public let changes: [Change]

    public init(proxyOnly: Bool, coreCheckPassed: Bool, changes: [Change]) {
        scope = proxyOnly && coreCheckPassed ? "runtimeFinal" : "host"
        coreCheck = coreCheckPassed ? "passed" : "unavailable"
        self.changes = Array(Set(changes)).sorted { $0.rawValue < $1.rawValue }
    }
    public var flutterResult: [String: Any] {
        ["preparationReport": ["version": 1, "scope": scope, "coreCheck": coreCheck,
                               "changes": changes.map(\.rawValue)]]
    }
}

/// Closed bridge errors never contain Core text, configuration values or paths.
public struct CorePreflightError: LocalizedError {
    public let stage: String
    public let section: String?
    public let index: Int?

    public static let assetPreparation = CorePreflightError(stage: "prepare", section: nil, index: nil)
    public static let activeProxySession = CorePreflightError(stage: "active-session", section: nil, index: nil)

    public var errorDescription: String? {
        if stage == "prepare" { return "Unable to prepare Xray runtime assets." }
        if stage == "active-session" { return "Stop the active proxy-only session before starting another configuration." }
        if stage == "environment-policy" { return "Xray Env configuration cannot be checked safely in this process yet." }
        if let section, let index {
            return "Xray rejected \(section)[\(index)] during \(stage)."
        }
        return "Xray configuration check failed during \(stage)."
    }

    public var details: [String: Any] {
        var result: [String: Any] = ["stage": stage]
        if stage == "environment-policy" { result["feature"] = "env" }
        if let section, let index { result["section"] = section; result["index"] = index }
        return result
    }
}

public enum CorePreflightPolicy {
    /// False explicitly identifies a legacy runtime; callers must not report a
    /// successful Core check in this case. Checking cannot start or stop Core.
    @discardableResult
    public static func validate(_ configuration: Data, check: (Data) -> Int64) throws -> Bool {
        // Native preparation serializes a dictionary, so root keys are unique.
        // Refuse Env before calling even a cached checker whose Build may set
        // process-wide values. Invalid/non-JSON input remains Core's decision.
        if let object = (try? JSONSerialization.jsonObject(with: configuration)) as? [String: Any],
           object.contains(where: { $0.key.lowercased() == "env" && ($0.value as? [String: Any])?.isEmpty == false }) {
            throw CorePreflightError(stage: "environment-policy", section: nil, index: nil)
        }
        let code = check(configuration)
        if code == -1 { return false }
        if code == 0 { return true }
        let stage: String
        switch code & 255 {
        case 1: stage = "privacy"
        case 2: stage = "decode"
        case 3: stage = "build"
        case 5: stage = "environment-policy"
        default: stage = "internal"
        }
        let sectionCode = (code >> 8) & 255
        let location = code >> 16
        let section = sectionCode == 1 ? "inbounds" : sectionCode == 2 ? "outbounds" : nil
        // Treat malformed/unknown future bridge results as unlocated errors.
        let located = stage == "build" && code > 0 && location > 0 && location <= Int64(Int32.max) && section != nil
        throw CorePreflightError(stage: stage, section: located ? section : nil,
            index: located ? Int(location - 1) : nil)
    }
}
