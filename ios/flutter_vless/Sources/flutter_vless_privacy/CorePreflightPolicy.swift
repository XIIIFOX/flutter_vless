import Foundation

/// Closed bridge errors never contain Core text, configuration values or paths.
public struct CorePreflightError: LocalizedError {
    public let stage: String
    public let section: String?
    public let index: Int?

    public static let activeProxySession = CorePreflightError(stage: "active-session", section: nil, index: nil)

    public var errorDescription: String? {
        if stage == "active-session" { return "Stop the active proxy-only session before starting another configuration." }
        if let section, let index {
            return "Xray rejected \(section)[\(index)] during \(stage)."
        }
        return "Xray configuration check failed during \(stage)."
    }

    public var details: [String: Any] {
        var result: [String: Any] = ["stage": stage]
        if let section, let index { result["section"] = section; result["index"] = index }
        return result
    }
}

public enum CorePreflightPolicy {
    /// False explicitly identifies a legacy runtime; callers must not report a
    /// successful Core check in this case. Checking cannot start or stop Core.
    @discardableResult
    public static func validate(_ configuration: Data, check: (Data) -> Int64) throws -> Bool {
        let code = check(configuration)
        if code == -1 { return false }
        if code == 0 { return true }
        let stage: String
        switch code & 255 {
        case 1: stage = "privacy"
        case 2: stage = "decode"
        case 3: stage = "build"
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
