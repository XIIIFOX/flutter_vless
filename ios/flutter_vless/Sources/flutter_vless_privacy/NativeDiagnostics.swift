import Foundation
import os

/// Strings supplied by configs, servers, callbacks and errors are never rendered.
/// Only source literals and explicitly typed scalar diagnostics reach a sink.
public struct NativeDiagnosticMessage: ExpressibleByStringLiteral, ExpressibleByStringInterpolation {
    public let text: String
    public init(stringLiteral value: String) { text = value }
    public init(stringInterpolation: StringInterpolation) { text = stringInterpolation.text }
    public struct StringInterpolation: StringInterpolationProtocol {
        var text = ""
        public init(literalCapacity: Int, interpolationCount: Int) { text.reserveCapacity(literalCapacity) }
        public mutating func appendLiteral(_ literal: String) { text += literal }
        public mutating func appendInterpolation(_ value: NativeDiagnosticMessage, privacy: OSLogPrivacy = .private) { text += value.text }
        public mutating func appendInterpolation<T>(_ value: T, privacy: OSLogPrivacy = .private) { text += "<redacted>" }
        public mutating func appendInterpolation<T: BinaryInteger>(_ value: T, privacy: OSLogPrivacy = .private) { text += String(value) }
        public mutating func appendInterpolation(_ value: Bool, privacy: OSLogPrivacy = .private) { text += value ? "true" : "false" }
        public mutating func appendInterpolation(_ value: Double, privacy: OSLogPrivacy = .private) { text += value.isFinite ? String(value) : "unknown" }
    }
}

/// A process-local monotonic diagnostic span, independent of wall-clock changes.
/// Integer milliseconds are truncated; a backwards injected clock reports zero.
public struct NativeDiagnosticTimer: Sendable {
    private let started: UInt64

    public init(now: UInt64 = DispatchTime.now().uptimeNanoseconds) {
        started = now
    }

    public func elapsedMilliseconds(now: UInt64 = DispatchTime.now().uptimeNanoseconds) -> UInt64 {
        guard now >= started else { return 0 }
        return (now - started) / 1_000_000
    }
}

public struct NativePrivacyLogger {
    private let logger: Logger
    public init(subsystem: String, category: String) { logger = Logger(subsystem: subsystem, category: category) }
    public func info(_ message: NativeDiagnosticMessage) { logger.info("\(message.text, privacy: .public)") }
    public func warning(_ message: NativeDiagnosticMessage) { logger.warning("\(message.text, privacy: .public)") }
    public func error(_ message: NativeDiagnosticMessage) { logger.error("\(message.text, privacy: .public)") }
    public func fault(_ message: NativeDiagnosticMessage) { logger.fault("\(message.text, privacy: .public)") }
}

public enum NativeLogPrivacy {
    public static let providerLogFilename = "flutter_vless_tunnel_private_v2.log"
    public static let snapshotCommand = "xray_debug_private_v2"

    /// Closed callback vocabulary: never infer that arbitrary runtime text is safe.
    public static func runtimeEvent(_ raw: String) -> NativeDiagnosticMessage {
        switch raw {
        case "Xray startup failed: privacy configuration": return "Xray startup failed: privacy configuration"
        case "Xray startup failed: decode configuration": return "Xray startup failed: decode configuration"
        case "Xray startup failed: build configuration": return "Xray startup failed: build configuration"
        case "Xray startup failed: create core": return "Xray startup failed: create core"
        case "Xray startup failed: start core": return "Xray startup failed: start core"
        case "Xray configuration error": return "Xray configuration error"
        case "Xray configuration warning": return "Xray configuration warning"
        case "Xray runtime error": return "Xray runtime error"
        case "Xray runtime warning": return "Xray runtime warning"
        default: return "Xray diagnostic details omitted"
        }
    }

    public static func operationError(_ error: Error) -> NSError {
        let original = error as NSError
        let stage = runtimeEvent(original.localizedDescription)
        let message: NativeDiagnosticMessage = stage.text == "Xray diagnostic details omitted"
            ? "Native operation failed (code \(original.code))" : stage
        return NSError(domain: "flutter_vless.native", code: original.code,
                       userInfo: [NSLocalizedDescriptionKey: message.text])
    }

    public static func removeLegacyProviderLog(in directory: URL) {
        try? FileManager.default.removeItem(at: directory.appendingPathComponent("flutter_vless_tunnel_debug.log"))
    }
}

/// Separate provider IPC for connection choices. Only ordinals can enter the reply.
public enum PrivateBalancerDiagnostics {
    public static let snapshotCommand = "xray_balancer_selections_v1"

    public static func snapshot(_ data: Data, maxBytes: Int, maxLines: Int) -> String {
        guard maxLines > 0, maxBytes > 0, data.count <= 18_000,
              let value = String(data: data, encoding: .utf8) else { return "" }
        let payload = value.last == "\n" ? value.dropLast() : value[...]
        let rows = payload.split(separator: "\n", omittingEmptySubsequences: false)
        guard rows.count <= 300 else { return "" }
        var previous: UInt64 = 0
        for row in rows {
            let fields = row.split(separator: ",", omittingEmptySubsequences: false)
            guard fields.count == 3, fields.allSatisfy({ field in
                !field.isEmpty && field.utf8.first != 48 && field.utf8.allSatisfy { (48...57).contains($0) }
                    && UInt64(field).map { $0 <= UInt64(Int64.max) } == true
            }), let sequence = UInt64(fields[0]), sequence > previous else { return "" }
            previous = sequence
        }
        var remaining = min(maxBytes, 18_000) + 1
        let bounded = rows.suffix(maxLines).reversed().prefix { row in
            remaining -= row.utf8.count + 1
            return remaining >= 0
        }
        return bounded.reversed().joined(separator: "\n")
    }
}
