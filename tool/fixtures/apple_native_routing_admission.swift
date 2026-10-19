import Foundation

// All functions below are inert records, with no Core/HEV/OS framework linked.
// The driver inserts the real provider's admission, RuntimeSpec and startXRay.
enum Boundary {
    static var capability: Int64 = 1, checkCode: Int64 = 0
    static var preflight = true, startSucceeds = true
    static var events: [String] = []
    static var checked: [(Data, Data?)] = [], started: [(Data, Data?)] = []
    static func reset() {
        capability = 1; checkCode = 0; preflight = true; startSucceeds = true
        events = []; checked = []; started = []
    }
}
func FLVlessCoreRoutingCapability() -> Int64 { Boundary.capability }
func FLVlessHasCorePreflight() -> Bool { Boundary.preflight }
func FLVlessCheckCoreRoutingPrivate(_ config: Data, _ spec: Data) -> Int64 {
    Boundary.events.append("routing-check"); Boundary.checked.append((config, spec)); return Boundary.checkCode
}
func FLVlessCheckCorePrivate(_ config: Data) -> Int64 {
    Boundary.events.append("ordinary-check"); Boundary.checked.append((config, nil)); return Boundary.checkCode
}
func XRaySetMemoryLimit() { Boundary.events.append("memory") }
func XRaySetAssetLocation(_ directory: String, _ error: inout NSError?) -> Bool { Boundary.events.append("assets"); return true }
func XRayGetVersion() -> String { "synthetic" }
func FLVlessStartCoreRoutingPrivate(_ config: Data, _ spec: Data, _ logger: NSObject, _ error: inout NSError?) -> Bool {
    Boundary.events.append("routing-start"); Boundary.started.append((config, spec)); return Boundary.startSucceeds
}
func XRayStartPrivate(_ config: Data, _ logger: NSObject, _ error: inout NSError?) -> Bool {
    Boundary.events.append("ordinary-start"); Boundary.started.append((config, nil)); return Boundary.startSucceeds
}
enum NativeLogPrivacy { static func operationError(_ error: Error) -> Error { error } }
struct FixtureMessage: ExpressibleByStringLiteral, ExpressibleByStringInterpolation {
    enum Privacy { case `public` }
    struct StringInterpolation: StringInterpolationProtocol {
        init(literalCapacity: Int, interpolationCount: Int) {}
        mutating func appendLiteral(_ literal: String) {}
        mutating func appendInterpolation<T>(_ value: T) {}
        mutating func appendInterpolation<T>(_ value: T, privacy: Privacy) {}
    }
    init(stringLiteral value: String) {}
    init(stringInterpolation: StringInterpolation) {}
}
struct FixtureLogger { func info(_ message: FixtureMessage) {}; func error(_ message: FixtureMessage) {} }
let tunnelLog = FixtureLogger()
func rememberTunnelLog(_ message: String) {}
enum TunnelSessionAdmission { typealias Epoch = Int }
struct VlessNativeOptions {}
struct FixturePrepared { let data: Data; let routingEnvelope: NativeRoutingEnvelope? }

final class Provider {
    let logger = NSObject()
    // SOURCE_RUNTIME_SPEC
    func tunnelError(_ message: String) -> NSError { NSError(domain: "synthetic", code: 1) }
    func admit(_ prepared: FixturePrepared, intent routingIntent: NativeRoutingIntent?) throws -> RuntimeSpec {
        let providerConfiguration: [String: Any] = [:]
        let epoch = 1, options = VlessNativeOptions(), parsed = (inboundPort: 10808, unused: false)
        let credentials = try LocalProxyCredentials(username: "fixture-user", password: "fixture-password")
        // SOURCE_ADMISSION
    }
    // SOURCE_START
    func start(_ spec: RuntimeSpec) throws {
        try startXRay(xrayConfig: spec.config, geoAssetsDirectory: spec.geoAssetsDirectory, routingMetadata: spec.routingMetadata)
    }
}

@main struct Probe {
    static func rejected(_ body: () throws -> Void) {
        do { try body(); preconditionFailure("Invalid routing operation was admitted") }
        catch { precondition(!String(reflecting: error).contains("fixture-password")) }
    }
    static func main() throws {
        let bytes = try JSONSerialization.data(withJSONObject: ["inbounds": [["tag": "managed", "listen": "127.0.0.1", "port": 10808,
            "protocol": "socks", "settings": ["auth": "password", "accounts": [["user": "fixture-user", "pass": "fixture-password"]]]]],
            "outbounds": [["tag": "direct", "protocol": "freedom"]]])
        let intent = try NativeRoutingIntent()
        let envelope = try NativeRoutingSpec.freeze(finalData: bytes, managedInboundIndex: 0, managedInboundTag: "managed", authUser: "fixture-user", intent: intent)!
        let prepared = FixturePrepared(data: bytes, routingEnvelope: envelope)
        let provider = Provider()
        for capability: Int64 in [0, 2] {
            Boundary.reset(); Boundary.capability = capability
            rejected { _ = try provider.admit(prepared, intent: intent) }
            precondition(Boundary.checked.isEmpty && Boundary.started.isEmpty && !Boundary.events.contains("routes"))
        }
        Boundary.reset(); Boundary.checkCode = 21
        rejected { _ = try provider.admit(prepared, intent: intent) }
        precondition(Boundary.checked.count == 1 && Boundary.started.isEmpty && !Boundary.events.contains("routes"))
        Boundary.reset(); Boundary.preflight = false
        let spec = try provider.admit(prepared, intent: intent)
        precondition(Boundary.events.firstIndex(of: "routing-check")! < Boundary.events.firstIndex(of: "routes")!)
        precondition(Boundary.checked[0].0 == bytes && Boundary.checked[0].1 == envelope.metadataData)
        precondition(spec.config == bytes && spec.routingMetadata == envelope.metadataData)
        try provider.start(spec); try provider.start(spec)
        precondition(Boundary.started.count == 2 && Boundary.started.allSatisfy { $0.0 == bytes && $0.1 == envelope.metadataData })
        precondition(!Boundary.events.contains("ordinary-start"))
        Boundary.reset(); Boundary.capability = 0
        rejected { try provider.start(spec) }
        precondition(Boundary.events.isEmpty && Boundary.started.isEmpty)
        Boundary.reset(); Boundary.startSucceeds = false
        rejected { try provider.start(spec) }
        precondition(Boundary.started.count == 1 && !Boundary.events.contains("ordinary-start"))
        for suppliedIntent: NativeRoutingIntent? in [nil, intent] {
            Boundary.reset()
            let missing = FixturePrepared(data: bytes, routingEnvelope: suppliedIntent == nil ? envelope : nil)
            rejected { _ = try provider.admit(missing, intent: suppliedIntent) }
            precondition(Boundary.events.isEmpty)
        }
        for available in [false, true] {
            Boundary.reset(); Boundary.preflight = available; Boundary.capability = 0
            let ordinary = try provider.admit(FixturePrepared(data: bytes, routingEnvelope: nil), intent: nil)
            precondition(Boundary.checked.count == (available ? 1 : 0) && ordinary.routingMetadata == nil)
            try provider.start(ordinary)
            precondition(Boundary.started.count == 1 && Boundary.started[0].0 == bytes && Boundary.started[0].1 == nil)
            precondition(Boundary.events.contains("ordinary-start") && !Boundary.events.contains("routing-start"))
        }
        print("PASS provider exact routing pair, capability admission and no fallback")
    }
}
