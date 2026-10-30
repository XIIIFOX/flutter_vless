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
struct VlessNativeOptions {}
struct TunnelEndpointPath: Equatable {
    var generation: UInt64 = 0
    func rebased(generation: UInt64) -> Self { Self(generation: generation) }
}
struct FixtureAddress { let isLoopback = true }
struct TunnelEndpointCandidate {
    let address = FixtureAddress(), isSingleAttemptOnly = false
    func isUsable(on path: TunnelEndpointPath, at now: TimeInterval, allowFreshZeroTTL: Bool) -> Bool { true }
}
struct TunnelEndpointCandidates { let path: TunnelEndpointPath }
struct TunnelEndpointSelection { let candidates: TunnelEndpointCandidates, selected: TunnelEndpointCandidate }
struct FixturePrepared {
    let data: Data
    let routingEnvelope: NativeRoutingEnvelope?
    var endpointPath: TunnelEndpointPath?
    let endpointSelections: [TunnelEndpointSelection] = [], bootstrapAddresses: [String] = []
    init(data: Data, routingEnvelope: NativeRoutingEnvelope?, endpointPath: TunnelEndpointPath? = nil) {
        self.data = data; self.routingEnvelope = routingEnvelope; self.endpointPath = endpointPath
    }
}
typealias TunnelPreparedConfig = FixturePrepared
enum TunnelDNSPolicy { static func allowsRouteExclusions(_ routes: [String]) -> Bool { true } }
enum TunnelXrayConfigPreparer { enum StartupError: Error { case endpointUnavailable, invalidConfiguration } }
func FLVlessCoreDarwinInterfaceBindingCapability() -> Int64 { 1 }

final class Provider: @unchecked Sendable {
    let logger = NSObject()
    let sessionAdmission = TunnelSessionAdmission(), endpointAdmission = TunnelEndpointPlanAdmission()
    let endpointCommitQueue = TunnelEndpointCommitQueue()
    let watchdogQueue = DispatchQueue(label: "fixture.routing.watchdog"), runtimeQueue = DispatchQueue(label: "fixture.routing.native")
    var runtimeSource: RuntimeSource?, physicalPath: TunnelEndpointPath?
    var installedSettingsKey: ProtectedSettingsKey?
    var suppliedPrepared: FixturePrepared?
    // SOURCE_ADMISSION_HELPERS
    func tunnelError(_ message: String) -> NSError { NSError(domain: "synthetic", code: 1) }
    func isIPv4Literal(_ text: String) -> Bool { false }
    func parseConfig(jsonData: Data) -> (inboundPort: Int, unused: Bool)? { (10808, false) }
    func setStartupPreparation(_ task: Task<TunnelPreparedConfig, Error>?, epoch: TunnelSessionAdmission.Epoch) {}
    func prepareEndpointConfig(_ source: RuntimeSource, token: TunnelEndpointPlanAdmission.Token,
        path: TunnelEndpointPath, attempt: UInt64, deadline: TimeInterval) async throws -> TunnelPreparedConfig {
        var prepared = suppliedPrepared!; prepared.endpointPath = path; return prepared
    }
    func protectedNetworkSettings(_ spec: RuntimeSpec) -> Int { 1 }
    func setTunnelNetworkSettings(_ settings: Int) async throws { Boundary.events.append("routes") }
    func admit(_ prepared: FixturePrepared, intent routingIntent: NativeRoutingIntent?) async throws -> RuntimeSpec {
        // SOURCE_CAPABILITY_ENTRY
        let epoch = sessionAdmission.begin(), options = VlessNativeOptions()
        let token = try endpointAdmission.begin(epoch)
        let credentials = try LocalProxyCredentials(username: "fixture-user", password: "fixture-password")
        let source = RuntimeSource(epoch: epoch, config: prepared.data, options: options, routingIntent: routingIntent,
            credentials: credentials, geoAssetsDirectory: nil, environment: XrayEnvironmentSnapshot(rawEntries: []))
        runtimeSource = source; physicalPath = TunnelEndpointPath(generation: token.generation); suppliedPrepared = prepared
        return try await prepareInitialRuntimeSpec(source)
    }
    // SOURCE_START
    func start(_ spec: RuntimeSpec) throws {
        // SOURCE_RUNTIME_START_PAIR
    }
}

@main struct Probe {
    static func rejected(_ body: () async throws -> Void) async {
        do { try await body(); preconditionFailure("Invalid routing operation was admitted") }
        catch { precondition(!String(reflecting: error).contains("fixture-password")) }
    }
    static func main() async throws {
        let bytes = try JSONSerialization.data(withJSONObject: ["inbounds": [["tag": "managed", "listen": "127.0.0.1", "port": 10808,
            "protocol": "socks", "settings": ["auth": "password", "accounts": [["user": "fixture-user", "pass": "fixture-password"]]]]],
            "outbounds": [["tag": "direct", "protocol": "freedom"]]])
        let intent = try NativeRoutingIntent()
        let envelope = try NativeRoutingSpec.freeze(finalData: bytes, managedInboundIndex: 0, managedInboundTag: "managed", authUser: "fixture-user", intent: intent)!
        // Both are valid JSON but differ byte-for-byte: a wrong choice of the
        // unpaired preparer data must fail the assertions below.
        let prepared = FixturePrepared(data: bytes + Data("\n".utf8), routingEnvelope: envelope)
        let provider = Provider()
        for capability: Int64 in [0, 2] {
            Boundary.reset(); Boundary.capability = capability
            await rejected { _ = try await provider.admit(prepared, intent: intent) }
            precondition(Boundary.checked.isEmpty && Boundary.started.isEmpty && !Boundary.events.contains("routes"))
        }
        Boundary.reset(); Boundary.checkCode = 21
        await rejected { _ = try await provider.admit(prepared, intent: intent) }
        precondition(Boundary.checked.count == 1 && Boundary.started.isEmpty && !Boundary.events.contains("routes"))
        Boundary.reset(); Boundary.preflight = false
        let spec = try await provider.admit(prepared, intent: intent)
        precondition(Boundary.events.firstIndex(of: "routing-check")! < Boundary.events.firstIndex(of: "routes")!)
        precondition(Boundary.checked[0].0 == bytes && Boundary.checked[0].1 == envelope.metadataData)
        precondition(spec.config == bytes && spec.routingMetadata == envelope.metadataData)
        try provider.start(spec); try provider.start(spec)
        precondition(Boundary.started.count == 2 && Boundary.started.allSatisfy { $0.0 == bytes && $0.1 == envelope.metadataData })
        precondition(!Boundary.events.contains("ordinary-start"))
        Boundary.reset(); Boundary.capability = 0
        await rejected { try provider.start(spec) }
        precondition(Boundary.events.isEmpty && Boundary.started.isEmpty)
        Boundary.reset(); Boundary.startSucceeds = false
        await rejected { try provider.start(spec) }
        precondition(Boundary.started.count == 1 && !Boundary.events.contains("ordinary-start"))
        for suppliedIntent: NativeRoutingIntent? in [nil, intent] {
            Boundary.reset()
            let missing = FixturePrepared(data: bytes, routingEnvelope: suppliedIntent == nil ? envelope : nil)
            await rejected { _ = try await provider.admit(missing, intent: suppliedIntent) }
            precondition(Boundary.events.isEmpty)
        }
        for available in [false, true] {
            Boundary.reset(); Boundary.preflight = available; Boundary.capability = 0
            let ordinary = try await provider.admit(FixturePrepared(data: bytes, routingEnvelope: nil), intent: nil)
            precondition(Boundary.checked.count == (available ? 1 : 0) && ordinary.routingMetadata == nil)
            try provider.start(ordinary)
            precondition(Boundary.started.count == 1 && Boundary.started[0].0 == bytes && Boundary.started[0].1 == nil)
            precondition(Boundary.events.contains("ordinary-start") && !Boundary.events.contains("routing-start"))
        }
        print("PASS provider exact routing pair, capability admission and no fallback")
    }
}

func FLVlessCoreGeodataLifetimeCapability() -> Int64 { 1 }
func FLVlessCoreXdriveLifetimeCapability() -> Int64 { 2 }
