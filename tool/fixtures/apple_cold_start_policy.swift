import Foundation

class NEVPNProtocol { var includeAllNetworks = true, excludeLocalNetworks = false, excludeAPNs = false, excludeCellularServices = false }
class NETunnelProviderProtocol: NEVPNProtocol {
    var providerBundleIdentifier: String? = "fixture.provider"
    var providerConfiguration: [String: Any]? = ["xrayConfigReference": Data([1]), "options": ["reconnect": ["enabled": true], "protection": ["onDemand": "enabled"]]]
}
class NEOnDemandRule {}
final class NEOnDemandRuleConnect: NEOnDemandRule { enum Kind { case any }; var interfaceTypeMatch = Kind.any }
enum NEProviderStopReason: Int { case userInitiated, providerFailed }
let NEVPNErrorDomain = "fixture.vpn"
enum NEVPNError: Int { case configurationStale = 4 }
final class NETunnelProviderManager {
    var protocolConfiguration: NEVPNProtocol? = NETunnelProviderProtocol()
    var isEnabled = true, isOnDemandEnabled = false
    var onDemandRules: [NEOnDemandRule]?
    func copy() -> NETunnelProviderManager {
        let manager = NETunnelProviderManager(); manager.protocolConfiguration = protocolConfiguration
        manager.isEnabled = isEnabled; manager.isOnDemandEnabled = isOnDemandEnabled; manager.onDemandRules = onDemandRules; return manager
    }
    static func loadAllFromPreferences(completionHandler: @escaping ([NETunnelProviderManager]?, Error?) -> Void) { Kernel.onPolicyLoad?(); completionHandler([Kernel.profile.copy()], nil) }
    func saveToPreferences(completionHandler: @escaping (Error?) -> Void) {
        Kernel.record(isOnDemandEnabled ? "arm" : "disarm"); Kernel.profile = copy()
        if isOnDemandEnabled { Kernel.onArm?() }
        completionHandler(nil)
    }
    func loadFromPreferences(completionHandler: @escaping (Error?) -> Void) {
        if Kernel.consumeRefreshFailure() { completionHandler(NSError(domain: "fixture.refresh", code: 1)); return }
        isOnDemandEnabled = Kernel.profile.isOnDemandEnabled; onDemandRules = Kernel.profile.onDemandRules; completionHandler(nil)
    }
}
// ACTUAL_POLICY

struct XrayEnvironmentSnapshot { static func capture() -> Self { Self() } }
struct LocalProxyCredentials { static func generate() throws -> Self { Self() } }
enum NativeRoutingIntent { case fixture; static func parse(_ value: Any?) throws -> Self? { nil } }
enum NativeRoutingSpecError: Error { case invalidIntent }
enum NativeRoutingSpec {
    static func requireRuntime(_ capability: Int64) throws {}
    static func validateSource(_ data: Data, intent: NativeRoutingIntent?) throws {}
    static func check(_ envelope: Envelope, capability: () -> Int64, check: (Data, Data) -> Int64) throws {}
}
struct Envelope { let configurationData = Data(), metadataData = Data() }
struct TunnelEndpointPath: Equatable {
    var generation: UInt64 = 0
    var supportsIPv4 = true, supportsIPv6 = true
    func rebased(generation: UInt64) -> Self {
        Self(generation: generation, supportsIPv4: supportsIPv4, supportsIPv6: supportsIPv6)
    }
}
struct TunnelEndpointCandidate {
    var expiry: TimeInterval? = nil
    struct Address { let isLoopback = false }; let address = Address()
    var isSingleAttemptOnly: Bool { false }
    func isUsable(on path: TunnelEndpointPath, at now: TimeInterval, allowFreshZeroTTL: Bool) -> Bool { expiry.map { now < $0 } ?? true }
}
struct TunnelEndpointCandidates { let path: TunnelEndpointPath }
struct TunnelEndpointSelection { let candidates: TunnelEndpointCandidates; let selected: TunnelEndpointCandidate }

final class TunnelEndpointDiscovery: @unchecked Sendable {
    private let state = FixtureState((cancelled: false, invalidated: false, sealed: false, expired: false))
    private let current: () -> Bool
    private let invalidated: () -> Void
    init(path: TunnelEndpointPath, deadline: TimeInterval, isCurrent: @escaping () -> Bool,
         event: @escaping (String) -> Void, onInvalidated: @escaping () -> Void) {
        current = isCurrent; invalidated = onInvalidated
        Kernel.register(self); Kernel.record("fast-discovery")
    }
    var isInvalidated: Bool { state.withValue { $0.invalidated } }
    var hasUnsealedSystemSelections: Bool { state.withValue { !$0.sealed } }
    var wasCancelled: Bool { state.withValue { $0.cancelled } }
    func resolveCandidates(_ host: String) async throws -> TunnelEndpointCandidates {
        guard current(), !wasCancelled else { throw CancellationError() }
        Kernel.record("fast-dns")
        return TunnelEndpointCandidates(path: TunnelEndpointPath())
    }
    func admitSelections(_ selections: [TunnelEndpointSelection]) -> Bool { current() && !wasCancelled && !isInvalidated }
    func isFresh(_ selections: [TunnelEndpointSelection], at time: TimeInterval) -> Bool {
        current() && state.withValue { !$0.cancelled && !$0.invalidated && !$0.expired }
    }
    func claimInitialInvalidationIfNeeded() -> Bool {
        let claimed = state.withValue { value -> Bool in
            guard !value.cancelled, !value.invalidated, !value.sealed, value.expired else { return false }
            value.invalidated = true; return true
        }
        if claimed { invalidated() }; return claimed
    }
    func expireWitness() { state.withValue { $0.expired = true } }
    func finishAdmission() -> Bool { Kernel.record("discovery-core-admitted"); return current() && !wasCancelled && !isInvalidated }
    func noteProtectedSettingsInstalled() { Kernel.record("discovery-protected-settings") }
    func cancel() { state.withValue { $0.cancelled = true }; Kernel.record("discovery-cancel") }
    func addLateAAAA() { Kernel.record("late-AAAA") }
    func latchRemovalWithoutNotification() { state.withValue { $0.invalidated = true } }
    func notifyLatchedRemoval() { invalidated() }
    func seal() { state.withValue { $0.sealed = true } }
    func removeSelected(includingStaleCallback: Bool = false) {
        let notify = state.withValue { value -> Bool in
            guard includingStaleCallback || (!value.cancelled && !value.sealed && !value.invalidated) else { return false }
            value.invalidated = true; return true
        }
        if notify { invalidated() }
    }
}

struct TunnelPreparedConfig {
    var data = Data("{}".utf8)
    var bootstrapAddresses = Kernel.preparedAddresses
    let routingEnvelope: Envelope? = nil
    var endpointPath: TunnelEndpointPath?
    var endpointSelections: [TunnelEndpointSelection] = []
}
final class TunnelPhysicalPathObserver {
    var onChange: ((TunnelEndpointPath?) -> Void)?
    func start(onChange: @escaping (TunnelEndpointPath?) -> Void) { self.onChange = onChange }
    func initialSnapshot(deadline: TimeInterval) async throws -> TunnelEndpointPath { TunnelEndpointPath() }
    func cancel() {}
}
enum TunnelSecretProfile { static func load(_ data: [String: Any], providerBundleIdentifier: String) throws -> Data { Data("{}".utf8) } }
enum DesktopBypassPolicy { static func apply(to data: Data, cidrs: [String]) throws -> Data { data } }
enum LocalProxyAccessPolicy { static func isTCPPortAvailable(_ port: Int) -> Bool { true } }
enum TunnelXrayConfigPreparer {
    enum StartupError: Error { case endpointUnavailable, invalidConfiguration }
    static func prepareForStartup(jsonData: Data, credentials: LocalProxyCredentials, routingIntent: NativeRoutingIntent?, tcpPortAvailable: (Int) -> Bool,
        environmentSnapshot: XrayEnvironmentSnapshot, endpointPath: TunnelEndpointPath, selectedAttempt: UInt64,
        resolveCandidates: (String) async throws -> TunnelEndpointCandidates, isCurrent: () -> Bool, attempts: Int) async throws -> TunnelPreparedConfig {
        Kernel.record("prepare")
        Kernel.onPrepare?()
        try await Kernel.onPrepareAsync?(endpointPath)
        if Kernel.failure == "endpoint" { throw StartupError.endpointUnavailable }
        if Kernel.failure == "config" { throw StartupError.invalidConfiguration }
        _ = try await resolveCandidates("fixture.endpoint.invalid")
        return TunnelPreparedConfig(data: Kernel.preparedData, endpointPath: endpointPath,
            endpointSelections: Kernel.dnsOnly ? [] : [TunnelEndpointSelection(candidates: TunnelEndpointCandidates(path: endpointPath), selected: TunnelEndpointCandidate())])
    }
}
enum TunnelEndpointResolver {
    static func resolveCandidates(_ value: String, on path: TunnelEndpointPath, deadline: TimeInterval,
        isCurrent: @escaping () -> Bool, event: (String) -> Void) async throws -> TunnelEndpointCandidates {
        Kernel.record("legacy-dns"); Kernel.recordLegacyGeneration(path.generation)
        try await Kernel.onLegacyResolve?()
        guard isCurrent() else { throw CancellationError() }
        return TunnelEndpointCandidates(path: path)
    }
}
final class TunnelDebugStore { static let shared = TunnelDebugStore(); func configure(groupIdentifier: String?, options: VlessNativeOptions) {} }
func FLVlessCoreRoutingCapability() -> Int64 { 1 }
func FLVlessCoreDarwinInterfaceBindingCapability() -> Int64 { Kernel.bindingCapability }
func FLVlessHasCorePreflight() -> Bool { true }
func FLVlessCheckCorePrivate(_ value: Data) -> Int64 { Kernel.record("check"); Kernel.onCoreCheck?(); return Kernel.failure == "core" ? 3 : 0 }
func FLVlessCheckCoreRoutingPrivate(_ data: Data, _ metadata: Data) -> Int64 { 0 }
func XRaySetAssetLocation(_ value: String, _ error: inout NSError?) -> Bool { Kernel.record("assets"); return true }
func rememberTunnelLog(_ message: String) {}
func isIPv4Literal(_ value: String) -> Bool { true }
enum TunnelDNSPolicy {
    static let virtualServer = "10.0.85.53"
    static func allowsRouteExclusions(_ value: [String]) -> Bool { true }
    // ACTUAL_DNS_BINDING_REQUIREMENT
}
enum TunnelIPv6Policy { static func networkSettings(proxyAddresses: [String]) -> Int { 0 } }
final class NEPacketTunnelNetworkSettings {
    init(tunnelRemoteAddress: String) {}
    var mtu: NSNumber?, ipv4Settings: NEIPv4Settings?, ipv6Settings: Int?, dnsSettings: NEDNSSettings?
}
final class NEIPv4Settings { init(addresses: [String], subnetMasks: [String]) {}; var includedRoutes: [NEIPv4Route] = [], excludedRoutes: [NEIPv4Route] = [] }
final class NEIPv4Route { init(destinationAddress: String, subnetMask: String) {}; static func `default`() -> Self { Self(destinationAddress: "0.0.0.0", subnetMask: "0.0.0.0") } }
final class NEDNSSettings { init(servers: [String]) {}; var matchDomains: [String] = [] }
/// Preserve the provider's serial queue ownership in the in-memory fixture.
/// Reentrant sync is local to this fake; asynchronous writes still use FIFO.
final class FakeQueue: @unchecked Sendable {
    private let queue = DispatchQueue(label: "fixture.provider.serial")
    private let identity = DispatchSpecificKey<UInt8>()
    init() { queue.setSpecific(key: identity, value: 1) }
    func async(execute: @escaping () -> Void) { queue.async(execute: execute) }
    func asyncAfter(deadline: DispatchTime, execute: @escaping () -> Void) { queue.asyncAfter(deadline: deadline, execute: execute) }
    func sync<T>(execute: () throws -> T) rethrows -> T {
        if DispatchQueue.getSpecific(key: identity) != nil { return try execute() }
        return try queue.sync(execute: execute)
    }
}

/// Detached overlap starts and OS callbacks may run on different executors.
/// A snapshot retains Array/closure storage under the same lock as mutations.
final class FixtureState<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value
    init(_ value: Value) { self.value = value }
    func withValue<Result>(_ body: (inout Value) -> Result) -> Result {
        lock.lock(); defer { lock.unlock() }
        return body(&value)
    }
}
enum Kernel {
    private struct State {
        var events: [String] = [], failure = ""
        var bindingCapability: Int64 = 1
        var preparedData = Data("{}".utf8), dnsOnly = false
        var profile = NETunnelProviderManager()
        var onArm: (() -> Void)?, refreshFailures = 0
        var onPrepare: (() -> Void)?
        var onPrepareAsync: ((TunnelEndpointPath) async throws -> Void)?
        var onCoreCheck: (() -> Void)?
        var onSettings: (() async -> Void)?
        var onLegacyResolve: (() async throws -> Void)?
        var onPolicyLoad: (() -> Void)?
        var onWatchdogAdmission: (() -> Void)?
        var onNativeStop: (() -> Void)?
        var rejectHealth = false
        var legacyGenerations: [UInt64] = []
        var discoveries: [TunnelEndpointDiscovery] = []
        var preparedAddresses = ["192.0.2.1"]
        var coreInputs: [Data] = []
    }
    private static let state = FixtureState(State())
    static var events: [String] { state.withValue { $0.events } }
    static func record(_ event: String) { state.withValue { $0.events.append(event) } }
    static var failure: String {
        get { state.withValue { $0.failure } }
        set { state.withValue { $0.failure = newValue } }
    }
    static var bindingCapability: Int64 {
        get { state.withValue { $0.bindingCapability } }
        set { state.withValue { $0.bindingCapability = newValue } }
    }
    static var preparedData: Data {
        get { state.withValue { $0.preparedData } }
        set { state.withValue { $0.preparedData = newValue } }
    }
    static var dnsOnly: Bool {
        get { state.withValue { $0.dnsOnly } }
        set { state.withValue { $0.dnsOnly = newValue } }
    }
    static var profile: NETunnelProviderManager {
        get { state.withValue { $0.profile } }
        set { state.withValue { $0.profile = newValue } }
    }
    static var onArm: (() -> Void)? {
        get { state.withValue { $0.onArm } }
        set { state.withValue { $0.onArm = newValue } }
    }
    static var refreshFailures: Int {
        get { state.withValue { $0.refreshFailures } }
        set { state.withValue { $0.refreshFailures = newValue } }
    }
    static var onPrepare: (() -> Void)? {
        get { state.withValue { $0.onPrepare } }
        set { state.withValue { $0.onPrepare = newValue } }
    }
    static var onPrepareAsync: ((TunnelEndpointPath) async throws -> Void)? {
        get { state.withValue { $0.onPrepareAsync } }
        set { state.withValue { $0.onPrepareAsync = newValue } }
    }
    static var onCoreCheck: (() -> Void)? {
        get { state.withValue { $0.onCoreCheck } }
        set { state.withValue { $0.onCoreCheck = newValue } }
    }
    static var onSettings: (() async -> Void)? {
        get { state.withValue { $0.onSettings } }
        set { state.withValue { $0.onSettings = newValue } }
    }
    static var discoveries: [TunnelEndpointDiscovery] { state.withValue { $0.discoveries } }
    static var preparedAddresses: [String] {
        get { state.withValue { $0.preparedAddresses } }
        set { state.withValue { $0.preparedAddresses = newValue } }
    }
    static var coreInputs: [Data] { state.withValue { $0.coreInputs } }
    static func recordCore(_ bytes: Data) { state.withValue { $0.coreInputs.append(bytes) } }
    static var rejectHealth: Bool {
        get { state.withValue { $0.rejectHealth } }
        set { state.withValue { $0.rejectHealth = newValue } }
    }
    static var legacyGenerations: [UInt64] { state.withValue { $0.legacyGenerations } }
    static func recordLegacyGeneration(_ value: UInt64) { state.withValue { $0.legacyGenerations.append(value) } }
    static var onNativeStop: (() -> Void)? {
        get { state.withValue { $0.onNativeStop } }
        set { state.withValue { $0.onNativeStop = newValue } }
    }
    static var onPolicyLoad: (() -> Void)? {
        get { state.withValue { $0.onPolicyLoad } }
        set { state.withValue { $0.onPolicyLoad = newValue } }
    }
    static var onWatchdogAdmission: (() -> Void)? {
        get { state.withValue { $0.onWatchdogAdmission } }
        set { state.withValue { $0.onWatchdogAdmission = newValue } }
    }
    static func register(_ value: TunnelEndpointDiscovery) { state.withValue { $0.discoveries.append(value) } }
    static var onLegacyResolve: (() async throws -> Void)? {
        get { state.withValue { $0.onLegacyResolve } }
        set { state.withValue { $0.onLegacyResolve = newValue } }
    }
    static func consumeRefreshFailure() -> Bool {
        state.withValue {
            guard $0.refreshFailures > 0 else { return false }
            $0.refreshFailures -= 1; return true
        }
    }
    static func reset(armed: Bool = false, failure: String = "") {
        var next = State(); next.failure = failure
        next.profile.isOnDemandEnabled = armed
        next.profile.onDemandRules = armed ? [NEOnDemandRuleConnect()] : nil
        state.withValue { $0 = next }
    }
}
final class FixturePacketBridge { func shutdown() {} }
final class FixtureHEVLifecycle { var isRunning = true }
final class Provider {
    var packetBridge: FixturePacketBridge?
    var packetBridgeEpoch: TunnelSessionAdmission.Epoch?
    var packetBridgeToken: TunnelEndpointPlanAdmission.Token?
    let sessionAdmission = TunnelSessionAdmission(), watchdogQueue = FakeQueue(), runtimeQueue = FakeQueue()
    let forwardingLock = NSLock()
    var forwardingReady = false, reasserting = false
    var forwardingEpoch: TunnelSessionAdmission.Epoch?
    var startupPreparation: (epoch: TunnelSessionAdmission.Epoch, token: TunnelEndpointPlanAdmission.Token, task: Task<TunnelPreparedConfig, Error>)?
    func fixtureRegister(_ task: Task<TunnelPreparedConfig, Error>, token: TunnelEndpointPlanAdmission.Token) {
        setStartupPreparation(task, epoch: token.epoch, token: token)
    }
    func fixtureClear(token: TunnelEndpointPlanAdmission.Token) { setStartupPreparation(nil, epoch: token.epoch, token: token) }
    func fixtureOwns(_ token: TunnelEndpointPlanAdmission.Token) -> Bool { startupPreparation?.token == token }
    var runtimeSpec: RuntimeSpec?
    var startupDiscovery: (epoch: TunnelSessionAdmission.Epoch, token: TunnelEndpointPlanAdmission.Token, discovery: TunnelEndpointDiscovery)?
    var pendingSleep: PendingSleep?
    var initialDiscoveryCorrection: (epoch: TunnelSessionAdmission.Epoch, id: UUID, deadline: TimeInterval, terminal: Bool, task: Task<Void, Never>)?
    var watchdogSuspended = false, recoveryExhausted = false, initialRuntimeAttempted = false
    let hevLifecycle = FixtureHEVLifecycle()
    var watchdogInboundPort: Int?, watchdogInboundHealthy = false
    var recoveryFailures = 0, nativeOptions = try! VlessNativeOptions()
    var nativeRuntimeEpoch: TunnelSessionAdmission.Epoch?, nativeRuntimeToken: TunnelEndpointPlanAdmission.Token?
    enum EndpointTransitionFailure: Error { case drainPending }
    func startXRay(xrayConfig: Data, geoAssetsDirectory: String?, routingMetadata: Data?) throws { Kernel.record("Core-start"); Kernel.recordCore(xrayConfig) }
    func startSocks5Tunnel(serverPort: Int, credentials: LocalProxyCredentials, epoch: TunnelSessionAdmission.Epoch, token: TunnelEndpointPlanAdmission.Token) throws { Kernel.record("HEV-start") }
    func performTunnelHealthCheck(trigger: String, epoch: TunnelSessionAdmission.Epoch) -> Bool {
        Kernel.record("health-" + trigger); setForwardingReady(!Kernel.rejectHealth, epoch: epoch); return !Kernel.rejectHealth
    }
    func cancelTunnelWithError(_ error: Error?) { Kernel.record("terminal-cancel") }
    var protocolConfiguration: NEVPNProtocol? { Kernel.profile.protocolConfiguration }
    let tunnelMTU = 1500, dnsServers = ["10.0.85.53"]
    let endpointAdmission = TunnelEndpointPlanAdmission()
    let endpointCommitQueue = TunnelEndpointCommitQueue()
    var installedSettingsKey: ProtectedSettingsKey?
    var runtimeSource: RuntimeSource?, physicalPath: TunnelEndpointPath?
    var observedPhysicalPath = false, selectedAttempt: UInt64 = 0
    var runtimeRecoveryInFlight = false
    var pathObserver: TunnelPhysicalPathObserver?
    var endpointPreparation: (token: TunnelEndpointPlanAdmission.Token, task: Task<Void, Never>)?
    func makePhysicalPathObserver() -> TunnelPhysicalPathObserver { TunnelPhysicalPathObserver() }
    func refreshEndpointPlan(after delay: TimeInterval, epoch: TunnelSessionAdmission.Epoch, rotate: Bool) { Kernel.record("ordinary-refresh") }
    // ACTUAL_PREPARATION_HELPERS
    func tunnelError(_ message: String) -> NSError { NSError(domain: "fixture.provider", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    func parseConfig(jsonData: Data) -> (inboundPort: Int, unused: Int)? { (10808, 0) }
    func buildIPv4ExcludedRoutes(serverAddresses: [String]) -> [NEIPv4Route] { [] }
    func setTunnelNetworkSettings(_ settings: NEPacketTunnelNetworkSettings?) async throws {
        Kernel.record(settings == nil ? "clear-settings" : "settings")
        await Kernel.onSettings?()
    }
    func startTunnelWatchdog(_ spec: RuntimeSpec) -> Bool {
        Kernel.onWatchdogAdmission?()
        return watchdogQueue.sync {
            guard endpointAdmission.mayStart(spec.token), endpointSpecIsFresh(spec), sessionAdmission.activate(spec.epoch) else { return false }
            runtimeSpec = spec; nativeOptions = spec.options
            initialRuntimeAttempted = false; watchdogSuspended = false
            Kernel.record("runtime-admission"); return true
        }
    }
    func stopTunnelWatchdog(epoch: TunnelSessionAdmission.Epoch?) {
        watchdogQueue.sync {
            if let current = runtimeSource?.epoch ?? runtimeSpec?.epoch, current != epoch { return }
            cancelInitialDiscoveryCorrection(epoch: epoch)
            pathObserver?.cancel(); pathObserver = nil; runtimeSource = nil; physicalPath = nil; runtimeSpec = nil
        }
    }
    func stopNativeRuntime(ownedBy epoch: TunnelSessionAdmission.Epoch? = nil, token: TunnelEndpointPlanAdmission.Token? = nil) -> Bool { Kernel.record("native-stop"); Kernel.onNativeStop?(); return true }
    // ACTUAL_STOP
    func scheduleNativeRecovery(after delay: Int, epoch: TunnelSessionAdmission.Epoch) {}
    // ACTUAL_START
}
// Inert boundary: the actual provider owns tasks/tokens; this gate replaces only
// the expensive asynchronous preparer, which is not compiled or invoked here.
enum CancellationCases {
    static func until(_ body: () -> Bool) async -> Bool {
        let end = ProcessInfo.processInfo.systemUptime + 1
        while !body(), ProcessInfo.processInfo.systemUptime < end {
            try? await Task.sleep(nanoseconds: 1_000_000)
        }
        return body()
    }

    static func pending() -> Task<TunnelPreparedConfig, Error> {
        Task {
            try await Task.sleep(nanoseconds: 2_000_000_000)
            return TunnelPreparedConfig()
        }
    }

    static func run() async -> [(String, Bool)] {
        var checks: [(String, Bool)] = []
        func record(_ name: String, _ passed: Bool) { checks.append((name, passed)) }

        // The first query produces no callback. An opaque same-path DNS64 change
        // must cancel that obsolete preparation, not wait out its 2s boundary.
        Kernel.reset()
        let changed = Provider()
        let state = FixtureState((entries: 0, cancellations: 0))
        Kernel.onPrepareAsync = { _ in
            let ordinal = state.withValue { $0.entries += 1; return $0.entries }
            if ordinal == 1 {
                do { try await Task.sleep(nanoseconds: 2_000_000_000) }
                catch {
                    state.withValue { $0.cancellations += 1 }
                    throw error
                }
            }
        }
        let first = Task.detached { try await changed.startTunnel() }
        let entered = await until { state.withValue { $0.entries == 1 } }
        let began = ProcessInfo.processInfo.systemUptime
        let previous = changed.endpointAdmission.currentToken
        changed.watchdogQueue.sync {
            if let epoch = changed.sessionAdmission.currentEpoch {
                changed.physicalPathChanged(TunnelEndpointPath(), epoch: epoch)
            }
        }
        let tokenChanged = previous != changed.endpointAdmission.currentToken
        var succeeded = false
        do { try await first.value; succeeded = true } catch {}
        let milliseconds = (ProcessInfo.processInfo.systemUptime - began) * 1000
        print("STARTUP_CANCEL_MEASURE=same-path-refresh-to-completion;ms=\(milliseconds)")
        record("path-refresh-cancels-silent-startup-promptly", entered && succeeded && milliseconds < 500 && state.withValue { $0.cancellations == 1 })
        record("same-path-opaque-DNS64-refresh-reprepares", tokenChanged && succeeded && state.withValue { $0.entries == 2 } && Kernel.events.filter { $0 == "runtime-admission" }.count == 1)

        // Four ordinary path updates can land after four separate DNS children
        // register. None of those incomplete plans may consume a preflight slot.
        Kernel.reset()
        let bursting = Provider()
        let burstState = FixtureState((entries: 0, cancellations: 0))
        Kernel.onPrepareAsync = { _ in
            let ordinal = burstState.withValue { $0.entries += 1; return $0.entries }
            if ordinal <= 4 {
                do { try await Task.sleep(nanoseconds: 2_000_000_000) }
                catch { burstState.withValue { $0.cancellations += 1 }; throw error }
            }
        }
        let burstStart = Task.detached { try await bursting.startTunnel() }
        var allRegistered = true
        for ordinal in 1...4 {
            guard await until({ burstState.withValue { $0.entries == ordinal } }) else { allRegistered = false; break }
            bursting.watchdogQueue.sync {
                if let epoch = bursting.sessionAdmission.currentEpoch {
                    bursting.physicalPathChanged(TunnelEndpointPath(), epoch: epoch)
                }
            }
        }
        var burstSucceeded = false
        do { try await burstStart.value; burstSucceeded = true } catch {}
        record("four-staggered-path-updates-keep-one-admitted-startup", allRegistered && burstSucceeded &&
            burstState.withValue { $0.entries == 5 && $0.cancellations == 4 } &&
            Kernel.events.filter { $0 == "check" }.count == 1 &&
            Kernel.events.filter { $0 == "settings" }.count == 1 &&
            Kernel.events.filter { $0 == "runtime-admission" }.count == 1)

        // A completed, current preparation DOES consume its attempt before
        // preflight/settings. Three later invalidations retain the original cap.
        Kernel.reset()
        let preflightChanges = Provider()
        Kernel.onCoreCheck = {
            preflightChanges.watchdogQueue.sync {
                if let epoch = preflightChanges.sessionAdmission.currentEpoch {
                    preflightChanges.physicalPathChanged(TunnelEndpointPath(), epoch: epoch)
                }
            }
        }
        var boundedRefusal = false
        do { try await preflightChanges.startTunnel() }
        catch { boundedRefusal = !(error is CancellationError) }
        record("two-fast-plus-three-legacy-preflight-attempts-still-bounded", boundedRefusal &&
            Kernel.events.filter { $0 == "prepare" }.count == 5 &&
            Kernel.events.filter { $0 == "check" }.count == 5 &&
            Kernel.discoveries.count == 2 && Kernel.events.filter { $0 == "legacy-dns" }.count == 3 &&
            !Kernel.events.contains("settings") && !Kernel.events.contains("arm") && !Kernel.events.contains("runtime-admission"))

        // A refresh can win after the old task is created but before registration.
        // Setter must reject the stale token, even though its epoch is current.
        Kernel.reset()
        let beforeRegister = Provider()
        let epoch = beforeRegister.sessionAdmission.begin()
        let stale = try! beforeRegister.endpointAdmission.begin(epoch)
        _ = try! beforeRegister.endpointAdmission.refresh(epoch)
        let staleTask = pending()
        beforeRegister.fixtureRegister(staleTask, token: stale)
        record("refresh-before-registration-rejects-stale-child", staleTask.isCancelled && beforeRegister.startupPreparation == nil)
        staleTask.cancel(); _ = try? await staleTask.value

        // An old defer must not clear the next task from the SAME session.
        Kernel.reset()
        let replacing = Provider()
        let owner = replacing.sessionAdmission.begin()
        let oldToken = try! replacing.endpointAdmission.begin(owner)
        let old = pending()
        replacing.fixtureRegister(old, token: oldToken)
        let newToken = try! replacing.endpointAdmission.refresh(owner)
        let next = pending()
        replacing.fixtureRegister(next, token: newToken)
        replacing.fixtureClear(token: oldToken)
        record("old-token-clear-cannot-clear-new-startup", replacing.fixtureOwns(newToken) && !next.isCancelled)
        old.cancel(); next.cancel(); _ = try? await old.value; _ = try? await next.value

        // Invalidating an otherwise unreplaced token must still allow its own
        // defer to release the completed task rather than retaining stale data.
        Kernel.reset()
        let clearing = Provider()
        let clearEpoch = clearing.sessionAdmission.begin()
        let clearToken = try! clearing.endpointAdmission.begin(clearEpoch)
        let clearTask = pending()
        clearing.fixtureRegister(clearTask, token: clearToken)
        _ = try! clearing.endpointAdmission.refresh(clearEpoch)
        clearing.fixtureClear(token: clearToken)
        record("matching-stale-token-defer-releases-own-child", clearing.startupPreparation == nil)
        clearTask.cancel(); _ = try? await clearTask.value

        // Old-session callbacks/setters must leave a replacement session intact.
        Kernel.reset()
        let swapped = Provider()
        let earlierEpoch = swapped.sessionAdmission.begin()
        let earlier = try! swapped.endpointAdmission.begin(earlierEpoch)
        let currentEpoch = swapped.sessionAdmission.begin()
        let current = try! swapped.endpointAdmission.begin(currentEpoch)
        let currentTask = pending()
        swapped.fixtureRegister(currentTask, token: current)
        let lateTask = pending()
        swapped.fixtureRegister(lateTask, token: earlier)
        swapped.fixtureClear(token: earlier)
        swapped.watchdogQueue.sync { swapped.physicalPathChanged(TunnelEndpointPath(), epoch: earlierEpoch) }
        record("old-session-work-cannot-clear-cancel-current-child", lateTask.isCancelled && swapped.fixtureOwns(current) && !currentTask.isCancelled)
        lateTask.cancel(); currentTask.cancel(); _ = try? await lateTask.value; _ = try? await currentTask.value

        // Actual Stop revokes and cancels a waiting startup, after which the same
        // provider accepts one clean new session. No OnDemand/OS/Core is real.
        Kernel.reset()
        let stopped = Provider()
        let stopState = FixtureState((entries: 0, cancellations: 0))
        Kernel.onPrepareAsync = { _ in
            let ordinal = stopState.withValue { $0.entries += 1; return $0.entries }
            if ordinal == 1 {
                do { try await Task.sleep(nanoseconds: 2_000_000_000) }
                catch { stopState.withValue { $0.cancellations += 1 }; throw error }
            }
        }
        let stoppedStart = Task.detached { try await stopped.startTunnel() }
        let stopEntered = await until { stopState.withValue { $0.entries == 1 } }
        await withCheckedContinuation { done in stopped.stopTunnel(with: .providerFailed) { done.resume() } }
        var cancelled = false, restarted = false
        do { try await stoppedStart.value } catch { cancelled = error is CancellationError }
        do { try await stopped.startTunnel(); restarted = true } catch {}
        record("Stop-cancels-startup-and-next-session-starts", stopEntered && cancelled && restarted && stopState.withValue { $0.cancellations == 1 && $0.entries == 2 } && Kernel.events.filter { $0 == "runtime-admission" }.count == 1)
        return checks
    }
}


enum InitialDiscoveryCases {
    static func run() async -> [(String, Bool)] {
        var checks: [(String, Bool)] = []
        func record(_ name: String, _ passed: Bool) { checks.append((name, passed)) }
        func disabledOptions() {
            (Kernel.profile.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration?["options"] =
                ["reconnect": ["enabled": false], "protection": ["onDemand": "disabled"]]
        }
        func startCore(_ provider: Provider) async throws {
            guard let spec = provider.runtimeSpec else { throw CancellationError() }
            try await provider.onRuntimeQueue { try provider.startNativeRuntime(spec) }
        }
        func stop(_ provider: Provider) async {
            await withCheckedContinuation { next in provider.stopTunnel(with: .providerFailed) { next.resume() } }
        }

        // Fast initial preparation can now complete between ordinary path events.
        // Two superseded fast admissions must leave all three legacy slots.
        Kernel.reset(); disabledOptions()
        let burst = Provider(), changes = FixtureState(0), legacy = FixtureState((entries: 0, cancelled: 0))
        Kernel.onCoreCheck = {
            let ordinal = changes.withValue { $0 += 1; return $0 }
            if ordinal <= 2 {
                burst.watchdogQueue.sync { burst.physicalPathChanged(TunnelEndpointPath(), epoch: burst.sessionAdmission.currentEpoch!) }
            }
        }
        Kernel.onLegacyResolve = {
            let ordinal = legacy.withValue { $0.entries += 1; return $0.entries }
            if ordinal <= 4 {
                do { try await Task.sleep(nanoseconds: 2_000_000_000) }
                catch { legacy.withValue { $0.cancelled += 1 }; throw error }
            }
        }
        let burstStart = Task.detached { try await burst.startTunnel() }
        var everyChild = true
        for ordinal in 1...4 {
            if !(await CancellationCases.until { legacy.withValue { $0.entries == ordinal } }) { everyChild = false; break }
            // Stagger events while the full-window DNS child is outstanding.
            try? await Task.sleep(nanoseconds: UInt64([20, 60, 80, 90][ordinal - 1]) * 1_000_000)
            burst.watchdogQueue.sync { burst.physicalPathChanged(TunnelEndpointPath(), epoch: burst.sessionAdmission.currentEpoch!) }
        }
        var burstOK = false
        do { try await burstStart.value; try await startCore(burst); burstOK = true } catch {}
        record("fast-two-admissions-fall-back-to-legacy-through-four-early-path-events", everyChild && burstOK && Kernel.discoveries.count == 2 &&
            legacy.withValue { $0.entries == 5 && $0.cancelled == 4 } && Kernel.events.filter { $0 == "settings" }.count == 1 &&
            Kernel.events.filter { $0 == "Core-start" }.count == 1 && Kernel.events.filter { $0 == "runtime-admission" }.count == 1)
        await stop(burst)


        // The immutable profile can finish arming while the fast numeric plan
        // changes. Exactly one legacy fallback closes the handoff gap without
        // writing the preference transaction a second time.
        Kernel.reset(); let loadingArm = Provider(), loadReplacement = Data(#"{"fixture":"arming-load-B"}"#.utf8)
        Kernel.onPolicyLoad = {
            Kernel.onPolicyLoad = nil; Kernel.preparedData = loadReplacement; Kernel.preparedAddresses = ["192.0.2.2"]
            Kernel.discoveries.last!.removeSelected()
        }
        var loadArmSucceeded = false
        do { try await loadingArm.startTunnel(); try await startCore(loadingArm); loadArmSucceeded = true } catch {}
        record("selected-remove-before-arming-update-retains-epoch-authority-and-one-full-fallback", loadArmSucceeded &&
            Kernel.events.filter { $0 == "arm" }.count == 1 && Kernel.events.filter { $0 == "legacy-dns" }.count == 1 &&
            Kernel.events.filter { $0 == "Core-start" }.count == 1 && Kernel.coreInputs.last == loadReplacement &&
            loadingArm.runtimeSpec?.discovery == nil && Kernel.discoveries.count == 1)
        await stop(loadingArm)

        Kernel.reset(); let arming = Provider(), replacement = Data(#"{"fixture":"arming-B"}"#.utf8)
        Kernel.onArm = {
            Kernel.onArm = nil; Kernel.preparedData = replacement; Kernel.preparedAddresses = ["192.0.2.2"]
            Kernel.discoveries.last!.removeSelected()
        }
        var armingSucceeded = false
        do { try await arming.startTunnel(); try await startCore(arming); armingSucceeded = true } catch {}
        record("selected-remove-during-arming-uses-one-full-fallback-with-one-Core-and-one-arm", armingSucceeded &&
            Kernel.events.filter { $0 == "arm" }.count == 1 && Kernel.events.filter { $0 == "legacy-dns" }.count == 1 &&
            Kernel.events.filter { $0 == "Core-start" }.count == 1 && Kernel.coreInputs.last == replacement &&
            arming.runtimeSpec?.bootstrapAddresses == ["192.0.2.2"] && arming.runtimeSpec?.discovery == nil && Kernel.discoveries.count == 1)
        await stop(arming)

        Kernel.reset(); let activating = Provider(), activationBytes = Data(#"{"fixture":"activation-B"}"#.utf8)
        Kernel.onWatchdogAdmission = {
            Kernel.onWatchdogAdmission = nil
            Kernel.preparedData = activationBytes; Kernel.preparedAddresses = ["192.0.2.2"]
            Kernel.discoveries.last!.removeSelected()
            // Drain the callback while the session is still inactive: its
            // bounded correction cannot own this preactivation handoff.
            activating.watchdogQueue.sync {}
        }
        var activationSucceeded = false
        do { try await activating.startTunnel(); try await startCore(activating); activationSucceeded = true } catch {}
        record("selected-remove-after-commit-before-activation-uses-one-full-fallback-no-rearm", activationSucceeded &&
            Kernel.discoveries.count == 1 && Kernel.events.filter { $0 == "legacy-dns" }.count == 1 &&
            Kernel.events.filter { $0 == "arm" }.count == 1 && Kernel.events.filter { $0 == "Core-start" }.count == 1 &&
            Kernel.events.filter { $0 == "runtime-admission" }.count == 1 && Kernel.coreInputs.last == activationBytes &&
            activating.runtimeSpec?.discovery == nil && activating.initialDiscoveryCorrection == nil)
        await stop(activating)

        Kernel.reset(); let stoppedArming = Provider()
        Kernel.onArm = {
            Kernel.onArm = nil
            _ = stoppedArming.sessionAdmission.revoke()
        }
        var armingCancelled = false
        do { try await stoppedArming.startTunnel() } catch { armingCancelled = error is CancellationError }
        record("Stop-during-fast-arming-never-enters-DNS-fallback-or-Core", armingCancelled &&
            !Kernel.events.contains("legacy-dns") && !Kernel.events.contains("Core-start") && !Kernel.profile.isOnDemandEnabled)
        await stop(stoppedArming)

        Kernel.reset(); let replacedArming = Provider()
        Kernel.onArm = { Kernel.onArm = nil; _ = replacedArming.sessionAdmission.begin() }
        var newOwnerPreserved = false
        do { try await replacedArming.startTunnel() } catch { newOwnerPreserved = error is CancellationError }
        record("new-owner-during-fast-arming-never-falls-back-or-rolls-back-new-profile", newOwnerPreserved &&
            !Kernel.events.contains("legacy-dns") && !Kernel.events.contains("Core-start") && Kernel.profile.isOnDemandEnabled && !Kernel.events.contains("disarm"))
        await stop(replacedArming)

        Kernel.reset(); let failedArming = Provider()
        Kernel.onArm = {
            Kernel.onArm = nil; Kernel.failure = "endpoint"
            Kernel.discoveries.last!.removeSelected()
        }
        var fallbackRefused = false
        do { try await failedArming.startTunnel() } catch { fallbackRefused = true }
        record("current-arming-fallback-failure-rolls-back-exact-arming-receipt", fallbackRefused &&
            Kernel.events.filter { $0 == "prepare" }.count == 2 && Kernel.events.filter { $0 == "arm" }.count == 1 && Kernel.events.contains("disarm") &&
            !Kernel.profile.isOnDemandEnabled && !Kernel.events.contains("Core-start") && !Kernel.events.contains("runtime-admission"))
        await stop(failedArming)


        Kernel.reset(); let legacyArming = Provider()
        Kernel.onArm = {
            Kernel.onArm = nil; Kernel.discoveries.last!.removeSelected()
            Kernel.onCoreCheck = {
                legacyArming.watchdogQueue.sync { legacyArming.physicalPathChanged(TunnelEndpointPath(), epoch: legacyArming.sessionAdmission.currentEpoch!) }
            }
        }
        var threeLegacyRefused = false
        do { try await legacyArming.startTunnel() } catch { threeLegacyRefused = true }
        record("arming-fallback-retains-exactly-three-legacy-admissions-and-no-rearm", threeLegacyRefused &&
            Kernel.discoveries.count == 1 && Kernel.events.filter { $0 == "legacy-dns" }.count == 3 &&
            Kernel.events.filter { $0 == "arm" }.count == 1 && Kernel.events.contains("disarm") &&
            !Kernel.events.contains("Core-start") && !Kernel.events.contains("runtime-admission"))
        await stop(legacyArming)

        // The lease's latest accepted TTL is authoritative after renewal;
        // the original early candidate's shorter TTL cannot force a restart.
        Kernel.reset(); disabledOptions(); let renewal = Provider()
        try? await renewal.startTunnel(); try? await startCore(renewal)
        let renewalGroup = Kernel.discoveries.last!, renewalToken = renewal.endpointAdmission.currentToken!
        let initialTTLExpired = TunnelPreparedConfig(endpointPath: renewal.runtimeSpec!.path,
            endpointSelections: [TunnelEndpointSelection(candidates: TunnelEndpointCandidates(path: renewal.runtimeSpec!.path),
                selected: TunnelEndpointCandidate(expiry: ProcessInfo.processInfo.systemUptime - 1))])
        let renewedSpec = Provider.RuntimeSpec(source: renewal.runtimeSource!, prepared: initialTTLExpired, token: renewalToken,
            path: renewal.runtimeSpec!.path, port: 10808, discovery: renewalGroup,
            discoveryDeadline: ProcessInfo.processInfo.systemUptime + 25)
        record("leased-latest-TTL-renewal-outlives-original-published-candidate-without-Core-restart",
            renewal.endpointSpecIsFresh(renewedSpec) && renewal.endpointAdmission.currentToken == renewalToken &&
            !renewalGroup.isInvalidated && Kernel.events.filter { $0 == "Core-start" }.count == 1)
        await stop(renewal)

        // Expiry caused by a live TTL shortening is atomically claimed before
        // pre-Core retry. It cannot masquerade as a sealed ordinary expiry.
        Kernel.reset(); disabledOptions(); let shortening = Provider()
        Kernel.onCoreCheck = {
            Kernel.onCoreCheck = nil; Kernel.discoveries.last!.expireWitness()
        }
        var shorteningSucceeded = false
        do { try await shortening.startTunnel(); try await startCore(shortening); shorteningSucceeded = true } catch {}
        record("live-TTL-shortening-expiry-claims-initial-invalidation-before-Core-and-retries",
            shorteningSucceeded && Kernel.discoveries.count == 2 && Kernel.discoveries.first!.isInvalidated &&
            Kernel.events.filter { $0 == "Core-start" }.count == 1 && !Kernel.events.contains("terminal-cancel"))
        await stop(shortening)

        // A sealed ordinary TTL expiry must use existing recovery policy; it
        // cannot borrow the initial 25-second correction authority after expiry.
        Kernel.reset(); disabledOptions(); let ttl = Provider()
        try? await ttl.startTunnel(); try? await startCore(ttl)
        let sealedGroup = Kernel.discoveries.last!, ttlToken = ttl.endpointAdmission.currentToken!
        sealedGroup.seal(); sealedGroup.expireWitness(); ttl.setForwardingReady(true, epoch: ttl.sessionAdmission.currentEpoch!)
        let expiredPrepared = TunnelPreparedConfig(endpointPath: ttl.runtimeSpec!.path,
            endpointSelections: [TunnelEndpointSelection(candidates: TunnelEndpointCandidates(path: ttl.runtimeSpec!.path),
                                                        selected: TunnelEndpointCandidate(expiry: ProcessInfo.processInfo.systemUptime - 1))])
        let expiredSpec = Provider.RuntimeSpec(source: ttl.runtimeSource!, prepared: expiredPrepared, token: ttlToken,
            path: ttl.runtimeSpec!.path, port: 10808, discovery: sealedGroup,
            discoveryDeadline: ProcessInfo.processInfo.systemUptime - 1)
        let ttlStale = !ttl.endpointSpecIsFresh(expiredSpec)
        ttl.watchdogQueue.sync {}
        record("sealed-normal-TTL-expiry-cannot-claim-expired-initial-correction-budget", ttlStale && !sealedGroup.isInvalidated &&
            ttl.endpointAdmission.currentToken == ttlToken && ttl.initialDiscoveryCorrection == nil && ttl.forwardingReady &&
            !Kernel.events.contains("terminal-cancel") && Kernel.events.filter { $0 == "Core-start" }.count == 1)
        await stop(ttl)

        // An unfinished initial DNS snapshot must follow a changed physical
        // underlay even when ordinary automatic reconnect is disabled.
        Kernel.reset(); disabledOptions(); let moved = Provider()
        try? await moved.startTunnel(); try? await startCore(moved)
        let movingGroup = Kernel.discoveries.last!
        let movedBytes = Data(#"{"fixture":"IPv6-path-B"}"#.utf8)
        Kernel.preparedData = movedBytes; Kernel.preparedAddresses = ["2001:db8::2"]
        moved.watchdogQueue.sync { moved.physicalPathChanged(nil, epoch: moved.sessionAdmission.currentEpoch!) }
        let nilOwner = moved.watchdogQueue.sync { moved.initialDiscoveryCorrection?.id }
        try? await Task.sleep(nanoseconds: 20_000_000)
        let noDNSWithoutPath = !Kernel.events.contains("legacy-dns")
        moved.watchdogQueue.sync {
            moved.physicalPathChanged(TunnelEndpointPath(supportsIPv4: false, supportsIPv6: true), epoch: moved.sessionAdmission.currentEpoch!)
        }
        let movedReady = await CancellationCases.until { Kernel.events.contains("health-initial-dns-correction") }
        record("healthy-unsealed-path-change-pauses-without-underlay-then-full-resolves-IPv6-with-disabled-reconnect", movedReady &&
            nilOwner != nil && noDNSWithoutPath && movingGroup.wasCancelled && !movingGroup.isInvalidated &&
            Kernel.events.filter { $0 == "legacy-dns" }.count == 1 && Kernel.events.filter { $0 == "Core-start" }.count == 2 &&
            moved.runtimeSpec?.path.supportsIPv4 == false && moved.runtimeSpec?.path.supportsIPv6 == true &&
            moved.runtimeSpec?.bootstrapAddresses == ["2001:db8::2"] && Kernel.coreInputs.last == movedBytes &&
            moved.recoveryFailures == 0 && !moved.nativeOptions.reconnectEnabled && !Kernel.events.contains("terminal-cancel"))
        await stop(moved)

        Kernel.reset(); disabledOptions(); let sealedMove = Provider()
        try? await sealedMove.startTunnel(); try? await startCore(sealedMove)
        Kernel.discoveries.last!.seal()
        sealedMove.watchdogQueue.sync {
            sealedMove.physicalPathChanged(TunnelEndpointPath(supportsIPv4: false, supportsIPv6: true), epoch: sealedMove.sessionAdmission.currentEpoch!)
        }
        record("sealed-healthy-path-change-does-not-borrow-initial-correction-with-disabled-reconnect",
            sealedMove.initialDiscoveryCorrection == nil && !Kernel.events.contains("legacy-dns") &&
            Kernel.events.filter { $0 == "Core-start" }.count == 1 && !sealedMove.nativeOptions.reconnectEnabled)
        await stop(sealedMove)

        // Additions enrich the live set but never create another native worker.
        Kernel.reset(); disabledOptions(); let additions = Provider()
        try? await additions.startTunnel(); try? await startCore(additions)
        let firstGroup = Kernel.discoveries.last!
        firstGroup.addLateAAAA()
        additions.watchdogQueue.sync {}
        record("late-AAAA-addition-keeps-one-Core-and-disabled-reconnect", Kernel.events.filter { $0 == "Core-start" }.count == 1 &&
            additions.initialDiscoveryCorrection == nil && !additions.nativeOptions.reconnectEnabled)
        await stop(additions)

        // A removed early address is part of this Connect's unfinished DNS,
        // even when the caller did not authorize automatic reconnect.
        Kernel.reset(); disabledOptions(); let removed = Provider()
        try? await removed.startTunnel(); try? await startCore(removed)
        let selected = Kernel.discoveries.last!
        let replacementBytes = Data(#"{"fixture":"B"}"#.utf8)
        Kernel.preparedData = replacementBytes; Kernel.preparedAddresses = ["192.0.2.2"]
        selected.removeSelected()
        let corrected = await CancellationCases.until { Kernel.events.contains("health-initial-dns-correction") }
        let correctedSpec = removed.runtimeSpec
        record("selected-remove-after-Core-corrects-once-with-full-DNS-and-disabled-reconnect", corrected &&
            Kernel.events.filter { $0 == "Core-start" }.count == 2 && Kernel.events.filter { $0 == "legacy-dns" }.count == 1 &&
            removed.recoveryFailures == 0 && !removed.nativeOptions.reconnectEnabled && removed.initialDiscoveryCorrection == nil &&
            !Kernel.events.contains("terminal-cancel") && removed.forwardingReady &&
            removed.runtimeSpec?.bootstrapAddresses == ["192.0.2.2"] && Kernel.coreInputs.last == replacementBytes)
        var replayRejected = false
        if let correctedSpec {
            do { try await removed.onRuntimeQueue { try removed.startNativeRuntime(correctedSpec) } }
            catch { replayRejected = error is CancellationError }
        }
        record("finished-correction-permit-cannot-authorize-external-restart", replayRejected && Kernel.events.filter { $0 == "Core-start" }.count == 2)
        await stop(removed)


        // A genuine ordinary TTL expiry after the initial lease ended must
        // retain the caller's original true/false automatic recovery policy.
        for enabled in [false, true] {
            Kernel.reset()
            if !enabled { disabledOptions() }
            let ordinary = Provider(); try? await ordinary.startTunnel(); try? await startCore(ordinary)
            let ordinaryGroup = Kernel.discoveries.last!, ordinaryToken = ordinary.endpointAdmission.currentToken!
            ordinaryGroup.seal(); ordinaryGroup.expireWitness()
            let staleData = TunnelPreparedConfig(endpointPath: ordinary.runtimeSpec!.path,
                endpointSelections: [TunnelEndpointSelection(candidates: TunnelEndpointCandidates(path: ordinary.runtimeSpec!.path),
                                                            selected: TunnelEndpointCandidate(expiry: ProcessInfo.processInfo.systemUptime - 1))])
            let ordinarySpec = Provider.RuntimeSpec(source: ordinary.runtimeSource!, prepared: staleData, token: ordinaryToken,
                path: ordinary.runtimeSpec!.path, port: 10808, discovery: ordinaryGroup,
                discoveryDeadline: ProcessInfo.processInfo.systemUptime - 1)
            ordinary.runtimeSpec = ordinarySpec
            let staleOrdinary = !ordinary.endpointSpecIsFresh(ordinarySpec)
            ordinary.watchdogQueue.sync { ordinary.fixtureRefreshEndpointPlan(after: 0, epoch: ordinary.sessionAdmission.currentEpoch!, rotate: false) }
            let ordinaryCompleted = enabled ? await CancellationCases.until { Kernel.events.contains("health-endpoint-refresh") } : true
            record("sealed-TTL-keeps-original-reconnect-policy-\(enabled)", staleOrdinary && ordinaryCompleted &&
                ordinary.initialDiscoveryCorrection == nil && !Kernel.events.contains("terminal-cancel") &&
                Kernel.events.filter { $0 == "Core-start" }.count == (enabled ? 2 : 1) &&
                Kernel.events.filter { $0 == "legacy-dns" }.count == (enabled ? 1 : 0) &&
                ordinary.recoveryFailures == (enabled ? 1 : 0))
            await stop(ordinary)
        }

        // The old native-start completion can arrive only after a terminal DNS
        // correction. Its defer must not reopen normal recovery before NE Stop.
        final class NativeStopGate: @unchecked Sendable {
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            func waitUntilEntered() -> Bool { entered.wait(timeout: .now() + 1) == .success }
        }
        Kernel.reset(); let terminal = Provider(), nativeGate = NativeStopGate()
        try? await terminal.startTunnel()
        Kernel.onNativeStop = {
            nativeGate.entered.signal()
            _ = nativeGate.release.wait(timeout: .now() + 3)
        }
        terminal.watchdogQueue.sync { terminal.fixtureScheduleNativeRecovery(after: 0, epoch: terminal.sessionAdmission.currentEpoch!) }
        let oldNativeEntered = nativeGate.waitUntilEntered()
        Kernel.failure = "endpoint"; Kernel.discoveries.last!.removeSelected()
        let terminalRequested = await CancellationCases.until { Kernel.events.contains("terminal-cancel") }
        Kernel.onNativeStop = nil; nativeGate.release.signal()
        terminal.runtimeQueue.sync {}; terminal.watchdogQueue.sync {}
        record("old-native-defer-cannot-reopen-recovery-after-terminal-correction", oldNativeEntered && terminalRequested &&
            terminal.initialDiscoveryCorrection?.terminal == true && terminal.runtimeRecoveryInFlight &&
            !Kernel.events.contains("ordinary-refresh") && !Kernel.events.contains("legacy-dns") && !Kernel.events.contains("Core-start"))
        await stop(terminal)


        // A timer already running on watchdogQueue must not overtake the queued
        // private owner after the DNS callback atomically refreshed its token.
        Kernel.reset(); let pendingOwner = Provider()
        try? await pendingOwner.startTunnel(); try? await startCore(pendingOwner)
        let pendingGroup = Kernel.discoveries.last!, ownerGap = FixtureState(false)
        pendingOwner.watchdogQueue.sync {
            pendingGroup.removeSelected()
            let replacement = pendingOwner.endpointAdmission.currentToken
            pendingOwner.fixtureRefreshEndpointPlan(after: 0, epoch: pendingOwner.sessionAdmission.currentEpoch!, rotate: false)
            ownerGap.withValue { $0 = pendingOwner.endpointAdmission.currentToken == replacement && pendingOwner.recoveryFailures == 0 &&
                Kernel.events.filter { $0 == "legacy-dns" }.count == 0 }
        }
        let gapCorrected = await CancellationCases.until { Kernel.events.contains("health-initial-dns-correction") }
        record("ordinary-timer-cannot-overtake-queued-initial-DNS-owner", ownerGap.withValue { $0 } && gapCorrected &&
            Kernel.events.filter { $0 == "Core-start" }.count == 2 && pendingOwner.recoveryFailures == 0 && !Kernel.events.contains("terminal-cancel"))
        await stop(pendingOwner)

        // Latching and notifying happen on opposite sides of the discovery
        // lock. A physical update can win in between without orphaning the
        // invalid initial runtime or granting a stale callback the new token.
        Kernel.reset(); disabledOptions(); let pathWon = Provider()
        try? await pathWon.startTunnel(); try? await startCore(pathWon)
        let racingGroup = Kernel.discoveries.last!
        racingGroup.latchRemovalWithoutNotification()
        pathWon.watchdogQueue.sync { pathWon.physicalPathChanged(TunnelEndpointPath(), epoch: pathWon.sessionAdmission.currentEpoch!) }
        let pathToken = pathWon.endpointAdmission.currentToken
        racingGroup.notifyLatchedRemoval()
        let pathCorrected = await CancellationCases.until { Kernel.events.contains("health-initial-dns-correction") }
        record("physical-path-winning-invalidation-race-uses-fresh-bounded-correction", pathCorrected &&
            pathWon.endpointAdmission.currentToken == pathToken && Kernel.events.filter { $0 == "Core-start" }.count == 2 &&
            Kernel.events.filter { $0 == "legacy-dns" }.count == 1 && pathWon.recoveryFailures == 0 && !Kernel.events.contains("terminal-cancel"))
        await stop(pathWon)

        // An unavailable underlay pauses the same initial transaction without
        // DNS work, cached-answer rebasing, or a fresh deadline/budget.
        Kernel.reset(); disabledOptions(); let nilPath = Provider()
        try? await nilPath.startTunnel(); try? await startCore(nilPath)
        let pause = FixtureState((entered: false, cancelled: false))
        Kernel.onLegacyResolve = {
            let first = pause.withValue { value -> Bool in if value.entered { return false }; value.entered = true; return true }
            if first {
                do { try await Task.sleep(nanoseconds: 2_000_000_000) }
                catch { pause.withValue { $0.cancelled = true }; throw error }
            }
        }
        Kernel.discoveries.last!.removeSelected()
        let nilEntered = await CancellationCases.until { pause.withValue { $0.entered } }
        nilPath.watchdogQueue.sync { nilPath.physicalPathChanged(nil, epoch: nilPath.sessionAdmission.currentEpoch!) }
        let nilCancelled = await CancellationCases.until { pause.withValue { $0.cancelled } }
        try? await Task.sleep(nanoseconds: 150_000_000)
        let noDNSWhileMissing = Kernel.events.filter { $0 == "legacy-dns" }.count == 1 &&
            Kernel.events.filter { $0 == "Core-start" }.count == 1 && !Kernel.events.contains("terminal-cancel")
        nilPath.watchdogQueue.sync { nilPath.physicalPathChanged(TunnelEndpointPath(), epoch: nilPath.sessionAdmission.currentEpoch!) }
        let nilRecovered = await CancellationCases.until { Kernel.events.contains("health-initial-dns-correction") }
        record("nil-underlay-pauses-correction-without-DNS-and-restored-path-resolves-afresh", nilEntered && nilCancelled && noDNSWhileMissing && nilRecovered &&
            Kernel.legacyGenerations.count == 2 && Kernel.legacyGenerations[0] != Kernel.legacyGenerations[1] &&
            Kernel.events.filter { $0 == "Core-start" }.count == 2 && nilPath.recoveryFailures == 0)
        await stop(nilPath)

        Kernel.reset(); disabledOptions(); let unhealthy = Provider()
        try? await unhealthy.startTunnel(); try? await startCore(unhealthy)
        Kernel.rejectHealth = true; Kernel.discoveries.last!.removeSelected()
        let healthEnded = await CancellationCases.until { Kernel.events.contains("terminal-cancel") }
        record("current-correction-readiness-failure-terminates-instead-of-publishing-success", healthEnded &&
            Kernel.events.filter { $0 == "Core-start" }.count == 2 && Kernel.events.filter { $0 == "legacy-dns" }.count == 1 &&
            !unhealthy.forwardingReady && unhealthy.initialDiscoveryCorrection?.terminal == true && unhealthy.runtimeRecoveryInFlight)
        await stop(unhealthy)

        // No surviving candidate must end the provider rather than leave a
        // CONNECTED indication with an unavailable transport.
        Kernel.reset(); disabledOptions(); let unavailable = Provider()
        try? await unavailable.startTunnel(); try? await startCore(unavailable)
        Kernel.failure = "endpoint"
        Kernel.discoveries.last!.removeSelected()
        let ended = await CancellationCases.until { Kernel.events.contains("terminal-cancel") }
        record("failed-current-initial-DNS-correction-ends-tunnel-without-retry-authorization", ended &&
            Kernel.events.filter { $0 == "Core-start" }.count == 1 && !unavailable.forwardingReady &&
            unavailable.recoveryFailures == 0 && !unavailable.nativeOptions.reconnectEnabled)
        await stop(unavailable)

        // Once the original collection is sealed, an unrelated future event
        // cannot reopen its special admission budget.
        Kernel.reset(); disabledOptions(); let sealed = Provider()
        try? await sealed.startTunnel(); try? await startCore(sealed)
        Kernel.discoveries.last!.seal(); Kernel.discoveries.last!.removeSelected()
        sealed.watchdogQueue.sync {}
        record("sealed-DNS-does-not-authorize-later-automatic-reconnect", Kernel.events.filter { $0 == "Core-start" }.count == 1 &&
            sealed.initialDiscoveryCorrection == nil && !sealed.nativeOptions.reconnectEnabled)
        await stop(sealed)

        // A stale callback and atomic token refresh must not revoke a new plan.
        Kernel.reset(); let stale = Provider(); try? await stale.startTunnel()
        let oldGroup = Kernel.discoveries.last!, oldToken = stale.endpointAdmission.currentToken!
        stale.watchdogQueue.sync { stale.physicalPathChanged(TunnelEndpointPath(), epoch: stale.sessionAdmission.currentEpoch!) }
        let freshToken = stale.endpointAdmission.currentToken!
        oldGroup.removeSelected(includingStaleCallback: true)
        stale.watchdogQueue.sync {}
        var oldRejected = false
        do { _ = try stale.endpointAdmission.refresh(ifCurrent: oldToken) } catch { oldRejected = true }
        record("stale-DNS-callback-and-atomic-refresh-cannot-revoke-new-token", oldRejected && stale.endpointAdmission.currentToken == freshToken)
        await stop(stale)

        // Repeated invalidations after complete full-window preparation retain
        // the legacy three-admission cap; no bad replacement reaches Core.
        Kernel.reset(); disabledOptions(); let bounded = Provider()
        try? await bounded.startTunnel(); try? await startCore(bounded)
        Kernel.onCoreCheck = {
            bounded.watchdogQueue.sync { bounded.physicalPathChanged(TunnelEndpointPath(), epoch: bounded.sessionAdmission.currentEpoch!) }
        }
        Kernel.discoveries.last!.removeSelected()
        let boundedEnded = await CancellationCases.until { Kernel.events.contains("terminal-cancel") }
        record("initial-correction-has-three-full-preflight-admissions-and-no-unbounded-Core-retry", boundedEnded &&
            Kernel.events.filter { $0 == "legacy-dns" }.count == 3 && Kernel.events.filter { $0 == "Core-start" }.count == 1 &&
            bounded.recoveryFailures == 0 && !bounded.nativeOptions.reconnectEnabled)
        await stop(bounded)

        Kernel.reset(); disabledOptions(); let expired = Provider()
        try? await expired.startTunnel(); try? await startCore(expired)
        expired.invalidateStartupDiscovery(epoch: expired.sessionAdmission.currentEpoch!, token: expired.endpointAdmission.currentToken!,
                                            deadline: ProcessInfo.processInfo.systemUptime - 1)
        let expiredEnded = await CancellationCases.until { Kernel.events.contains("terminal-cancel") }
        record("expired-original-discovery-deadline-admits-no-new-DNS-or-Core", expiredEnded &&
            !Kernel.events.contains("legacy-dns") && Kernel.events.filter { $0 == "Core-start" }.count == 1)
        await stop(expired)

        // Stop must cancel a silent full-window correction child promptly.
        Kernel.reset(); disabledOptions(); let dnsStop = Provider()
        try? await dnsStop.startTunnel(); try? await startCore(dnsStop)
        let silent = FixtureState((entered: false, cancelled: false))
        Kernel.onLegacyResolve = {
            silent.withValue { $0.entered = true }
            do { try await Task.sleep(nanoseconds: 2_000_000_000) }
            catch { silent.withValue { $0.cancelled = true }; throw error }
        }
        Kernel.discoveries.last!.removeSelected()
        let silentEntered = await CancellationCases.until { silent.withValue { $0.entered } }
        let silentParent = dnsStop.watchdogQueue.sync { dnsStop.initialDiscoveryCorrection?.task }
        let stopBegan = ProcessInfo.processInfo.systemUptime
        await stop(dnsStop); await silentParent?.value
        record("Stop-cancels-initial-correction-parent-and-silent-DNS-child", silentEntered &&
            ProcessInfo.processInfo.systemUptime - stopBegan < 0.5 && silent.withValue { $0.cancelled } &&
            Kernel.events.filter { $0 == "Core-start" }.count == 1 && !Kernel.events.contains("terminal-cancel") &&
            dnsStop.startupPreparation == nil && dnsStop.initialDiscoveryCorrection == nil)

        // An un-cancellable OS settings write remains FIFO-owned across Stop
        // and a new session. Its old correction parent cannot publish or cancel
        // the replacement provider when that callback finally returns.
        final class HeldSettings: @unchecked Sendable {
            private let state = FixtureState((entered: false, continuation: Optional<CheckedContinuation<Void, Never>>.none))
            func wait() async {
                await withCheckedContinuation { value in state.withValue { $0.entered = true; $0.continuation = value } }
            }
            var entered: Bool { state.withValue { $0.entered } }
            func release() { let next = state.withValue { value -> CheckedContinuation<Void, Never>? in let c = value.continuation; value.continuation = nil; return c }; next?.resume() }
        }
        Kernel.reset(); disabledOptions(); let replaced = Provider(), settings = HeldSettings()
        try? await replaced.startTunnel(); try? await startCore(replaced)
        let obsoleteGroup = Kernel.discoveries.last!
        Kernel.preparedAddresses = ["192.0.2.2"]
        Kernel.onSettings = { await settings.wait() }
        obsoleteGroup.removeSelected()
        let settingsEntered = await CancellationCases.until { settings.entered }
        let obsoleteParent = replaced.watchdogQueue.sync { replaced.initialDiscoveryCorrection?.task }
        await stop(replaced)
        Kernel.onSettings = nil
        let nextStart = Task.detached { try await replaced.startTunnel() }
        let nextPrepared = await CancellationCases.until { Kernel.events.filter { $0 == "prepare" }.count == 3 }
        let stillOneCore = Kernel.events.filter { $0 == "Core-start" }.count == 1
        settings.release(); await obsoleteParent?.value
        var nextSucceeded = false
        do { try await nextStart.value; try await startCore(replaced); nextSucceeded = true } catch {}
        let nextToken = replaced.endpointAdmission.currentToken
        obsoleteGroup.removeSelected(includingStaleCallback: true)
        replaced.watchdogQueue.sync {}
        record("Stop-newStart-held-correction-settings-cannot-start-or-cancel-stale-owner", settingsEntered && nextPrepared && stillOneCore && nextSucceeded &&
            Kernel.events.filter { $0 == "Core-start" }.count == 2 && !Kernel.events.contains("terminal-cancel") &&
            replaced.endpointAdmission.currentToken == nextToken && replaced.startupDiscovery?.token == nextToken &&
            replaced.initialDiscoveryCorrection == nil)
        await stop(replaced)
        return checks
    }
}

@main struct Main {
    static func main() async {
        setbuf(stdout, nil)
        var failures = 0, cases = 0
        func check(_ name: String, _ value: Bool) { cases += 1; if !value { failures += 1 }; print("APPLE_COLD_START_CASE=" + name + ";PASS=" + String(value)) }
        for (name, passed) in await CancellationCases.run() { check(name, passed) }
        for (name, passed) in await InitialDiscoveryCases.run() { check(name, passed) }
        for failure in ["endpoint", "config", "core"] {
            Kernel.reset(failure: failure); let provider = Provider()
            do { try await provider.startTunnel(); check("refusal-" + failure, false) }
            catch { check("refusal-" + failure, !Kernel.profile.isOnDemandEnabled && !Kernel.events.contains("arm") && !Kernel.events.contains("runtime-admission")) }
        }
        Kernel.reset(); Kernel.bindingCapability = 0
        do { try await Provider().startTunnel(); check("stock-runtime-binding-capability-refused", false) }
        catch { check("stock-runtime-binding-capability-refused", !Kernel.events.contains("settings") && !Kernel.events.contains("arm") && !Kernel.events.contains("runtime-admission")) }
        for capability: Int64 in [0, 2, 1] {
            Kernel.reset(); Kernel.bindingCapability = capability; Kernel.dnsOnly = true
            Kernel.preparedData = Data(#"{"outbounds":[{"protocol":"blackhole"},{"protocol":"freedom","streamSettings":{"sockopt":{"interface":"en0"}}}]}"#.utf8)
            do {
                try await Provider().startTunnel()
                check("DNS-only-binding-capability-\(capability)", capability == 1 && Kernel.events.contains("check") && Kernel.events.contains("runtime-admission"))
            } catch {
                check("DNS-only-binding-capability-\(capability)", capability != 1 && !Kernel.events.contains("check") && !Kernel.events.contains("settings") && !Kernel.events.contains("arm") && !Kernel.events.contains("runtime-admission"))
            }
        }
        Kernel.reset(); let changedDuringLookup = Provider()
        Kernel.onPrepare = {
            Kernel.onPrepare = nil
            _ = try? changedDuringLookup.endpointAdmission.refresh(changedDuringLookup.sessionAdmission.currentEpoch!)
        }
        do { try await changedDuringLookup.startTunnel()
            check("initial-path-replaced-reprepares", Kernel.events.filter { $0 == "prepare" }.count == 2 && Kernel.events.filter { $0 == "runtime-admission" }.count == 1)
        } catch { check("initial-path-replaced-reprepares", false) }
        Kernel.reset(); let ownSettings = Provider()
        let ownSettingsCallback = FixtureState((queued: false, applied: false))
        Kernel.onSettings = {
            Kernel.onSettings = nil
            let previous = ownSettings.watchdogQueue.sync {
                let token = ownSettings.endpointAdmission.currentToken
                ownSettings.pathObserver?.onChange?(TunnelEndpointPath())
                // The observer only enqueues work: returning from its callback
                // does not mean that the provider has handled the path event.
                ownSettingsCallback.withValue { $0.queued = token != nil && ownSettings.endpointAdmission.currentToken == token }
                return token
            }
            // This case models a path event DURING the settings write. Drain
            // that exact FIFO event before the mocked OS completes the write.
            ownSettings.watchdogQueue.sync {
                ownSettingsCallback.withValue { $0.applied = previous != nil && ownSettings.endpointAdmission.currentToken != previous }
            }
        }
        func ownSettingsResult(started: Bool) -> Bool {
            let events = Kernel.events, callback = ownSettingsCallback.withValue { $0 }
            let prepares = events.filter { $0 == "prepare" }.count, settings = events.filter { $0 == "settings" }.count
            let arms = events.filter { $0 == "arm" }.count, admissions = events.filter { $0 == "runtime-admission" }.count
            let passed = started && callback.queued && callback.applied && prepares == 2 && settings == 1 && arms == 1 && admissions == 1
            if !passed {
                print("APPLE_COLD_START_DIAGNOSTIC=own-settings-event-reprepares-without-second-write;started=\(started);callbackQueued=\(callback.queued);pathAppliedBeforeSettingsReturn=\(callback.applied);prepare=\(prepares);settings=\(settings);arm=\(arms);runtime-admission=\(admissions);events=\(events.joined(separator: ","))")
            }
            return passed
        }
        do { try await ownSettings.startTunnel()
            check("own-settings-event-reprepares-without-second-write", ownSettingsResult(started: true))
        } catch {
            print("APPLE_COLD_START_ERROR=own-settings-event-reprepares-without-second-write;type=\(String(reflecting: type(of: error)))")
            check("own-settings-event-reprepares-without-second-write", ownSettingsResult(started: false))
        }
        Kernel.reset(); try? await Provider().startTunnel()
        let order = Kernel.events
        check("arm-after-settings-before-admission", Kernel.profile.isOnDemandEnabled && order.firstIndex(of: "settings")! < order.firstIndex(of: "arm")! && order.firstIndex(of: "arm")! < order.firstIndex(of: "runtime-admission")!)
        Kernel.reset(armed: true, failure: "endpoint"); do { try await Provider().startTunnel() } catch {}
        check("established-recovery-preserved", Kernel.profile.isOnDemandEnabled && !Kernel.events.contains("disarm"))
        Kernel.reset(); (Kernel.profile.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration?["options"] = ["reconnect": ["enabled": false], "protection": ["onDemand": "disabled"]]
        try? await Provider().startTunnel()
        check("disabled-never-arms", !Kernel.profile.isOnDemandEnabled && !Kernel.events.contains("arm") && Kernel.events.contains("runtime-admission"))
        // Exercise actual Stop and two actual startTunnel entries on ONE provider.
        // The fake OS stores the old write until its callback is explicitly released.
        final class SettingsGate: @unchecked Sendable {
            let entered = DispatchSemaphore(value: 0)
            private let lock = NSLock()
            private var continuation: CheckedContinuation<Void, Never>?
            private var released = false
            func wait() async {
                await withCheckedContinuation { next in
                    lock.lock()
                    precondition(continuation == nil, "Only one controlled settings write may wait")
                    if released { lock.unlock(); next.resume() }
                    else { continuation = next; lock.unlock() }
                    entered.signal()
                }
            }
            func release() {
                lock.lock(); released = true
                let pending = continuation; continuation = nil; lock.unlock()
                pending?.resume()
            }
        }
        Kernel.reset(); let overlap = Provider(), gate = SettingsGate()
        Kernel.onSettings = { await gate.wait() }
        let oldStart = Task.detached { try await overlap.startTunnel() }
        precondition(gate.entered.wait(timeout: .now() + 3) == .success)
        await withCheckedContinuation { done in overlap.stopTunnel(with: .providerFailed) { done.resume() } }
        Kernel.onSettings = nil
        let newStart = Task.detached { try await overlap.startTunnel() }
        for _ in 0..<1000 {
            if Kernel.events.filter({ $0 == "prepare" }).count == 2 { break }
            await Task.yield()
        }
        let oldStillOwnsSettingsSlot = Kernel.events.filter { $0 == "settings" }.count == 1 && !Kernel.events.contains("runtime-admission")
        gate.release()
        var oldCancelled = false, newSucceeded = false
        do { try await oldStart.value } catch { oldCancelled = error is CancellationError }
        do { try await newStart.value; newSucceeded = true } catch {}
        check("Stop-newStart-settings-complete-FIFO", oldStillOwnsSettingsSlot && oldCancelled && newSucceeded &&
            Kernel.events.filter { $0 == "settings" }.count == 2 && Kernel.events.filter { $0 == "runtime-admission" }.count == 1 &&
            Kernel.events.filter { $0 == "arm" }.count == 1 && !Kernel.events.contains("clear-settings"))
        #if ARM_RECEIPT_TESTS
        Kernel.reset(); Kernel.refreshFailures = 1
        do { try await Provider().startTunnel(); check("late-arm-readback-failure", false) }
        catch { check("late-arm-readback-failure", !Kernel.profile.isOnDemandEnabled && Kernel.events.contains("arm") && Kernel.events.contains("disarm") && !Kernel.events.contains("runtime-admission")) }
        Kernel.reset(); let stopped = Provider(); Kernel.onArm = { _ = stopped.sessionAdmission.revoke() }
        do { try await stopped.startTunnel(); check("stop-after-late-arm", false) }
        catch { check("stop-after-late-arm", !Kernel.profile.isOnDemandEnabled && Kernel.events.contains("disarm") && !Kernel.events.contains("runtime-admission")) }
        Kernel.reset(); let replaced = Provider(); Kernel.onArm = { _ = replaced.sessionAdmission.begin() }
        do { try await replaced.startTunnel(); check("new-epoch-same-reference-preserved", false) }
        catch { check("new-epoch-same-reference-preserved", Kernel.profile.isOnDemandEnabled && !Kernel.events.contains("disarm") && !Kernel.events.contains("runtime-admission")) }

        func failure(_ result: Result<TunnelOnDemandPolicy.Outcome, Error>, _ expected: TunnelOnDemandPolicy.Failure) -> Bool {
            guard case .failure(let error) = result else { return false }; return error as? TunnelOnDemandPolicy.Failure == expected
        }
        func arm(_ config: NETunnelProviderProtocol, _ receipt: TunnelOnDemandPolicy.StartArmingReceipt,
                 _ preferences: TunnelOnDemandPolicy.Preferences) async -> Result<TunnelOnDemandPolicy.Outcome, Error> {
            await withCheckedContinuation { continuation in
                TunnelOnDemandPolicy.enableForStart(configuration: config, armingReceipt: receipt,
                    preferences: preferences, timeout: 0.02) { continuation.resume(returning: $0) }
            }
        }
        func rollback(_ config: NETunnelProviderProtocol, _ receipt: TunnelOnDemandPolicy.StartArmingReceipt,
                      _ preferences: TunnelOnDemandPolicy.Preferences, cancelled: @escaping () -> Bool = { false }) async -> Result<TunnelOnDemandPolicy.Outcome, Error> {
            await withCheckedContinuation { continuation in
                TunnelOnDemandPolicy.rollbackFailedStart(configuration: config, armingReceipt: receipt,
                    preferences: preferences, timeout: 0.02, isCancelled: cancelled) { continuation.resume(returning: $0) }
            }
        }
        // The persisted profile is NOT the mutable object passed into save.
        // Pending writes capture their own immutable snapshot and may commit late.
        final class Store {
            var stored = NETunnelProviderManager(), loads = 0, saves = 0
            var pending: NETunnelProviderManager?, saved: ((Error?) -> Void)?
            var hold = false, saveError = false, refreshError = false, rearmRefresh = false
            var preferences: TunnelOnDemandPolicy.Preferences {
                .init(load: { self.loads += 1; $0([self.stored.copy()], nil) },
                    save: { manager, done in
                        self.saves += 1
                        let snapshot = manager.copy()
                        if self.hold { self.pending = snapshot; self.saved = done }
                        else if self.saveError { self.pending = snapshot; done(NSError(domain: "fixture.save", code: 1)) }
                        else { self.stored = snapshot; done(nil) }
                    }, refresh: { manager, done in
                        if self.refreshError { done(NSError(domain: "fixture.refresh", code: 1)); return }
                        if self.rearmRefresh { manager.isOnDemandEnabled = true; manager.onDemandRules = [NEOnDemandRuleConnect()] }
                        else { manager.isOnDemandEnabled = self.stored.isOnDemandEnabled; manager.onDemandRules = self.stored.onDemandRules }
                        done(nil)
                    })
            }
            var configuration: NETunnelProviderProtocol { stored.protocolConfiguration as! NETunnelProviderProtocol }
            func commitPending() { stored = pending!.copy(); pending = nil; saved?(nil); saved = nil }
        }
        let normal = Store(), normalReceipt = try! TunnelOnDemandPolicy.StartArmingReceipt(configuration: Store().configuration)
        let normalConfig = normal.configuration
        _ = await arm(normalConfig, normalReceipt, normal.preferences)
        let restored = await rollback(normalConfig, normalReceipt, normal.preferences)
        check("settled-exact-arm-rolls-back", (try? restored.get()) == .updated && !normal.stored.isOnDemandEnabled && normal.saves == 2 && normal.stored.isEnabled)
        let inherited = Store(); inherited.stored.isOnDemandEnabled = true; inherited.stored.onDemandRules = [NEOnDemandRuleConnect()]
        let inheritedConfig = inherited.configuration, inheritedReceipt = try! TunnelOnDemandPolicy.StartArmingReceipt(configuration: inherited.configuration)
        _ = await arm(inheritedConfig, inheritedReceipt, inherited.preferences)
        let retained = await rollback(inheritedConfig, inheritedReceipt, inherited.preferences)
        check("already-armed-recovery-not-owned", (try? retained.get()) == .unchanged && inherited.stored.isOnDemandEnabled && inherited.saves == 0)
        let pending = Store(); pending.hold = true
        let pendingConfig = pending.configuration, pendingReceipt = try! TunnelOnDemandPolicy.StartArmingReceipt(configuration: pending.configuration)
        let pendingResult = await arm(pendingConfig, pendingReceipt, pending.preferences)
        let loadsBefore = pending.loads
        let uncertain = await rollback(pendingConfig, pendingReceipt, pending.preferences)
        let earlyOFF = !pending.stored.isOnDemandEnabled
        pending.commitPending(); try? await Task.sleep(nanoseconds: 5_000_000)
        check("pending-save-early-OFF-is-not-cleanup", failure(pendingResult, .timedOut) && failure(uncertain, .cleanupUncertain) && pending.loads == loadsBefore && earlyOFF && pending.stored.isOnDemandEnabled && pending.saves == 1)
        let saveError = Store(); saveError.saveError = true
        let saveConfig = saveError.configuration, saveReceipt = try! TunnelOnDemandPolicy.StartArmingReceipt(configuration: saveError.configuration)
        _ = await arm(saveConfig, saveReceipt, saveError.preferences)
        let saveCleanup = await rollback(saveConfig, saveReceipt, saveError.preferences)
        saveError.commitPending()
        check("uncertain-save-error-not-cleanup", failure(saveCleanup, .cleanupUncertain) && saveError.stored.isOnDemandEnabled && saveError.saves == 1)
        let changed = Store(), changedReceipt = try! TunnelOnDemandPolicy.StartArmingReceipt(configuration: Store().configuration)
        let changedConfig = changed.configuration; _ = await arm(changedConfig, changedReceipt, changed.preferences)
        let other = NETunnelProviderProtocol(); other.providerConfiguration?["xrayConfigReference"] = Data([2]); changed.stored.protocolConfiguration = other
        let changedCleanup = await rollback(changedConfig, changedReceipt, changed.preferences)
        check("replacement-reference-not-disabled", failure(changedCleanup, .profileChanged) && changed.stored.isOnDemandEnabled && changed.saves == 1)
        let cancelled = Store(), cancelledReceipt = try! TunnelOnDemandPolicy.StartArmingReceipt(configuration: Store().configuration)
        let cancelledConfig = cancelled.configuration; _ = await arm(cancelledConfig, cancelledReceipt, cancelled.preferences)
        let cancelCleanup = await rollback(cancelledConfig, cancelledReceipt, cancelled.preferences, cancelled: { true })
        check("new-owner-cancels-rollback", failure(cancelCleanup, .cancelled) && cancelled.stored.isOnDemandEnabled && cancelled.saves == 1)
        let unreadable = Store(), unreadableReceipt = try! TunnelOnDemandPolicy.StartArmingReceipt(configuration: Store().configuration)
        let unreadableConfig = unreadable.configuration; _ = await arm(unreadableConfig, unreadableReceipt, unreadable.preferences)
        unreadable.rearmRefresh = true
        let unverified = await rollback(unreadableConfig, unreadableReceipt, unreadable.preferences)
        check("rollback-readback-must-prove-OFF", failure(unverified, .verificationFailed) && unreadable.saves == 2)
        let broken = Store(), brokenReceipt = try! TunnelOnDemandPolicy.StartArmingReceipt(configuration: Store().configuration)
        let brokenConfig = broken.configuration; _ = await arm(brokenConfig, brokenReceipt, broken.preferences)
        broken.refreshError = true
        let brokenCleanup = await rollback(brokenConfig, brokenReceipt, broken.preferences)
        check("rollback-readback-error-not-ACK", (try? brokenCleanup.get()) == nil && broken.saves == 2)
        #endif
        print("APPLE_COLD_START_CASES=" + String(cases)); print("APPLE_COLD_START_FAILURES=" + String(failures)); exit(failures == 0 ? 0 : 7)
    }
}

func FLVlessCoreGeodataLifetimeCapability() -> Int64 { 1 }
func FLVlessCoreXdriveLifetimeCapability() -> Int64 { 2 }
