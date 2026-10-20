import Foundation

// SDK/Core/HEV boundaries are in memory. The runner inserts actual provider
// methods below; no Xray, HEV, NetworkExtension, socket or resolver is linked.
typealias NativeDiagnosticMessage = String
struct LocalProxyCredentials {}
struct NativeRoutingIntent {}
struct XrayEnvironmentSnapshot {}
struct FixtureEnvelope { let configurationData: Data, metadataData: Data }
struct TunnelEndpointPath: Equatable {
    var generation: UInt64 = 0
    var interfaceIndex: UInt32 = 1
    func rebased(generation: UInt64) -> Self { Self(generation: generation, interfaceIndex: interfaceIndex) }
}
struct TunnelEndpointCandidate {
    var expiry: TimeInterval? = nil
    var singleAttempt = false
    var isSingleAttemptOnly: Bool { singleAttempt }
    func isUsable(on path: TunnelEndpointPath, at now: TimeInterval, allowFreshZeroTTL: Bool) -> Bool {
        expiry.map { now < $0 || (singleAttempt && allowFreshZeroTTL) } ?? true
    }
}
struct TunnelEndpointCandidates { let path: TunnelEndpointPath }
struct TunnelEndpointSelection { let candidates: TunnelEndpointCandidates; let selected: TunnelEndpointCandidate }
struct TunnelPreparedConfig {
    var data = Data(), bootstrapAddresses = ["192.0.2.1"]
    var routingEnvelope: FixtureEnvelope? = nil
    var endpointPath: TunnelEndpointPath? = TunnelEndpointPath()
    var endpointSelections: [TunnelEndpointSelection] = []
}
final class TunnelPhysicalPathObserver {
    var onChange: ((TunnelEndpointPath?) -> Void)?
    func cancel() {}
}
struct FixtureOptions {
    var retries = 0
    var reconnectEnabled = true
    func mayRetry(failures: Int) -> Bool { reconnectEnabled && failures < retries }
    func retryDelay(failures: Int) -> TimeInterval { 0 }
}
typealias VlessNativeOptions = FixtureOptions
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
struct FixtureLogger {
    func info(_ message: FixtureMessage) {}
    func warning(_ message: FixtureMessage) {}
}
let tunnelLog = FixtureLogger()
let hevShutdownTimeoutSeconds: TimeInterval = 0.05
let watchdogIntervalSeconds: TimeInterval = 60
final class FixtureLog: @unchecked Sendable {
    static let shared = FixtureLog()
    private let lock = NSLock()
    private var lines: [String] = []
    func append(_ line: String) { lock.lock(); defer { lock.unlock() }; lines.append(line) }
    func count(_ line: String) -> Int { lock.lock(); defer { lock.unlock() }; return lines.filter { $0 == line }.count }
}
func rememberTunnelLog(_ message: String) { FixtureLog.shared.append(message) }
class NEVPNProtocol {}
final class NETunnelProviderProtocol: NEVPNProtocol {}
struct NEProviderStopReason { let rawValue: Int }
enum TunnelOnDemandPolicy {
    enum Outcome { case preservedForRecovery, disabled }
    static func disableForUserStop(reason: NEProviderStopReason, configuration: NETunnelProviderProtocol,
                                  completion: (Result<Outcome, Error>) -> Void) { completion(.success(.disabled)) }
}
final class FixtureTimer {
    var event: (() -> Void)?
    var cancelled = false
    func schedule(deadline: DispatchTime, repeating: TimeInterval, leeway: DispatchTimeInterval) {}
    func setEventHandler(handler: @escaping () -> Void) { event = handler }
    func resume() {}
    func cancel() { cancelled = true }
}
typealias DispatchSourceTimer = FixtureTimer
enum DispatchSource {
    static func makeTimerSource(queue: DispatchQueue) -> FixtureTimer { FixtureTimer() }
}
struct FixturePath { enum Status { case satisfied }; let status = Status.satisfied }
final class NWPathMonitor {
    var pathUpdateHandler: ((FixturePath) -> Void)?
    func start(queue: DispatchQueue) {}
    func cancel() {}
}
final class TunnelPacketBridge {
    func pause() {}
    func shutdown() {}
}
enum FixtureSleep {
    static var hold = false
    static var delays: [UInt64] = []
    static func sleep(nanoseconds: UInt64) async throws {
        delays.append(nanoseconds)
        if hold { try await Task.sleep(nanoseconds: 10_000_000_000) }
        else { await Task.yield(); try Task.checkCancellation() }
    }
}
final class FixtureAsyncGate: @unchecked Sendable {
    let entered = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?
    func wait() async {
        await withCheckedContinuation { value in
            lock.lock(); continuation = value; lock.unlock(); entered.signal()
        }
    }
    func release() { lock.lock(); let value = continuation; continuation = nil; lock.unlock(); value?.resume() }
    func waitUntilEntered(timeout: TimeInterval) -> Bool { entered.wait(timeout: .now() + timeout) == .success }
}
enum SyntheticFailure: Error { case core }
enum TunnelXrayConfigPreparer { enum StartupError: Error { case invalidConfiguration } }

// Records production scheduling without sleeping or invoking native work.
// One control holds delayed callbacks to prove drain refusal cannot hot-loop.
final class FixtureRuntimeQueue: @unchecked Sendable {
    private let queue = DispatchQueue(label: "fixture.runtime")
    private let lock = NSLock()
    var holdDelayed = false
    private var delays: [TimeInterval] = []
    private var held: [@Sendable () -> Void] = []
    func async(execute work: @escaping @Sendable () -> Void) { queue.async(execute: work) }
    func sync<T>(execute work: () throws -> T) rethrows -> T { try queue.sync(execute: work) }
    func asyncAfter(deadline: DispatchTime, execute work: @escaping @Sendable () -> Void) {
        let now = DispatchTime.now().uptimeNanoseconds
        let delay = deadline.uptimeNanoseconds > now ? Double(deadline.uptimeNanoseconds - now) / 1e9 : 0
        lock.lock()
        delays.append(delay)
        let hold = holdDelayed && delay > 0.5
        if hold { held.append(work) }
        lock.unlock()
        if !hold { queue.async(execute: work) }
    }
    func scheduledDelays() -> [TimeInterval] { lock.lock(); defer { lock.unlock() }; return delays }
    func releaseHeld() {
        lock.lock(); let work = held; held.removeAll(); lock.unlock()
        for callback in work { queue.async(execute: callback) }
    }
}

final class FixtureProvider: @unchecked Sendable {
    let watchdogQueue = DispatchQueue(label: "fixture.watchdog")
    let runtimeQueue = FixtureRuntimeQueue()
    let sessionAdmission = TunnelSessionAdmission()
    let forwardingLock = NSLock()
    var forwardingReady = false, reasserting = false
    var forwardingEpoch: TunnelSessionAdmission.Epoch?
    var startupPreparation: (epoch: TunnelSessionAdmission.Epoch, task: Task<TunnelPreparedConfig, Error>)?
    var protocolConfiguration: NEVPNProtocol?
    var watchdogTimer: DispatchSourceTimer?, pathObserver: TunnelPhysicalPathObserver?
    let endpointAdmission = TunnelEndpointPlanAdmission(), endpointCommitQueue = TunnelEndpointCommitQueue()
    var installedSettingsKey: ProtectedSettingsKey?
    var runtimeSource: RuntimeSource?, physicalPath: TunnelEndpointPath?
    var observedPhysicalPath = true
    var selectedAttempt: UInt64 = 0
    var endpointPreparation: (token: TunnelEndpointPlanAdmission.Token, task: Task<Void, Never>)?
    var lastEndpointHealthCheck: Date = .distantPast
    var watchdogPolicy = TunnelWatchdogFailurePolicy(failureThreshold: 3)
    var watchdogSuspended = false, watchdogInboundHealthy = false
    var watchdogInboundPort: Int?, recoveryCheck: DispatchWorkItem?
    var runtimeSpec: RuntimeSpec?
    var runtimeRecoveryInFlight = false, recoveryExhausted = false
    var initialRuntimeAttempted = false {
        didSet {
            if initialRuntimeAttempted && !oldValue {
                let hook = attemptAdmissionHook; attemptAdmissionHook = nil
                hook?()
            }
        }
    }
    var recoveryFailures = 0, nativeOptions = FixtureOptions()
    var hasStartedHEV = false, hevStopSignal: DispatchGroup?
    let hevLifecycle = TunnelProcessLifecycle()
    var nativeRuntimeEpoch: TunnelSessionAdmission.Epoch?
    var nativeRuntimeToken: TunnelEndpointPlanAdmission.Token?
    var packetBridge: TunnelPacketBridge?, packetBridgeEpoch: TunnelSessionAdmission.Epoch?
    var packetBridgeToken: TunnelEndpointPlanAdmission.Token?
    var hevLogURL: URL?
    // Read counters only after their owner queue is drained.
    var coreStarts = 0, workerStarts = 0, coreStops = 0, healthChecks = 0
    var startedPairs: [(Data, Data?)] = []
    var drainHook: (() -> Void)?, coreHook: (() -> Void)?, workerHook: (() -> Void)?
    var attemptAdmissionHook: (() -> Void)?
    var rejectCore = false, rejectHealth = false, rejectWorkerStop = false
    var inboundHealthHook: (() -> Void)?, connectHealthHook: (() -> Void)?
    var connectHealthChecks = 0, httpHealthChecks = 0
    func startXRay(xrayConfig: Data, geoAssetsDirectory: String?, routingMetadata: Data? = nil) throws {
        coreStarts += 1
        startedPairs.append((xrayConfig, routingMetadata))
        coreHook?()
        if rejectCore { throw SyntheticFailure.core }
    }
    func startSocks5Tunnel(serverPort: Int, credentials: LocalProxyCredentials, epoch: TunnelSessionAdmission.Epoch, token: TunnelEndpointPlanAdmission.Token) throws {
        workerStarts += 1
        hasStartedHEV = true
        hevLifecycle.beginStart(); hevLifecycle.markThreadEntered()
        workerHook?()
    }
    func stopXRay() {
        coreStops += 1
        let hook = drainHook; drainHook = nil
        hook?()
    }
    func requestHEVStop() {
        _ = hevLifecycle.requestStop()
        if !rejectWorkerStop { hevLifecycle.markExited(code: 0) }
    }
    func socksInboundHealthCheck(port: Int, credentials: LocalProxyCredentials, budget: LocalProxyIOBudget) -> String {
        healthChecks += 1; inboundHealthHook?()
        return rejectHealth ? "fixture unavailable" : "ok"
    }
    func socksConnectHealthCheck(port: Int, credentials: LocalProxyCredentials, budget: LocalProxyIOBudget) -> String {
        connectHealthChecks += 1; connectHealthHook?(); return "ok"
    }
    func socksHTTPHealthCheck(port: Int, credentials: LocalProxyCredentials, budget: LocalProxyIOBudget) -> String {
        httpHealthChecks += 1; return "ok"
    }
    var originalPreparationInputs: [Data] = []
    var preparationHook: (() async throws -> Void)?
    var preflightHook: (() throws -> Void)?
    var settingsHook: (() async throws -> Void)?
    var settingGenerations: [UInt64] = []
    var rejectPreparation = false, rejectPreflight = false
    var preparationExpiry: TimeInterval?
    var preparationAddresses = ["192.0.2.1"]
    func prepareEndpointConfig(_ source: RuntimeSource, token: TunnelEndpointPlanAdmission.Token, path: TunnelEndpointPath, attempt: UInt64) async throws -> TunnelPreparedConfig {
        originalPreparationInputs.append(source.config)
        try await preparationHook?()
        if rejectPreparation { throw SyntheticFailure.core }
        guard sessionAdmission.isCurrent(source.epoch), endpointAdmission.isCurrent(token) else { throw CancellationError() }
        let data = source.config + Data("-generated-\(attempt)".utf8)
        return TunnelPreparedConfig(data: data, bootstrapAddresses: preparationAddresses,
            routingEnvelope: FixtureEnvelope(configurationData: data, metadataData: data + Data("-metadata".utf8)),
            endpointPath: path,
            endpointSelections: preparationExpiry.map { [TunnelEndpointSelection(candidates: TunnelEndpointCandidates(path: path), selected: TunnelEndpointCandidate(expiry: $0))] } ?? [])
    }
    func tunnelError(_ message: String) -> NSError { NSError(domain: "fixture", code: 1) }
    func parseConfig(jsonData: Data) -> (inboundPort: Int, unused: Int)? { (10808, 0) }
    func checkEndpointPreflight(_ spec: RuntimeSpec, prepared: TunnelPreparedConfig, source: RuntimeSource) throws {
        try preflightHook?()
        if rejectPreflight { throw SyntheticFailure.core }
        guard sessionAdmission.isCurrent(spec.epoch), endpointAdmission.isCurrent(spec.token), spec.isFresh() else { throw CancellationError() }
    }
    func protectedNetworkSettings(_ spec: RuntimeSpec) -> UInt64 { spec.token.generation }
    func setTunnelNetworkSettings(_ generation: UInt64) async throws {
        settingGenerations.append(generation)
        try await settingsHook?()
    }
    // SOURCE_PROVIDER_METHODS
    func spec(_ epoch: TunnelSessionAdmission.Epoch, options: FixtureOptions = FixtureOptions(), config: Data = Data("original-source".utf8)) -> RuntimeSpec {
        let token = try! endpointAdmission.begin(epoch)
        let path = TunnelEndpointPath(generation: token.generation)
        let source = RuntimeSource(epoch: epoch, config: config, options: options, routingIntent: nil,
            credentials: LocalProxyCredentials(), geoAssetsDirectory: nil, environment: XrayEnvironmentSnapshot())
        runtimeSource = source; physicalPath = path; pathObserver = TunnelPhysicalPathObserver()
        pathObserver?.onChange = { [weak self] path in self?.physicalPathChanged(path, epoch: epoch) }
        let bytes = config + Data("-generated-0".utf8)
        let prepared = TunnelPreparedConfig(data: bytes,
            routingEnvelope: FixtureEnvelope(configurationData: bytes, metadataData: bytes + Data("-metadata".utf8)), endpointPath: path)
        precondition(endpointAdmission.commit(token))
        return RuntimeSpec(source: source, prepared: prepared, token: token, path: path, port: 10808)
    }
    func begin(options: FixtureOptions = FixtureOptions()) -> RuntimeSpec {
        let epoch = sessionAdmission.begin()
        setForwardingReady(false, epoch: epoch)
        let value = spec(epoch, options: options)
        installedSettingsKey = ProtectedSettingsKey(value)
        precondition(startTunnelWatchdog(value))
        return value
    }
    func recover(_ epoch: TunnelSessionAdmission.Epoch) {
        watchdogQueue.sync { scheduleNativeRecovery(after: 0, epoch: epoch) }
    }
    func waitUntil(_ predicate: () -> Bool) {
        for _ in 0..<1000 {
            if predicate() { return }
            Thread.sleep(forTimeInterval: 0.002)
        }
        precondition(predicate(), "bounded fake callback did not arrive")
    }
    func flushAsync() async {
        for _ in 0..<1000 {
            watchdogQueue.sync {}; runtimeQueue.sync {}; watchdogQueue.sync {}
            await Task.yield()
            if watchdogQueue.sync(execute: { !runtimeRecoveryInFlight }) { return }
        }
        precondition(!runtimeRecoveryInFlight, "bounded asynchronous transition did not settle")
    }
    func flush() {
        for _ in 0..<200 {
            watchdogQueue.sync {}; runtimeQueue.sync {}; watchdogQueue.sync {}
            if watchdogQueue.sync(execute: { !runtimeRecoveryInFlight }) { return }
            Thread.sleep(forTimeInterval: 0.002)
        }
    }
    func stop() async {
        await withCheckedContinuation { continuation in
            stopTunnel(with: NEProviderStopReason(rawValue: 1)) { continuation.resume() }
        }
    }
}

@main struct Probe {
    static func main() async {
        setbuf(stdout, nil)
        // Actual recovery code passes its first check, then the fake native
        // drain blocks. Stop must return from revocation without that queue.
        let duringDrain = FixtureProvider(), spec = duringDrain.begin()
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        duringDrain.drainHook = { entered.signal(); precondition(release.wait(timeout: .now() + 3) == .success) }
        let oldTimer = duringDrain.watchdogTimer?.event
        let oldPath = duringDrain.pathObserver?.onChange
        duringDrain.watchdogQueue.sync { duringDrain.scheduleRecoveryCheck(epoch: spec.epoch) }
        let oldCheck = duringDrain.recoveryCheck
        duringDrain.recover(spec.epoch)
        precondition(entered.wait(timeout: .now() + 3) == .success)
        await withCheckedContinuation { continuation in
            duringDrain.stopTunnel(with: NEProviderStopReason(rawValue: 1)) { continuation.resume() }
            precondition(!duringDrain.sessionAdmission.isCurrent(spec.epoch), "Stop revocation must not await native drain")
            release.signal()
        }
        duringDrain.flush()
        precondition(duringDrain.coreStarts == 0 && duringDrain.workerStarts == 0)
        duringDrain.wake()
        duringDrain.watchdogQueue.sync {
            oldTimer?(); oldPath?(TunnelEndpointPath()); oldCheck?.perform()
            duringDrain.scheduleTunnelHealthCheck(trigger: "late", after: 0, epoch: spec.epoch)
        }
        duringDrain.reportTerminalFailure("late worker failure", code: 1, epoch: spec.epoch)
        precondition(!duringDrain.startTunnelWatchdog(spec), "Late startup completion must not rearm Stop")
        duringDrain.flush()
        precondition(duringDrain.coreStarts == 0 && duringDrain.workerStarts == 0 && duringDrain.healthChecks == 0)
        precondition(!duringDrain.isForwardingReady() && duringDrain.watchdogSuspended)
        print("PASS Stop during drain + late wake/failure/timer/path/recovery/startup completion")

        // Sleep keeps ownership but cancels current runtime admission. Its
        // completion must clear in-flight state so a legitimate wake can retry.
        let sleeping = FixtureProvider(), sleepSpec = sleeping.begin(options: FixtureOptions(retries: 2))
        let sleepEntered = DispatchSemaphore(value: 0), sleepRelease = DispatchSemaphore(value: 0)
        sleeping.drainHook = { sleepEntered.signal(); precondition(sleepRelease.wait(timeout: .now() + 3) == .success) }
        sleeping.recover(sleepSpec.epoch)
        precondition(sleepEntered.wait(timeout: .now() + 3) == .success)
        sleeping.sleep {}
        sleepRelease.signal(); sleeping.flush()
        precondition(sleeping.coreStarts == 0 && !sleeping.runtimeRecoveryInFlight)
        sleeping.wake(); sleeping.watchdogQueue.sync {
            precondition(sleeping.sessionAdmission.permitsRuntime(sleepSpec.epoch))
            _ = sleeping.performTunnelHealthCheck(trigger: "fixture-wake", epoch: sleepSpec.epoch)
        }
        sleeping.flush()
        precondition(sleeping.coreStarts == 1 && sleeping.workerStarts == 1 && sleeping.isForwardingReady())
        await sleeping.stop()
        print("PASS sleep during drain releases recovery admission for a valid wake")

        // Hold both owner queues so an earlier wake cannot run until after
        // the later sleep callback has synchronously suspended admission.
        let supersededWake = FixtureProvider(), supersededSpec = supersededWake.begin(options: FixtureOptions(retries: 2))
        let supersededDrainEntered = DispatchSemaphore(value: 0), supersededDrainRelease = DispatchSemaphore(value: 0)
        let watchdogEntered = DispatchSemaphore(value: 0), watchdogRelease = DispatchSemaphore(value: 0)
        supersededWake.drainHook = {
            supersededDrainEntered.signal()
            precondition(supersededDrainRelease.wait(timeout: .now() + 3) == .success)
        }
        supersededWake.recover(supersededSpec.epoch)
        precondition(supersededDrainEntered.wait(timeout: .now() + 3) == .success)
        supersededWake.watchdogQueue.async {
            watchdogEntered.signal()
            precondition(watchdogRelease.wait(timeout: .now() + 3) == .success)
        }
        precondition(watchdogEntered.wait(timeout: .now() + 3) == .success)
        supersededWake.wake()
        supersededWake.sleep {}
        let suspendedImmediately = !supersededWake.sessionAdmission.permitsRuntime(supersededSpec.epoch)
        watchdogRelease.signal()
        supersededWake.watchdogQueue.sync {}
        let remainsSuspended = !supersededWake.sessionAdmission.permitsRuntime(supersededSpec.epoch)
            && supersededWake.watchdogSuspended
        supersededDrainRelease.signal(); supersededWake.flush()
        let noWorkerRestart = supersededWake.coreStarts == 0 && supersededWake.workerStarts == 0
        await supersededWake.stop()
        guard suspendedImmediately && remainsSuspended && noWorkerRestart else {
            print("FAIL queued earlier wake overrode later sleep or admitted workers after drain")
            exit(1)
        }
        // Reverse callback order must also retain the latest wake, including
        // when the earlier sleep's queued mirror has not executed yet.
        let supersededSleep = FixtureProvider(), awakeSpec = supersededSleep.begin()
        let sleepQueueEntered = DispatchSemaphore(value: 0), sleepQueueRelease = DispatchSemaphore(value: 0)
        supersededSleep.watchdogQueue.async {
            sleepQueueEntered.signal()
            precondition(sleepQueueRelease.wait(timeout: .now() + 3) == .success)
        }
        precondition(sleepQueueEntered.wait(timeout: .now() + 3) == .success)
        supersededSleep.sleep {}
        supersededSleep.wake()
        let awakeImmediately = supersededSleep.sessionAdmission.permitsRuntime(awakeSpec.epoch)
        sleepQueueRelease.signal(); supersededSleep.watchdogQueue.sync {}
        let remainsAwake = supersededSleep.sessionAdmission.permitsRuntime(awakeSpec.epoch) && !supersededSleep.watchdogSuspended
        supersededSleep.recover(awakeSpec.epoch); supersededSleep.flush()
        let awakeWorkerStarted = supersededSleep.coreStarts == 1 && supersededSleep.workerStarts == 1
        await supersededSleep.stop()
        guard awakeImmediately && remainsAwake && awakeWorkerStarted else {
            print("FAIL queued earlier sleep overrode the latest wake or blocked its workers")
            exit(1)
        }
        print("PASS queued sleep/wake mirrors retain latest admission and workers stay stopped after final sleep")

        // A pending check owns a scheduling slot, not permission to do runtime
        // work. Firing during sleep must release that slot for the valid wake.
        let sleptCheck = FixtureProvider(), checkSpec = sleptCheck.begin(options: FixtureOptions(retries: 2))
        sleptCheck.recover(checkSpec.epoch); sleptCheck.flush()
        sleptCheck.rejectHealth = true
        sleptCheck.watchdogQueue.sync { _ = sleptCheck.performTunnelHealthCheck(trigger: "before-sleep", epoch: checkSpec.epoch) }
        let sleepingCheck = sleptCheck.recoveryCheck
        precondition(sleepingCheck != nil)
        sleptCheck.sleep {}
        let checksBeforeSleep = sleptCheck.healthChecks
        sleptCheck.watchdogQueue.sync { sleepingCheck?.perform() }
        sleepingCheck?.cancel()
        let slotClearedWhileSleeping = sleptCheck.recoveryCheck == nil && sleptCheck.healthChecks == checksBeforeSleep
        sleptCheck.wake(); sleptCheck.flush()
        sleptCheck.watchdogQueue.sync { _ = sleptCheck.performTunnelHealthCheck(trigger: "after-wake", epoch: checkSpec.epoch) }
        let rearmedCheck = sleptCheck.recoveryCheck
        let rearmedAfterWake = rearmedCheck != nil && rearmedCheck !== sleepingCheck
            && sleptCheck.healthChecks >= checksBeforeSleep + 1
        await sleptCheck.stop()
        guard slotClearedWhileSleeping && rearmedAfterWake else {
            print("FAIL recovery check firing during sleep stranded the retry slot after wake")
            exit(1)
        }
        print("PASS recovery check firing during sleep releases its slot and valid wake rearms failed health retry")

        // Stop in an already admitted Core call cannot preempt that native call;
        // its completion must skip HEV and clean the candidate before NE finish.
        for stage in ["core", "worker"] {
            let provider = FixtureProvider(), current = provider.begin()
            await withCheckedContinuation { continuation in
                let stopping = {
                    provider.stopTunnel(with: NEProviderStopReason(rawValue: 1)) { continuation.resume() }
                }
                if stage == "core" { provider.coreHook = stopping }
                else { provider.workerHook = stopping }
                provider.recover(current.epoch)
            }
            provider.flush()
            precondition(provider.coreStarts == 1 && provider.workerStarts == (stage == "core" ? 0 : 1))
            precondition(provider.coreStops >= 2 && provider.nativeRuntimeEpoch == nil)
            precondition(!provider.isForwardingReady() && provider.healthChecks == 0)
        }
        print("PASS Stop between native stages cleans admitted candidates and does not publish readiness")

        // A new authorized epoch works; callbacks and teardown from the old
        // epoch cannot touch its workers, watchdog, readiness or retry state.
        let newer = FixtureProvider(), old = newer.begin()
        let lateTimer = newer.watchdogTimer?.event, latePath = newer.pathObserver?.onChange
        await newer.stop()
        let fresh = newer.begin(); newer.recover(fresh.epoch); newer.flush()
        precondition(newer.coreStarts == 1 && newer.workerStarts == 1 && newer.isForwardingReady())
        let stopsBefore = newer.coreStops, healthBefore = newer.healthChecks
        newer.watchdogQueue.sync { lateTimer?(); latePath?(TunnelEndpointPath()) }
        newer.reportTerminalFailure("old failure", code: 1, epoch: old.epoch)
        precondition(!newer.startTunnelWatchdog(old))
        newer.stopTunnelWatchdog(epoch: old.epoch)
        newer.runtimeQueue.sync { precondition(!newer.stopNativeRuntime(ownedBy: old.epoch)) }
        newer.flush()
        precondition(newer.coreStarts == 1 && newer.workerStarts == 1 && newer.coreStops == stopsBefore)
        precondition(newer.isForwardingReady() && newer.healthChecks == healthBefore && newer.runtimeSpec?.epoch == fresh.epoch)
        await newer.stop()
        print("PASS authorized new epoch + stale callbacks/teardown cannot affect it")

        // Stale preparation completion must not clear the next session's task.
        let preparation = FixtureProvider()
        let oldPreparation = preparation.sessionAdmission.begin()
        preparation.sessionAdmission.revoke()
        let newPreparation = preparation.sessionAdmission.begin()
        let task = Task<TunnelPreparedConfig, Error> { try await Task.sleep(nanoseconds: 10_000_000_000); return TunnelPreparedConfig() }
        preparation.setStartupPreparation(task, epoch: newPreparation)
        preparation.setStartupPreparation(nil, epoch: oldPreparation)
        precondition(preparation.startupPreparation?.epoch == newPreparation)
        await preparation.stop()
        precondition(task.isCancelled)
        _ = try? await task.value
        print("PASS preparation cancellation is epoch-scoped")

        // Recovery must regenerate a paired document from immutable source.
        let retained = FixtureProvider(), retainedEpoch = retained.sessionAdmission.begin()
        let original = Data("original-config-canary".utf8)
        let retainedSpec = retained.spec(retainedEpoch, options: FixtureOptions(retries: 2), config: original)
        precondition(retained.startTunnelWatchdog(retainedSpec))
        retained.recover(retainedEpoch); retained.flush()
        retained.recover(retainedEpoch); retained.flush()
        precondition(retained.startedPairs.count == 2)
        precondition(retained.originalPreparationInputs == [original])
        precondition(retained.startedPairs.allSatisfy { $0.1 == $0.0 + Data("-metadata".utf8) })
        precondition(retained.startedPairs[0].0 != retained.startedPairs[1].0)
        await retained.stop()
        print("PASS native recovery regenerates paired routing config and metadata from original source")

        // Unexpected errors remain diagnostic failures rather than silently
        // being treated as Stop/cancellation.
        let failed = FixtureProvider(), failureSpec = failed.begin()
        let failuresBefore = FixtureLog.shared.count("Native restart failed; protected traffic remains blocked")
        failed.rejectCore = true; failed.recover(failureSpec.epoch); failed.flush()
        precondition(FixtureLog.shared.count("Native restart failed; protected traffic remains blocked") == failuresBefore + 1)
        precondition(failed.coreStarts == 1 && failed.workerStarts == 0 && failed.recoveryExhausted)
        await failed.stop()
        print("PASS unexpected native errors retain failure diagnostics")

        // Sleep before the first actual native call must not turn that initial
        // launch into a forbidden retry when automatic reconnect is disabled.
        var budgetFailures = 0
        let disabled = FixtureProvider()
        let disabledSpec = disabled.begin(options: FixtureOptions(retries: 1000, reconnectEnabled: false))
        let disabledEntered = DispatchSemaphore(value: 0), disabledRelease = DispatchSemaphore(value: 0)
        disabled.drainHook = {
            disabledEntered.signal()
            precondition(disabledRelease.wait(timeout: .now() + 3) == .success)
        }
        disabled.recover(disabledSpec.epoch)
        precondition(disabledEntered.wait(timeout: .now() + 3) == .success)
        disabled.sleep {}
        disabledRelease.signal(); disabled.flush()
        let noInitialAttempt = disabled.coreStarts == 0 && disabled.workerStarts == 0
            && disabled.recoveryFailures == 0 && !disabled.runtimeRecoveryInFlight
        disabled.wake()
        disabled.watchdogQueue.sync {
            _ = disabled.performTunnelHealthCheck(trigger: "disabled-wake", epoch: disabledSpec.epoch)
        }
        disabled.flush()
        let initialStartedAfterWake = disabled.coreStarts == 1 && disabled.workerStarts == 1
            && disabled.isForwardingReady() && disabled.recoveryFailures == 0
        _ = disabled.hevLifecycle.markExited(code: 1)
        disabled.recover(disabledSpec.epoch); disabled.flush()
        let disabledStillPreventsRealRetry = disabled.coreStarts == 1 && disabled.recoveryExhausted
        await disabled.stop()
        if noInitialAttempt && initialStartedAfterWake && disabledStillPreventsRealRetry {
            print("PASS sleep-cancelled initial launch survives disabled reconnect without allowing a real retry")
        } else {
            print("FAIL disabled reconnect stranded a sleep-cancelled initial launch or admitted a real retry")
            budgetFailures += 1
        }

        // A cancelled retry consumes no attempt. Once a real retry is admitted
        // and fails, the one-attempt limit must still stop further native starts.
        let limited = FixtureProvider(), limitedSpec = limited.begin(options: FixtureOptions(retries: 1))
        limited.recover(limitedSpec.epoch); limited.flush()
        precondition(limited.coreStarts == 1 && limited.workerStarts == 1 && limited.isForwardingReady())
        _ = limited.hevLifecycle.markExited(code: 1)
        let limitedEntered = DispatchSemaphore(value: 0), limitedRelease = DispatchSemaphore(value: 0)
        limited.drainHook = {
            limitedEntered.signal()
            precondition(limitedRelease.wait(timeout: .now() + 3) == .success)
        }
        limited.recover(limitedSpec.epoch)
        precondition(limitedEntered.wait(timeout: .now() + 3) == .success)
        limited.sleep {}
        limitedRelease.signal(); limited.flush()
        let cancelledRetryUncounted = limited.coreStarts == 1 && limited.recoveryFailures == 0
            && !limited.runtimeRecoveryInFlight
        var realRetryEnteredWithBudget = false
        limited.coreHook = { realRetryEnteredWithBudget = limited.recoveryFailures == 1 }
        limited.rejectCore = true
        limited.wake()
        limited.watchdogQueue.sync {
            _ = limited.performTunnelHealthCheck(trigger: "limited-wake", epoch: limitedSpec.epoch)
        }
        limited.flush()
        let actualFailureCountedOnce = limited.coreStarts == 2 && limited.workerStarts == 1
            && limited.recoveryFailures == 1 && limited.recoveryExhausted && !limited.isForwardingReady()
            && realRetryEnteredWithBudget
        limited.recover(limitedSpec.epoch); limited.flush()
        let furtherStartsRefused = limited.coreStarts == 2
        await limited.stop()
        if cancelledRetryUncounted && actualFailureCountedOnce && furtherStartsRefused {
            print("PASS sleep-cancelled retry preserves finite budget and one actual failed retry exhausts it")
        } else {
            print("FAIL sleep consumed the finite retry budget or real failed starts escaped its limit", cancelledRetryUncounted, actualFailureCountedOnce, furtherStartsRefused, limited.coreStarts, limited.workerStarts, limited.recoveryFailures, limited.recoveryExhausted, realRetryEnteredWithBudget)
            budgetFailures += 1
        }
        // A failed drain performs no attempt, but its explicit retry pause must
        // still be honored rather than repeatedly scheduling immediate work.
        let undrained = FixtureProvider(), undrainedSpec = undrained.begin()
        undrained.runtimeQueue.holdDelayed = true
        FixtureSleep.hold = true; FixtureSleep.delays = []
        undrained.rejectWorkerStop = true
        undrained.hasStartedHEV = true
        undrained.hevLifecycle.beginStart(); undrained.hevLifecycle.markThreadEntered()
        undrained.recover(undrainedSpec.epoch); undrained.flush()
        let drainPauses = undrained.runtimeQueue.scheduledDelays()
        let noAttemptAndBoundedPause = undrained.coreStarts == 0 && undrained.workerStarts == 0
            && undrained.recoveryFailures == 0 && !undrained.initialRuntimeAttempted
            && drainPauses.count == 1 && FixtureSleep.delays.contains(where: { $0 >= 2_500_000_000 })
        await undrained.stop()
        undrained.runtimeQueue.releaseHeld(); undrained.flush(); FixtureSleep.hold = false
        if noAttemptAndBoundedPause && undrained.coreStarts == 0 {
            print("PASS failed native drain retains attempt budget and honors the explicit bounded recovery pause")
        } else {
            print("FAIL failed drain consumed an attempt or ignored its explicit recovery pause")
            budgetFailures += 1
        }

        // Enter sleep immediately when the attempt commits. A consumption
        // placed before startNativeRuntime's last guard would count no Core
        // call here. After the final guard, it is a real admitted call and must
        // count even though its completion is then cancelled and cleaned up.
        let boundary = FixtureProvider()
        let boundarySpec = boundary.begin(options: FixtureOptions(retries: 1000, reconnectEnabled: false))
        boundary.attemptAdmissionHook = { boundary.sleep {} }
        var coreSawCommittedAttempt = false
        boundary.coreHook = { coreSawCommittedAttempt = boundary.initialRuntimeAttempted }
        boundary.recover(boundarySpec.epoch); boundary.flush()
        let committedAttemptActuallyEnteredCore = boundary.coreStarts == 1 && boundary.workerStarts == 0
            && coreSawCommittedAttempt && !boundary.isForwardingReady()
        boundary.wake()
        boundary.watchdogQueue.sync {
            _ = boundary.performTunnelHealthCheck(trigger: "commit-boundary-wake", epoch: boundarySpec.epoch)
        }
        boundary.flush()
        let admittedAttemptNotRefunded = boundary.coreStarts == 1 && boundary.recoveryExhausted
        await boundary.stop()
        if committedAttemptActuallyEnteredCore && admittedAttemptNotRefunded {
            print("PASS last pre-Core admission counts only a call actually entered and cancellation does not refund it")
        } else {
            print("FAIL attempt consumption preceded the last native guard or refunded a real admitted call")
            budgetFailures += 1
        }
        // Revocation while one synchronous probe is returning must stop this
        // sample. It cannot admit another probe, publish its result or consume
        // the ordinary watchdog failure/recovery policy.
        let inboundCancelled = FixtureProvider(), inboundCancelledSpec = inboundCancelled.begin()
        inboundCancelled.hevLifecycle.beginStart(); inboundCancelled.hevLifecycle.markThreadEntered()
        inboundCancelled.inboundHealthHook = { _ = inboundCancelled.sessionAdmission.revoke() }
        let inboundResult = inboundCancelled.watchdogQueue.sync {
            inboundCancelled.performTunnelHealthCheck(trigger: "cancel-after-inbound", epoch: inboundCancelledSpec.epoch)
        }
        let inboundCancellationRespected = !inboundResult && inboundCancelled.healthChecks == 1
            && inboundCancelled.connectHealthChecks == 0 && inboundCancelled.httpHealthChecks == 0
            && !inboundCancelled.watchdogInboundHealthy && !inboundCancelled.isForwardingReady()
            && inboundCancelled.watchdogPolicy.consecutiveFailures == 0
            && inboundCancelled.recoveryCheck == nil && inboundCancelled.coreStarts == 0
        await inboundCancelled.stop()
        if inboundCancellationRespected {
            print("PASS cancellation after inbound prevents later probes and stale health or failure publication")
        } else {
            print("FAIL cancellation after inbound admitted later probes or published cancelled health")
            budgetFailures += 1
        }

        let connectCancelled = FixtureProvider(), connectCancelledSpec = connectCancelled.begin()
        connectCancelled.hevLifecycle.beginStart(); connectCancelled.hevLifecycle.markThreadEntered()
        connectCancelled.connectHealthHook = { _ = connectCancelled.sessionAdmission.revoke() }
        let connectResult = connectCancelled.watchdogQueue.sync {
            connectCancelled.performTunnelHealthCheck(trigger: "cancel-after-connect", epoch: connectCancelledSpec.epoch)
        }
        let connectCancellationRespected = !connectResult && connectCancelled.healthChecks == 1
            && connectCancelled.connectHealthChecks == 1 && connectCancelled.httpHealthChecks == 0
            && !connectCancelled.isForwardingReady() && connectCancelled.watchdogPolicy.consecutiveFailures == 0
            && connectCancelled.recoveryCheck == nil && connectCancelled.coreStarts == 0
        await connectCancelled.stop()
        if connectCancellationRespected {
            print("PASS cancellation after CONNECT prevents HTTP and consumes no watchdog failure or retry")
        } else {
            print("FAIL cancellation after CONNECT admitted HTTP or consumed a cancelled health sample")
            budgetFailures += 1
        }
        // The one pending DNS lookup deliberately ignores Task cancellation.
        // A newer path must start its own plan, not await or adopt the old answer.
        let lateLookup = FixtureProvider(), lookupSpec = lateLookup.begin(options: FixtureOptions(retries: 3))
        lateLookup.recover(lookupSpec.epoch); lateLookup.flush()
        let lookupGate = FixtureAsyncGate(), lookupStops = lateLookup.coreStops
        lateLookup.preparationHook = { await lookupGate.wait() }
        lateLookup.watchdogQueue.sync { lateLookup.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 2), epoch: lookupSpec.epoch) }
        precondition(lookupGate.entered.wait(timeout: .now() + 3) == .success)
        precondition(lateLookup.coreStops == lookupStops && lateLookup.isForwardingReady())
        lateLookup.preparationHook = nil
        lateLookup.watchdogQueue.sync { lateLookup.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 3), epoch: lookupSpec.epoch) }
        lateLookup.flush(); let latestLookupToken = lateLookup.nativeRuntimeToken, latestLookupStops = lateLookup.coreStops
        lookupGate.release(); lateLookup.flush()
        precondition(lateLookup.coreStarts == 2 && lateLookup.nativeRuntimeToken == latestLookupToken)
        lateLookup.runtimeQueue.sync { precondition(!lateLookup.stopNativeRuntime(ownedBy: lookupSpec.epoch, token: lookupSpec.token)) }
        lateLookup.reportTerminalFailure("old same-session worker failed", code: 1, epoch: lookupSpec.epoch, token: lookupSpec.token)
        lateLookup.flush()
        precondition(lateLookup.coreStops == latestLookupStops && lateLookup.isForwardingReady())
        await lateLookup.stop()
        print("PASS late DNS answer and same-session old teardown/error cannot replace or stop newer plan")

        for refusal in ["lookup", "preflight"] {
            let preserved = FixtureProvider(), preservedSpec = preserved.begin(options: FixtureOptions(retries: 1))
            preserved.recover(preservedSpec.epoch); preserved.flush()
            let before = preserved.coreStops
            if refusal == "lookup" { preserved.rejectPreparation = true }
            else { preserved.rejectPreflight = true }
            preserved.watchdogQueue.sync { preserved.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 2), epoch: preservedSpec.epoch) }
            preserved.flush()
            precondition(preserved.coreStarts == 1 && preserved.coreStops == before && preserved.isForwardingReady())
            precondition(preserved.settingGenerations.isEmpty && preserved.recoveryExhausted)
            precondition(preserved.originalPreparationInputs.allSatisfy { $0 == preserved.runtimeSource!.config })
            await preserved.stop()
        }
        print("PASS lookup/preflight refusal preserves working old worker and consumes finite preparation budget")

        let staleCheck = FixtureProvider(), checkPlan = staleCheck.begin(options: FixtureOptions(retries: 3))
        staleCheck.recover(checkPlan.epoch); staleCheck.flush()
        let checkEntered = DispatchSemaphore(value: 0), checkRelease = DispatchSemaphore(value: 0)
        staleCheck.preflightHook = {
            staleCheck.preflightHook = nil; checkEntered.signal()
            precondition(checkRelease.wait(timeout: .now() + 3) == .success)
        }
        let beforeCheckStops = staleCheck.coreStops
        staleCheck.watchdogQueue.sync { staleCheck.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 2), epoch: checkPlan.epoch) }
        precondition(checkEntered.wait(timeout: .now() + 3) == .success)
        staleCheck.watchdogQueue.sync { staleCheck.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 3), epoch: checkPlan.epoch) }
        precondition(staleCheck.coreStops == beforeCheckStops && staleCheck.isForwardingReady())
        checkRelease.signal(); staleCheck.flush()
        precondition(staleCheck.coreStarts == 2 && staleCheck.settingGenerations.count == 1 && staleCheck.runtimeSpec?.path.interfaceIndex == 3)
        await staleCheck.stop()
        print("PASS path change during Core preflight discards old candidate before drain")

        let staleDrain = FixtureProvider(), drainPlan = staleDrain.begin(options: FixtureOptions(retries: 3))
        staleDrain.recover(drainPlan.epoch); staleDrain.flush()
        staleDrain.drainHook = {
            staleDrain.watchdogQueue.sync { staleDrain.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 3), epoch: drainPlan.epoch) }
        }
        staleDrain.watchdogQueue.sync { staleDrain.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 2), epoch: drainPlan.epoch) }
        staleDrain.waitUntil { staleDrain.watchdogQueue.sync { staleDrain.runtimeSpec?.path.interfaceIndex == 3 && !staleDrain.runtimeRecoveryInFlight } }
        staleDrain.flush()
        precondition(staleDrain.coreStarts == 2 && staleDrain.settingGenerations.count == 1)
        await staleDrain.stop()
        print("PASS superseded drain completion installs no obsolete settings or native runtime")

        let ordered = FixtureProvider(), orderedSpec = ordered.begin(options: FixtureOptions(retries: 3))
        ordered.recover(orderedSpec.epoch); ordered.flush()
        let settingsGate = FixtureAsyncGate()
        ordered.settingsHook = { await settingsGate.wait() }
        ordered.watchdogQueue.sync { ordered.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 2), epoch: orderedSpec.epoch) }
        precondition(settingsGate.entered.wait(timeout: .now() + 3) == .success)
        ordered.settingsHook = nil
        ordered.watchdogQueue.sync { ordered.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 3), epoch: orderedSpec.epoch) }
        ordered.waitUntil { ordered.originalPreparationInputs.count == 2 }
        precondition(ordered.settingGenerations.count == 1 && ordered.coreStarts == 1 && !ordered.isForwardingReady(), "new settings overtook pending callback")
        settingsGate.release(); await ordered.flushAsync()
        precondition(ordered.settingGenerations.count == 2 && ordered.settingGenerations[0] < ordered.settingGenerations[1], "settings FIFO generations")
        precondition(ordered.coreStarts == 2 && ordered.runtimeSpec?.path.interfaceIndex == 3 && ordered.isForwardingReady())
        await ordered.stop()
        print("PASS asynchronous settings complete FIFO and stale completion cannot start Core")

        let stopSettings = FixtureProvider(), stopSettingsSpec = stopSettings.begin(options: FixtureOptions(retries: 3))
        stopSettings.recover(stopSettingsSpec.epoch); stopSettings.flush()
        let stoppedSettingsGate = FixtureAsyncGate()
        stopSettings.settingsHook = { await stoppedSettingsGate.wait() }
        stopSettings.watchdogQueue.sync { stopSettings.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 2), epoch: stopSettingsSpec.epoch) }
        precondition(stoppedSettingsGate.entered.wait(timeout: .now() + 3) == .success)
        await stopSettings.stop(); stoppedSettingsGate.release(); stopSettings.flush()
        precondition(stopSettings.coreStarts == 1 && !stopSettings.isForwardingReady() && stopSettings.nativeRuntimeToken == nil)
        print("PASS explicit Stop revokes held settings completion before any replacement Core or HEV")

        let expired = FixtureProvider(), expirySpec = expired.begin(options: FixtureOptions(retries: 1))
        expired.recover(expirySpec.epoch); expired.flush()
        expired.preparationExpiry = ProcessInfo.processInfo.systemUptime - 1
        let expiryStops = expired.coreStops
        expired.watchdogQueue.sync { expired.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 2), epoch: expirySpec.epoch) }
        expired.flush()
        precondition(expired.coreStarts == 1 && expired.coreStops == expiryStops && expired.settingGenerations.isEmpty && expired.isForwardingReady())
        await expired.stop()
        print("PASS expired selected address cannot newly drain old runtime or alter routes")

        let unavailable = FixtureProvider(), unavailableSpec = unavailable.begin(options: FixtureOptions(retries: 2))
        unavailable.recover(unavailableSpec.epoch); unavailable.flush()
        let unavailableStops = unavailable.coreStops
        unavailable.watchdogQueue.sync { unavailable.physicalPathChanged(nil, epoch: unavailableSpec.epoch) }
        unavailable.flush()
        precondition(unavailable.coreStarts == 1 && unavailable.coreStops == unavailableStops && unavailable.isForwardingReady())
        unavailable.watchdogQueue.sync { unavailable.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 7), epoch: unavailableSpec.epoch) }
        unavailable.flush()
        precondition(unavailable.coreStarts == 2 && unavailable.runtimeSpec?.path.interfaceIndex == 7)
        await unavailable.stop()
        print("PASS absent physical snapshot preserves old runtime and a later real path regenerates it")

        let ttlRefresh = FixtureProvider(), ttlSpec = ttlRefresh.begin(options: FixtureOptions(retries: 2))
        ttlRefresh.recover(ttlSpec.epoch); ttlRefresh.flush()
        let ttlSource = ttlRefresh.runtimeSource!, ttlPath = ttlSpec.path
        let timed = TunnelPreparedConfig(data: ttlSpec.config, endpointPath: ttlPath,
            endpointSelections: [TunnelEndpointSelection(candidates: TunnelEndpointCandidates(path: ttlPath), selected: TunnelEndpointCandidate(expiry: ProcessInfo.processInfo.systemUptime - 1))])
        ttlRefresh.watchdogQueue.sync {
            ttlRefresh.runtimeSpec = FixtureProvider.RuntimeSpec(source: ttlSource, prepared: timed, token: ttlSpec.token, path: ttlPath, port: ttlSpec.port)
            ttlRefresh.watchdogTimer?.event?()
        }
        await ttlRefresh.flushAsync()
        precondition(ttlRefresh.coreStarts == 2 && ttlRefresh.originalPreparationInputs == [ttlSource.config])
        await ttlRefresh.stop()
        print("PASS selected positive TTL expiry triggers original-source re-preparation before a new native attempt")

        let zeroTTL = FixtureProvider(), zeroSpec = zeroTTL.begin(options: FixtureOptions(retries: 2))
        zeroTTL.recover(zeroSpec.epoch); zeroTTL.flush()
        let zeroSource = zeroTTL.runtimeSource!, zeroPath = zeroSpec.path
        let single = TunnelPreparedConfig(data: zeroSpec.config, endpointPath: zeroPath,
            endpointSelections: [TunnelEndpointSelection(candidates: TunnelEndpointCandidates(path: zeroPath), selected: TunnelEndpointCandidate(expiry: ProcessInfo.processInfo.systemUptime - 1, singleAttempt: true))])
        zeroTTL.watchdogQueue.sync {
            zeroTTL.runtimeSpec = FixtureProvider.RuntimeSpec(source: zeroSource, prepared: single, token: zeroSpec.token, path: zeroPath, port: zeroSpec.port)
            zeroTTL.watchdogTimer?.event?(); zeroTTL.watchdogTimer?.event?()
        }
        zeroTTL.flush()
        precondition(zeroTTL.coreStarts == 1 && zeroTTL.originalPreparationInputs.isEmpty)
        zeroTTL.recover(zeroSpec.epoch); await zeroTTL.flushAsync()
        precondition(zeroTTL.coreStarts == 2 && zeroTTL.originalPreparationInputs == [zeroSource.config])
        await zeroTTL.stop()
        print("PASS fresh zero TTL causes no timer spin and later retry still performs a new lookup")

        let sameSettings = FixtureProvider(), sameSpec = sameSettings.begin(options: FixtureOptions(retries: 3))
        sameSettings.recover(sameSpec.epoch); sameSettings.flush()
        sameSettings.watchdogQueue.sync { sameSettings.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 1), epoch: sameSpec.epoch) }
        await sameSettings.flushAsync()
        precondition(sameSettings.originalPreparationInputs.count == 1 && sameSettings.coreStarts == 2 && sameSettings.settingGenerations.isEmpty)
        sameSettings.preparationAddresses = ["198.51.100.7"]
        sameSettings.watchdogQueue.sync { sameSettings.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 1), epoch: sameSpec.epoch) }
        await sameSettings.flushAsync()
        precondition(sameSettings.originalPreparationInputs.count == 2 && sameSettings.settingGenerations.count == 1)
        await sameSettings.stop()
        print("PASS equal public path still re-resolves; identical settings skip write but changed selected address writes")

        let staleSame = FixtureProvider(), staleSameSpec = staleSame.begin(options: FixtureOptions(retries: 3))
        staleSame.recover(staleSameSpec.epoch); staleSame.flush()
        let staleSameGate = FixtureAsyncGate()
        staleSame.settingsHook = { await staleSameGate.wait() }
        staleSame.watchdogQueue.sync { staleSame.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 2), epoch: staleSameSpec.epoch) }
        precondition(staleSameGate.entered.wait(timeout: .now() + 3) == .success)
        staleSame.settingsHook = nil
        staleSame.watchdogQueue.sync { staleSame.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 2), epoch: staleSameSpec.epoch) }
        staleSameGate.release(); await staleSame.flushAsync()
        precondition(staleSame.originalPreparationInputs.count == 2 && staleSame.settingGenerations.count == 1 && staleSame.coreStarts == 2)
        precondition(staleSame.installedSettingsKey == FixtureProvider.ProtectedSettingsKey(staleSame.runtimeSpec!))
        await staleSame.stop()
        print("PASS successful stale settings callback is retained only for exact same-epoch installed key")

        let failedSettings = FixtureProvider(), failedSettingsSpec = failedSettings.begin(options: FixtureOptions(retries: 2))
        failedSettings.recover(failedSettingsSpec.epoch)
        // Await the actual initial native block and its queued completion, rather
        // than assuming a bounded number of scheduling yields drained the work.
        let failedInitialCoreStarts = try! await failedSettings.onRuntimeQueue { failedSettings.coreStarts }
        let failedInitialReady = failedSettings.watchdogQueue.sync {
            !failedSettings.runtimeRecoveryInFlight && failedSettings.isForwardingReady()
        }
        guard failedInitialCoreStarts == 1 && failedInitialReady else {
            print("FAIL failed-settings/initial-runtime-not-complete coreStarts=\(failedInitialCoreStarts) ready=\(failedInitialReady)")
            await failedSettings.stop(); exit(1)
        }
        let failedSettingsCallback = FixtureAsyncGate()
        failedSettings.settingsHook = { await failedSettingsCallback.wait(); throw SyntheticFailure.core }
        failedSettings.watchdogQueue.sync { failedSettings.physicalPathChanged(TunnelEndpointPath(interfaceIndex: 2), epoch: failedSettingsSpec.epoch) }
        guard failedSettingsCallback.waitUntilEntered(timeout: 3) else {
            print("FAIL failed-settings/callback-not-entered")
            await failedSettings.stop(); exit(1)
        }
        // The first callback is explicitly held. A retry uses a new callback;
        // neither the gate's entry nor a queue yield proves its catch completed.
        failedSettings.settingsHook = { throw SyntheticFailure.core }
        failedSettingsCallback.release()
        // There are exactly two permitted failed preparation attempts. Await
        // their actual Tasks and watchdog completions; the runner's process
        // deadline remains the hard bound if a callback/task never completes.
        for _ in 0..<2 {
            let pending = failedSettings.watchdogQueue.sync { failedSettings.endpointPreparation?.task }
            if let pending { await pending.value }
            failedSettings.watchdogQueue.sync {}
        }
        // Each observed value comes from its actual owner after completion.
        let failedSettingsCache = try! await failedSettings.endpointCommitQueue.submit {
            (keyNil: failedSettings.installedSettingsKey == nil, callbacks: failedSettings.settingGenerations.count)
        }.value
        let failedSettingsCoreStarts = try! await failedSettings.onRuntimeQueue { failedSettings.coreStarts }
        let failedSettingsState = failedSettings.watchdogQueue.sync {
            (inFlight: failedSettings.runtimeRecoveryInFlight, exhausted: failedSettings.recoveryExhausted,
             failures: failedSettings.recoveryFailures)
        }
        guard failedSettingsCache.keyNil && failedSettingsCoreStarts == 1 && failedSettingsCache.callbacks >= 1 &&
            !failedSettingsState.inFlight && failedSettingsState.exhausted else {
            print("FAIL failed-settings/outcome keyNil=\(failedSettingsCache.keyNil) coreStarts=\(failedSettingsCoreStarts) callbacks=\(failedSettingsCache.callbacks) inFlight=\(failedSettingsState.inFlight) exhausted=\(failedSettingsState.exhausted) failures=\(failedSettingsState.failures)")
            await failedSettings.stop(); exit(1)
        }
        await failedSettings.stop()
        print("PASS failed settings callback invalidates installed-key knowledge and never admits Core")

        #if MACOS_PROVIDER
        let bridgeFailure = FixtureProvider(), bridgeSpec = bridgeFailure.begin(options: FixtureOptions(retries: 1))
        bridgeFailure.recover(bridgeSpec.epoch); bridgeFailure.flush()
        bridgeFailure.packetBridge = TunnelPacketBridge()
        bridgeFailure.packetBridgeEpoch = bridgeSpec.epoch; bridgeFailure.packetBridgeToken = bridgeSpec.token
        bridgeFailure.rejectCore = true
        bridgeFailure.recover(bridgeSpec.epoch); await bridgeFailure.flushAsync()
        if bridgeFailure.coreStarts == 2 && bridgeFailure.nativeRuntimeToken == nil &&
            bridgeFailure.packetBridge == nil && bridgeFailure.packetBridgeToken == nil {
            print("PASS drained old packet bridge cannot refuse cleanup of replacement Core startup failure")
        } else {
            print("FAIL old bridge token stranded replacement Core failure cleanup")
            budgetFailures += 1
        }
        await bridgeFailure.stop()
        #endif

        if budgetFailures != 0 { exit(1) }
    }
}
