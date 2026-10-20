import Foundation

// SDK/Core/HEV boundaries are in memory. The runner inserts actual provider
// methods below; no Xray, HEV, NetworkExtension, socket or resolver is linked.
typealias NativeDiagnosticMessage = String
struct LocalProxyCredentials {}
struct TunnelPreparedConfig {}
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
enum SyntheticFailure: Error { case core }

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
    var watchdogTimer: DispatchSourceTimer?, pathMonitor: NWPathMonitor?
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
    var packetBridge: TunnelPacketBridge?, packetBridgeEpoch: TunnelSessionAdmission.Epoch?
    var hevLogURL: URL?
    // Read counters only after their owner queue is drained.
    var coreStarts = 0, workerStarts = 0, coreStops = 0, healthChecks = 0
    var startedPairs: [(Data, Data?)] = []
    var drainHook: (() -> Void)?, coreHook: (() -> Void)?, workerHook: (() -> Void)?
    var attemptAdmissionHook: (() -> Void)?
    var rejectCore = false, rejectHealth = false, rejectWorkerStop = false
    func startXRay(xrayConfig: Data, geoAssetsDirectory: String?, routingMetadata: Data? = nil) throws {
        coreStarts += 1
        startedPairs.append((xrayConfig, routingMetadata))
        coreHook?()
        if rejectCore { throw SyntheticFailure.core }
    }
    func startSocks5Tunnel(serverPort: Int, credentials: LocalProxyCredentials, epoch: TunnelSessionAdmission.Epoch) throws {
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
    func socksInboundHealthCheck(port: Int, credentials: LocalProxyCredentials) -> String { healthChecks += 1; return rejectHealth ? "fixture unavailable" : "ok" }
    func socksConnectHealthCheck(port: Int, credentials: LocalProxyCredentials) -> String { "ok" }
    func socksHTTPHealthCheck(port: Int, credentials: LocalProxyCredentials) -> String { "ok" }
    // SOURCE_PROVIDER_METHODS
    func spec(_ epoch: TunnelSessionAdmission.Epoch, options: FixtureOptions = FixtureOptions()) -> RuntimeSpec {
        RuntimeSpec(epoch: epoch, options: options, config: Data(), port: 10808, geoAssetsDirectory: nil, credentials: LocalProxyCredentials())
    }
    func begin(options: FixtureOptions = FixtureOptions()) -> RuntimeSpec {
        let epoch = sessionAdmission.begin()
        setForwardingReady(false, epoch: epoch)
        let value = spec(epoch, options: options)
        precondition(startTunnelWatchdog(value))
        return value
    }
    func recover(_ epoch: TunnelSessionAdmission.Epoch) {
        watchdogQueue.sync { scheduleNativeRecovery(after: 0, epoch: epoch) }
    }
    func flush() { watchdogQueue.sync {}; runtimeQueue.sync {}; watchdogQueue.sync {} }
    func stop() async {
        await withCheckedContinuation { continuation in
            stopTunnel(with: NEProviderStopReason(rawValue: 1)) { continuation.resume() }
        }
    }
}

@main struct Probe {
    static func main() async {
        // Actual recovery code passes its first check, then the fake native
        // drain blocks. Stop must return from revocation without that queue.
        let duringDrain = FixtureProvider(), spec = duringDrain.begin()
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        duringDrain.drainHook = { entered.signal(); precondition(release.wait(timeout: .now() + 3) == .success) }
        let oldTimer = duringDrain.watchdogTimer?.event
        let oldPath = duringDrain.pathMonitor?.pathUpdateHandler
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
            oldTimer?(); oldPath?(FixturePath()); oldCheck?.perform()
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
        sleptCheck.wake()
        sleptCheck.watchdogQueue.sync { _ = sleptCheck.performTunnelHealthCheck(trigger: "after-wake", epoch: checkSpec.epoch) }
        let rearmedCheck = sleptCheck.recoveryCheck
        let rearmedAfterWake = rearmedCheck != nil && rearmedCheck !== sleepingCheck
            && sleptCheck.healthChecks == checksBeforeSleep + 1
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
        let lateTimer = newer.watchdogTimer?.event, latePath = newer.pathMonitor?.pathUpdateHandler
        await newer.stop()
        let fresh = newer.begin(); newer.recover(fresh.epoch); newer.flush()
        precondition(newer.coreStarts == 1 && newer.workerStarts == 1 && newer.isForwardingReady())
        let stopsBefore = newer.coreStops, healthBefore = newer.healthChecks
        newer.watchdogQueue.sync { lateTimer?(); latePath?(FixturePath()) }
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

        // Actual recovery must reuse the admitted pair, without rebuilding its
        // digest/credentials or falling back to the ordinary native entry point.
        let retained = FixtureProvider(), retainedEpoch = retained.sessionAdmission.begin()
        let configBytes = Data("final-config-canary".utf8), metadataBytes = Data("final-spec-canary".utf8)
        let retainedSpec = FixtureProvider.RuntimeSpec(epoch: retainedEpoch, options: FixtureOptions(retries: 2),
            config: configBytes, port: 10808, geoAssetsDirectory: nil, credentials: LocalProxyCredentials(), routingMetadata: metadataBytes)
        precondition(retained.startTunnelWatchdog(retainedSpec))
        retained.recover(retainedEpoch); retained.flush()
        retained.recover(retainedEpoch); retained.flush()
        precondition(retained.startedPairs.count == 2)
        precondition(retained.startedPairs.allSatisfy { $0.0 == configBytes && $0.1 == metadataBytes })
        precondition(retained.runtimeSpec?.config == configBytes && retained.runtimeSpec?.routingMetadata == metadataBytes)
        await retained.stop()
        print("PASS native recovery retains exact admitted routing config and metadata")

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
            print("FAIL sleep consumed the finite retry budget or real failed starts escaped its limit")
            budgetFailures += 1
        }
        // A failed drain performs no attempt, but its explicit retry pause must
        // still be honored rather than repeatedly scheduling immediate work.
        let undrained = FixtureProvider(), undrainedSpec = undrained.begin()
        undrained.runtimeQueue.holdDelayed = true
        undrained.rejectWorkerStop = true
        undrained.hasStartedHEV = true
        undrained.hevLifecycle.beginStart(); undrained.hevLifecycle.markThreadEntered()
        undrained.recover(undrainedSpec.epoch); undrained.flush()
        let drainPauses = undrained.runtimeQueue.scheduledDelays()
        let noAttemptAndBoundedPause = undrained.coreStarts == 0 && undrained.workerStarts == 0
            && undrained.recoveryFailures == 0 && !undrained.initialRuntimeAttempted
            && drainPauses.count == 2 && drainPauses[1] >= 2.5
        await undrained.stop()
        undrained.runtimeQueue.releaseHeld(); undrained.flush()
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
        if budgetFailures != 0 { exit(1) }
    }
}
