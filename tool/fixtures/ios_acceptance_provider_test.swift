import Foundation

// The script inserts the actual guarded provider fields, methods and message
// dispatch. Only the SDK/worker boundary below is synthetic; no Core is linked.
final class FixtureLog: @unchecked Sendable {
    static let shared = FixtureLog()
    private let lock = NSLock()
    private var entries: [String] = []
    func append(_ message: String) { lock.lock(); defer { lock.unlock() }; entries.append(message) }
    func snapshot() -> [String] { lock.lock(); defer { lock.unlock() }; return entries }
}
func rememberTunnelLog(_ message: String) { FixtureLog.shared.append(message) }
struct FixtureOptions {
    var reconnectEnabled = true, onDemand = "disabled"
    var enableOnDemand: Bool { reconnectEnabled && onDemand != "disabled" }
}
struct FixtureHEV: Equatable { var isRunning = true, isStopRequested = false }
struct FixturePolicy: Equatable { var consecutiveFailures = 0 }
struct FixtureSpec { var epoch = 7 }
struct ProtectedState: Equatable {
    let hev: FixtureHEV
    let hasStartedHEV: Bool
    let ready: Bool
    let failures: Int
    let policy: FixturePolicy
    let generation: Int
    let recovering: Bool
}
final class FixtureProvider: @unchecked Sendable {
    let watchdogQueue = DispatchQueue(label: "fixture.watchdog")
    let runtimeQueue = DispatchQueue(label: "fixture.runtime")
    var watchdogSuspended = false, runtimeRecoveryInFlight = false, recoveryExhausted = false
    var recoveryCheck: Bool?
    var watchdogPolicy = FixturePolicy()
    var initialRuntimeAttempted = true, watchdogInboundHealthy = true
    var runtimeSpec: FixtureSpec? = FixtureSpec()
    var watchdogInboundPort: Int? = 10808
    var nativeOptions = FixtureOptions()
    var hevLifecycle = FixtureHEV()
    var hasStartedHEV = true, startupStopped = false, forwardingReady = true
    var recoveryFailures = 5, stopCalls = 0
    func isStartupStopped() -> Bool { startupStopped }
    func isForwardingReady() -> Bool { forwardingReady && hevLifecycle.isRunning }
    func stopXRay() {
        dispatchPrecondition(condition: .onQueue(runtimeQueue))
        stopCalls += 1
    }
    func protectedState() -> ProtectedState {
        ProtectedState(hev: hevLifecycle, hasStartedHEV: hasStartedHEV, ready: forwardingReady,
            failures: recoveryFailures, policy: watchdogPolicy, generation: runtimeSpec?.epoch ?? -1,
            recovering: runtimeRecoveryInFlight)
    }
    // SOURCE_ACCEPTANCE_STATE
    // SOURCE_ACCEPTANCE_HELPER
    func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
    // SOURCE_ACCEPTANCE_DISPATCH
        completionHandler?(Data("unhandled".utf8))
    }
}
func request(_ provider: FixtureProvider, message: String = "acceptance-stop-core") async -> String {
    await withCheckedContinuation { continuation in
        provider.handleAppMessage(Data(message.utf8)) { data in
            continuation.resume(returning: data.map { String(decoding: $0, as: UTF8.self) } ?? "nil")
        }
    }
}
@main struct Probe {
    static func main() async {
        for message in ["acceptance-stop-core-extra", "acceptance-stop-core\n", "ACCEPTANCE-STOP-CORE"] {
            let provider = FixtureProvider()
            let before = provider.protectedState()
            let reply = await request(provider, message: message)
            precondition(reply == "unhandled" && provider.stopCalls == 0 && provider.protectedState() == before)
        }
        #if FLUTTER_VLESS_ACCEPTANCE_TESTING
        let healthy = FixtureProvider(), before = healthy.protectedState()
        let accepted = await request(healthy)
        precondition(accepted == "acceptance-core-stopped" && healthy.stopCalls == 1)
        precondition(healthy.protectedState() == before, "Only Core is stopped; HEV/readiness/retry state must survive")
        let repeated = await request(healthy)
        precondition(repeated == "acceptance-rejected" && healthy.stopCalls == 1)
        let cases: [(String, (FixtureProvider) -> Void)] = [
            ("suspended", { $0.watchdogSuspended = true }),
            ("recovering", { $0.runtimeRecoveryInFlight = true }),
            ("exhausted", { $0.recoveryExhausted = true }),
            ("pending-check", { $0.recoveryCheck = true }),
            ("health-failures", { $0.watchdogPolicy.consecutiveFailures = 1 }),
            ("not-started", { $0.initialRuntimeAttempted = false }),
            ("no-spec", { $0.runtimeSpec = nil }),
            ("no-adapter", { $0.watchdogInboundPort = nil }),
            ("bad-inbound", { $0.watchdogInboundHealthy = false }),
            ("reconnect-disabled", { $0.nativeOptions.reconnectEnabled = false }),
            ("ondemand-enabled", { $0.nativeOptions.onDemand = "enabled" }),
            ("ondemand-default", { $0.nativeOptions.onDemand = "platformDefault" }),
            ("stopping", { $0.startupStopped = true }),
            ("hev-stopping", { $0.hevLifecycle.isStopRequested = true }),
            ("hev-dead", { $0.hevLifecycle.isRunning = false }),
            ("not-ready", { $0.forwardingReady = false })
        ]
        for (name, change) in cases {
            let provider = FixtureProvider(); change(provider)
            let before = provider.protectedState()
            let reply = await request(provider)
            precondition(reply == "acceptance-rejected" && provider.stopCalls == 0, name)
            precondition(provider.protectedState() == before, name)
        }
        let noHEV = FixtureProvider(); noHEV.hasStartedHEV = false
        let noHEVReply = await request(noHEV)
        precondition(noHEVReply == "acceptance-stale" && noHEV.stopCalls == 0)
        for staleMode in 0..<3 {
            let provider = FixtureProvider()
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            provider.runtimeQueue.async { entered.signal(); release.wait() }
            precondition(entered.wait(timeout: .now() + 2) == .success)
            let reply: String = await withCheckedContinuation { continuation in
                provider.handleAppMessage(Data("acceptance-stop-core".utf8)) { data in
                    continuation.resume(returning: String(decoding: data!, as: UTF8.self))
                }
                // Ordered after the initial watchdog reservation, before the
                // queued runtime operation can check the same generation.
                provider.watchdogQueue.async {
                    if staleMode == 0 { provider.runtimeSpec?.epoch += 1 }
                    if staleMode == 1 { provider.runtimeRecoveryInFlight = true }
                    if staleMode == 2 { provider.startupStopped = true }
                    release.signal()
                }
            }
            precondition(reply == "acceptance-stale" && provider.stopCalls == 0)
            provider.watchdogQueue.sync { provider.runtimeRecoveryInFlight = false; provider.startupStopped = false }
            let repeated = await request(provider)
            precondition(repeated == "acceptance-rejected" && provider.stopCalls == 0)
        }
        let noReply = FixtureProvider()
        noReply.handleAppMessage(Data("acceptance-stop-core".utf8), completionHandler: nil)
        noReply.watchdogQueue.sync {}; noReply.runtimeQueue.sync {}
        precondition(noReply.stopCalls == 0)
        let laterReply = await request(noReply)
        precondition(laterReply == "acceptance-core-stopped" && noReply.stopCalls == 1,
                     "A missing callback cannot execute or consume the one-shot operation")
        precondition(FixtureLog.shared.snapshot() == Array(repeating: "Acceptance worker-loss injection: Core stopped", count: 2))
        print("PASS provider acceptance hook: exact message, healthy once, 16 rejected states, stale generation/recovery/Stop, callback and preserved HEV/readiness/retry state")
        #else
        let provider = FixtureProvider(), before = provider.protectedState()
        let reply = await request(provider)
        precondition(reply == "unhandled" && provider.stopCalls == 0 && provider.protectedState() == before)
        precondition(FixtureLog.shared.snapshot().isEmpty)
        print("PASS normal provider build: acceptance message has no effect")
        #endif
    }
}
