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
    static func loadAllFromPreferences(completionHandler: @escaping ([NETunnelProviderManager]?, Error?) -> Void) { completionHandler([Kernel.profile.copy()], nil) }
    func saveToPreferences(completionHandler: @escaping (Error?) -> Void) {
        Kernel.events.append(isOnDemandEnabled ? "arm" : "disarm"); Kernel.profile = copy()
        if isOnDemandEnabled { Kernel.onArm?() }
        completionHandler(nil)
    }
    func loadFromPreferences(completionHandler: @escaping (Error?) -> Void) {
        if Kernel.refreshFailures > 0 { Kernel.refreshFailures -= 1; completionHandler(NSError(domain: "fixture.refresh", code: 1)); return }
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
    func rebased(generation: UInt64) -> Self { Self(generation: generation) }
}
struct TunnelEndpointCandidate {
    struct Address { let isLoopback = false }; let address = Address()
    var isSingleAttemptOnly: Bool { false }
    func isUsable(on path: TunnelEndpointPath, at now: TimeInterval, allowFreshZeroTTL: Bool) -> Bool { true }
}
struct TunnelEndpointCandidates { let path: TunnelEndpointPath }
struct TunnelEndpointSelection { let candidates: TunnelEndpointCandidates; let selected: TunnelEndpointCandidate }
struct TunnelPreparedConfig {
    let data = Data("{}".utf8), bootstrapAddresses = ["192.0.2.1"]
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
        Kernel.events.append("prepare")
        Kernel.onPrepare?()
        if Kernel.failure == "endpoint" { throw StartupError.endpointUnavailable }
        if Kernel.failure == "config" { throw StartupError.invalidConfiguration }
        return TunnelPreparedConfig(endpointPath: endpointPath, endpointSelections: [TunnelEndpointSelection(candidates: TunnelEndpointCandidates(path: endpointPath), selected: TunnelEndpointCandidate())])
    }
}
enum TunnelEndpointResolver {
    static func resolveCandidates(_ value: String, on path: TunnelEndpointPath, deadline: TimeInterval,
        isCurrent: @escaping () -> Bool, event: (String) -> Void) async throws -> TunnelEndpointCandidates { TunnelEndpointCandidates(path: path) }
}
final class TunnelDebugStore { static let shared = TunnelDebugStore(); func configure(groupIdentifier: String?, options: VlessNativeOptions) {} }
func FLVlessCoreRoutingCapability() -> Int64 { 1 }
func FLVlessCoreDarwinInterfaceBindingCapability() -> Int64 { Kernel.bindingCapability }
func FLVlessHasCorePreflight() -> Bool { true }
func FLVlessCheckCorePrivate(_ value: Data) -> Int64 { Kernel.events.append("check"); return Kernel.failure == "core" ? 3 : 0 }
func FLVlessCheckCoreRoutingPrivate(_ data: Data, _ metadata: Data) -> Int64 { 0 }
func XRaySetAssetLocation(_ value: String, _ error: inout NSError?) -> Bool { Kernel.events.append("assets"); return true }
func rememberTunnelLog(_ message: String) {}
func isIPv4Literal(_ value: String) -> Bool { true }
enum TunnelDNSPolicy {
    static let virtualServer = "10.0.85.53"
    static func allowsRouteExclusions(_ value: [String]) -> Bool { true }
}
enum TunnelIPv6Policy { static func networkSettings(proxyAddresses: [String]) -> Int { 0 } }
final class NEPacketTunnelNetworkSettings {
    init(tunnelRemoteAddress: String) {}
    var mtu: NSNumber?, ipv4Settings: NEIPv4Settings?, ipv6Settings: Int?, dnsSettings: NEDNSSettings?
}
final class NEIPv4Settings { init(addresses: [String], subnetMasks: [String]) {}; var includedRoutes: [NEIPv4Route] = [], excludedRoutes: [NEIPv4Route] = [] }
final class NEIPv4Route { init(destinationAddress: String, subnetMask: String) {}; static func `default`() -> Self { Self(destinationAddress: "0.0.0.0", subnetMask: "0.0.0.0") } }
final class NEDNSSettings { init(servers: [String]) {}; var matchDomains: [String] = [] }
struct FakeQueue { func async(execute: () -> Void) { execute() }; func sync<T>(execute: () throws -> T) rethrows -> T { try execute() } }
enum Kernel {
    static var events: [String] = [], failure = ""
    static var bindingCapability: Int64 = 1
    static var profile = NETunnelProviderManager()
    static var onArm: (() -> Void)?, refreshFailures = 0
    static var onPrepare: (() -> Void)?
    static var onSettings: (() async -> Void)?
    static func reset(armed: Bool = false, failure: String = "") {
        events = []; self.failure = failure; bindingCapability = 1; profile = NETunnelProviderManager(); onArm = nil; refreshFailures = 0; onPrepare = nil; onSettings = nil
        profile.isOnDemandEnabled = armed; profile.onDemandRules = armed ? [NEOnDemandRuleConnect()] : nil
    }
}
final class FixturePacketBridge { func shutdown() {} }
final class Provider {
    var packetBridge: FixturePacketBridge?
    var packetBridgeEpoch: TunnelSessionAdmission.Epoch?
    var packetBridgeToken: TunnelEndpointPlanAdmission.Token?
    let sessionAdmission = TunnelSessionAdmission(), watchdogQueue = FakeQueue(), runtimeQueue = FakeQueue()
    let forwardingLock = NSLock()
    var forwardingReady = false, reasserting = false
    var forwardingEpoch: TunnelSessionAdmission.Epoch?
    var startupPreparation: (epoch: TunnelSessionAdmission.Epoch, task: Task<TunnelPreparedConfig, Error>)?
    var runtimeSpec: RuntimeSpec?
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
    func refreshEndpointPlan(after delay: TimeInterval, epoch: TunnelSessionAdmission.Epoch, rotate: Bool) {}
    // ACTUAL_PREPARATION_HELPERS
    func tunnelError(_ message: String) -> NSError { NSError(domain: "fixture.provider", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    func setForwardingReady(_ value: Bool, epoch: TunnelSessionAdmission.Epoch) {}
    func setStartupPreparation(_ value: Task<TunnelPreparedConfig, Error>?, epoch: TunnelSessionAdmission.Epoch) {
        if let value { startupPreparation = (epoch, value) }
        else if startupPreparation?.epoch == epoch { startupPreparation = nil }
    }
    func parseConfig(jsonData: Data) -> (inboundPort: Int, unused: Int)? { (10808, 0) }
    func buildIPv4ExcludedRoutes(serverAddresses: [String]) -> [NEIPv4Route] { [] }
    func setTunnelNetworkSettings(_ settings: NEPacketTunnelNetworkSettings?) async throws {
        Kernel.events.append(settings == nil ? "clear-settings" : "settings")
        await Kernel.onSettings?()
    }
    func startTunnelWatchdog(_ spec: RuntimeSpec) -> Bool {
        guard sessionAdmission.activate(spec.epoch) else { return false }
        runtimeSpec = spec; Kernel.events.append("runtime-admission"); return true
    }
    func stopTunnelWatchdog(epoch: TunnelSessionAdmission.Epoch?) {
        if runtimeSpec?.epoch == epoch || runtimeSource?.epoch == epoch {
            pathObserver?.cancel(); pathObserver = nil; runtimeSource = nil; physicalPath = nil; runtimeSpec = nil
        }
    }
    func stopNativeRuntime(ownedBy epoch: TunnelSessionAdmission.Epoch?) -> Bool { true }
    // ACTUAL_STOP
    func scheduleNativeRecovery(after delay: Int, epoch: TunnelSessionAdmission.Epoch) {}
    // ACTUAL_START
}
@main struct Main {
    static func main() async {
        setbuf(stdout, nil)
        var failures = 0, cases = 0
        func check(_ name: String, _ value: Bool) { cases += 1; if !value { failures += 1 }; print("APPLE_COLD_START_CASE=" + name + ";PASS=" + String(value)) }
        for failure in ["endpoint", "config", "core"] {
            Kernel.reset(failure: failure); let provider = Provider()
            do { try await provider.startTunnel(); check("refusal-" + failure, false) }
            catch { check("refusal-" + failure, !Kernel.profile.isOnDemandEnabled && !Kernel.events.contains("arm") && !Kernel.events.contains("runtime-admission")) }
        }
        Kernel.reset(); Kernel.bindingCapability = 0
        do { try await Provider().startTunnel(); check("stock-runtime-binding-capability-refused", false) }
        catch { check("stock-runtime-binding-capability-refused", !Kernel.events.contains("settings") && !Kernel.events.contains("arm") && !Kernel.events.contains("runtime-admission")) }
        Kernel.reset(); let changedDuringLookup = Provider()
        Kernel.onPrepare = {
            Kernel.onPrepare = nil
            _ = try? changedDuringLookup.endpointAdmission.refresh(changedDuringLookup.sessionAdmission.currentEpoch!)
        }
        do { try await changedDuringLookup.startTunnel()
            check("initial-path-replaced-reprepares", Kernel.events.filter { $0 == "prepare" }.count == 2 && Kernel.events.filter { $0 == "runtime-admission" }.count == 1)
        } catch { check("initial-path-replaced-reprepares", false) }
        Kernel.reset(); let ownSettings = Provider()
        Kernel.onSettings = {
            Kernel.onSettings = nil
            ownSettings.pathObserver?.onChange?(TunnelEndpointPath())
        }
        do { try await ownSettings.startTunnel()
            check("own-settings-event-reprepares-without-second-write", Kernel.events.filter { $0 == "prepare" }.count == 2 &&
                Kernel.events.filter { $0 == "settings" }.count == 1 && Kernel.events.filter { $0 == "arm" }.count == 1 &&
                Kernel.events.filter { $0 == "runtime-admission" }.count == 1)
        } catch { check("own-settings-event-reprepares-without-second-write", false) }
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
            var continuation: CheckedContinuation<Void, Never>?
            func wait() async { await withCheckedContinuation { continuation = $0; entered.signal() } }
            func release() { continuation?.resume(); continuation = nil }
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
