import Foundation

// Every API below is an in-memory substitute. A committed profile is an
// independent value snapshot; loadAll/load return newly materialized copies.
final class InertDefaults {
    static var values: [String: [String: Any]] = [:]
    let suite: String
    init?(suiteName: String) { suite = suiteName }
    func dictionary(forKey key: String) -> [String: Any]? { Self.values[suite]?[key] as? [String: Any] }
    func set(_ value: Any, forKey key: String) { Self.values[suite, default: [:]][key] = value }
    func removePersistentDomain(forName name: String) { Self.values.removeValue(forKey: name) }
}
struct ControlCenter {
    static let shared = ControlCenter()
    func reloadControls(ofKind: String) {}
}
enum NEVPNStatus { case invalid, disconnected, connecting, connected, reasserting, disconnecting }
class NEVPNProtocol {}
final class NETunnelProviderProtocol: NEVPNProtocol {
    var providerBundleIdentifier: String?
    var providerConfiguration: [String: Any]?
    var includeAllNetworks = true
    var excludeLocalNetworks = false
}
class NEOnDemandRule {}
final class NEOnDemandRuleConnect: NEOnDemandRule {
    enum Interface { case any }
    var interfaceTypeMatch = Interface.any
}
enum InertFailure: Error, LocalizedError {
    case unavailable
    var errorDescription: String? { "synthetic-private-config-canary" }
}
final class InertConnection {
    var status = NEVPNStatus.disconnected
    func startVPNTunnel() throws {
        Boundary.starts += 1
        Boundary.startWasDisarmed.append(Boundary.stored?.onDemand == false && Boundary.stored?.rules == 0)
        if Boundary.failNextStart { Boundary.failNextStart = false; throw InertFailure.unavailable }
        status = .connecting
    }
    func stopVPNTunnel() { Boundary.stops += 1; status = .disconnected }
}
struct Stored {
    var enabled: Bool
    var onDemand: Bool
    var rules: Int
    var provider: String?
    var metadata: [String: Any]
    var includeAll: Bool
    var excludeLocal: Bool
    let connection: InertConnection
    init(_ manager: NETunnelProviderManager) {
        let configuration = manager.protocolConfiguration as! NETunnelProviderProtocol
        enabled = manager.isEnabled; onDemand = manager.isOnDemandEnabled; rules = manager.onDemandRules?.count ?? 0
        provider = configuration.providerBundleIdentifier; metadata = configuration.providerConfiguration ?? [:]
        includeAll = configuration.includeAllNetworks; excludeLocal = configuration.excludeLocalNetworks
        connection = manager.connection
    }
    func apply(to manager: NETunnelProviderManager) {
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = provider; configuration.providerConfiguration = metadata
        configuration.includeAllNetworks = includeAll; configuration.excludeLocalNetworks = excludeLocal
        manager.protocolConfiguration = configuration
        manager.isEnabled = enabled; manager.isOnDemandEnabled = onDemand
        manager.onDemandRules = rules == 0 ? nil : (0..<rules).map { _ in NEOnDemandRuleConnect() }
    }
    func manager() -> NETunnelProviderManager {
        let manager = NETunnelProviderManager(connection: connection); apply(to: manager); return manager
    }
}
final class NETunnelProviderManager {
    var protocolConfiguration: NEVPNProtocol?
    var isEnabled = false
    var isOnDemandEnabled = false
    var onDemandRules: [NEOnDemandRule]?
    let connection: InertConnection
    init(connection: InertConnection = InertConnection()) { self.connection = connection }
    static func loadAllFromPreferences() async throws -> [NETunnelProviderManager] {
        Boundary.loads += 1
        let callback = Boundary.onLoadAll; Boundary.onLoadAll = nil; callback?()
        if Boundary.failNextLoadAll { Boundary.failNextLoadAll = false; throw InertFailure.unavailable }
        return Boundary.stored.map { [$0.manager()] } ?? []
    }
    func saveToPreferences() async throws {
        Boundary.saves += 1
        let snapshot = Stored(self)
        if Boundary.failNextSave { Boundary.failNextSave = false; throw InertFailure.unavailable }
        let before = Boundary.onBeforeSaveCommit; Boundary.onBeforeSaveCommit = nil; before?()
        Boundary.stored = snapshot
        let callback = Boundary.onSave; Boundary.onSave = nil; callback?()
        let suspension = Boundary.onSaveSuspension; Boundary.onSaveSuspension = nil
        if let suspension { await suspension() }
        if Boundary.commitThenThrow { Boundary.commitThenThrow = false; throw InertFailure.unavailable }
    }
    func loadFromPreferences() async throws {
        let callback = Boundary.onRefresh; Boundary.onRefresh = nil; callback?()
        if Boundary.failNextRefresh { Boundary.failNextRefresh = false; throw InertFailure.unavailable }
        if let stored = Boundary.stored { stored.apply(to: self) }
    }
}
enum Boundary {
    static var stored: Stored?
    static var profile: NETunnelProviderManager? {
        get { stored?.manager() }
        set { stored = newValue.map(Stored.init) }
    }
    static var onLoadAll: (() -> Void)?
    static var onSave: (() -> Void)?
    static var onBeforeSaveCommit: (() -> Void)?
    static var onRefresh: (() -> Void)?
    static var onSaveSuspension: (() async -> Void)?
    static var failNextSave = false, failNextRefresh = false, failNextLoadAll = false, commitThenThrow = false, failNextStart = false
    static var starts = 0, stops = 0, saves = 0, authorizations = 0, loads = 0
    static var startWasDisarmed: [Bool] = []
    static func mutateStore(_ body: (inout Stored) -> Void) { var snapshot = stored!; body(&snapshot); stored = snapshot }
    static func reset() {
        stored = nil; onLoadAll = nil; onSave = nil; onBeforeSaveCommit = nil; onRefresh = nil; onSaveSuspension = nil
        failNextSave = false; failNextRefresh = false; failNextLoadAll = false; commitThenThrow = false; failNextStart = false
        starts = 0; stops = 0; saves = 0; authorizations = 0; loads = 0; startWasDisarmed = []
        InertDefaults.values = [:]
    }
}
