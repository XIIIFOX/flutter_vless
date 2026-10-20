import Foundation
import Combine
import os

// In-memory NetworkExtension boundary for executing the real manager's error paths.
// This fixture never loads or changes the host's VPN preferences.
let pluginLog = Logger(subsystem: "flutter_vless.manager.test", category: "policy")
enum NEVPNStatus: Int { case invalid, disconnected, connecting, connected, reasserting, disconnecting }
class NEVPNProtocol {
    var includeAllNetworks = false
    var excludeLocalNetworks = true
    var disconnectOnSleep = true
    var excludeAPNs = true
    var excludeCellularServices = true
}
class NETunnelProviderProtocol: NEVPNProtocol {
    var providerBundleIdentifier: String?
    var serverAddress: String?
    var providerConfiguration: [String: Any]?
}
class NEVPNConnection {
    var status = NEVPNStatus.disconnected
    var connectedDate: Date?
    func startVPNTunnel() throws {
        SDK.startCalls += 1
        SDK.startWasDisarmed.append(SDK.profile?.isOnDemandEnabled == false && (SDK.profile?.onDemandRules ?? []).isEmpty)
        if SDK.failNextStart { SDK.failNextStart = false; throw SDKError.unavailable }
        status = .connecting
    }
    func stopVPNTunnel() {
        SDK.stopCalls += 1
        if SDK.delayedStop {
            status = .disconnecting
            Task {
                try? await Task.sleep(nanoseconds: 150_000_000)
                self.status = .disconnected
            }
        } else {
            status = .disconnected
        }
    }
}
class NETunnelProviderSession: NEVPNConnection {
    func sendProviderMessage(_ data: Data, responseHandler: ((Data?) -> Void)?) throws {
        responseHandler?(SDK.providerResponse)
    }
}
class NEOnDemandRule {}
class NEOnDemandRuleConnect: NEOnDemandRule {
    enum Interface { case any }
    var interfaceTypeMatch = Interface.any
}
enum SDKError: Error { case unavailable }
enum SDK {
    enum CandidateRefreshMutation: String, CaseIterable {
        case onDemandEnabled, disabledManager, rulesWhileDisabled, normalizedEmptyRules
    }
    static var routingCapability: Int64 = 0
    static var profile: NETunnelProviderManager?
    static var failAllLoads = false
    static var failAfterNextSave = false
    static var failNextRefresh = false
    static var rearmOnNextRefresh = false
    static var failNextSave = false
    static var loads = 0
    static var notifyTemporaryConnections = false
    static var saves = 0
    static var stopCalls = 0
    static var startCalls = 0
    static var startWasDisarmed: [Bool] = []
    static var failNextStart = false
    static var delayedStop = false
    static var providerResponse: Data?
    static var nextCandidateRefreshMutation: CandidateRefreshMutation?
    static var pendingCandidateRefreshMutation: (mutation: CandidateRefreshMutation, reference: Data)?
    static var candidateRefreshMutations = 0
    static var candidateReferenceUnchanged = false

    // Explicit external provider-admission boundary. Host start never invokes
    // this; the real provider's admission/rollback helper has separate tests.
    static func simulateProviderAdmission() throws {
        let profile = profile!
        let metadata = (profile.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
        let options = try VlessNativeOptions(metadata["options"] as? [String: Any])
        profile.isOnDemandEnabled = options.enableOnDemand
        profile.onDemandRules = options.enableOnDemand ? [NEOnDemandRuleConnect()] : nil
    }

    static func reset() {
        profile = nil; routingCapability = 0; failAllLoads = false
        failAfterNextSave = false; failNextRefresh = false; rearmOnNextRefresh = false
        failNextSave = false; loads = 0; notifyTemporaryConnections = false
        saves = 0; stopCalls = 0; startCalls = 0; startWasDisarmed = []; failNextStart = false
        delayedStop = false; providerResponse = nil
        nextCandidateRefreshMutation = nil; pendingCandidateRefreshMutation = nil
        candidateRefreshMutations = 0; candidateReferenceUnchanged = false
    }
}
func FLVlessCoreRoutingCapability() -> Int64 { SDK.routingCapability }
class NETunnelProviderManager {
    var protocolConfiguration: NEVPNProtocol?
    var localizedDescription: String?
    var isEnabled = false
    var isOnDemandEnabled = false
    var onDemandRules: [NEOnDemandRule]?
    let connection: NEVPNConnection = NETunnelProviderSession()
    static func loadAllFromPreferences() async throws -> [NETunnelProviderManager] {
        SDK.loads += 1
        if SDK.notifyTemporaryConnections {
            NotificationCenter.default.post(name: .NEVPNStatusDidChange, object: NEVPNConnection())
        }
        if SDK.failAllLoads { throw SDKError.unavailable }
        return SDK.profile.map { [$0] } ?? []
    }
    func loadFromPreferences() async throws {
        if SDK.failNextRefresh { SDK.failNextRefresh = false; throw SDKError.unavailable }
        if let pending = SDK.pendingCandidateRefreshMutation {
            SDK.pendingCandidateRefreshMutation = nil
            switch pending.mutation {
            case .onDemandEnabled: isOnDemandEnabled = true; onDemandRules = [NEOnDemandRuleConnect()]
            case .disabledManager: isEnabled = false
            case .rulesWhileDisabled: onDemandRules = [NEOnDemandRuleConnect()]
            case .normalizedEmptyRules: onDemandRules = []
            }
            let reference = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["xrayConfigReference"] as? Data
            SDK.candidateReferenceUnchanged = reference == pending.reference
            SDK.candidateRefreshMutations += 1
        }
        if SDK.rearmOnNextRefresh && !isEnabled {
            SDK.rearmOnNextRefresh = false
            isEnabled = true
            isOnDemandEnabled = true
        }
    }
    func saveToPreferences() async throws {
        if SDK.failNextSave { SDK.failNextSave = false; throw SDKError.unavailable }
        SDK.saves += 1; SDK.profile = self
        // Only the next saved candidate reference can inject this readback;
        // permission placeholders, loadAll calls and rollback saves cannot.
        if let mutation = SDK.nextCandidateRefreshMutation,
           let reference = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["xrayConfigReference"] as? Data {
            SDK.nextCandidateRefreshMutation = nil
            SDK.pendingCandidateRefreshMutation = (mutation, reference)
        }
        if SDK.failAfterNextSave { SDK.failAfterNextSave = false; SDK.failNextRefresh = true }
    }
    func removeFromPreferences() async throws { SDK.profile = nil }
}
extension Notification.Name {
    static let NEVPNConfigurationChange = Notification.Name("fixture.config")
    static let NEVPNStatusDidChange = Notification.Name("fixture.status")
}
enum NativeLogPrivacy {
    static let providerLogFilename = "unused.log"
    static func removeLegacyProviderLog(in url: URL) {}
    static func operationError(_ error: Error) -> NSError { error as NSError }
}
