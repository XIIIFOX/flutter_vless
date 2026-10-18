import Foundation

@main struct ControlProbe {
    static func main() async throws {
        let group = "dev.tfox.controls.fixture.\(UUID().uuidString)", provider = "fixture.XrayTunnel"
        defer { UserDefaults(suiteName: group)?.removePersistentDomain(forName:group) }
        let manager = NETunnelProviderManager(), configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = provider
        configuration.includeAllNetworks = true; configuration.excludeLocalNetworks = false
        configuration.providerConfiguration = ["groupIdentifier":group,"xrayConfigReference":Data([1,2,3])]
        manager.protocolConfiguration = configuration; manager.isEnabled = true; SDK.profile = manager
        let options = try VlessNativeOptions(["quickAccess":["enabled":true]])
        VlessSystemControl.configure(group:group,provider:provider,options:options)
        VlessSystemControl.authorizeProfile(group:group,provider:provider,reference:Data([1,2,3]))
        try await VlessSystemControl.setConnected(true,group:group,provider:provider)
        precondition(manager.connection.status == .connecting && manager.isOnDemandEnabled)
        let active = await VlessSystemControl.isConnected(group:group,provider:provider)
        precondition(active)
        let savesBeforeIdempotent = SDK.saves
        try await VlessSystemControl.setConnected(true,group:group,provider:provider)
        precondition(SDK.saves == savesBeforeIdempotent, "An active connection keeps its policy snapshot")
        SDK.delayedStop = true
        SDK.failNextSave = true
        do { try await VlessSystemControl.setConnected(false,group:group,provider:provider); fatalError("Expected failed disarm") } catch {}
        precondition(SDK.stopCalls == 0, "Do not stop before confirmed disarm")
        SDK.rearmOnNextRefresh = true
        do { try await VlessSystemControl.setConnected(false,group:group,provider:provider); fatalError("Expected failed recovery readback") } catch {}
        precondition(SDK.stopCalls == 0, "A system control must verify the disabled profile before stopping")
        try await VlessSystemControl.setConnected(false,group:group,provider:provider)
        precondition(SDK.stopCalls == 1 && !manager.isEnabled && !manager.isOnDemandEnabled && manager.onDemandRules == nil)
        precondition(manager.connection.status == .disconnected, "Stop must wait for provider teardown before a queued reconnect")
        precondition(configuration.includeAllNetworks && !configuration.excludeLocalNetworks)
        precondition(configuration.providerConfiguration?["xrayConfigReference"] as? Data == Data([1,2,3]))

        // A recovering provider still owns capture. The control must offer Stop
        // and authenticate it without mistaking forwarding loss for disconnect.
        manager.connection.status = .reasserting
        manager.isEnabled = true; manager.isOnDemandEnabled = true
        manager.onDemandRules = [NEOnDemandRuleConnect()]
        let recovering = await VlessSystemControl.isConnected(group:group,provider:provider)
        precondition(recovering, "A recovering accepted tunnel remains active for the system control")
        let savesBeforeRecoveryStop = SDK.saves, stopsBeforeRecoveryStop = SDK.stopCalls
        var recoveryAuthorizations = 0
        do {
            try await VlessSystemControl.perform(false,group:group,provider:provider) {
                recoveryAuthorizations += 1
                throw SDKError.unavailable
            }
            fatalError("Cancelled owner authentication must preserve the recovering session")
        } catch {}
        precondition(recoveryAuthorizations == 1)
        precondition(SDK.saves == savesBeforeRecoveryStop && SDK.stopCalls == stopsBeforeRecoveryStop)
        precondition(manager.connection.status == .reasserting && manager.isEnabled && manager.isOnDemandEnabled)
        precondition(manager.onDemandRules?.count == 1)
        try await VlessSystemControl.perform(false,group:group,provider:provider) {
            recoveryAuthorizations += 1
        }
        precondition(recoveryAuthorizations == 2)
        precondition(SDK.saves == savesBeforeRecoveryStop + 1 && SDK.stopCalls == stopsBeforeRecoveryStop + 1)
        precondition(!manager.isEnabled && !manager.isOnDemandEnabled && manager.onDemandRules == nil)
        precondition(manager.connection.status == .disconnected, "Authorized recovery Stop awaits delayed provider termination")
        let stoppedRecovery = await VlessSystemControl.isConnected(group:group,provider:provider)
        precondition(!stoppedRecovery)
        precondition(configuration.includeAllNetworks && !configuration.excludeLocalNetworks)
        precondition(configuration.providerConfiguration?["xrayConfigReference"] as? Data == Data([1,2,3]))
        VlessSystemControl.clear(group:group)
        VlessSystemControl.configure(group:group,provider:provider,options:options)
        do { try await VlessSystemControl.setConnected(true,group:group,provider:provider); fatalError("Cleared permission") } catch {}
        VlessSystemControl.configure(group:group,provider:provider,options:options)
        VlessSystemControl.authorizeProfile(group:group,provider:provider,reference:Data([1,2,3]))
        configuration.providerConfiguration?["proxyOnly"] = true
        do { try await VlessSystemControl.setConnected(true,group:group,provider:provider); fatalError("Proxy profile") } catch {}
        configuration.providerConfiguration?["proxyOnly"] = false
        do { try await VlessSystemControl.setConnected(true,group:group,provider:"another.XrayTunnel"); fatalError("Unrelated profile") } catch {}
        let disabled = try VlessNativeOptions(["quickAccess":["enabled":true],"reconnect":["enabled":false]])
        VlessSystemControl.configure(group:group,provider:provider,options:disabled)
        var authentications=0
        do { try await VlessSystemControl.perform(true,group:group,provider:provider) { throw SDKError.unavailable }; fatalError("Authentication must cancel action") } catch {}
        try await VlessSystemControl.perform(true,group:group,provider:provider) { authentications += 1 }
        precondition(authentications == 1)
        try await VlessSystemControl.setConnected(true,group:group,provider:provider)
        precondition(!manager.isOnDemandEnabled && manager.connection.status == .connecting)
        precondition((configuration.providerConfiguration?["options"] as? [String:Any])?["reconnect"] is [String:Any])
        let openOptions=try VlessNativeOptions(["quickAccess":["enabled":true,"action":"openApp","requireUnlock":false]])
        VlessSystemControl.configure(group:group,provider:provider,options:openOptions)
        let beforeOpen=SDK.saves
        try await VlessSystemControl.perform(false,group:group,provider:provider) { fatalError("Unlock disabled") }
        precondition(SDK.saves==beforeOpen)
        print("PASS native Apple control: opt-in, identity, protected profile, verified disarm, failed save, authenticated recovery Stop, clear and disabled recovery (in-memory SDK)")
    }
}
