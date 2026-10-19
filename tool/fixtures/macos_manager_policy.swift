import Foundation
import Security

@main struct MacManagerPolicyProbe {
    static func main() async throws {
        let keychain = FixtureKeychain()
        let manager = PacketTunnelManager(providerBundleIdentifier: "fixture.XrayTunnel", groupIdentifier: "fixture",
            keychainAccessGroup: "TEAM.fixture.shared", keychainClient: keychain)
        let original = Data(#"{"secret":"manager-secret-canary"}"#.utf8)
        manager.xrayConfig = original
        while manager.isProcessing { await Task.yield() }
        let permission = await manager.testSaveAndLoadProfile()
        precondition(permission && keychain.records.isEmpty)
        try await manager.start()
        let profile = SDK.profile!
        let policy = profile.protocolConfiguration!
        precondition(manager.isRecoveryEnabled && policy.includeAllNetworks && !policy.excludeLocalNetworks)
        precondition(!policy.disconnectOnSleep && !policy.excludeAPNs && !policy.excludeCellularServices)
        let metadata = (policy as! NETunnelProviderProtocol).providerConfiguration!
        precondition(metadata["xrayConfig"] == nil)
        let stored = try TunnelSecretProfile.load(metadata, providerBundleIdentifier: "fixture.XrayTunnel", client: keychain)
        precondition(stored == original)
        profile.connection.status = .connected
        await manager.refreshForwardingState()
        precondition(!manager.forwardingReady)
        SDK.providerResponse = Data("ready".utf8)
        await manager.refreshForwardingState()
        precondition(manager.forwardingReady)
        let saved = SDK.saves
        try await manager.start()
        precondition(SDK.saves == saved && SDK.stopCalls == 0, "Idempotent start must preserve the live provider")
        manager.nativeOptions = try VlessNativeOptions(["reconnect": ["enabled": false]])
        do { try await manager.start(); fatalError("Options changes must require a stopped session") } catch {}
        precondition(SDK.saves == saved && manager.forwardingReady)
        manager.nativeOptions = try VlessNativeOptions()
        manager.xrayConfig = Data(#"{"secret":"replacement"}"#.utf8)
        do { try await manager.start(); fatalError("Live configuration replacement must be explicit") } catch {}
        precondition(SDK.saves == saved && SDK.stopCalls == 0 && manager.isRecoveryEnabled)
        manager.xrayConfig = original
        manager.bypassSubnets = ["::/0"]
        do { try await manager.start(); fatalError("IPv6 bypass must be rejected") } catch {}
        precondition(SDK.saves == saved && manager.isRecoveryEnabled)
        manager.bypassSubnets = []
        SDK.providerResponse = Data("recovering".utf8)
        await manager.refreshForwardingState()
        precondition(!manager.forwardingReady && manager.isRecoveryEnabled)
        SDK.failNextSave = true
        do { try await manager.stop(); fatalError("Failed disarm must not stop provider") } catch {}
        precondition(SDK.stopCalls == 0 && profile.isOnDemandEnabled)
        SDK.rearmOnNextRefresh = true
        do { try await manager.stop(); fatalError("Stop must reject recovery remaining enabled after readback") }
        catch let error as NSError { precondition(error.domain == "VPN" && error.code == 6) }
        precondition(SDK.stopCalls == 0 && manager.isRecoveryEnabled)
        SDK.delayedStop = true
        try await manager.stop()
        precondition(SDK.stopCalls == 1 && profile.connection.status == .disconnected)
        precondition(!manager.isRecoveryEnabled && !profile.isOnDemandEnabled && !profile.isEnabled)
        manager.bypassSubnets = ["192.168.0.0/16"]
        try await manager.start()
        let newMetadata = (SDK.profile!.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
        precondition(newMetadata["bypassSubnets"] as? [String] == ["192.168.0.0/16"])
        precondition(SDK.profile!.protocolConfiguration!.includeAllNetworks)
        try await manager.stop(waitForDisconnect: true)
        try await manager.removeFromPreferences()
        precondition(SDK.profile == nil && keychain.records.isEmpty)
        manager.nativeOptions = try VlessNativeOptions(["quickAccess":["enabled":true],"reconnect":["enabled":false]])
        manager.bypassSubnets = []
        manager.xrayConfig = Data(#"{"inbounds":[],"outbounds":[{"protocol":"freedom"}]}"#.utf8)
        var notifiedReference: Data?
        manager.didSaveQuickProfile = { notifiedReference = $0 }
        try await manager.start()
        precondition(SDK.profile!.isEnabled && !SDK.profile!.isOnDemandEnabled && SDK.profile!.onDemandRules == nil)
        let optionMetadata = (SDK.profile!.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
        precondition((optionMetadata["options"] as? [String:Any])?["reconnect"] is [String:Any])
        precondition(notifiedReference == optionMetadata["xrayConfigReference"] as? Data)
        SDK.profile!.connection.status = .connected
        SDK.providerResponse = Data("recovering".utf8)
        await manager.refreshForwardingState()
        precondition(!manager.forwardingReady && !manager.isRecoveryEnabled)
        SDK.providerResponse = Data("ready".utf8)
        await manager.refreshForwardingState()
        precondition(manager.forwardingReady, "Readiness must not depend on On Demand")
        let beforeNoRecoveryStart = SDK.saves
        try await manager.start()
        precondition(manager.forwardingReady && SDK.saves == beforeNoRecoveryStart)
        SDK.profile!.connection.status = .disconnected
        await manager.refreshForwardingState()
        precondition(!manager.forwardingReady)
        try await manager.stop(waitForDisconnect:true)
        let routingSaves = SDK.saves, routingStops = SDK.stopCalls
        manager.vpnRouting = try NativeRoutingIntent()
        do { try await manager.start(); fatalError("Unavailable routing runtime changed the profile") }
        catch NativeRoutingSpecError.unsupportedRuntime {}
        precondition(SDK.saves == routingSaves && SDK.stopCalls == routingStops)
        SDK.routingCapability = 1
        try await manager.start()
        let routingMetadata = (SDK.profile!.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
        precondition((routingMetadata["vpnRouting"] as? [String: Any])?.isEmpty == true)
        precondition(routingMetadata["source_sha256"] == nil && routingMetadata["auth_user"] == nil)
        SDK.profile!.connection.status = .connected
        let beforeSelectionChange = SDK.saves
        manager.vpnRouting = nil
        do { try await manager.start(); fatalError("Changed routing intent reused a live provider") } catch {}
        precondition(SDK.saves == beforeSelectionChange)
        manager.vpnRouting = try NativeRoutingIntent()
        try await manager.stop(waitForDisconnect: true)
        manager.nativeOptions = try VlessNativeOptions()
        try await manager.start()
        let retainedSelection = (SDK.profile!.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
        precondition((retainedSelection["vpnRouting"] as? [String: Any])?.isEmpty == true)
        try await manager.stop(waitForDisconnect: true)
        manager.vpnRouting = nil; SDK.routingCapability = 0
        try await manager.removeFromPreferences()
        print("PASS macOS routing selection persistence, capability admission and active-profile identity")
        print("PASS macOS manager: mandatory policy, private persistence, readiness, live-config rejection, subnet policy, failed disarm, ordered stop and secret cleanup")
    }
}
