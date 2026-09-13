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
        SDK.delayedStop = true
        try await manager.stop(waitForDisconnect: true)
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
        print("PASS macOS manager: mandatory policy, private persistence, readiness, live-config rejection, subnet policy, failed disarm, ordered stop and secret cleanup")
    }
}
