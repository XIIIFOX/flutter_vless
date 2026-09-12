import Foundation

@main struct Probe {
    static func main() async throws {
        let manager = PacketTunnelManager(providerBundleIdentifier: "fixture.XrayTunnel", groupIdentifier: "fixture")
        while manager.isProcessing { await Task.yield() }
        let permissionGranted = await manager.testSaveAndLoadProfile()
        precondition(permissionGranted)
        precondition(SDK.profile?.isEnabled == false && SDK.profile?.isOnDemandEnabled == false)
        try await manager.start()
        precondition(manager.isRecoveryEnabled)
        let protected = SDK.profile!.protocolConfiguration!
        precondition(protected.includeAllNetworks && !protected.excludeLocalNetworks)
        precondition(!protected.excludeAPNs && !protected.excludeCellularServices)
        precondition(!protected.disconnectOnSleep)
        SDK.profile?.connection.status = .connected
        await manager.refreshForwardingState()
        precondition(!manager.forwardingReady, "NE connected alone does not prove forwarding")
        SDK.providerResponse = Data("recovering".utf8)
        await manager.refreshForwardingState()
        precondition(!manager.forwardingReady)
        SDK.providerResponse = Data("ready".utf8)
        await manager.refreshForwardingState()
        precondition(manager.forwardingReady)
        SDK.profile?.connection.status = .reasserting
        await manager.refreshForwardingState()
        precondition(!manager.forwardingReady)
        let saved = SDK.saves
        SDK.failAllLoads = true
        do { try await manager.stop(); preconditionFailure("A failed preference load must fail stop") } catch SDKError.unavailable {}
        precondition(manager.isRecoveryEnabled && SDK.stopCalls == 0)
        do { try await manager.start(); preconditionFailure("Do not create a replacement profile when loading fails") } catch SDKError.unavailable {}
        precondition(SDK.saves == saved)
        let permission = await manager.testSaveAndLoadProfile()
        precondition(!permission && SDK.saves == saved && manager.isRecoveryEnabled)
        SDK.failAllLoads = false
        try await manager.stop()
        precondition(!manager.isRecoveryEnabled && SDK.stopCalls == 1)
        SDK.failAfterNextSave = true
        do { try await manager.start(); preconditionFailure("Expected post-save refresh failure") } catch SDKError.unavailable {}
        precondition(manager.isRecoveryEnabled, "An error after saving must retain the activated policy")
        SDK.profile?.connection.status = .connected
        SDK.providerResponse = Data("ready".utf8)
        await manager.refreshForwardingState()
        precondition(manager.forwardingReady)
        manager.bypassSubnets = ["1.1.1.1/32"]
        let beforeReject = SDK.saves
        do { try await manager.start(); preconditionFailure("Strict mode must reject route exclusions") } catch {}
        precondition(SDK.saves == beforeReject && manager.isRecoveryEnabled && manager.forwardingReady)
        try await manager.stop()
        precondition(SDK.profile?.isEnabled == false && SDK.profile?.isOnDemandEnabled == false)
        let legacy = NETunnelProviderProtocol()
        legacy.includeAllNetworks = false
        legacy.providerConfiguration = ["protectTraffic": false]
        SDK.profile?.protocolConfiguration = legacy
        manager.bypassSubnets = []
        try await manager.start()
        precondition(manager.isRecoveryEnabled)
        let migrated = SDK.profile!.protocolConfiguration as! NETunnelProviderProtocol
        precondition(migrated.includeAllNetworks && !migrated.excludeLocalNetworks)
        precondition(!migrated.excludeAPNs && !migrated.excludeCellularServices)
        precondition(migrated.providerConfiguration?["protectTraffic"] == nil)
        SDK.profile?.connection.status = .connected
        SDK.delayedStop = true
        try await manager.stop(waitForDisconnect: true)
        precondition(manager.status == .disconnected, "Proxy-only must wait for extension teardown before reusing its port")
        precondition(SDK.profile?.isEnabled == false && SDK.profile?.isOnDemandEnabled == false)
        for invalid in [["10.0.0.0/8"], ["10.0.0.0/8", 42] as [Any], "10.0.0.0/8"] as [Any] {
            let entry = NativeStartEntryProbe()
            entry.start(arguments: ["bypass_subnets": invalid, "ios_traffic_protection": false])
            precondition(!entry.reachedQueue, "Rejected raw bypass input must not enqueue any session change")
        }
        for arguments in [[:], ["bypass_subnets": NSNull()], ["bypass_subnets": [String](), "ios_traffic_protection": false], ["proxy_only": true, "bypass_subnets": ["10.0.0.0/8"]]] as [[String: Any]] {
            let entry = NativeStartEntryProbe()
            entry.start(arguments: arguments)
            precondition(entry.reachedQueue)
        }
        let provider = ProviderEntryProbe()
        let oldProfile = NETunnelProviderProtocol()
        oldProfile.providerConfiguration = ["protectTraffic": true]
        provider.protocolConfiguration = oldProfile
        do { try await provider.startTunnel(options: nil); preconditionFailure("Legacy unprotected profiles must not reach bootstrap") } catch {}
        precondition(!provider.reachedBootstrap)
        oldProfile.includeAllNetworks = true
        oldProfile.excludeLocalNetworks = false
        oldProfile.excludeAPNs = false
        oldProfile.excludeCellularServices = false
        oldProfile.providerConfiguration = ["bypassSubnets": ["10.0.0.0/8"]]
        do { try await provider.startTunnel(options: nil); preconditionFailure("Saved route exclusions must not reach bootstrap") } catch {}
        precondition(!provider.reachedBootstrap)
        for invalid in [["10.0.0.0/8", 42] as [Any], "10.0.0.0/8", ["route": "10.0.0.0/8"]] as [Any] {
            oldProfile.providerConfiguration = ["bypassSubnets": invalid]
            do { try await provider.startTunnel(options: nil); preconditionFailure("Malformed saved bypass input must not be ignored") } catch {}
            precondition(!provider.reachedBootstrap)
        }
        for exclusion in ["local", "apns", "cellular"] {
            oldProfile.providerConfiguration = [:]
            oldProfile.excludeLocalNetworks = exclusion == "local"
            oldProfile.excludeAPNs = exclusion == "apns"
            oldProfile.excludeCellularServices = exclusion == "cellular"
            do { try await provider.startTunnel(options: nil); preconditionFailure("Excluded service profile must not reach bootstrap") } catch {}
            precondition(!provider.reachedBootstrap)
        }
        oldProfile.excludeLocalNetworks = false
        oldProfile.excludeAPNs = false
        oldProfile.excludeCellularServices = false
        oldProfile.providerConfiguration = ["protectTraffic": false, "bypassSubnets": [String]()]
        try await provider.startTunnel(options: nil)
        precondition(provider.reachedBootstrap, "Obsolete metadata cannot disable the required OS protection")
        print("PASS: preference-load errors; post-save failure; strict bypass rejection; mandatory policy, legacy migration and proxy-switch teardown")
    }
}
