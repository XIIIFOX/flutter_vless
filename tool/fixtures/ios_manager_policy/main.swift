import Foundation
import Security

@main struct Probe {
    static func main() async throws {
        let keychain = FixtureKeychain()
        let manager = PacketTunnelManager(providerBundleIdentifier: "fixture.XrayTunnel", groupIdentifier: "fixture",
                                          keychainAccessGroup: "TEAM.fixture.shared", keychainClient: keychain)
        manager.xrayConfig = Data("{\"secret\":\"control-password\"}".utf8)
        while manager.isProcessing { await Task.yield() }
        let permissionGranted = await manager.testSaveAndLoadProfile()
        precondition(permissionGranted)
        precondition(keychain.records.isEmpty, "Permission must not write any secret")
        precondition((SDK.profile?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["xrayConfig"] == nil)
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
        provider.keychain = keychain
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
        oldProfile.providerConfiguration = ["protectTraffic": false, "bypassSubnets": [String](), "xrayConfig": Data("legacy-password".utf8)]
        do { try await provider.startTunnel(options: nil); preconditionFailure("Legacy plaintext must require app migration") }
        catch TunnelSecretError.migrationRequired {}
        precondition(!provider.reachedBootstrap)
        oldProfile.providerBundleIdentifier = "fixture.XrayTunnel"
        let providerStore = try TunnelSecretStore(accessGroup: "TEAM.fixture.shared", providerBundleIdentifier: "fixture.XrayTunnel", client: keychain)
        let providerReference = try providerStore.insert(Data("working-config".utf8))
        oldProfile.providerConfiguration = ["protectTraffic": false, "bypassSubnets": [String](),
            "configSchemaVersion": 2, "xrayConfigReference": providerReference, "keychainAccessGroup": "TEAM.fixture.shared"]
        keychain.failure = errSecInteractionNotAllowed
        do { try await provider.startTunnel(options: nil); preconditionFailure("Locked Keychain cannot reach DNS bootstrap or install routes") } catch {}
        precondition(!provider.reachedBootstrap)
        keychain.failure = nil
        try await provider.startTunnel(options: nil)
        precondition(provider.reachedBootstrap, "Obsolete metadata cannot disable the required OS protection")
        try await verifyStatusNotificationScope(manager)
        try await verifySecretTransactions()
        print("PASS: preference-load errors; transactional Keychain rollback/migration/cleanup; permission privacy; cold-start secret denial; traffic protection and proxy-switch teardown")
    }
}

func verifySecretTransactions() async throws {
    SDK.profile = nil
    SDK.delayedStop = false
    let keychain = FixtureKeychain()
    let manager = PacketTunnelManager(providerBundleIdentifier: "transaction.XrayTunnel", groupIdentifier: "fixture",
        keychainAccessGroup: "TEAM.fixture.shared", keychainClient: keychain)
    while manager.isProcessing { await Task.yield() }
    manager.xrayConfig = Data("{\"remote-password\":\"old-secret\"}".utf8)
    try await manager.start()
    let firstMetadata = (SDK.profile!.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
    let first = try TunnelSecretProfile.reference(in: firstMetadata)
    precondition(firstMetadata["xrayConfig"] == nil)
    SDK.profile!.connection.status = .connected
    SDK.providerResponse = Data("ready".utf8)
    await manager.refreshForwardingState()
    let stops = SDK.stopCalls
    let saves = SDK.saves
    keychain.failure = errSecMissingEntitlement
    manager.xrayConfig = Data("new-secret".utf8)
    do { try await manager.start(); preconditionFailure("Wrong access group must reject the new profile") } catch {}
    precondition(SDK.saves == saves && SDK.stopCalls == stops && manager.forwardingReady && manager.isRecoveryEnabled)
    keychain.failure = nil
    SDK.failNextSave = true
    do { try await manager.start(); preconditionFailure("Profile save failure must rollback") } catch {}
    precondition((try? TunnelSecretProfile.reference(in: (SDK.profile!.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!)) == first)
    precondition(keychain.records[first] != nil && manager.isRecoveryEnabled)
    keychain.failReadNumber = keychain.readCount + 2
    do { try await manager.start(); preconditionFailure("Post-save Keychain read failure must rollback") } catch {}
    keychain.failReadNumber = nil
    precondition((try? TunnelSecretProfile.reference(in: (SDK.profile!.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!)) == first)
    precondition(keychain.records[first] != nil && SDK.stopCalls == stops && manager.isRecoveryEnabled)
    // Successful replacement still retains every possibly active old revision.
    try await manager.start()
    let second = try TunnelSecretProfile.reference(in: (SDK.profile!.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!)
    precondition(second != first && keychain.records[first] != nil)
    keychain.deleteFailure = errSecInteractionNotAllowed
    try await manager.stop(waitForDisconnect: true)
    precondition(keychain.records[first] != nil, "A deletion failure is retried from persistent inventory")
    keychain.deleteFailure = nil
    await manager.reload()
    precondition(keychain.records.count == 1 && keychain.records[second] != nil, "Stop keeps the profile secret; reload retires old revisions")
    // Migration on app load is idempotent and never saves plaintext on success.
    let legacy = SDK.profile!.protocolConfiguration as! NETunnelProviderProtocol
    legacy.providerConfiguration = ["xrayConfig": Data("legacy-secret".utf8), "groupIdentifier": "fixture", "accidentalPassword": "must-drop"]
    SDK.failNextSave = true
    await manager.reload()
    precondition((SDK.profile!.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration?["xrayConfig"] as? Data == Data("legacy-secret".utf8),
                 "Interrupted migration keeps the original profile until a successful retry")
    await manager.reload()
    let migrated = (SDK.profile!.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
    precondition(migrated["xrayConfig"] == nil && migrated["accidentalPassword"] == nil)
    let count = keychain.records.count
    await manager.reload()
    precondition(keychain.records.count == count)
    SDK.profile!.connection.status = .connected
    SDK.delayedStop = true
    try await manager.removeFromPreferences()
    precondition(SDK.profile == nil && keychain.records.isEmpty && manager.status == nil)
}

@MainActor func verifyStatusNotificationScope(_ manager: PacketTunnelManager) async throws {
    var callbacks = 0
    manager.statusDidChange = { _ in callbacks += 1 }
    let loads = SDK.loads
    NotificationCenter.default.post(name: .NEVPNStatusDidChange, object: NEVPNConnection())
    try await Task.sleep(nanoseconds: 100_000_000)
    precondition(callbacks == 0 && SDK.loads == loads,
                 "Foreign or temporary connection notifications must not trigger status or preference reads")
    SDK.notifyTemporaryConnections = true
    NotificationCenter.default.post(name: .NEVPNStatusDidChange, object: SDK.profile!.connection)
    try await Task.sleep(nanoseconds: 100_000_000)
    SDK.notifyTemporaryConnections = false
    precondition(callbacks == 1 && SDK.loads == loads + 1,
                 "Current connection must emit once; cleanup loads must not recursively trigger cleanup")
    manager.statusDidChange = nil
}
