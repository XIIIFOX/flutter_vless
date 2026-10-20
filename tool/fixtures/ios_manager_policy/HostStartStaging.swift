import Foundation

// Executes actual PacketTunnelManager.start/persist with only the OS and
// Keychain boundaries replaced. No NetworkExtension preferences are accessed.
func verifyHostStartStaging() async throws {
    var failures: [String] = []
    func check(_ value: Bool, _ name: String) {
        FileHandle.standardOutput.write(Data("HOST_START_STAGING \(value ? "PASS" : "FAIL") \(name)\n".utf8))
        if !value { failures.append(name) }
    }
    func makeManager() async -> (PacketTunnelManager, FixtureKeychain) {
        let keychain = FixtureKeychain()
        let manager = PacketTunnelManager(providerBundleIdentifier: "staging.XrayTunnel", groupIdentifier: "fixture",
            keychainAccessGroup: "TEAM.fixture.shared", keychainClient: keychain)
        while manager.isProcessing { await Task.yield() }
        manager.xrayConfig = Data("host-staging-config".utf8)
        return (manager, keychain)
    }

    SDK.reset()
    do {
        let (manager, _) = await makeManager()
        try await manager.start()
        let profile = SDK.profile!
        let metadata = (profile.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
        check(profile.isEnabled && !profile.isOnDemandEnabled && profile.onDemandRules == nil
            && !manager.isRecoveryEnabled && SDK.startWasDisarmed == [true], "fresh-start-staged-before-os-start")
        check(try VlessNativeOptions(metadata["options"] as? [String: Any]).enableOnDemand,
            "requested-on-demand-policy-retained")
        try SDK.simulateProviderAdmission()
        check(manager.isRecoveryEnabled && profile.onDemandRules?.count == 1, "explicit-provider-admission")
        profile.connection.status = .connected
        let saves = SDK.saves, starts = SDK.startCalls
        try await manager.start()
        check(SDK.saves == saves && SDK.startCalls == starts && manager.isRecoveryEnabled, "active-idempotence")
        manager.xrayConfig = Data("different-active-config".utf8)
        var refused = false
        do { try await manager.start() } catch { refused = true }
        check(refused && SDK.saves == saves && manager.isRecoveryEnabled, "active-replacement-refused")
        do {
            _ = try VlessNativeOptions(["reconnect": ["initialDelayMs": -1]])
            check(false, "invalid-options-no-mutation")
        } catch {
            check(SDK.saves == saves && manager.isRecoveryEnabled, "invalid-options-no-mutation")
        }
        try await manager.stop()
        check(!profile.isEnabled && !profile.isOnDemandEnabled && profile.onDemandRules == nil
            && SDK.stopCalls == 1 && profile.connection.status == .disconnected, "explicit-stop-disarmed")
    }

    SDK.reset()
    do {
        let (manager, _) = await makeManager()
        SDK.failNextStart = true
        var refused = false
        do { try await manager.start() } catch SDKError.unavailable { refused = true }
        check(refused && SDK.startCalls == 1 && SDK.startWasDisarmed == [true]
            && SDK.profile?.isEnabled == true && SDK.profile?.isOnDemandEnabled == false
            && SDK.profile?.onDemandRules == nil && !manager.isRecoveryEnabled, "os-start-throw-stays-disarmed")
    }

    SDK.reset()
    do {
        let (manager, _) = await makeManager()
        try await manager.saveToPreferences()
        let prior = SDK.profile!.protocolConfiguration
        SDK.failAfterNextSave = true
        var refused = false
        do { try await manager.start() } catch SDKError.unavailable { refused = true }
        check(refused && SDK.startCalls == 0 && SDK.profile?.protocolConfiguration === prior
            && SDK.profile?.isEnabled == false && SDK.profile?.isOnDemandEnabled == false
            && SDK.profile?.onDemandRules == nil && !manager.isRecoveryEnabled, "refresh-failure-restores-prior-off")
    }

    for mutation in SDK.CandidateRefreshMutation.allCases {
        SDK.reset()
        let (manager, _) = await makeManager()
        try await manager.saveToPreferences()
        let prior = SDK.profile!.protocolConfiguration
        SDK.nextCandidateRefreshMutation = mutation
        var refused = false
        do { try await manager.start() } catch TunnelSecretError.profileVerificationFailed { refused = true }
        if mutation == .normalizedEmptyRules {
            check(!refused && SDK.candidateRefreshMutations == 1 && SDK.candidateReferenceUnchanged
                && SDK.startCalls == 1 && SDK.startWasDisarmed == [true] && SDK.profile?.isEnabled == true
                && SDK.profile?.isOnDemandEnabled == false && SDK.profile?.onDemandRules?.isEmpty == true
                && !manager.isRecoveryEnabled, "candidate-readback-normalized-empty-rules-accepted")
        } else {
            check(refused && SDK.candidateRefreshMutations == 1 && SDK.candidateReferenceUnchanged
                && SDK.startCalls == 0 && SDK.profile?.protocolConfiguration === prior
                && SDK.profile?.isEnabled == false && SDK.profile?.isOnDemandEnabled == false
                && SDK.profile?.onDemandRules == nil && !manager.isRecoveryEnabled,
                "candidate-readback-\(mutation.rawValue)-refused-before-os-start")
        }
    }

    SDK.reset()
    do {
        let (manager, keychain) = await makeManager()
        try await manager.start()
        try SDK.simulateProviderAdmission()
        let profile = SDK.profile!, prior = profile.protocolConfiguration
        let priorRules = profile.onDemandRules!
        let metadata = (prior as! NETunnelProviderProtocol).providerConfiguration!
        let reference = try TunnelSecretProfile.reference(in: metadata)
        profile.connection.status = .disconnected
        manager.xrayConfig = Data("new-staging-config".utf8)
        SDK.failAfterNextSave = true
        var refused = false
        do { try await manager.start() } catch SDKError.unavailable { refused = true }
        check(refused && SDK.startCalls == 1 && profile.protocolConfiguration === prior
            && profile.isEnabled && profile.isOnDemandEnabled && manager.isRecoveryEnabled
            && profile.onDemandRules?.first === priorRules.first && keychain.records[reference] != nil,
            "failed-replacement-restores-old-armed-reference")
    }

    SDK.reset()
    do {
        let profile = NETunnelProviderManager(), legacy = NETunnelProviderProtocol()
        legacy.providerBundleIdentifier = "staging.XrayTunnel"
        legacy.includeAllNetworks = true
        legacy.providerConfiguration = ["xrayConfig": Data("legacy-staging-config".utf8), "groupIdentifier": "fixture"]
        profile.protocolConfiguration = legacy
        profile.isEnabled = true; profile.isOnDemandEnabled = true
        let priorRule = NEOnDemandRuleConnect()
        profile.onDemandRules = [priorRule]
        SDK.profile = profile
        let (manager, keychain) = await makeManager()
        let migrated = (profile.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration!
        let reference = try TunnelSecretProfile.reference(in: migrated)
        check(profile.isEnabled && profile.isOnDemandEnabled && profile.onDemandRules?.first === priorRule
            && manager.isRecoveryEnabled && migrated["xrayConfig"] == nil && keychain.records[reference] != nil
            && SDK.startCalls == 0, "migration-preserves-established-recovery")
        let saves = SDK.saves
        await manager.reload()
        check(SDK.saves == saves && profile.isOnDemandEnabled && profile.onDemandRules?.first === priorRule,
            "migrated-reload-preserves-established-recovery")
    }

    SDK.reset()
    if !failures.isEmpty {
        throw NSError(domain: "fixture.host-start-staging", code: failures.count,
            userInfo: [NSLocalizedDescriptionKey: failures.joined(separator: ",")])
    }
    print("PASS host start staging, failure rollback and established recovery preservation")
}
