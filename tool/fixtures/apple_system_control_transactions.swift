import Foundation

actor InertGate {
    private var entered = false
    private var held: CheckedContinuation<Void, Never>?
    private var observers: [CheckedContinuation<Void, Never>] = []
    func hold() async {
        entered = true
        let waiting = observers; observers = []
        waiting.forEach { $0.resume() }
        await withCheckedContinuation { held = $0 }
    }
    func waitUntilHeld() async {
        if entered { return }
        await withCheckedContinuation { observers.append($0) }
    }
    func release() { let pending = held; held = nil; pending?.resume() }
}
actor InertSignal {
    private var signaled = false
    private var observers: [CheckedContinuation<Void, Never>] = []
    func signal() { signaled = true; let waiting = observers; observers = []; waiting.forEach { $0.resume() } }
    func wait() async { if signaled { return }; await withCheckedContinuation { observers.append($0) } }
}

@main struct Audit {
    static let group = "in-memory-only.group", provider = "in-memory-only.provider"
    static var failures = 0, controls = 0, cases = 0
    static var lastFailure: Error?
    static func options(action: String = "toggle", unlock: Bool = true, enabled: Bool = true) -> VlessNativeOptions {
        try! VlessNativeOptions(["quickAccess": ["enabled": enabled, "action": action, "requireUnlock": unlock]])
    }
    static func configure(_ value: VlessNativeOptions) {
        VlessSystemControl.configure(group: group, provider: provider, options: value)
    }
    static func setup(_ value: VlessNativeOptions) {
        Boundary.reset()
        let manager = NETunnelProviderManager(), configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = provider
        configuration.providerConfiguration = ["groupIdentifier": group, "xrayConfigReference": Data([1, 2, 3])]
        manager.protocolConfiguration = configuration; Boundary.profile = manager
        configure(value)
        VlessSystemControl.authorizeProfile(group: group, provider: provider, reference: Data([1, 2, 3]))
    }
    static func check(_ desired: Bool, _ name: String, control: Bool = false) {
        cases += 1
        if !desired { failures += 1 }
        if control && desired { controls += 1 }
        print("CASE=\(name);DESIRED_PASS=\(desired);STARTS=\(Boundary.starts);SAVES=\(Boundary.saves);AUTH=\(Boundary.authorizations);STORED_ON_DEMAND=\(Boundary.stored?.onDemand ?? false)")
    }
    static func perform(_ connected: Bool = true, duringAuth: (() -> Void)? = nil) async -> Bool {
        lastFailure = nil
        do {
            try await VlessSystemControl.perform(connected, group: group, provider: provider) {
                Boundary.authorizations += 1; duringAuth?()
            }
            return true
        } catch { lastFailure = error; return false }
    }
    static func main() async {
        setup(options())
        let normal = await perform()
        check(normal && Boundary.starts == 1 && Boundary.authorizations == 1, "unchanged-toggle", control: true)

        setup(options(action: "openApp"))
        let open = await perform()
        check(open && Boundary.starts == 0 && Boundary.saves == 0, "unchanged-openApp", control: true)

        setup(options(action: "openApp"))
        _ = await perform(duringAuth: { configure(options(action: "toggle")) })
        check(Boundary.starts == 0 && Boundary.saves == 0, "openApp-must-not-become-toggle-during-auth")

        setup(options())
        let disabled = await perform(duringAuth: { configure(options(enabled: false)) })
        check(!disabled && Boundary.starts == 0 && Boundary.saves == 0, "disabled-during-auth-refuses", control: true)

        setup(options())
        Boundary.onLoadAll = { configure(options(action: "openApp")) }
        _ = await perform()
        check(Boundary.starts == 0 && Boundary.saves == 0, "action-change-during-profile-load-refuses")

        setup(options(unlock: false))
        Boundary.onSave = { configure(options(unlock: true)) }
        _ = await perform()
        check(Boundary.starts == 0 && Boundary.authorizations == 0, "new-unlock-requirement-during-save-refuses")

        setup(options())
        Boundary.onSave = { configure(options(enabled: false)) }
        let revoked = await perform()
        check(!revoked && Boundary.starts == 0 && Boundary.stored?.onDemand == false,
              "disabled-after-save-must-not-leave-new-arming")

        setup(options(action: "openApp"))
        Boundary.stored = nil
        VlessSystemControl.clear(group: group)
        let openWithoutProfile = await perform()
        check(openWithoutProfile && Boundary.loads == 0 && Boundary.saves == 0 && Boundary.starts == 0,
              "openApp-without-profile-or-reference", control: true)

        setup(options())
        let staged = await perform()
        let savedOptions = try? VlessNativeOptions(Boundary.stored?.metadata["options"] as? [String: Any])
        check(staged && Boundary.stored?.enabled == true && Boundary.stored?.onDemand == false
              && Boundary.stored?.rules == 0 && savedOptions?.enableOnDemand == true
              && Boundary.startWasDisarmed == [true], "start-stages-OFF-with-requested-provider-recovery", control: true)

        setup(options())
        _ = await perform(duringAuth: {
            VlessSystemControl.authorizeProfile(group: group, provider: provider, reference: Data([4, 5, 6]))
        })
        check(Boundary.starts == 0 && Boundary.saves == 0, "profile-authorization-change-during-auth-refuses")

        setup(options())
        Boundary.mutateStore { $0.enabled = true; $0.onDemand = true; $0.rules = 1; $0.connection.status = .connected }
        VlessSystemControl.clear(group: group)
        let stoppedAfterClear = await perform(false)
        check(stoppedAfterClear && Boundary.stops == 1 && Boundary.starts == 0
              && Boundary.stored?.enabled == false && Boundary.stored?.onDemand == false,
              "authenticated-Stop-after-clear", control: true)

        setup(options())
        Boundary.mutateStore { $0.enabled = true; $0.onDemand = true; $0.rules = 1; $0.connection.status = .connected }
        VlessSystemControl.clear(group: group)
        _ = await perform(false, duringAuth: {
            Boundary.mutateStore { $0.metadata["xrayConfigReference"] = Data([4, 5, 6]) }
        })
        check(Boundary.stops == 0 && Boundary.saves == 0 && Boundary.stored?.onDemand == true,
              "Stop-does-not-switch-protected-profile-after-auth")

        setup(options())
        Boundary.onRefresh = {
            Boundary.mutateStore {
                $0.metadata["xrayConfigReference"] = Data([4, 5, 6])
                $0.metadata["flutterVlessControlWrite"] = "synthetic-newer-write"
                $0.enabled = true; $0.onDemand = true; $0.rules = 1
            }
        }
        let newerProfile = await perform()
        check(!newerProfile && Boundary.starts == 0 && Boundary.saves == 1
              && Boundary.stored?.metadata["xrayConfigReference"] as? Data == Data([4, 5, 6])
              && Boundary.stored?.onDemand == true, "failed-stage-preserves-newer-unrelated-profile-without-compensation")

        setup(options())
        Boundary.onRefresh = {
            Boundary.mutateStore {
                $0.metadata["flutterVlessControlWrite"] = "synthetic-newer-write"
                $0.enabled = true; $0.onDemand = true; $0.rules = 1
            }
        }
        let newerWrite = await perform()
        check(!newerWrite && Boundary.starts == 0 && Boundary.saves == 1 && Boundary.stored?.onDemand == true,
              "failed-stage-preserves-newer-write-on-same-reference-without-compensation")

        setup(options())
        Boundary.onRefresh = { Boundary.mutateStore { $0.enabled = false; $0.onDemand = false; $0.rules = 0 } }
        let hostStop = await perform()
        check(!hostStop && Boundary.starts == 0 && Boundary.saves == 1 && Boundary.stored?.enabled == false,
              "failed-stage-preserves-observed-host-Stop-without-compensation")

        setup(options())
        Boundary.failNextStart = true
        let nativeThrow = await perform()
        check(!nativeThrow && Boundary.starts == 1 && Boundary.saves == 1
              && Boundary.stored?.enabled == true && Boundary.stored?.onDemand == false
              && (lastFailure as? VlessSystemControl.Failure) == .cleanupUncertain,
              "native-Start-throw-reports-uncertainty-without-compensating-write")

        setup(options())
        Boundary.failNextSave = true
        let failedSave = await perform()
        check(!failedSave && Boundary.starts == 0 && Boundary.saves == 1
              && (lastFailure as? VlessSystemControl.Failure) == .cleanupUncertain,
              "failed-save-is-fixed-cleanup-uncertain")

        setup(options())
        Boundary.commitThenThrow = true
        let uncertain = await perform()
        check(!uncertain && Boundary.starts == 0 && Boundary.saves == 1
              && Boundary.stored?.onDemand == false
              && (lastFailure as? VlessSystemControl.Failure) == .cleanupUncertain,
              "uncertain-save-does-not-claim-rollback-or-arm")

        setup(options())
        Boundary.onSave = { Boundary.failNextRefresh = true }
        let refreshFailure = await perform()
        check(!refreshFailure && Boundary.starts == 0 && Boundary.saves == 1
              && Boundary.stored?.enabled == true && Boundary.stored?.onDemand == false
              && (lastFailure as? VlessSystemControl.Failure) == .cleanupUncertain,
              "completed-save-refresh-failure-preserves-OFF-stage-without-compensation")

        setup(options())
        Boundary.onRefresh = {
            Boundary.mutateStore { $0.enabled = true; $0.onDemand = true; $0.rules = 1 }
        }
        let rearmed = await perform()
        check(!rearmed && Boundary.starts == 0 && Boundary.saves == 1
              && (lastFailure as? VlessSystemControl.Failure) == .cleanupUncertain,
              "unexpected-rearm-refuses-without-false-cleanup-ACK")

        setup(options())
        Boundary.mutateStore { $0.enabled = true; $0.onDemand = true; $0.rules = 1; $0.connection.status = .reasserting }
        let alreadyActive = await perform()
        check(alreadyActive && Boundary.saves == 0 && Boundary.starts == 0 && Boundary.stored?.onDemand == true,
              "active-runtime-keeps-existing-policy", control: true)

        setup(options())
        let copy = Boundary.profile!
        copy.isEnabled = true; copy.isOnDemandEnabled = true
        (copy.protocolConfiguration as! NETunnelProviderProtocol).providerConfiguration?["xrayConfigReference"] = Data([9])
        check(Boundary.stored?.enabled == false && Boundary.stored?.onDemand == false
              && Boundary.stored?.metadata["xrayConfigReference"] as? Data == Data([1, 2, 3]),
              "fake-loaded-profile-is-not-persisted-snapshot-alias", control: true)

        setup(options())
        Boundary.mutateStore { $0.enabled = true; $0.onDemand = true; $0.rules = 1; $0.connection.status = .connected }
        Boundary.onRefresh = {
            // A newer same-reference host/control transaction is visible in
            // readback even if its final flags also happen to be disabled.
            Boundary.mutateStore { $0.metadata["flutterVlessControlWrite"] = "synthetic-newer-stop-owner" }
        }
        let replacedStop = await perform(false)
        check(!replacedStop && Boundary.saves == 1 && Boundary.stops == 0,
              "Stop-readback-refuses-newer-same-reference-write-token")

        setup(options())
        Boundary.onSave = { configure(options(enabled: false)) }
        let cancelledStage = await perform()
        check(!cancelledStage && Boundary.saves == 1 && Boundary.starts == 0 && Boundary.loads == 1
              && Boundary.stored?.enabled == true && Boundary.stored?.onDemand == false
              && (lastFailure as? VlessSystemControl.Failure) == .cleanupUncertain,
              "revocation-does-not-read-or-write-compensating-rollback")

        setup(options())
        Boundary.failNextStart = true
        _ = await perform()
        let text = (lastFailure as? LocalizedError)?.errorDescription
        check(text == "VPN action could not finish. Check the VPN status in the app before retrying."
              && text?.contains("synthetic-private-config-canary") == false && Boundary.saves == 1,
              "cleanup-uncertainty-has-fixed-user-message-without-native-details")

        setup(options())
        let heldAuth = InertGate()
        let oldStart = Task { () -> Bool in
            do {
                try await VlessSystemControl.perform(true, group: group, provider: provider) {
                    Boundary.authorizations += 1; await heldAuth.hold()
                }
                return true
            } catch { return false }
        }
        await heldAuth.waitUntilHeld()
        let laterStop = await perform(false)
        await heldAuth.release()
        let oldStartResult = await oldStart.value
        check(laterStop && !oldStartResult && Boundary.starts == 0 && Boundary.stops == 1
              && Boundary.saves == 1 && Boundary.stored?.enabled == false,
              "later-Control-Stop-revokes-older-held-auth-Start")

        setup(options())
        let reconfigureAuth = InertGate()
        let reconfiguredStart = Task { () -> Bool in
            do { try await VlessSystemControl.perform(true, group: group, provider: provider) { await reconfigureAuth.hold() }; return true }
            catch { return false }
        }
        await reconfigureAuth.waitUntilHeld()
        configure(options()) // Identical values still revoke the old transaction.
        await reconfigureAuth.release()
        let reconfiguredResult = await reconfiguredStart.value
        check(!reconfiguredResult && Boundary.starts == 0 && Boundary.saves == 0,
              "same-options-configure-revokes-held-auth-Start")

        setup(options())
        let clearedAuth = InertGate()
        let clearedStart = Task { () -> Bool in
            do { try await VlessSystemControl.perform(true, group: group, provider: provider) { await clearedAuth.hold() }; return true }
            catch { return false }
        }
        await clearedAuth.waitUntilHeld()
        VlessSystemControl.clear(group: group)
        VlessSystemControl.authorizeProfile(group: group, provider: provider, reference: Data([1, 2, 3]))
        await clearedAuth.release()
        let clearedResult = await clearedStart.value
        check(!clearedResult && Boundary.starts == 0 && Boundary.saves == 0,
              "clear-and-same-reference-reauthorize-revokes-held-auth-Start")

        setup(options())
        let heldSave = InertGate(), stopAdmitted = InertSignal()
        Boundary.onSaveSuspension = { await heldSave.hold() }
        let savingStart = Task { await perform() }
        await heldSave.waitUntilHeld()
        Boundary.onLoadAll = { Task { await stopAdmitted.signal() } }
        let stopWhileSaving = Task { await perform(false) }
        await stopAdmitted.wait() // Stop captured/revoked before entering its first profile await.
        await heldSave.release()
        let savingStartResult = await savingStart.value, savingStopResult = await stopWhileSaving.value
        check(!savingStartResult && savingStopResult && Boundary.starts == 0 && Boundary.stops == 1
              && Boundary.saves == 2 && Boundary.stored?.enabled == false && Boundary.stored?.onDemand == false,
              "Control-Stop-during-pending-save-prevents-old-native-Start")

        setup(options())
        Boundary.onSave = {
            VlessSystemControl.clear(group: group)
            VlessSystemControl.authorizeProfile(group: group, provider: provider, reference: Data([1, 2, 3]))
        }
        let clearDuringSave = await perform()
        check(!clearDuringSave && Boundary.starts == 0 && Boundary.saves == 1
              && Boundary.stored?.onDemand == false
              && (lastFailure as? VlessSystemControl.Failure) == .cleanupUncertain,
              "native-clear-during-save-prevents-Start-after-same-ref-reauthorize")

        setup(options())
        let stableStop = await perform(false), stableStart = await perform()
        check(stableStop && stableStart && Boundary.stops == 1 && Boundary.starts == 1 && Boundary.saves == 2
              && Boundary.stored?.onDemand == false, "stable-Control-off-then-on-retains-new-intent", control: true)

        setup(options())
        let unrelatedGroupAuth = InertGate()
        let unrelatedGroupStart = Task { () -> Bool in
            do { try await VlessSystemControl.perform(true, group: group, provider: provider) { await unrelatedGroupAuth.hold() }; return true }
            catch { return false }
        }
        await unrelatedGroupAuth.waitUntilHeld()
        VlessSystemControl.configure(group: "in-memory-only.other-group", provider: provider, options: options())
        await unrelatedGroupAuth.release()
        let unrelatedGroupResult = await unrelatedGroupStart.value
        check(unrelatedGroupResult && Boundary.starts == 1 && Boundary.saves == 1,
              "unrelated-group-configure-does-not-revoke-original-intent", control: true)

        setup(options())
        let unrelatedProviderAuth = InertGate()
        let unrelatedProviderStart = Task { () -> Bool in
            do { try await VlessSystemControl.perform(true, group: group, provider: provider) { await unrelatedProviderAuth.hold() }; return true }
            catch { return false }
        }
        await unrelatedProviderAuth.waitUntilHeld()
        do { try await VlessSystemControl.perform(false, group: group, provider: "in-memory-only.other-provider") {} } catch {}
        await unrelatedProviderAuth.release()
        let unrelatedProviderResult = await unrelatedProviderStart.value
        check(unrelatedProviderResult && Boundary.starts == 1 && Boundary.saves == 1,
              "unrelated-provider-Stop-does-not-revoke-original-intent", control: true)

        setup(options())
        let heldStopAuth = InertGate()
        let oldStop = Task { () -> Bool in
            do {
                try await VlessSystemControl.perform(false, group: group, provider: provider) { await heldStopAuth.hold() }
                return true
            } catch { return false }
        }
        await heldStopAuth.waitUntilHeld()
        let newerStart = await perform()
        await heldStopAuth.release()
        let oldStopResult = await oldStop.value
        check(newerStart && !oldStopResult && Boundary.starts == 1 && Boundary.stops == 0
              && Boundary.saves == 1 && Boundary.stored?.connection.status == .connecting,
              "later-Control-Start-revokes-older-held-auth-Stop")

        setup(options())
        let firstSameProfileStart = await perform(), secondSameProfileStart = await perform()
        check(firstSameProfileStart && secondSameProfileStart && Boundary.starts == 1 && Boundary.stops == 0
              && Boundary.saves == 1 && Boundary.stored?.connection.status == .connecting,
              "duplicate-stable-same-profile-Start-keeps-active-runtime", control: true)

        setup(options())
        Boundary.mutateStore { $0.enabled = true; $0.onDemand = true; $0.rules = 1; $0.connection.status = .connected }
        let oldControlStopAuth = InertGate()
        let oldControlStop = Task { () -> Bool in
            do {
                try await VlessSystemControl.perform(false, group: group, provider: provider) { await oldControlStopAuth.hold() }
                return true
            } catch { return false }
        }
        await oldControlStopAuth.waitUntilHeld()
        // Explicit app Connect has accepted its immutable revision; its owner
        // can be new even though the logical protected reference is unchanged.
        VlessSystemControl.authorizeProfile(group: group, provider: provider, reference: Data([1, 2, 3]))
        Boundary.mutateStore {
            $0.metadata["flutterVlessControlWrite"] = "synthetic-new-app-owner"
            $0.enabled = true; $0.onDemand = true; $0.rules = 1; $0.connection.status = .connected
        }
        await oldControlStopAuth.release()
        let oldControlStopResult = await oldControlStop.value
        check(!oldControlStopResult && Boundary.stops == 0 && Boundary.saves == 0
              && Boundary.stored?.connection.status == .connected && Boundary.stored?.onDemand == true,
              "same-reference-App-authorization-revokes-held-old-Control-Stop")

        print("DESIRED_FAILURES=\(failures);CONTROLS_PASS=\(controls);CASES=\(cases);REAL_AUTH_SETTINGS_OR_VPN_ACTIONS=0")
        exit(failures == 0 ? 0 : 1)
    }
}
