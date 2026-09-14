import Foundation
import NetworkExtension
import XCTest
@testable import flutter_vless_tunnel_support

final class TunnelOnDemandPolicyTests: XCTestCase {
    private func profile(_ identifier: String = "test.provider", reference: UInt8 = 1,
                         armed: Bool = true) -> NETunnelProviderManager {
        let manager = NETunnelProviderManager()
        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = identifier
        configuration.providerConfiguration = ["xrayConfigReference": Data([reference])]
        configuration.includeAllNetworks = true
        configuration.excludeLocalNetworks = false
        manager.protocolConfiguration = configuration
        manager.isEnabled = true
        manager.isOnDemandEnabled = armed
        manager.onDemandRules = armed ? [NEOnDemandRuleConnect()] : nil
        return manager
    }

    private func apply(_ enabled: Bool, _ manager: NETunnelProviderManager,
                       preferences: TunnelOnDemandPolicy.Preferences,
                       timeout: TimeInterval = 1) async -> Result<TunnelOnDemandPolicy.Outcome, Error> {
        await withCheckedContinuation { continuation in
            TunnelOnDemandPolicy.apply(enabled: enabled,
                configuration: manager.protocolConfiguration as! NETunnelProviderProtocol,
                preferences: preferences, timeout: timeout) { continuation.resume(returning: $0) }
        }
    }

    func testUserStopDisarmsOnlyItsProfileAndPreservesProtection() async throws {
        let target = profile(), other = profile("other.provider")
        let configuration = target.protocolConfiguration
        var saves = 0
        let result = await apply(false, target, preferences: .init(
            load: { $0([other, target], nil) },
            save: { manager, done in
                XCTAssertTrue(manager === target)
                saves += 1
                done(nil)
            }, refresh: { _, done in done(nil) }))
        XCTAssertEqual(try result.get(), .updated)
        XCTAssertEqual(saves, 1)
        XCTAssertFalse(target.isOnDemandEnabled)
        XCTAssertNil(target.onDemandRules)
        XCTAssertTrue(target.isEnabled)
        XCTAssertTrue(target.protocolConfiguration === configuration)
        XCTAssertTrue(target.protocolConfiguration!.includeAllNetworks)
        XCTAssertTrue(other.isOnDemandEnabled)
    }

    func testSystemConnectRearmsCrashRecovery() async throws {
        let target = profile(armed: false)
        let result = await apply(true, target, preferences: .init(
            load: { $0([target], nil) }, save: { _, done in done(nil) },
            refresh: { _, done in done(nil) }))
        XCTAssertEqual(try result.get(), .updated)
        XCTAssertTrue(target.isOnDemandEnabled)
        let rule = try XCTUnwrap(target.onDemandRules?.first as? NEOnDemandRuleConnect)
        XCTAssertEqual(rule.interfaceTypeMatch, .any)
    }

    func testAllNonUserStopsLeaveRecoveryArmedWithoutLoadingPreferences() throws {
        // Includes provider failure, network loss, sleep, update and future reasons.
        for raw in 0...20 where raw != NEProviderStopReason.userInitiated.rawValue {
            guard let reason = NEProviderStopReason(rawValue: raw) else { continue }
            let target = profile()
            var completed = false
            TunnelOnDemandPolicy.disableForUserStop(reason: reason,
                configuration: target.protocolConfiguration as! NETunnelProviderProtocol) { result in
                XCTAssertEqual(try? result.get(), .preservedForRecovery)
                completed = true
            }
            XCTAssertTrue(completed)
            XCTAssertTrue(target.isOnDemandEnabled)
        }
    }

    func testAlreadyDisarmedProfileIsNotSavedAgain() async throws {
        let target = profile(armed: false)
        let result = await apply(false, target, preferences: .init(
            load: { $0([target], nil) },
            save: { _, _ in XCTFail("No redundant save") },
            refresh: { _, _ in XCTFail("No redundant refresh") }))
        XCTAssertEqual(try result.get(), .unchanged)
    }

    func testOlderProviderCannotDisarmNewExplicitConnection() async {
        let old = profile(), replacement = profile(reference: 2)
        let result = await apply(false, old, preferences: .init(
            load: { $0([replacement], nil) },
            save: { _, _ in XCTFail("Must not disable replacement") },
            refresh: { _, _ in XCTFail("No save expected") }))
        guard case .failure(TunnelOnDemandPolicy.Failure.profileChanged) = result else {
            return XCTFail("Expected replaced profile")
        }
        XCTAssertTrue(replacement.isOnDemandEnabled)
    }

    func testAmbiguousProfileIsNotMutated() async {
        let target = profile(), duplicate = profile()
        let result = await apply(false, target, preferences: .init(
            load: { $0([target, duplicate], nil) },
            save: { _, _ in XCTFail("Ambiguous profile") }, refresh: { _, _ in }))
        guard case .failure(TunnelOnDemandPolicy.Failure.ambiguousProfile) = result else {
            return XCTFail("Expected ambiguity failure")
        }
        XCTAssertTrue(target.isOnDemandEnabled)
        XCTAssertTrue(duplicate.isOnDemandEnabled)
    }

    func testStaleSaveReloadsAndDoesNotDisarmReplacement() async {
        let target = profile(), replacement = profile(reference: 2)
        var loads = 0, saves = 0
        let result = await apply(false, target, preferences: .init(
            load: { callback in loads += 1; callback([loads == 1 ? target : replacement], nil) },
            save: { _, done in
                saves += 1
                done(NSError(domain: NEVPNErrorDomain, code: NEVPNError.configurationStale.rawValue))
            }, refresh: { _, _ in XCTFail("Save failed") }))
        guard case .failure(TunnelOnDemandPolicy.Failure.profileChanged) = result else {
            return XCTFail("Expected replaced profile")
        }
        XCTAssertEqual(loads, 2)
        XCTAssertEqual(saves, 1)
        XCTAssertTrue(replacement.isOnDemandEnabled)
    }

    func testReadbackMustConfirmDisarm() async {
        let target = profile()
        let result = await apply(false, target, preferences: .init(
            load: { $0([target], nil) }, save: { _, done in done(nil) },
            refresh: { manager, done in manager.isOnDemandEnabled = true; done(nil) }))
        guard case .failure(TunnelOnDemandPolicy.Failure.verificationFailed) = result else {
            return XCTFail("Must not report an unverified disarm")
        }
    }

    func testPermissionFailureIsReportedWithoutFurtherMutation() async {
        let target = profile()
        let result = await apply(false, target, preferences: .init(
            load: { $0(nil, NSError(domain: NEVPNErrorDomain, code: 5)) },
            save: { _, _ in XCTFail("Load failed") }, refresh: { _, _ in }))
        guard case .failure = result else { return XCTFail("Expected failure") }
        XCTAssertTrue(target.isOnDemandEnabled)
    }

    func testLateLoadAfterDeadlineDoesNotSaveOrCompleteTwice() async {
        let target = profile()
        var lateLoad: (([NETunnelProviderManager]?, Error?) -> Void)?
        var completions = 0
        let done = expectation(description: "bounded stop")
        TunnelOnDemandPolicy.apply(enabled: false,
            configuration: target.protocolConfiguration as! NETunnelProviderProtocol,
            preferences: .init(load: { lateLoad = $0 },
                save: { _, _ in XCTFail("Deadline expired") }, refresh: { _, _ in }),
            timeout: 0.02) { result in
                guard case .failure(TunnelOnDemandPolicy.Failure.timedOut) = result else {
                    XCTFail("Expected deadline"); return
                }
                completions += 1
                done.fulfill()
            }
        await fulfillment(of: [done], timeout: 1)
        lateLoad?([target], nil)
        try? await Task.sleep(nanoseconds: 30_000_000)
        XCTAssertEqual(completions, 1)
        XCTAssertTrue(target.isOnDemandEnabled)
    }

    func testStopDuringStartupLoadCannotRearmRecovery() async {
        let target = profile(armed: false)
        var stopped = false
        let done = expectation(description: "cancel startup policy")
        TunnelOnDemandPolicy.apply(enabled: true,
            configuration: target.protocolConfiguration as! NETunnelProviderProtocol,
            preferences: .init(load: { callback in
                stopped = true
                callback([target], nil)
            }, save: { _, _ in XCTFail("Startup was stopped") }, refresh: { _, _ in }),
            isCancelled: { stopped }) { result in
                guard case .failure(TunnelOnDemandPolicy.Failure.cancelled) = result else {
                    XCTFail("Expected cancelled startup"); return
                }
                done.fulfill()
            }
        await fulfillment(of: [done], timeout: 1)
        XCTAssertFalse(target.isOnDemandEnabled)
    }
}
