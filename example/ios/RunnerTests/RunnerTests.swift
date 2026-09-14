import Flutter
import UIKit
import XCTest
import Security
import NetworkExtension

class RunnerTests: XCTestCase {

  /// Opt in on a physical test device with an existing example VPN profile.
  /// This calls the system stop API directly, without the plugin's Disconnect.
  func testSystemStopDisarmsRecoveryAndSystemStartRearmsIt() async throws {
    guard ProcessInfo.processInfo.environment["FLUTTER_VLESS_TEST_SYSTEM_STOP"] == "1" else {
      throw XCTSkip("Requires an explicitly selected physical VPN test device")
    }
    let managers = try await NETunnelProviderManager.loadAllFromPreferences()
    let manager = try XCTUnwrap(managers.first {
      ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
        == "dev.tfox.flutterXrayExample.XrayTunnel"
    })
    XCTAssertNotNil((manager.protocolConfiguration as? NETunnelProviderProtocol)?
      .providerConfiguration?["xrayConfigReference"] as? Data)
    do {
      // Only this example's profile is changed; keep the user's server in Keychain.
      manager.isEnabled = true
      let rule = NEOnDemandRuleConnect()
      rule.interfaceTypeMatch = .any
      manager.onDemandRules = [rule]
      manager.isOnDemandEnabled = true
      try await manager.saveToPreferences()
      try await manager.loadFromPreferences()
      try manager.connection.startVPNTunnel()
      try await waitForTunnel(manager, status: .connected, onDemand: true)

      for _ in 0..<2 {
        manager.connection.stopVPNTunnel()
        try await waitForTunnel(manager, status: .disconnected, onDemand: false)
        try await Task.sleep(nanoseconds: 5_000_000_000)
        try await manager.loadFromPreferences()
        XCTAssertEqual(manager.connection.status, .disconnected)
        XCTAssertTrue(manager.isEnabled, "System Connect must remain available")
        XCTAssertTrue((manager.protocolConfiguration?.includeAllNetworks) == true)
        try manager.connection.startVPNTunnel()
        try await waitForTunnel(manager, status: .connected, onDemand: true)
      }
    } catch {
      try? await stopTestTunnel(manager)
      throw error
    }
    try await stopTestTunnel(manager)
  }

  private func waitForTunnel(_ manager: NETunnelProviderManager, status: NEVPNStatus,
                            onDemand: Bool) async throws {
    let deadline = Date().addingTimeInterval(90)
    while Date() < deadline {
      try await manager.loadFromPreferences()
      if manager.connection.status == status && manager.isOnDemandEnabled == onDemand { return }
      try await Task.sleep(nanoseconds: 500_000_000)
    }
    throw NSError(domain: "VPNLifecycleTest", code: 1, userInfo: [NSLocalizedDescriptionKey:
      "Timed out: status=\(manager.connection.status.rawValue), onDemand=\(manager.isOnDemandEnabled)"])
  }

  private func stopTestTunnel(_ manager: NETunnelProviderManager) async throws {
    try await manager.loadFromPreferences()
    manager.isOnDemandEnabled = false
    manager.onDemandRules = nil
    try await manager.saveToPreferences()
    manager.connection.stopVPNTunnel()
  }

  /// Staged device probe: the external test driver terminates the containing
  /// app and/or provider between phases. No crash trigger is shipped in the VPN.
  /// Install once while VPN is stopped, then use .xctestrun
  /// UseDestinationArtifacts=true between phases so Xcode does not replace a
  /// running protected extension and turn the probe into an app-update test.
  func testExternalLifecycleProbe() async throws {
    let phase = ProcessInfo.processInfo.environment["FLUTTER_VLESS_TEST_EXTERNAL_LIFECYCLE"] ?? ""
    guard ["prepare", "verify-recovery", "verify-stop"].contains(phase) else {
      throw XCTSkip("Requires an external driver and an explicitly selected test device")
    }
    let profiles = try await NETunnelProviderManager.loadAllFromPreferences()
    let manager = try XCTUnwrap(profiles.first {
      ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
        == "dev.tfox.flutterXrayExample.XrayTunnel"
    })
    do {
      if phase == "prepare" {
        manager.isEnabled = true
        let rule = NEOnDemandRuleConnect()
        rule.interfaceTypeMatch = .any
        manager.onDemandRules = [rule]
        manager.isOnDemandEnabled = true
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        try manager.connection.startVPNTunnel()
      }
      if phase == "verify-stop" {
        // Check the persisted state before any plugin or test stop operation.
        XCTAssertFalse(manager.isOnDemandEnabled)
        XCTAssertTrue((manager.onDemandRules ?? []).isEmpty)
        XCTAssertEqual(manager.connection.status, .disconnected)
      } else {
        try await waitForTunnel(manager, status: .connected, onDemand: true)
        XCTAssertTrue(manager.protocolConfiguration?.includeAllNetworks == true)
      }
    } catch {
      try? await stopTestTunnel(manager)
      throw error
    }
    // prepare / verify-recovery intentionally leave the tunnel running so the
    // driver can test it with this app process absent. verify-stop leaves it off.
  }

  func testSignedKeychainPersistentReferenceRoundTripAndScope() throws {
    let group = try XCTUnwrap(Bundle.main.object(forInfoDictionaryKey: "FlutterVlessKeychainAccessGroup") as? String)
    let provider = "test." + UUID().uuidString
    let store = try TunnelSecretStore(accessGroup: group, providerBundleIdentifier: provider)
    let data = Data("device-only-test-canary".utf8)
    let reference = try store.insert(data)
    defer { try? store.reconcile(keeping: []) }
    XCTAssertEqual(try store.read(reference), data)
    let other = try TunnelSecretStore(accessGroup: group, providerBundleIdentifier: provider + ".other")
    XCTAssertThrowsError(try other.read(reference))
    try other.remove(reference)
    XCTAssertEqual(try store.read(reference), data)
    try store.reconcile(keeping: [reference])
    XCTAssertEqual(try store.read(reference), data)
    try store.remove(reference)
    XCTAssertThrowsError(try store.read(reference))
  }

}
