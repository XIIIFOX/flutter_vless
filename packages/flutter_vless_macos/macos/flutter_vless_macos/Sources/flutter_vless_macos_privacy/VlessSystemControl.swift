import Foundation
import NetworkExtension
import WidgetKit

/// Native entry point shared by the app, menu bar and Control Widget intents.
/// Shared defaults contain presentation/identity only. Credentials stay in Keychain.
public enum VlessSystemControl {
    public enum Failure: Error { case unavailable, profileMissing, ambiguousProfile, profileChanged, verificationFailed }
    private static let metadataKey = "flutter_vless.controls.v1"
    private static let operations = OperationSerialiser()

    public static func reloadControls() {
        #if os(macOS) && compiler(<6.2)
        return
        #else
        if #available(iOS 18.0, macOS 26.0, *) { ControlCenter.shared.reloadControls(ofKind: "dev.tfox.flutter-vless.control") }
        #endif
    }

    public static func configure(group: String, provider: String, options: VlessNativeOptions) {
        guard let defaults = UserDefaults(suiteName: group) else { return }
        var metadata: [String: Any] = ["provider": provider, "options": options.dictionary]
        if options.quickAccessEnabled, let previous = defaults.dictionary(forKey: metadataKey),
           previous["provider"] as? String == provider, let reference = previous["reference"] as? Data {
            metadata["reference"] = reference
        }
        defaults.set(metadata, forKey: metadataKey)
        reloadControls()
    }

    public static func options(group: String) -> VlessNativeOptions? {
        guard let metadata = UserDefaults(suiteName: group)?.dictionary(forKey: metadataKey),
              let raw = metadata["options"] as? [String: Any] else { return nil }
        return try? VlessNativeOptions(raw)
    }

    /// Removes permission to reuse the saved system profile, without stopping it.
    public static func clear(group: String) {
        guard let defaults = UserDefaults(suiteName: group), var metadata = defaults.dictionary(forKey: metadataKey) else { return }
        metadata.removeValue(forKey: "reference")
        defaults.set(metadata, forKey: metadataKey)
        reloadControls()
    }

    /// Called after an explicit app Connect verifies its immutable Keychain revision.
    public static func authorizeProfile(group: String, provider: String, reference: Data) {
        guard !reference.isEmpty, let defaults = UserDefaults(suiteName: group),
              var metadata = defaults.dictionary(forKey: metadataKey), metadata["provider"] as? String == provider,
              options(group: group)?.quickAccessEnabled == true else { return }
        metadata["reference"] = reference
        defaults.set(metadata, forKey: metadataKey)
        reloadControls()
    }

    public static func isConnected(group: String, provider: String) async -> Bool {
        guard let options = options(group: group), options.quickAccessEnabled,
              let manager = try? await matching(group: group, provider: provider, requireAuthorization: false) else { return false }
        return isActive(manager.connection.status)
    }

    /// Authentication is injected so tests never present UI or touch host VPNs.
    public static func perform(_ connected: Bool, group: String, provider: String,
                               authorize: () async throws -> Void) async throws {
        guard let initial = options(group: group), initial.quickAccessEnabled else { throw Failure.unavailable }
        if initial.requireUnlock { try await authorize() }
        guard let current = options(group: group), current.quickAccessEnabled,
              !current.requireUnlock || initial.requireUnlock else { throw Failure.unavailable }
        if current.quickAccessAction == "toggle" { try await setConnected(connected, group: group, provider: provider) }
    }

    public static func setConnected(_ connected: Bool, group: String, provider: String) async throws {
        try await operations.run {
            guard let options = options(group: group), options.quickAccessEnabled,
                  options.quickAccessAction == "toggle" else { throw Failure.unavailable }
            let manager = try await matching(group: group, provider: provider, requireAuthorization: connected)
            // A preceding provider's stop callback must finish before rearming
            // the same immutable profile from a rapid off/on control sequence.
            try await waitForDisconnectIfStopping(manager)
            if connected && isActive(manager.connection.status) { return }
            guard let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  let reference = configuration.providerConfiguration?["xrayConfigReference"] as? Data else { throw Failure.profileMissing }
            // The app has already validated and saved this immutable Keychain revision.
            // A control never accepts JSON, URL, arbitrary provider id or credentials.
            if connected {
                var metadata = configuration.providerConfiguration ?? [:]
                metadata["options"] = options.dictionary
                configuration.providerConfiguration = metadata
            }
            manager.isEnabled = connected
            manager.isOnDemandEnabled = connected && options.enableOnDemand
            if manager.isOnDemandEnabled {
                let rule = NEOnDemandRuleConnect(); rule.interfaceTypeMatch = .any
                manager.onDemandRules = [rule]
            } else { manager.onDemandRules = nil }
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            guard let fresh = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  fresh.providerBundleIdentifier == provider,
                  fresh.providerConfiguration?["groupIdentifier"] as? String == group,
                  fresh.providerConfiguration?["xrayConfigReference"] as? Data == reference,
                  manager.isEnabled == connected,
                  manager.isOnDemandEnabled == (connected && options.enableOnDemand) else { throw Failure.verificationFailed }
            // Recheck opt-in after the asynchronous preference transaction.
            guard self.options(group: group)?.quickAccessEnabled == true,
                  (!connected || UserDefaults(suiteName: group)?.dictionary(forKey: metadataKey)?["reference"] as? Data == reference) else { throw Failure.unavailable }
            if connected {
                if !isActive(manager.connection.status) { try manager.connection.startVPNTunnel() }
            } else {
                manager.connection.stopVPNTunnel()
                let deadline = Date().addingTimeInterval(8)
                while manager.connection.status != .disconnected && manager.connection.status != .invalid {
                    guard Date() < deadline else { throw Failure.verificationFailed }
                    try await Task.sleep(nanoseconds: 50_000_000)
                }
            }
            reloadControls()
        }
    }

    public static func isActive(_ status: NEVPNStatus) -> Bool {
        [.connecting, .connected, .reasserting].contains(status)
    }

    private static func waitForDisconnectIfStopping(_ manager: NETunnelProviderManager) async throws {
        let deadline = Date().addingTimeInterval(8)
        while manager.connection.status == .disconnecting {
            guard Date() < deadline else { throw Failure.verificationFailed }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
    }

    private static func matching(group: String, provider: String, requireAuthorization: Bool = true) async throws -> NETunnelProviderManager {
        guard let metadata = UserDefaults(suiteName: group)?.dictionary(forKey: metadataKey),
              metadata["provider"] as? String == provider else { throw Failure.unavailable }
        let authorizedReference = metadata["reference"] as? Data
        guard !requireAuthorization || authorizedReference != nil else { throw Failure.unavailable }
        let matches = try await NETunnelProviderManager.loadAllFromPreferences().filter { manager in
            guard let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol else { return false }
            let data = configuration.providerConfiguration ?? [:]
            return configuration.providerBundleIdentifier == provider && data["groupIdentifier"] as? String == group
                && (data["xrayConfigReference"] as? Data)?.isEmpty == false
                && (!requireAuthorization || data["xrayConfigReference"] as? Data == authorizedReference) && configuration.includeAllNetworks
                && !configuration.excludeLocalNetworks && data["proxyOnly"] as? Bool != true
        }
        guard matches.count == 1, let manager = matches.first else {
            throw matches.isEmpty ? Failure.profileMissing : Failure.ambiguousProfile
        }
        return manager
    }

    private actor OperationSerialiser {
        private var tail: Task<Void, Never>?
        func run(_ body: @escaping () async throws -> Void) async throws {
            let previous = tail
            let task = Task { await previous?.value; try await body() }
            tail = Task { _ = try? await task.value }
            try await task.value
        }
    }
}
