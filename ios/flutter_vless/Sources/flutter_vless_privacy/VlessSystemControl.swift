import Foundation
import NetworkExtension
import WidgetKit

/// Native entry point shared by the app, menu bar and Control Widget intents.
/// Shared defaults contain presentation/identity only. Credentials stay in Keychain.
public enum VlessSystemControl {
    public enum Failure: Error, LocalizedError {
        case unavailable, profileMissing, ambiguousProfile, profileChanged, verificationFailed, cleanupUncertain
        public var errorDescription: String? {
            switch self {
            case .cleanupUncertain: return "VPN action could not finish. Check the VPN status in the app before retrying."
            default: return nil
            }
        }
    }
    private static let metadataKey = "flutter_vless.controls.v1"
    private static let operations = OperationSerialiser()

    private struct Context: Hashable { let group: String; let provider: String }
    private static let generationLock = NSLock()
    private static var generations: [Context: UUID] = [:]

    // This process-local fence invalidates older intents before authentication
    // or preference awaits. It is not an OS preference compare-and-save.
    private static func generation(group: String, provider: String, revoke: Bool = false) -> UUID {
        generationLock.lock()
        defer { generationLock.unlock() }
        let key = Context(group: group, provider: provider)
        if !revoke, let value = generations[key] { return value }
        let value = UUID()
        generations[key] = value
        return value
    }

    public static func reloadControls() {
        #if os(macOS) && compiler(<6.2)
        return
        #else
        if #available(iOS 18.0, macOS 26.0, *) { ControlCenter.shared.reloadControls(ofKind: "dev.tfox.flutter-vless.control") }
        #endif
    }

    public static func configure(group: String, provider: String, options: VlessNativeOptions) {
        _ = generation(group: group, provider: provider, revoke: true)
        guard let defaults = UserDefaults(suiteName: group) else { return }
        if let previousProvider = defaults.dictionary(forKey: metadataKey)?["provider"] as? String,
           previousProvider != provider { _ = generation(group: group, provider: previousProvider, revoke: true) }
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
        if let provider = metadata["provider"] as? String { _ = generation(group: group, provider: provider, revoke: true) }
        metadata.removeValue(forKey: "reference")
        defaults.set(metadata, forKey: metadataKey)
        reloadControls()
    }

    /// Called after an explicit app Connect verifies its immutable Keychain revision.
    public static func authorizeProfile(group: String, provider: String, reference: Data) {
        guard !reference.isEmpty, let defaults = UserDefaults(suiteName: group),
              var metadata = defaults.dictionary(forKey: metadataKey), metadata["provider"] as? String == provider,
              options(group: group)?.quickAccessEnabled == true else { return }
        _ = generation(group: group, provider: provider, revoke: true)
        metadata["reference"] = reference
        defaults.set(metadata, forKey: metadataKey)
        reloadControls()
    }

    public static func isConnected(group: String, provider: String) async -> Bool {
        guard let options = options(group: group), options.quickAccessEnabled,
              let manager = try? await matching(group: group, provider: provider, requireAuthorization: false) else { return false }
        return isActive(manager.connection.status)
    }

    // A system intent keeps its original meaning across authentication and
    // preference awaits. In particular, openApp never acquires toggle authority.
    private struct Request {
        let group: String
        let provider: String
        let options: VlessNativeOptions
        let authorizedReference: Data?
        let generation: UUID
        var profileReference: Data?

        func check() throws {
            guard VlessSystemControl.generation(group: group, provider: provider) == generation else { throw Failure.unavailable }
            guard let metadata = UserDefaults(suiteName: group)?.dictionary(forKey: metadataKey),
                  metadata["provider"] as? String == provider,
                  metadata["reference"] as? Data == authorizedReference,
                  let current = VlessSystemControl.options(group: group), current.quickAccessEnabled,
                  NSDictionary(dictionary: current.dictionary).isEqual(to: options.dictionary) else { throw Failure.unavailable }
        }
    }

    private static func request(_ connected: Bool, group: String, provider: String) async throws -> Request {
        guard let metadata = UserDefaults(suiteName: group)?.dictionary(forKey: metadataKey),
              metadata["provider"] as? String == provider,
              let options = options(group: group), options.quickAccessEnabled else { throw Failure.unavailable }
        let generation = generation(group: group, provider: provider,
                                    revoke: options.quickAccessAction == "toggle")
        var request = Request(group: group, provider: provider, options: options,
                              authorizedReference: metadata["reference"] as? Data, generation: generation)
        if options.quickAccessAction == "toggle" {
            if connected {
                guard let reference = request.authorizedReference, !reference.isEmpty else { throw Failure.unavailable }
                request.profileReference = reference
            } else {
                // Stop still works after clear() revokes permission to start.
                let manager = try await matching(group: group, provider: provider, requireAuthorization: false)
                request.profileReference = (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerConfiguration?["xrayConfigReference"] as? Data
            }
        }
        try request.check()
        return request
    }

    /// Authentication is injected so tests never present UI or touch host VPNs.
    public static func perform(_ connected: Bool, group: String, provider: String,
                               authorize: () async throws -> Void) async throws {
        let request = try await request(connected, group: group, provider: provider)
        if request.options.requireUnlock { try await authorize() }
        try request.check()
        if request.options.quickAccessAction == "toggle" { try await setConnected(connected, request: request) }
    }

    public static func setConnected(_ connected: Bool, group: String, provider: String) async throws {
        let request = try await request(connected, group: group, provider: provider)
        guard request.options.quickAccessAction == "toggle" else { throw Failure.unavailable }
        try await setConnected(connected, request: request)
    }

    private static let writeKey = "flutterVlessControlWrite"

    private static func setConnected(_ connected: Bool, request: Request) async throws {
        try await operations.run {
            try request.check()
            let manager = try await matching(group: request.group, provider: request.provider,
                                             requireAuthorization: connected, expectedReference: request.profileReference)
            try request.check()
            // A preceding provider's stop callback must finish before rearming
            // the same immutable profile from a rapid off/on control sequence.
            try await waitForDisconnectIfStopping(manager)
            try request.check()
            if connected && isActive(manager.connection.status) { return }
            guard let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  let reference = configuration.providerConfiguration?["xrayConfigReference"] as? Data,
                  reference == request.profileReference else { throw Failure.profileChanged }
            let write = UUID().uuidString
            var metadata = configuration.providerConfiguration ?? [:]
            if connected { metadata["options"] = request.options.dictionary }
            metadata[writeKey] = write
            configuration.providerConfiguration = metadata
            // The provider arms recovery only after bootstrap/Core/settings
            // admission. A control must not arm an unstarted candidate itself.
            manager.isEnabled = connected
            manager.isOnDemandEnabled = false
            manager.onDemandRules = nil
            var saveAttempted = false
            do {
                try request.check()
                saveAttempted = true
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()
                guard let fresh = manager.protocolConfiguration as? NETunnelProviderProtocol,
                      fresh.providerBundleIdentifier == request.provider,
                      fresh.providerConfiguration?["groupIdentifier"] as? String == request.group,
                      fresh.providerConfiguration?["xrayConfigReference"] as? Data == reference,
                      fresh.includeAllNetworks, !fresh.excludeLocalNetworks,
                      fresh.providerConfiguration?["proxyOnly"] as? Bool != true,
                      manager.isEnabled == connected, !manager.isOnDemandEnabled,
                      (manager.onDemandRules ?? []).isEmpty,
                      fresh.providerConfiguration?[writeKey] as? String == write,
                      (!connected || NSDictionary(dictionary: fresh.providerConfiguration?["options"] as? [String: Any] ?? [:])
                        .isEqual(to: request.options.dictionary)) else { throw Failure.verificationFailed }
                try request.check()
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
            } catch {
                if connected && saveAttempted {
                    // No compensating write: preferences have no documented
                    // cross-process compare-and-save. Rewriting an old stage
                    // could overwrite a newer app/Stop/profile transaction.
                    // The attempted stage requested On Demand OFF. Its inactive
                    // enabled flag may remain; do not claim cleanup succeeded.
                    throw Failure.cleanupUncertain
                }
                throw error
            }
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

    private static func matching(group: String, provider: String, requireAuthorization: Bool = true, expectedReference: Data? = nil) async throws -> NETunnelProviderManager {
        guard let metadata = UserDefaults(suiteName: group)?.dictionary(forKey: metadataKey),
              metadata["provider"] as? String == provider else { throw Failure.unavailable }
        let authorizedReference = metadata["reference"] as? Data
        guard !requireAuthorization || authorizedReference != nil else { throw Failure.unavailable }
        let matches = try await NETunnelProviderManager.loadAllFromPreferences().filter { manager in
            guard let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol else { return false }
            let data = configuration.providerConfiguration ?? [:]
            return configuration.providerBundleIdentifier == provider && data["groupIdentifier"] as? String == group
                && (data["xrayConfigReference"] as? Data)?.isEmpty == false
                && (expectedReference == nil || data["xrayConfigReference"] as? Data == expectedReference)
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
