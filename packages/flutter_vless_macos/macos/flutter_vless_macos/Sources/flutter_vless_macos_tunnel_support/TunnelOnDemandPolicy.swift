import Foundation
import NetworkExtension

/// Changes recovery policy from the provider process, including when its app
/// is suspended or terminated. Only an explicit user stop disarms recovery.
public enum TunnelOnDemandPolicy {
    public enum Outcome: Equatable {
        case updated, unchanged, preservedForRecovery
    }

    public enum Failure: Error {
        case invalidIdentity, profileChanged, ambiguousProfile, timedOut, verificationFailed, cancelled
    }

    public static func enableForStart(configuration: NETunnelProviderProtocol,
                                      isCancelled: @escaping () -> Bool = { false },
                                      completion: @escaping (Result<Outcome, Error>) -> Void) {
        apply(enabled: true, configuration: configuration, isCancelled: isCancelled, completion: completion)
    }

    public static func disableForUserStop(reason: NEProviderStopReason,
                                          configuration: NETunnelProviderProtocol,
                                          completion: @escaping (Result<Outcome, Error>) -> Void) {
        guard reason == .userInitiated else {
            completion(.success(.preservedForRecovery))
            return
        }
        apply(enabled: false, configuration: configuration, completion: completion)
    }

    // Injectable OS boundary. Tests never read or mutate the host VPN profiles.
    struct Preferences {
        var load: (@escaping ([NETunnelProviderManager]?, Error?) -> Void) -> Void
        var save: (NETunnelProviderManager, @escaping (Error?) -> Void) -> Void
        var refresh: (NETunnelProviderManager, @escaping (Error?) -> Void) -> Void

        static let system = Preferences(
            load: { NETunnelProviderManager.loadAllFromPreferences(completionHandler: $0) },
            save: { $0.saveToPreferences(completionHandler: $1) },
            refresh: { $0.loadFromPreferences(completionHandler: $1) })
    }

    static func apply(enabled: Bool, configuration: NETunnelProviderProtocol,
                      preferences: Preferences = .system, timeout: TimeInterval = 4,
                      isCancelled: @escaping () -> Bool = { false },
                      completion: @escaping (Result<Outcome, Error>) -> Void) {
        guard let identifier = configuration.providerBundleIdentifier, !identifier.isEmpty,
              let reference = configuration.providerConfiguration?["xrayConfigReference"] as? Data,
              !reference.isEmpty else {
            completion(.failure(Failure.invalidIdentity))
            return
        }
        let operation = Operation(enabled: enabled, identifier: identifier, reference: reference,
                                  preferences: preferences, isCancelled: isCancelled, completion: completion)
        DispatchQueue.main.async { operation.start(timeout: timeout) }
    }

    private final class Operation {
        let enabled: Bool
        let identifier: String
        let reference: Data
        let preferences: Preferences
        let isCancelled: () -> Bool
        var completion: ((Result<Outcome, Error>) -> Void)?
        var timeoutWork: DispatchWorkItem?
        var staleRetries = 0

        init(enabled: Bool, identifier: String, reference: Data, preferences: Preferences,
             isCancelled: @escaping () -> Bool,
             completion: @escaping (Result<Outcome, Error>) -> Void) {
            self.enabled = enabled
            self.identifier = identifier
            self.reference = reference
            self.preferences = preferences
            self.isCancelled = isCancelled
            self.completion = completion
        }

        // All callbacks are serialized on main, including the deadline. A late
        // load/retry must never change preferences after teardown has completed.
        func start(timeout: TimeInterval) {
            let work = DispatchWorkItem { self.finish(.failure(Failure.timedOut)) }
            timeoutWork = work
            DispatchQueue.main.asyncAfter(deadline: .now() + timeout, execute: work)
            load()
        }

        func matches(_ manager: NETunnelProviderManager) -> Bool {
            guard let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol else { return false }
            return configuration.providerBundleIdentifier == identifier
                && configuration.providerConfiguration?["xrayConfigReference"] as? Data == reference
        }

        func load() {
            guard !isCancelled() else { finish(.failure(Failure.cancelled)); return }
            preferences.load { managers, error in
                DispatchQueue.main.async {
                    guard self.completion != nil else { return }
                    if let error { self.finish(.failure(error)); return }
                    let matches = (managers ?? []).filter(self.matches)
                    guard matches.count == 1, let manager = matches.first else {
                        self.finish(.failure(matches.isEmpty ? Failure.profileChanged : Failure.ambiguousProfile))
                        return
                    }
                    self.update(manager)
                }
            }
        }

        func update(_ manager: NETunnelProviderManager) {
            guard !isCancelled() else { finish(.failure(Failure.cancelled)); return }
            // A fresh explicit Connect stores a new immutable Keychain reference.
            // Never let an older provider disable that replacement session.
            guard matches(manager) else { finish(.failure(Failure.profileChanged)); return }
            if enabled && !manager.isEnabled { finish(.failure(Failure.profileChanged)); return }
            let rules = manager.onDemandRules ?? []
            if manager.isOnDemandEnabled == enabled && (enabled ? !rules.isEmpty : rules.isEmpty) {
                finish(.success(.unchanged))
                return
            }
            manager.isOnDemandEnabled = enabled
            if enabled {
                let rule = NEOnDemandRuleConnect()
                rule.interfaceTypeMatch = .any
                manager.onDemandRules = [rule]
            } else {
                manager.onDemandRules = nil
            }
            // Keep isEnabled and the routing/secret configuration unchanged so
            // the user can also reconnect from the system VPN control.
            preferences.save(manager) { error in
                DispatchQueue.main.async {
                    guard self.completion != nil else { return }
                    if let error {
                        let failure = error as NSError
                        if failure.domain == NEVPNErrorDomain,
                           failure.code == NEVPNError.configurationStale.rawValue,
                           self.staleRetries < 2 {
                            self.staleRetries += 1
                            self.load()
                        } else {
                            self.finish(.failure(error))
                        }
                        return
                    }
                    self.preferences.refresh(manager) { error in
                        DispatchQueue.main.async {
                            guard self.completion != nil else { return }
                            if let error { self.finish(.failure(error)); return }
                            guard self.matches(manager) else {
                                self.finish(.failure(Failure.profileChanged)); return
                            }
                            guard manager.isOnDemandEnabled == self.enabled,
                                  self.enabled ? !(manager.onDemandRules ?? []).isEmpty : (manager.onDemandRules ?? []).isEmpty else {
                                self.finish(.failure(Failure.verificationFailed)); return
                            }
                            self.finish(.success(.updated))
                        }
                    }
                }
            }
        }

        func finish(_ result: Result<Outcome, Error>) {
            guard let completion else { return }
            self.completion = nil
            timeoutWork?.cancel()
            timeoutWork = nil
            completion(result)
        }
    }
}
