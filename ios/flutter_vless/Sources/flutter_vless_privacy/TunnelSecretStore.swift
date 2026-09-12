import Foundation
import Security

/// Only fixed, non-sensitive messages cross the Flutter / provider boundary.
public enum TunnelSecretError: Error, LocalizedError, CustomNSError {
    case accessGroupRequired
    case accessGroupChanged
    case migrationRequired
    case invalidProfile
    case emptyConfiguration
    case keychain(operation: String, status: OSStatus)
    case profileVerificationFailed

    public static var errorDomain: String { "flutter_vless.keychain" }
    public var errorCode: Int {
        switch self {
        case .accessGroupRequired: return 1001
        case .accessGroupChanged: return 1006
        case .migrationRequired: return 1002
        case .invalidProfile: return 1003
        case .emptyConfiguration: return 1004
        case .keychain(_, let status): return Int(status)
        case .profileVerificationFailed: return 1005
        }
    }
    public var errorDescription: String? {
        switch self {
        case .accessGroupChanged: return "Remove the existing VPN profile before changing its Keychain access group."
        case .accessGroupRequired: return "Configure the shared Keychain access group in the app and tunnel extension."
        case .migrationRequired: return "Open the containing app to migrate the VPN profile to Keychain, then reconnect."
        case .invalidProfile: return "The VPN profile has no valid Keychain configuration reference. Open the app and reconnect."
        case .emptyConfiguration: return "The VPN configuration is empty."
        case .profileVerificationFailed: return "The saved VPN configuration could not be verified."
        case .keychain(let operation, let status):
            return "Keychain \(operation) failed (status \(status)). Verify shared access and unlock the device after restart."
        }
    }
    public var errorUserInfo: [String: Any] { [NSLocalizedDescriptionKey: errorDescription ?? "Keychain operation failed."] }
}

/// Injectable Security boundary. Tests exercise the real query policy without
/// modifying the developer's Keychain or requiring a signing identity.
public protocol TunnelKeychainClient {
    func add(_ query: [String: Any]) -> (OSStatus, Any?)
    func copy(_ query: [String: Any]) -> (OSStatus, Any?)
    func delete(_ query: [String: Any]) -> OSStatus
}

public struct SystemTunnelKeychainClient: TunnelKeychainClient {
    public init() {}
    public func add(_ query: [String: Any]) -> (OSStatus, Any?) {
        var result: CFTypeRef?
        let status = SecItemAdd(query as CFDictionary, &result)
        return (status, result)
    }
    public func copy(_ query: [String: Any]) -> (OSStatus, Any?) {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return (status, result)
    }
    public func delete(_ query: [String: Any]) -> OSStatus { SecItemDelete(query as CFDictionary) }
}

/// An immutable item per profile revision makes preference updates reversible.
/// Never update an item in place: a running extension may still use its revision.
public final class TunnelSecretStore {
    public let accessGroup: String
    private let service: String
    private let client: TunnelKeychainClient

    public init(accessGroup: String?, providerBundleIdentifier: String,
                client: TunnelKeychainClient = SystemTunnelKeychainClient()) throws {
        guard let group = accessGroup?.trimmingCharacters(in: .whitespacesAndNewlines),
              !group.isEmpty, !group.contains("$("), !providerBundleIdentifier.isEmpty else {
            throw TunnelSecretError.accessGroupRequired
        }
        self.accessGroup = group
        self.service = "dev.tfox.flutter-vless.tunnel-config." + providerBundleIdentifier
        self.client = client
    }

    private var scope: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccessGroup as String: accessGroup,
         kSecAttrSynchronizable as String: false,
         kSecUseDataProtectionKeychain as String: true]
    }

    public func insert(_ data: Data) throws -> Data {
        guard !data.isEmpty else { throw TunnelSecretError.emptyConfiguration }
        var query = scope
        query[kSecAttrAccount as String] = UUID().uuidString
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        query[kSecValueData as String] = data
        query[kSecReturnPersistentRef as String] = true
        let (status, value) = client.add(query)
        guard status == errSecSuccess else { throw TunnelSecretError.keychain(operation: "save", status: status) }
        guard let reference = value as? Data, !reference.isEmpty else {
            // An interrupted/incomplete insert remains scoped to this service
            // and will be reconciled when no provider can still be using it.
            throw TunnelSecretError.profileVerificationFailed
        }
        return reference
    }

    public func read(_ reference: Data) throws -> Data {
        guard !reference.isEmpty else { throw TunnelSecretError.invalidProfile }
        var query = scope
        query[kSecValuePersistentRef as String] = reference
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, value) = client.copy(query)
        guard status == errSecSuccess else { throw TunnelSecretError.keychain(operation: "read", status: status) }
        guard let data = value as? Data, !data.isEmpty else { throw TunnelSecretError.emptyConfiguration }
        return data
    }

    public func remove(_ reference: Data) throws {
        var query = scope
        query[kSecValuePersistentRef as String] = reference
        let status = client.delete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw TunnelSecretError.keychain(operation: "delete", status: status)
        }
    }

    /// Call only while the matching provider is disconnected. Inventory is the
    /// durable pending-cleanup journal, including process death during migration
    /// or a failed deletion. Never enumerate / delete another service or group.
    public func reconcile(keeping references: Set<Data>) throws {
        var query = scope
        query[kSecReturnPersistentRef as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        let (status, value) = client.copy(query)
        if status == errSecItemNotFound { return }
        guard status == errSecSuccess else { throw TunnelSecretError.keychain(operation: "inventory", status: status) }
        let inventory: [Data]
        if let values = value as? [Data] { inventory = values }
        else if let value = value as? Data { inventory = [value] }
        else { throw TunnelSecretError.profileVerificationFailed }
        for reference in inventory where !references.contains(reference) { try remove(reference) }
    }
}

public enum TunnelSecretProfile {
    public static let schemaVersion = 2

    public static func reference(in configuration: [String: Any]) throws -> Data {
        guard configuration["xrayConfig"] == nil else { throw TunnelSecretError.migrationRequired }
        guard configuration["configSchemaVersion"] as? Int == schemaVersion,
              let reference = configuration["xrayConfigReference"] as? Data, !reference.isEmpty else {
            throw TunnelSecretError.invalidProfile
        }
        return reference
    }

    public static func load(_ configuration: [String: Any], providerBundleIdentifier: String,
                            client: TunnelKeychainClient = SystemTunnelKeychainClient()) throws -> Data {
        let reference = try reference(in: configuration)
        let store = try TunnelSecretStore(accessGroup: configuration["keychainAccessGroup"] as? String,
                                          providerBundleIdentifier: providerBundleIdentifier, client: client)
        return try store.read(reference)
    }
}
