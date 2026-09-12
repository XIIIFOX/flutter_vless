import Foundation
import Security
import XCTest
@testable import flutter_vless_tunnel_support

private final class MemoryKeychain: TunnelKeychainClient {
    var items: [Data: [String: Any]] = [:]
    var lastQuery: [String: Any] = [:]
    var status: OSStatus = errSecSuccess
    func add(_ query: [String: Any]) -> (OSStatus, Any?) {
        lastQuery = query
        guard status == errSecSuccess else { return (status, nil) }
        let ref = Data(UUID().uuidString.utf8)
        items[ref] = query
        return (errSecSuccess, ref)
    }
    func copy(_ query: [String: Any]) -> (OSStatus, Any?) {
        lastQuery = query
        guard status == errSecSuccess else { return (status, nil) }
        func belongs(_ item: [String: Any]) -> Bool {
            item[kSecAttrAccessGroup as String] as? String == query[kSecAttrAccessGroup as String] as? String
                && item[kSecAttrService as String] as? String == query[kSecAttrService as String] as? String
        }
        if let ref = query[kSecValuePersistentRef as String] as? Data {
            guard let item = items[ref], belongs(item) else { return (errSecItemNotFound, nil) }
            return (errSecSuccess, item[kSecValueData as String])
        }
        return (errSecSuccess, items.filter { belongs($0.value) }.map(\.key))
    }
    func delete(_ query: [String: Any]) -> OSStatus {
        lastQuery = query
        guard status == errSecSuccess else { return status }
        guard let ref = query[kSecValuePersistentRef as String] as? Data,
              let item = items[ref],
              item[kSecAttrAccessGroup as String] as? String == query[kSecAttrAccessGroup as String] as? String,
              item[kSecAttrService as String] as? String == query[kSecAttrService as String] as? String else { return errSecItemNotFound }
        items.removeValue(forKey: ref)
        return errSecSuccess
    }
}

final class TunnelSecretStoreTests: XCTestCase {
    func testSharedGroupAndDeviceOnlyAccessibilityAreRequired() throws {
        for missing in [nil, "", "   ", "$(AppIdentifierPrefix)unexpanded"] as [String?] {
            XCTAssertThrowsError(try TunnelSecretStore(accessGroup: missing, providerBundleIdentifier: "extension"))
        }
        let client = MemoryKeychain()
        let store = try TunnelSecretStore(accessGroup: "TEAM.shared", providerBundleIdentifier: "extension", client: client)
        let ref = try store.insert(Data("secret-password".utf8))
        XCTAssertEqual(client.lastQuery[kSecAttrAccessible as String] as? String,
                       kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
        XCTAssertEqual(client.lastQuery[kSecAttrSynchronizable as String] as? Bool, false)
        XCTAssertEqual(client.lastQuery[kSecUseDataProtectionKeychain as String] as? Bool, true)
        XCTAssertEqual(client.lastQuery[kSecAttrAccessGroup as String] as? String, "TEAM.shared")
        XCTAssertEqual(try store.read(ref), Data("secret-password".utf8))
        let extensionStore = try TunnelSecretStore(accessGroup: "TEAM.shared", providerBundleIdentifier: "extension", client: client)
        XCTAssertEqual(try extensionStore.read(ref), Data("secret-password".utf8))
        let otherGroup = try TunnelSecretStore(accessGroup: "OTHER.shared", providerBundleIdentifier: "extension", client: client)
        XCTAssertThrowsError(try otherGroup.read(ref))
        let otherProvider = try TunnelSecretStore(accessGroup: "TEAM.shared", providerBundleIdentifier: "other-extension", client: client)
        XCTAssertThrowsError(try otherProvider.read(ref))
    }

    func testLargeConfigurationIsExactAndSecurityRefusalNeverTruncates() throws {
        let client = MemoryKeychain()
        let store = try TunnelSecretStore(accessGroup: "TEAM.shared", providerBundleIdentifier: "extension", client: client)
        let large = Data(repeating: 0x41, count: 2 * 1024 * 1024)
        let ref = try store.insert(large)
        XCTAssertEqual(try store.read(ref), large)
        for status in [errSecParam, errSecMissingEntitlement, errSecInteractionNotAllowed, errSecNotAvailable] {
            client.status = status
            XCTAssertThrowsError(try store.insert(large)) { error in
                XCTAssertEqual((error as NSError).code, Int(status))
                XCTAssertFalse(error.localizedDescription.contains("AAAA"))
            }
        }
        XCTAssertEqual(client.items.count, 1)
        XCTAssertThrowsError(try store.insert(Data()))
    }

    func testUnavailableItemAndLegacySchemaHaveNoPlaintextFallback() throws {
        let client = MemoryKeychain()
        let store = try TunnelSecretStore(accessGroup: "TEAM.shared", providerBundleIdentifier: "extension", client: client)
        let ref = try store.insert(Data("known-secret".utf8))
        let metadata: [String: Any] = ["configSchemaVersion": 2, "xrayConfigReference": ref, "keychainAccessGroup": "TEAM.shared"]
        XCTAssertEqual(try TunnelSecretProfile.load(metadata, providerBundleIdentifier: "extension", client: client), Data("known-secret".utf8))
        for status in [errSecItemNotFound, errSecInteractionNotAllowed, errSecMissingEntitlement] {
            client.status = status
            XCTAssertThrowsError(try TunnelSecretProfile.load(metadata, providerBundleIdentifier: "extension", client: client))
        }
        client.status = errSecSuccess
        var legacy = metadata
        legacy["xrayConfig"] = Data("plaintext-secret".utf8)
        XCTAssertThrowsError(try TunnelSecretProfile.load(legacy, providerBundleIdentifier: "extension", client: client)) { error in
            XCTAssertEqual((error as NSError).code, TunnelSecretError.migrationRequired.errorCode)
        }
        for invalid in [[:], ["configSchemaVersion": 99, "xrayConfigReference": ref], ["configSchemaVersion": 2, "xrayConfigReference": Data()]] as [[String: Any]] {
            XCTAssertThrowsError(try TunnelSecretProfile.reference(in: invalid))
        }
    }

    func testInterruptedTransactionAndDeletionFailureUseScopedInventory() throws {
        let client = MemoryKeychain()
        let store = try TunnelSecretStore(accessGroup: "TEAM.shared", providerBundleIdentifier: "extension", client: client)
        let other = try TunnelSecretStore(accessGroup: "TEAM.shared", providerBundleIdentifier: "other", client: client)
        let otherRef = try other.insert(Data("other-plugin-config".utf8))
        let old = try store.insert(Data("old".utf8))
        let current = try store.insert(Data("current".utf8))
        _ = try store.insert(Data("interrupted-before-profile-save".utf8))
        client.status = errSecInteractionNotAllowed
        XCTAssertThrowsError(try store.reconcile(keeping: [current]))
        XCTAssertEqual(client.items.count, 4)
        client.status = errSecSuccess
        try store.reconcile(keeping: [current])
        XCTAssertEqual(Set(client.items.keys), Set([current, otherRef]))
        try store.remove(old) // idempotent deletion
        try store.reconcile(keeping: [current])
        XCTAssertEqual(Set(client.items.keys), Set([current, otherRef]))
    }
}
