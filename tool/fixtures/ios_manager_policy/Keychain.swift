import Foundation
import Security

final class FixtureKeychain: TunnelKeychainClient {
    var records: [Data: [String: Any]] = [:]
    var insertedQueries: [[String: Any]] = []
    var failure: OSStatus?
    var nextReadFailure: OSStatus?
    var deleteFailure: OSStatus?
    var readCount = 0
    var failReadNumber: Int?
    func add(_ query: [String: Any]) -> (OSStatus, Any?) {
        if let failure { return (failure, nil) }
        let reference = Data(UUID().uuidString.utf8)
        records[reference] = query
        insertedQueries.append(query)
        return (errSecSuccess, reference)
    }
    private func matches(_ record: [String: Any], _ query: [String: Any]) -> Bool {
        record[kSecAttrService as String] as? String == query[kSecAttrService as String] as? String
            && record[kSecAttrAccessGroup as String] as? String == query[kSecAttrAccessGroup as String] as? String
    }
    func copy(_ query: [String: Any]) -> (OSStatus, Any?) {
        if let failure { return (failure, nil) }
        readCount += 1
        if failReadNumber == readCount { return (errSecInteractionNotAllowed, nil) }
        if let nextReadFailure { self.nextReadFailure = nil; return (nextReadFailure, nil) }
        if let reference = query[kSecValuePersistentRef as String] as? Data {
            guard let record = records[reference], matches(record, query) else { return (errSecItemNotFound, nil) }
            return (errSecSuccess, record[kSecValueData as String])
        }
        let references = records.filter { matches($0.value, query) }.map(\.key)
        return references.isEmpty ? (errSecItemNotFound, nil) : (errSecSuccess, references)
    }
    func delete(_ query: [String: Any]) -> OSStatus {
        if let failure { return failure }
        if let deleteFailure { return deleteFailure }
        guard let reference = query[kSecValuePersistentRef as String] as? Data,
              let record = records[reference], matches(record, query) else { return errSecItemNotFound }
        records.removeValue(forKey: reference)
        return errSecSuccess
    }
}
