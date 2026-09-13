import Flutter
import UIKit
import XCTest
import Security

class RunnerTests: XCTestCase {

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
