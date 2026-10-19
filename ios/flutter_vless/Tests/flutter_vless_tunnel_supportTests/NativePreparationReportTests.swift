import Foundation
import XCTest
@testable import flutter_vless_privacy

final class NativePreparationReportTests: XCTestCase {
    private func bytes(_ value: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: value) }
    private let safeLog: [String: Any] = ["access": "none", "error": "none", "loglevel": "warning", "dnsLog": false]

    func testExistingFunctionReferenceSignaturesRemainAvailable() throws {
        let certificate: (Data, String?) throws -> Data = XrayCertificatePaths.bind
        let address: (Data, XrayEnvironmentSnapshot) throws -> Data = XrayAddressEnvironment.bind
        let port: (Data, XrayEnvironmentSnapshot) throws -> Data = LocalProxyAccessPolicy.bindingPortEnvironment
        let privacy: (inout [String: Any]) -> Bool = XrayPrivacyConfig.apply
        let input = try bytes(["outbounds": [["protocol": "freedom"]]])
        let environment = XrayEnvironmentSnapshot(rawEntries: [])
        XCTAssertEqual(try certificate(input, nil), input)
        XCTAssertEqual(try address(input, environment), input)
        XCTAssertEqual(try port(input, environment), input)
        var object: [String: Any] = ["log": safeLog]
        XCTAssertTrue(privacy(&object))
    }

    func testTypedBindingsEmitOnlySuccessfulActualOperations() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let environment = XrayEnvironmentSnapshot(rawEntries: [Data("PORT=18095".utf8), Data("ADDRESS=192.0.2.7".utf8)])
        var events: [NativePreparationReport.Change] = []
        let source = try bytes(["inbounds": [["port": "env:PORT", "protocol": "socks"]],
            "outbounds": [["protocol": "socks", "settings": ["servers": [["address": "env:ADDRESS", "port": 443]]],
                "streamSettings": ["security": "tls", "tlsSettings": ["certificates": [["certificateFile": "fixture.pem"]]]]]],
            "custom": ["certificateFile": "secret-canary", "port": "env:PORT", "address": "env:ADDRESS"]])
        let cert = try XrayCertificatePaths.bind(configData: source, directory: directory.path, onBinding: { events.append(.certificateRefsBound) })
        let port = try LocalProxyAccessPolicy.bindingPortEnvironment(configData: cert, environmentSnapshot: environment, onBinding: { events.append(.portEnvironmentBound) })
        let address = try XrayAddressEnvironment.bind(configData: port, environmentSnapshot: environment, onBinding: { events.append(.addressEnvironmentBound) })
        XCTAssertEqual(events, [.certificateRefsBound, .portEnvironmentBound, .addressEnvironmentBound])
        events = []
        _ = try XrayCertificatePaths.bind(configData: address, directory: directory.path, onBinding: { events.append(.certificateRefsBound) })
        _ = try LocalProxyAccessPolicy.bindingPortEnvironment(configData: address, environmentSnapshot: environment, onBinding: { events.append(.portEnvironmentBound) })
        _ = try XrayAddressEnvironment.bind(configData: address, environmentSnapshot: environment, onBinding: { events.append(.addressEnvironmentBound) })
        XCTAssertTrue(events.isEmpty, "Idempotent or opaque values must not invent an operation")
        XCTAssertThrowsError(try XrayCertificatePaths.bind(configData: source, directory: "relative", onBinding: { events.append(.certificateRefsBound) }))
        XCTAssertTrue(events.isEmpty)
        // Existing one-lookup policy refuses re-emitting env: rather than
        // silently resolving twice; a failed operation emits no report code.
        let selfReference = try bytes(["outbounds": [["protocol": "socks", "settings": ["servers": [["address": "env:SELF", "port": 443]]]]]])
        let sameValue = XrayEnvironmentSnapshot(rawEntries: [Data("SELF=env:SELF".utf8)])
        XCTAssertThrowsError(try XrayAddressEnvironment.bind(configData: selfReference, environmentSnapshot: sameValue,
            onBinding: { events.append(.addressEnvironmentBound) }))
        XCTAssertTrue(events.isEmpty, "Refused same-literal expansion must not report a change")
        let output = try XCTUnwrap(JSONSerialization.jsonObject(with: address) as? [String: Any])
        XCTAssertEqual(output["custom"] as? NSDictionary, ["certificateFile": "secret-canary", "port": "env:PORT", "address": "env:ADDRESS"] as NSDictionary)
    }

    func testPrivacyReportTracksKnownWritesNotOpaqueMetadataOrDefaults() throws {
        var config: [String: Any] = ["log": safeLog, "outbounds": [["protocol": "freedom"]],
            "custom": ["access": "secret-canary", "tlsSettings": ["masterKeyLog": "secret-canary"]]]
        var count = 0
        XCTAssertTrue(XrayPrivacyConfig.apply(to: &config, onLoggingChange: { count += 1 }))
        XCTAssertEqual(count, 0)
        XCTAssertNotNil(config["stats"]); XCTAssertNotNil(config["policy"], "Defaults have no invented logging code")
        config["outbounds"] = [["protocol": "freedom", "streamSettings": ["tlsSettings": ["masterKeyLog": "secret-canary"]]]]
        XCTAssertTrue(XrayPrivacyConfig.apply(to: &config, onLoggingChange: { count += 1 }))
        XCTAssertEqual(count, 1)
        XCTAssertTrue(XrayPrivacyConfig.apply(to: &config, onLoggingChange: { count += 1 }))
        XCTAssertEqual(count, 1)
        config["log"] = ["access": "secret-canary", "error": "secret-canary", "loglevel": "debug", "dnsLog": true]
        XCTAssertTrue(XrayPrivacyConfig.apply(to: &config, onLoggingChange: { count += 1 }))
        XCTAssertEqual(count, 2, "One successful preparation emits one closed logging operation")
    }

    func testKnownRootLogRemovalIsReportedButOpaqueLogFieldsAreNot() throws {
        for key in ["maskAddress", "MaſkAddreſſ"] {
            for value: Any in [NSNull(), "", "secret-log-canary"] {
                var log = safeLog; log[key] = value
                var config: [String: Any] = ["log": log]
                var count = 0
                XCTAssertTrue(XrayPrivacyConfig.apply(to: &config, onLoggingChange: { count += 1 }))
                XCTAssertEqual(count, 1, "A present typed log field was removed")
                XCTAssertEqual(config["log"] as? NSDictionary, safeLog as NSDictionary)
                XCTAssertTrue(XrayPrivacyConfig.apply(to: &config, onLoggingChange: { count += 1 }))
                XCTAssertEqual(count, 1, "The repeated operation changed no typed logging field")
            }
        }
        var log = safeLog
        log["maskAddressCustom"] = "secret-log-canary"
        log["custom"] = ["maskAddress": "secret-log-canary"]
        var config: [String: Any] = ["log": log]
        var count = 0
        XCTAssertTrue(XrayPrivacyConfig.apply(to: &config, onLoggingChange: { count += 1 }))
        XCTAssertEqual(count, 0, "Opaque-only removals must not invent a typed logging operation")
        XCTAssertEqual(config["log"] as? NSDictionary, safeLog as NSDictionary)
    }

    func testClosedImmutableReportHasHonestScopeAndNoCanaries() throws {
        let expected: [String: Any] = ["preparationReport": ["version": 1, "scope": "runtimeFinal", "coreCheck": "passed", "changes": ["address_environment_bound", "certificate_refs_bound"]]]
        let report = NativePreparationReport(proxyOnly: true, coreCheckPassed: true,
            changes: [.certificateRefsBound, .addressEnvironmentBound, .certificateRefsBound])
        XCTAssertEqual(report.flutterResult as NSDictionary, expected as NSDictionary)
        XCTAssertEqual(NativePreparationReport(proxyOnly: false, coreCheckPassed: true, changes: []).scope, "host")
        let legacy = NativePreparationReport(proxyOnly: true, coreCheckPassed: false, changes: [])
        XCTAssertEqual(legacy.scope, "host"); XCTAssertEqual(legacy.coreCheck, "unavailable")
        let encoded = String(decoding: try JSONSerialization.data(withJSONObject: report.flutterResult), as: UTF8.self)
        for value in ["secret-canary", "/Users/", "fixture.pem", "192.0.2.7", "18095", "PORT", "ADDRESS"] { XCTAssertFalse(encoded.contains(value)) }
    }
}
