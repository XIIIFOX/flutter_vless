import XCTest
import CryptoKit
@testable import flutter_vless_tunnel_support

final class TunnelRoutingMetadataTests: XCTestCase {
    private let credentials = try! LocalProxyCredentials(username: "synthetic-session", password: "synthetic-session-password")

    private func source() throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "inbounds": [
                ["tag": "first", "listen": "127.0.0.1", "port": 19080, "protocol": "socks", "settings": ["auth": "noauth"]],
                ["tag": "", "listen": "127.0.0.1", "port": 19081, "protocol": "socks", "settings": ["auth": "noauth"]]
            ],
            "outbounds": [
                ["tag": "blocked", "protocol": "blackhole"],
                ["tag": "proxy", "protocol": "vless", "settings": ["address": "endpoint.invalid", "port": 443, "id": "22222222-2222-4222-8222-222222222222", "encryption": "none"],
                 "streamSettings": ["network": "xhttp", "security": "none", "xhttpSettings": ["path": "/synthetic"]]],
                ["tag": "direct", "protocol": "freedom"]
            ],
            "routing": ["domainStrategy": "IPIfNonMatch", "rules": [
                ["type": "field", "network": "udp", "port": "443", "outboundTag": "blocked", "callerMarker": "global-rule"],
                ["type": "field", "inboundTag": ["flutter-vless-tun"], "outboundTag": "direct", "callerMarker": "private-name-reference"]
            ]]
        ])
    }

    func testEnvelopeBindsFinalBytesAndOnlyGeneratedRules() throws {
        let input = try source(), original = input
        let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: input, credentials: credentials,
            routingIntent: try NativeRoutingIntent(sourceInboundIndex: 1, defaultOutboundTag: "proxy"), resolveIPv4: { _ in "203.0.113.8" }))
        let envelope = try XCTUnwrap(prepared.routingEnvelope)
        XCTAssertEqual(envelope.configurationData, prepared.data)
        let metadata = try XCTUnwrap(JSONSerialization.jsonObject(with: envelope.metadataData) as? [String: Any])
        let final = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
        let inputs = try XCTUnwrap(final["inbounds"] as? [[String: Any]])
        let routing = try XCTUnwrap(final["routing"] as? [String: Any])
        let rules = try XCTUnwrap(routing["rules"] as? [[String: Any]])
        let indices = try XCTUnwrap(metadata["guard_rule_indices"] as? [Int])
        XCTAssertEqual(metadata["source_sha256"] as? String, SHA256.hash(data: prepared.data).map { String(format: "%02x", $0) }.joined())
        XCTAssertEqual(metadata["managed_inbound_index"] as? Int, 0)
        XCTAssertEqual(metadata["source_inbound_index"] as? Int, 2)
        XCTAssertEqual(metadata["default_outbound_tag"] as? String, "proxy")
        XCTAssertEqual(inputs[2]["tag"] as? String, "")
        let managedTag = try XCTUnwrap(inputs[0]["tag"] as? String)
        XCTAssertEqual(metadata["managed_inbound_tag"] as? String, managedTag)
        XCTAssertEqual(metadata["auth_user"] as? String, credentials.username)
        XCTAssertFalse(indices.isEmpty)
        XCTAssertEqual(indices, Array(0..<(rules.count - 2)))
        XCTAssertTrue(indices.contains { rules[$0]["port"] as? String == "443" && rules[$0]["inboundTag"] as? [String] == [managedTag] })
        XCTAssertTrue(indices.allSatisfy { rules[$0]["callerMarker"] == nil })
        XCTAssertEqual(rules.suffix(2).compactMap { $0["callerMarker"] as? String }, ["global-rule", "private-name-reference"])
        XCTAssertEqual(input, original)
        if let directory = ProcessInfo.processInfo.environment["FLVLESS_EXPORT_ROUTING_PAIR"] {
            let root = URL(fileURLWithPath: directory, isDirectory: true)
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            for (name, data) in [("config.json", envelope.configurationData), ("spec.json", envelope.metadataData)] {
                let file = root.appendingPathComponent(name)
                try data.write(to: file, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            }
        }
    }

    func testOrdinaryPreparationDoesNotAdoptCallerMetadata() throws {
        var value = try XCTUnwrap(JSONSerialization.jsonObject(with: source()) as? [String: Any])
        value["nativeRoutingSpec"] = ["source_inbound_index": 1]
        let input = try JSONSerialization.data(withJSONObject: value)
        let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: input, credentials: credentials, resolveIPv4: { _ in "203.0.113.8" }))
        XCTAssertNil(prepared.routingEnvelope)
    }

    func testInvalidOriginalIndexRefusesBeforeBootstrap() throws {
        XCTAssertThrowsError(try NativeRoutingIntent(sourceInboundIndex: -1))
        for index in [2, Int.max] {
            var resolutions = 0
            XCTAssertNil(TunnelXrayConfigPreparer.prepare(jsonData: try source(), credentials: credentials,
                routingIntent: try NativeRoutingIntent(sourceInboundIndex: index), resolveIPv4: { _ in resolutions += 1; return "203.0.113.8" }))
            XCTAssertEqual(resolutions, 0)
        }
    }

    func testEmptyIntentKeepsCoreDefaultAndNoSourceAlias() throws {
        let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: try source(), credentials: credentials,
            routingIntent: try NativeRoutingIntent(), resolveIPv4: { _ in "203.0.113.8" }))
        let envelope = try XCTUnwrap(prepared.routingEnvelope)
        let metadata = try XCTUnwrap(JSONSerialization.jsonObject(with: envelope.metadataData) as? [String: Any])
        XCTAssertNil(metadata["source_inbound_index"])
        XCTAssertTrue(metadata["default_outbound_tag"] == nil || metadata["default_outbound_tag"] as? String == "")
    }
}
