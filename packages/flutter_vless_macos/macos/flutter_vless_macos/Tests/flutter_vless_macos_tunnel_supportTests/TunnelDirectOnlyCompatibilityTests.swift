import XCTest
@testable import flutter_vless_macos_tunnel_support

/// Config preparation only: no Core, resolver, socket or packet worker runs.
final class TunnelDirectOnlyCompatibilityTests: XCTestCase {
    private static let credentials = try! LocalProxyCredentials(username: "direct-session", password: "direct-session-password")

    private func cases() throws -> [[String: Any]] {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/direct-only.json").path) { break }
            root.deleteLastPathComponent()
        }
        let data = try Data(contentsOf: root.appendingPathComponent("tool/fixtures/compatibility/direct-only.json"))
        let cases = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
        XCTAssertEqual(cases.count, 2)
        return cases
    }

    private func profile(protocol expected: String) throws -> [String: Any] {
        let item = try XCTUnwrap(try cases().first { item in
            guard let config = item["config"] as? [String: Any],
                  let outbounds = config["outbounds"] as? [[String: Any]] else { return false }
            return outbounds.contains { ($0["protocol"] as? String) == expected }
        })
        return try XCTUnwrap(item["config"] as? [String: Any])
    }

    private func assertPrepared(_ source: [String: Any]) throws {
        let before = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
        let prepared = TunnelXrayConfigPreparer.prepare(jsonData: before, credentials: Self.credentials) { _ in
            XCTFail("A direct-only profile has no physical proxy endpoint to bootstrap")
            return nil
        }
        XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), before)
        let result = try XCTUnwrap(prepared, "An explicit caller DNS policy does not require a proxy endpoint")
        XCTAssertEqual(result.bootstrapAddresses, [])
        XCTAssertFalse(result.proxyUsesXhttp)
        let output = try XCTUnwrap(JSONSerialization.jsonObject(with: result.data) as? [String: Any])
        XCTAssertEqual(output["dns"] as? NSDictionary, source["dns"] as? NSDictionary)
        let original = try XCTUnwrap(source["outbounds"] as? [[String: Any]])
        let effective = try XCTUnwrap(output["outbounds"] as? [[String: Any]])
        XCTAssertEqual(effective.prefix(original.count).compactMap { $0["protocol"] as? String }, original.compactMap { $0["protocol"] as? String })
        XCTAssertEqual(effective.prefix(original.count).compactMap { $0["tag"] as? String }, original.compactMap { $0["tag"] as? String })
        // The caller's first handler remains Core's fallback; no generated
        // endpoint proxy or catch-all may replace its direct or blocked default.
        XCTAssertEqual(effective.first?["tag"] as? String, original.first?["tag"] as? String)
        let sourceRules = try XCTUnwrap((source["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        let rules = try XCTUnwrap((output["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertEqual(Array(rules.suffix(sourceRules.count)) as NSArray, sourceRules as NSArray)
        let additions = Array(rules.dropLast(sourceRules.count))
        XCTAssertEqual(additions.count, 1, "Only the private virtual resolver interception is required")
        let managed = try XCTUnwrap((output["inbounds"] as? [[String: Any]])?.first)
        XCTAssertEqual(additions.first?["inboundTag"] as? [String], [try XCTUnwrap(managed["tag"] as? String)])
        XCTAssertEqual(additions.first?["ip"] as? [String], [TunnelDNSPolicy.virtualServer + "/32"])
        let relay = try XCTUnwrap(effective.first { ($0["protocol"] as? String) == "dns" })
        let relayRules = try XCTUnwrap((relay["settings"] as? [String: Any])?["rules"] as? [[String: Any]])
        for kind in ["1", "28"] {
            XCTAssertEqual(relayRules.first { ($0["qType"] as? String)?.split(separator: ",").contains(Substring(kind)) == true }?["action"] as? String, "hijack")
        }
        XCTAssertEqual(relayRules.last?["action"] as? String, "return")
        XCTAssertEqual(relayRules.last?["rCode"] as? Int, 5)
    }

    func testFreedomOnlyKeepsExplicitCallerDNSOrderAndBlockingRules() throws {
        try assertPrepared(profile(protocol: "freedom"))
    }

    func testDirectAliasKeepsExplicitCallerDNSOrderAndBlockingRules() throws {
        try assertPrepared(profile(protocol: "direct"))
    }

    func testDirectOnlyMissingOrLocalDNSDoesNotInventANativeDetour() throws {
        for proto in ["freedom", "direct"] {
            for dns: Any? in [nil, ["servers": []], ["servers": ["localhost"]]] {
                var source = try profile(protocol: proto)
                if let dns { source["dns"] = dns } else { source.removeValue(forKey: "dns") }
                let data = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
                XCTAssertNil(TunnelXrayConfigPreparer.prepare(jsonData: data, credentials: Self.credentials) { _ in
                    XCTFail("No proxy endpoint may be guessed for an implicit native DNS detour")
                    return nil
                })
                XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), data)
            }
        }
    }
}
