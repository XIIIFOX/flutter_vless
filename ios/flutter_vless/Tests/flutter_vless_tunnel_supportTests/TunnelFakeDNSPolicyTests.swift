import XCTest
@testable import flutter_vless_tunnel_support

final class TunnelFakeDNSPolicyTests: XCTestCase {
    private let credentials = try! LocalProxyCredentials(username: "fake-session", password: "fake-session-password")

    func testSharedFakeDNSProfilesKeepCallerEngineDNSAndImportedSniffing() throws {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/fakedns.json").path) { break }
            root.deleteLastPathComponent()
        }
        let cases = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("tool/fixtures/compatibility/fakedns.json"))) as? [[String: Any]])
        XCTAssertEqual(cases.count, 5)
        for item in cases {
            let source = try XCTUnwrap(item["config"] as? [String: Any])
            let data = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
            let prepared = TunnelXrayConfigPreparer.prepare(jsonData: data, credentials: credentials, resolveIPv4: { name in
                XCTAssertEqual(name, "endpoint.invalid"); return "203.0.113.7"
            })
            XCTAssertNotNil(prepared, item["name"] as? String ?? "")
            guard let prepared else { continue }
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
            XCTAssertEqual(output["dns"] as? NSDictionary, source["dns"] as? NSDictionary)
            for key in source.keys where XrayJSONField.matches(key, "fakedns") {
                XCTAssertEqual(output[key] as? NSObject, source[key] as? NSObject)
            }
            let inbounds = try XCTUnwrap(output["inbounds"] as? [[String: Any]])
            XCTAssertEqual(Array(inbounds.dropFirst()) as NSArray, source["inbounds"] as? NSArray)
            let sniffing = try XCTUnwrap(inbounds.first?["sniffing"] as? [String: Any])
            XCTAssertEqual(sniffing["routeOnly"] as? Bool, true)
            XCTAssertEqual(sniffing["destOverride"] as? [String], ["http", "tls", "quic", "fakedns"])
            let rules = try XCTUnwrap((output["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
            XCTAssertEqual(rules.first?["ip"] as? [String], ["10.0.85.53/32"])
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), data)
        }
    }

    func testExplicitPoolOverlapAndMalformedValuesRefuseBeforeBootstrapWithoutMutation() throws {
        let invalid: [Any] = [
            ["ipPool": "10.0.85.128/25", "poolSize": 8], ["ipPool": "10.0.0.0/8", "poolSize": 8],
            ["ipPool": "26.26.26.1/32", "poolSize": 1], ["ipPool": "fd26:26:26::/126", "poolSize": 1],
            ["ipPool": "fd00:198:18::/65", "poolSize": 1],
            ["ipPool": "::ffff:10.0.85.0/120", "poolSize": 8], ["ipPool": "::ffff:0:0/80", "poolSize": 8],
            ["ipPool": "::ffff:26.26.26.0/126", "poolSize": 1],
            ["ipPool": "invalid/24", "poolSize": 1], ["ipPool": "198.19.0.0\0ignored/24", "poolSize": 1], ["ipPool": "198.19.0.0/33", "poolSize": 1],
            ["ipPool": "198.19.0.0/24 ", "poolSize": 1], ["ipPool": " 198.19.0.0/24", "poolSize": 1],
            ["ipPool": "198.019.0.0/24", "poolSize": 1], ["ipPool": "::ffff:010.0.85.0/120", "poolSize": 1], ["ipPool": "fe80::1%lo0/64", "poolSize": 1],
            ["ipPool": "198.19.0.0/24", "poolSize": true], ["ipPool": "198.19.0.0/24", "poolSize": "1"],
            ["ipPool": "198.19.0.0/24", "poolSize": 1.5], ["ipPool": "198.19.0.0/24", "poolSize": 0],
            ["ipPool": "198.19.0.0/24", "poolSize": -1], ["ipPool": "198.19.0.0/24", "poolSize": 256],
            ["ipPool": "198.19.0.0/24"], ["poolSize": 1], [String: Any](), [NSNull()], true,
            ["ipPool": "198.19.0.0/24", "IPPOOL": "198.20.0.0/24", "poolSize": 1],
            ["ipPool": "198.19.0.0/24", "poolSize": 1, "PoolSize": 2]
        ]
        for (index, pool) in invalid.enumerated() {
            var source = config(pool: pool)
            let original = source as NSDictionary
            XCTAssertNil(TunnelDNSPolicy.apply(to: &source, managedInboundTag: "managed", resolveIPv4: { _ in
                XCTFail("Invalid pool \(index) must refuse before endpoint resolution"); return nil
            }))
            XCTAssertEqual(source as NSDictionary, original)
        }
    }

    func testPoolCapacityAliasesAndNullOrUnusedEngine() throws {
        for pool: Any in [
            ["IPPOOL": "198.19.0.23/24", "POOLSIZE": 255],
            ["ipPool": "fc00::/18", "poolSize": Int64.max],
            ["ipPool": "2001:db8::/65", "poolSize": Int64(1) << 62],
            [Any](), NSNull()
        ] {
            var source = config(pool: pool)
            XCTAssertNotNil(TunnelDNSPolicy.apply(to: &source, managedInboundTag: "managed", resolveIPv4: { _ in "203.0.113.7" }))
        }
        // Core checks capacity after converting int64 to float64.
        var rounded = config(pool: ["ipPool": "2001:db8::/65", "poolSize": Int64.max])
        XCTAssertNil(TunnelDNSPolicy.apply(to: &rounded, managedInboundTag: "managed", resolveIPv4: { _ in XCTFail(); return nil }))
        var duplicate = config(pool: NSNull())
        duplicate["FakeDNS"] = []
        XCTAssertNil(TunnelDNSPolicy.apply(to: &duplicate, managedInboundTag: "managed", resolveIPv4: { _ in XCTFail(); return nil }))
    }

    func testManagedOnlyOverrideAndInactiveNullDoNotChangeImportedSniffing() throws {
        let imported: [String: Any] = ["tag": "caller", "protocol": "http", "sniffing": ["enabled": true, "routeOnly": false, "destOverride": ["tls"]]]
        for active in [false, true] {
            var source: [String: Any] = ["inbounds": [
                ["tag": "managed", "protocol": "socks", "sniffing": ["enabled": true, "routeOnly": true, "destOverride": ["http", "tls", "quic"]]], imported
            ], "fakeDnſ": active ? [Any]() as Any : NSNull()]
            XCTAssertTrue(TunnelIPv6Policy.apply(to: &source, managedInboundTag: "managed"))
            let inbounds = try XCTUnwrap(source["inbounds"] as? [[String: Any]])
            XCTAssertEqual(inbounds[1] as NSDictionary, imported as NSDictionary)
            XCTAssertEqual((inbounds[0]["sniffing"] as? [String: Any])?["destOverride"] as? [String], active ? ["http", "tls", "quic", "fakedns"] : ["http", "tls", "quic"])
            XCTAssertTrue(TunnelIPv6Policy.apply(to: &source, managedInboundTag: "managed"))
            XCTAssertEqual(source["inbounds"] as? NSArray, inbounds as NSArray)
        }
        XCTAssertEqual(TunnelDNSPolicy.virtualServer, "10.0.85.53")
    }

    func testSentinelGoEqualFoldAndBoundEnvironmentKeepRawDNS() throws {
        for token in ["fakednſ", "[ FaKeDnſ ]"] {
            let source: [String: Any] = ["dns": ["servers": [["address": "env:FAKE_SERVER", "tag": "caller-dns"]]],
                                         "outbounds": [["tag": "direct", "protocol": "freedom"]]]
            let data = try JSONSerialization.data(withJSONObject: source)
            let bound = try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: data, environment: ["FAKE_SERVER": token])
            let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: bound, credentials: credentials,
                resolveIPv4: { _ in XCTFail("FakeDNS is not a physical resolver address"); return nil }))
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
            let server = try XCTUnwrap(((output["dns"] as? [String: Any])?["servers"] as? [[String: Any]])?.first)
            XCTAssertEqual(server["address"] as? String, token)
            XCTAssertEqual(server["tag"] as? String, "caller-dns")
            let managed = try XCTUnwrap((output["inbounds"] as? [[String: Any]])?.first)
            XCTAssertTrue(((managed["sniffing"] as? [String: Any])?["destOverride"] as? [String])?.contains("fakedns") == true)
            XCTAssertEqual(((source["dns"] as? [String: Any])?["servers"] as? [[String: Any]])?.first?["address"] as? String, "env:FAKE_SERVER")
        }
    }

    private func config(pool: Any) -> [String: Any] {
        ["fakeDns": pool, "dns": ["servers": ["fakedns", "tcp://1.1.1.1"]],
         "outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "endpoint.invalid", "port": 443]]]]
    }
}
