import XCTest
import flutter_vless_macos_tunnel_support

final class XrayServiceTagsTests: XCTestCase {
    func testSharedDefinitionAndReferenceCorpusWithoutMutatingInput() throws {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/tags.json").path) { break }
            root.deleteLastPathComponent()
        }
        let data = try Data(contentsOf: root.appendingPathComponent("tool/fixtures/compatibility/tags.json"))
        let cases = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
        for item in cases {
            let config = try XCTUnwrap(item["config"] as? [String: Any])
            let before = try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])
            var tags = XrayServiceTags(configuration: config)
            let requests = try XCTUnwrap(item["requests"] as? [String])
            XCTAssertEqual(requests.map { tags.next($0) }, item["expected"] as? [String], item["name"] as? String ?? "")
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys]), before)
        }
    }

    func testVPNAndDelayAdaptersDoNotInheritDanglingUserRules() throws {
        let rules: [[String: Any]] = [
            ["inboundTag": ["flutter-vless-tun", "flutter-vless-delay"], "outboundTag": "blocked"],
            ["outboundTag": "flutter-vless-system-dns"], ["balancerTag": "flutter-vless-dns-upstream"]]
        var profile: [String: Any] = ["api": ["tag": "flutter-vless-tun-1"],
            "reverse": ["portals": [["tag": "flutter-vless-ipv6-block"]]],
            "outbounds": [["tag": "proxy", "protocol": "socks", "settings": ["servers": [["address": "127.0.0.1", "port": 19000]]]]],
            "routing": ["rules": rules]]
        let original = try JSONSerialization.data(withJSONObject: profile)
        let credentials = try LocalProxyCredentials(username: "private", password: "private-password")
        let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: original, credentials: credentials))
        let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
        XCTAssertEqual((output["inbounds"] as? [[String: Any]])?.first?["tag"] as? String, "flutter-vless-tun-2")
        let generated = try XCTUnwrap((output["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertEqual(generated[0]["outboundTag"] as? String, "flutter-vless-system-dns-1")
        XCTAssertEqual(output["reverse"] as? NSDictionary, profile["reverse"] as? NSDictionary)
        XCTAssertTrue(generated.contains { ($0["inboundTag"] as? [String]) == ["flutter-vless-dns-upstream-1"] && ($0["ip"] as? [String]) == ["1.1.1.1/32"] })
        XCTAssertTrue(generated.contains { ($0["inboundTag"] as? [String]) == ["flutter-vless-tun-2"] && ($0["outboundTag"] as? String) == "flutter-vless-system-dns-1" })
        XCTAssertEqual(Array(generated.suffix(rules.count)) as NSArray, rules as NSArray)
        try LocalProxyAccessPolicy.applyDelayProbe(to: &profile, port: 18080, credentials: credentials)
        XCTAssertEqual((profile["inbounds"] as? [[String: Any]])?.first?["tag"] as? String, "flutter-vless-delay-1")
    }
}
