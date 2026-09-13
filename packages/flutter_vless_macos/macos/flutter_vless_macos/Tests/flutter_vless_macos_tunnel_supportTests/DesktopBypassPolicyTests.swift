import XCTest
import flutter_vless_macos_privacy
@testable import flutter_vless_macos_tunnel_support

final class DesktopBypassPolicyTests: XCTestCase {
    func testSubnetsRemainInsideProtectedRuntimeBelowDNSAndIPv6() throws {
        let raw = Data(#"{"inbounds":[{"protocol":"socks","port":10808}],"outbounds":[{"protocol":"http","tag":"proxy","settings":{"address":"127.0.0.1","port":18090}},{"protocol":"freedom","tag":"flutter-vless-subnet-direct"}],"routing":{"rules":[{"domain":["domain:ru"],"outboundTag":"flutter-vless-subnet-direct"}]}}"#.utf8)
        let transformed = try DesktopBypassPolicy.apply(to: raw, cidrs: ["0.0.0.0/0", "192.168.0.0/16"])
        let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: transformed,
            credentials: LocalProxyCredentials(username: "session", password: "session-secret")))
        let config = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
        let routing = try XCTUnwrap(config["routing"] as? [String: Any])
        let rules = try XCTUnwrap(routing["rules"] as? [[String: Any]])
        let bypass = try XCTUnwrap(rules.firstIndex { ($0["outboundTag"] as? String) == "flutter-vless-subnet-direct-" })
        XCTAssertGreaterThan(bypass, 0)
        XCTAssertTrue(rules[..<bypass].contains { ($0["ip"] as? [String])?.contains("::/0") == true })
        XCTAssertTrue(rules[..<bypass].contains { ($0["ip"] as? [String])?.contains("198.18.0.2/32") == true })
        XCTAssertEqual(rules[bypass]["ip"] as? [String], ["0.0.0.0/0", "192.168.0.0/16"])
        XCTAssertEqual(rules.last?["domain"] as? [String], ["domain:ru"])
    }

    func testInvalidAndIPv6BypassesFailBeforeConfigurationChanges() {
        for cidr in ["::/0", "2001:db8::/32", "1.2.3.4", "1.2.3.4/33", "invalid/0", "1.2.3.4/24/0"] {
            XCTAssertThrowsError(try DesktopBypassPolicy.validate([cidr]), cidr)
        }
    }
}
