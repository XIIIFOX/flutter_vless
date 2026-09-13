import XCTest
import flutter_vless_macos_privacy
@testable import flutter_vless_macos_tunnel_support

final class DesktopListenerPolicyTests: XCTestCase {
    private let base: [String: Any] = [
        "inbounds": [["protocol": "socks", "listen": "127.0.0.1", "port": 10808]],
        "outbounds": [["protocol": "http", "tag": "proxy", "settings": ["address": "127.0.0.1", "port": 18090]]]
    ]
    func testEveryAdditionalInboundIsRejectedBeforeAndDuringPreparation() throws {
        let credentials = try LocalProxyCredentials(username: "test", password: "test-password")
        for kind in ["dokodemo-door", "mixed", "http", "socks", "tun", "unknown"] {
            var json = base
            var listeners = json["inbounds"] as! [[String: Any]]
            listeners.append(["protocol": kind, "listen": "127.0.0.1", "port": 18081])
            json["inbounds"] = listeners
            let data = try JSONSerialization.data(withJSONObject: json)
            XCTAssertThrowsError(try LocalProxyAccessPolicy.validateVPN(configData: data), kind)
            XCTAssertNil(TunnelXrayConfigPreparer.prepare(jsonData: data, credentials: credentials), kind)
        }
        XCTAssertNotNil(TunnelXrayConfigPreparer.prepare(jsonData: try JSONSerialization.data(withJSONObject: base), credentials: credentials))
    }
    func testManagementAliasesAreRemovedAndAmbiguityFails() throws {
        for field in ["api", "Api", "API", "aPI"] {
            var json = base
            json[field] = ["listen": "127.0.0.1:18081", "services": ["HandlerService", "RoutingService"]]
            XCTAssertTrue(XrayPrivacyConfig.apply(to: &json))
            XCTAssertNil(json["api"]); XCTAssertNil(json[field])
            XCTAssertNotNil(json["stats"])
            let policy = json["policy"] as! [String: Any]
            XCTAssertEqual((policy["system"] as! [String: Any])["statsOutboundUplink"] as? Bool, true)
        }
        var ambiguous = base; ambiguous["api"] = [:] as [String: Any]; ambiguous["API"] = [:] as [String: Any]
        XCTAssertFalse(XrayPrivacyConfig.apply(to: &ambiguous))
    }
}
