import XCTest
import flutter_vless_tunnel_support

final class XrayPortSpecTests: XCTestCase {
    func testPortEnvironmentIsBoundBeforeCrossProcessPersistenceAndReportsMissingValue() throws {
        let source = Data(#"{"inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":"10808,env:flutter.vless.fixture.ports"}],"outbounds":[{"protocol":"socks","tag":"proxy","settings":{"servers":[{"address":"127.0.0.1","port":19000}]}}]}"#.utf8)
        let environment = ["FLUTTER_VLESS_FIXTURE_PORTS": "010810-010811"]
        let bound = try LocalProxyAccessPolicy.bindingPortEnvironment(configData: source, environment: environment)
        XCTAssertEqual(bound, try LocalProxyAccessPolicy.bindingPortEnvironment(configData: source, environment: environment))
        XCTAssertNotEqual(bound, source)
        let config = try XCTUnwrap(JSONSerialization.jsonObject(with: bound) as? [String: Any])
        let inputs = try XCTUnwrap(config["inbounds"] as? [[String: Any]])
        XCTAssertEqual(inputs[0]["port"] as? String, "10808,10810-10811")
        // No environment is needed when an OS-launched provider reads the saved
        // session; caller-owned source still has its symbolic reference.
        XCTAssertEqual(try LocalProxyAccessPolicy.bindingPortEnvironment(configData: bound, environment: [:]), bound)
        XCTAssertNotNil(TunnelXrayConfigPreparer.prepare(jsonData: bound,
            credentials: try LocalProxyCredentials(username: "private", password: "private-password")))
        XCTAssertThrowsError(try LocalProxyAccessPolicy.bindingPortEnvironment(configData: source, environment: [:])) { error in
            XCTAssertEqual(error.localizedDescription, "Unable to resolve inbounds[0].port from the application environment.")
            XCTAssertFalse(error.localizedDescription.contains("flutter.vless.fixture"))
        }
    }

    func testUnixPortListDoesNotConsumeTCPPortsOrRewriteImportedAuthentication() throws {
        let input: [String: Any] = ["protocol": "socks", "listen": "/tmp/flutter-vless-port-corpus.sock",
            "port": "0-65535", "settings": ["auth": "password", "accounts": [["user": "caller", "pass": "caller-password"]]]]
        var config: [String: Any] = ["inbounds": [input]]
        let port = try LocalProxyAccessPolicy.applyVPN(to: &config,
            credentials: LocalProxyCredentials(username: "private", password: "private-password"))
        XCTAssertEqual(port, 10808)
        let inputs = try XCTUnwrap(config["inbounds"] as? [[String: Any]])
        XCTAssertEqual(inputs[1] as NSDictionary, input as NSDictionary)
    }

    func testSharedPinnedCorePortCorpus() throws {
        // Works in both source packages and the isolated script's copied package.
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/ports.json").path) { break }
            root.deleteLastPathComponent()
        }
        let data = try Data(contentsOf: root.appendingPathComponent("tool/fixtures/compatibility/ports.json"))
        let cases = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [[String: Any]])
        for item in cases {
            let name = try XCTUnwrap(item["name"] as? String)
            let value = try XCTUnwrap(item["value"])
            let environment = item["environment"] as? [String: String] ?? [:]
            if item["invalid"] as? Bool == true {
                XCTAssertThrowsError(try XrayPortSpec.reservedPorts(value, environment: { environment[$0] }), name)
            } else {
                XCTAssertEqual(try XrayPortSpec.reservedPorts(value, environment: { environment[$0] }),
                    Set(try XCTUnwrap(item["ports"] as? [Int])), name)
            }
        }
    }
}
