import XCTest
import flutter_vless_macos_tunnel_support

final class XrayPortSpecTests: XCTestCase {
    private func portEnvironmentCorpus() throws -> [[String: Any]] {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/port-env.json").path) { break }
            root.deleteLastPathComponent()
        }
        let cases = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf:
            root.appendingPathComponent("tool/fixtures/compatibility/port-env.json"))) as? [[String: Any]])
        XCTAssertEqual(cases.count, 8)
        return cases
    }

    func testSharedPortEnvironmentAliasesFreezeActualListenersWithoutChangingSource() throws {
        for item in try portEnvironmentCorpus() {
            let name = try XCTUnwrap(item["name"] as? String)
            let value = try XCTUnwrap(item["value"] as? String)
            let environment = try XCTUnwrap(item["environment"] as? [String: String])
            let input: [String: Any] = ["protocol": "socks", "listen": "127.0.0.1", "port": value,
                "settings": ["auth": "password", "accounts": [["user": "caller", "pass": "caller-password"]]]]
            let source = try JSONSerialization.data(withJSONObject: ["inbounds": [input]], options: [.sortedKeys])
            if item["invalid"] as? Bool == true {
                XCTAssertThrowsError(try XrayPortSpec.reservedPorts(value, environment: { environment[$0] }), name)
                XCTAssertThrowsError(try LocalProxyAccessPolicy.bindingPortEnvironment(configData: source, environment: environment), name)
            } else {
                let ports = try XCTUnwrap(item["ports"] as? [Int])
                do {
                    XCTAssertEqual(try XrayPortSpec.reservedPorts(value, environment: { environment[$0] }), Set(ports), name)
                    let bound = try LocalProxyAccessPolicy.bindingPortEnvironment(configData: source, environment: environment)
                    let config = try XCTUnwrap(JSONSerialization.jsonObject(with: bound) as? [String: Any])
                    let actual = try XCTUnwrap((config["inbounds"] as? [[String: Any]])?.first)
                    var expected = input; expected["port"] = ports.map(String.init).joined(separator: ",")
                    XCTAssertEqual(actual as NSDictionary, expected as NSDictionary, name)
                    XCTAssertEqual(try LocalProxyAccessPolicy.bindingPortEnvironment(configData: bound, environment: [:]), bound, name)
                } catch { XCTFail("\(name): valid Core environment alias was rejected: \(error)") }
            }
            let original = try XCTUnwrap(JSONSerialization.jsonObject(with: source) as? [String: Any])
            XCTAssertEqual((original["inbounds"] as? [[String: Any]])?.first as? NSDictionary, input as NSDictionary, name)
        }
    }

    func testSharedEnvironmentAliasesAlsoBindAddressesWithExactEmptyPrecedence() throws {
        for item in try portEnvironmentCorpus() {
            let name = try XCTUnwrap(item["name"] as? String)
            let value = try XCTUnwrap(item["value"] as? String)
            let portsEnvironment = try XCTUnwrap(item["environment"] as? [String: String])
            let environment = portsEnvironment.mapValues { value in
                value.isEmpty ? "" : "[ 127.0.0.\(Int(value)! - 10800) ]"
            }
            let expected = (item["ports"] as? [Int])?.first.map { "[ 127.0.0.\($0 - 10800) ]" } ?? ""
            do {
                XCTAssertEqual(try LocalProxyAccessPolicy.bindingAddressEnvironment(value, environment: environment), expected, name)
                let source = try JSONSerialization.data(withJSONObject: ["inbounds": [["protocol": "socks", "listen": value, "port": 10808]]], options: [.sortedKeys])
                let bound = try LocalProxyAccessPolicy.bindingPortEnvironment(configData: source, environment: environment)
                let config = try XCTUnwrap(JSONSerialization.jsonObject(with: bound) as? [String: Any])
                XCTAssertEqual((config["inbounds"] as? [[String: Any]])?.first?["listen"] as? String, expected, name)
                let original = try XCTUnwrap(JSONSerialization.jsonObject(with: source) as? [String: Any])
                XCTAssertEqual((original["inbounds"] as? [[String: Any]])?.first?["listen"] as? String, value, name)
            } catch { XCTFail("\(name): valid Core address environment lookup was rejected: \(error)") }
        }
    }

    func testGoWhitespaceAndSimpleUppercaseAreSharedWithoutTrimmingAddressPrefix() throws {
        let cases = [("\u{0085}fixture.ß.port\u{3000}", "FIXTURE_ß_PORT"),
                     ("\u{001c}fixture.port", "\u{001c}FIXTURE_PORT"),
                     ("\u{feff}fixture.port", "\u{feff}FIXTURE_PORT")]
        for (name, alias) in cases {
            do {
                XCTAssertEqual(try XrayPortSpec.reservedPorts("\u{0085}env:" + name,
                    environment: { $0 == alias ? "10807" : nil }), [10807])
                XCTAssertEqual(try LocalProxyAccessPolicy.bindingAddressEnvironment("env:" + name,
                    environment: [alias: "127.0.0.1"]), "127.0.0.1")
            } catch { XCTFail("Go whitespace/simple-uppercase lookup was rejected: \(error)") }
        }
        XCTAssertEqual(try LocalProxyAccessPolicy.bindingAddressEnvironment(" env:fixture.port",
            environment: ["FIXTURE_PORT": "127.0.0.1"]), " env:fixture.port")
    }

    func testEnvironmentUnixListenerIsFrozenBeforePersistenceAndPortAllocation() throws {
        let input: [String: Any] = ["protocol": "socks", "listen": "env:flutter.vless.fixture.listen", "port": "0-65535", "settings": ["auth": "password", "accounts": [["user": "caller", "pass": "caller-password"]]], "sniffing": ["enabled": true, "routeOnly": false]]
        let source = try JSONSerialization.data(withJSONObject: ["inbounds": [input]], options: [.sortedKeys])
        for address in ["/tmp/flutter-vless-env-listen.sock", "@flutter-vless-env-listen"] {
            let bound = try LocalProxyAccessPolicy.bindingPortEnvironment(configData: source, environment: ["flutter.vless.fixture.listen": address])
            var config = try XCTUnwrap(JSONSerialization.jsonObject(with: bound) as? [String: Any])
            let preparedInput = try XCTUnwrap((config["inbounds"] as? [[String: Any]])?.first)
            var expected = input; expected["listen"] = address
            XCTAssertEqual(preparedInput as NSDictionary, expected as NSDictionary)
            XCTAssertEqual(try LocalProxyAccessPolicy.bindingPortEnvironment(configData: bound, environment: [:]), bound)
            let privatePort = try LocalProxyAccessPolicy.applyVPN(to: &config, credentials: LocalProxyCredentials(username: "private", password: "private-password"))
            XCTAssertEqual(privatePort, 10808)
            XCTAssertEqual(((config["inbounds"] as? [[String: Any]])?[1]) as? NSDictionary, expected as NSDictionary)
        }
        let original = try XCTUnwrap(JSONSerialization.jsonObject(with: source) as? [String: Any])
        XCTAssertEqual(((original["inbounds"] as? [[String: Any]])?.first)?["listen"] as? String, "env:flutter.vless.fixture.listen")
    }

    func testListenerEnvironmentExactAliasEmptyMissingAndNonrecursiveSemantics() throws {
        let cases: [(String, [String: String], String)] = [
            ("127.0.0.1", [:], "127.0.0.1"),
            ("env: listen.fixture ", ["LISTEN_FIXTURE": "127.0.0.1"], "127.0.0.1"),
            ("env:listen.fixture", ["listen.fixture": "", "LISTEN_FIXTURE": "/tmp/unused.sock"], ""),
            ("env:listen.fixture", [:], "")
        ]
        for (listen, environment, expected) in cases {
            let source = try JSONSerialization.data(withJSONObject: ["inbounds": [["protocol": "socks", "listen": listen, "port": 10808]]], options: [.sortedKeys])
            let bound = try LocalProxyAccessPolicy.bindingPortEnvironment(configData: source, environment: environment)
            var config = try XCTUnwrap(JSONSerialization.jsonObject(with: bound) as? [String: Any])
            XCTAssertEqual(((config["inbounds"] as? [[String: Any]])?.first)?["listen"] as? String, expected)
            XCTAssertEqual(try LocalProxyAccessPolicy.applyVPN(to: &config, credentials: LocalProxyCredentials(username: "private", password: "private-password")), 10809)
            if listen == expected { XCTAssertEqual(bound, source) }
        }
        let nested = try JSONSerialization.data(withJSONObject: ["inbounds": [["protocol": "socks", "listen": "env:FIRST", "port": 10808]]])
        XCTAssertThrowsError(try LocalProxyAccessPolicy.bindingPortEnvironment(configData: nested, environment: ["FIRST": "env:SECOND", "SECOND": "/tmp/must-not-be-used.sock"]))
    }

    func testSharedListenerAddressEnvironmentCorpus() throws {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/listen-addresses.json").path) { break }
            root.deleteLastPathComponent()
        }
        let cases = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("tool/fixtures/compatibility/listen-addresses.json"))) as? [[String: Any]])
        for item in cases {
            let listen = try XCTUnwrap(item["listen"] as? String)
            let port = try XCTUnwrap(item["port"])
            let environment = try XCTUnwrap(item["environment"] as? [String: String])
            let source = try JSONSerialization.data(withJSONObject: ["inbounds": [["protocol": "socks", "listen": listen, "port": port]]], options: [.sortedKeys])
            if item["invalid"] as? Bool == true {
                XCTAssertThrowsError(try LocalProxyAccessPolicy.bindingPortEnvironment(configData: source, environment: environment))
                continue
            }
            let bound = try LocalProxyAccessPolicy.bindingPortEnvironment(configData: source, environment: environment)
            var config = try XCTUnwrap(JSONSerialization.jsonObject(with: bound) as? [String: Any])
            XCTAssertEqual(((config["inbounds"] as? [[String: Any]])?.first)?["listen"] as? String, item["resolved"] as? String)
            let privatePort = try LocalProxyAccessPolicy.applyVPN(to: &config, credentials: LocalProxyCredentials(username: "private", password: "private-password"))
            XCTAssertEqual(privatePort, item["unix"] as? Bool == true ? 10808 : 10810)
            XCTAssertEqual(try LocalProxyAccessPolicy.bindingPortEnvironment(configData: bound, environment: [:]), bound)
            let original = try XCTUnwrap(JSONSerialization.jsonObject(with: source) as? [String: Any])
            XCTAssertEqual(((original["inbounds"] as? [[String: Any]])?.first)?["listen"] as? String, listen)
        }
    }

    func testEffectiveUnixListenerClassificationUsesCoreBracketsThenWhitespace() throws {
        let addresses = [" \u{0085}/tmp/flutter-vless-listen.sock\u{00a0}", "[/tmp/flutter-vless-listen.sock]", "[ \u{0085}@flutter-vless-listen\u{00a0} ]"]
        for address in addresses {
            let source = try JSONSerialization.data(withJSONObject: ["inbounds": [["protocol": "socks", "listen": "env:FIXTURE", "port": "0-65535"]]])
            let bound = try LocalProxyAccessPolicy.bindingPortEnvironment(configData: source, environment: ["FIXTURE": address])
            var config = try XCTUnwrap(JSONSerialization.jsonObject(with: bound) as? [String: Any])
            XCTAssertEqual(((config["inbounds"] as? [[String: Any]])?.first)?["listen"] as? String, address)
            let privatePort = try LocalProxyAccessPolicy.applyVPN(to: &config, credentials: LocalProxyCredentials(username: "private", password: "private-password"))
            XCTAssertEqual(privatePort, 10808)
        }
    }

    func testUnicodeListenerEnvironmentUsesSimpleAliasAndNeverFullUppercaseExpansion() throws {
        let source = try JSONSerialization.data(withJSONObject: ["inbounds": [["protocol": "socks", "listen": "env:listen.ß", "port": "0-65535"]]])
        let absent = try LocalProxyAccessPolicy.bindingPortEnvironment(configData: source, environment: ["LISTEN_SS": "127.0.0.1"])
        let missing = try XCTUnwrap(JSONSerialization.jsonObject(with: absent) as? [String: Any])
        XCTAssertEqual(((missing["inbounds"] as? [[String: Any]])?.first)?["listen"] as? String, "")
        let path = "/tmp/flutter-vless-unicode-env-listen.sock"
        let simple = try LocalProxyAccessPolicy.bindingPortEnvironment(configData: source, environment: ["LISTEN_ß": path, "LISTEN_SS": "127.0.0.1"])
        let simpleConfig = try XCTUnwrap(JSONSerialization.jsonObject(with: simple) as? [String: Any])
        XCTAssertEqual(((simpleConfig["inbounds"] as? [[String: Any]])?.first)?["listen"] as? String, path)
        let bound = try LocalProxyAccessPolicy.bindingPortEnvironment(configData: source, environment: ["listen.ß": path, "LISTEN_ß": "127.0.0.2", "LISTEN_SS": "127.0.0.1"])
        var config = try XCTUnwrap(JSONSerialization.jsonObject(with: bound) as? [String: Any])
        XCTAssertEqual(((config["inbounds"] as? [[String: Any]])?.first)?["listen"] as? String, path)
        let privatePort = try LocalProxyAccessPolicy.applyVPN(to: &config, credentials: LocalProxyCredentials(username: "private", password: "private-password"))
        XCTAssertEqual(privatePort, 10808)
    }

    func testSharedNumericMetricsListenerCorpusWithoutResolvingNamesOrChangingSource() throws {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/metrics-listeners.json").path) { break }
            root.deleteLastPathComponent()
        }
        let cases = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf:
            root.appendingPathComponent("tool/fixtures/compatibility/metrics-listeners.json"))) as? [[String: Any]])
        for item in cases {
            let config = try XCTUnwrap(item["config"] as? [String: Any])
            let before = try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])
            XCTAssertEqual(XrayPortSpec.serviceListenerPorts(configuration: config), Set(item["ports"] as? [Int] ?? []), item["name"] as? String ?? "")
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys]), before)
        }
    }

    func testPrivateAdapterAvoidsBothManagementServicesAndImportedPorts() throws {
        let api: [String: Any] = ["tag": "caller-api", "listen": "127.0.0.1:10808", "services": ["StatsService"]]
        let metrics: [String: Any] = ["tag": "caller-metrics", "Liſten": "127.0.0.1:+10809"]
        var config: [String: Any] = ["api": api, "Metricſ": metrics,
            "inbounds": [["protocol": "http", "port": "10810-10811"]]]
        let port = try LocalProxyAccessPolicy.applyVPN(to: &config,
            credentials: LocalProxyCredentials(username: "native-user", password: "native-password"))
        XCTAssertEqual(port, 10812)
        XCTAssertEqual(config["api"] as? NSDictionary, api as NSDictionary)
        XCTAssertEqual(config["Metricſ"] as? NSDictionary, metrics as NSDictionary)
        XCTAssertEqual(((config["inbounds"] as? [[String: Any]])?[1]["port"]) as? String, "10810-10811")
    }

    func testSharedNumericAPIListenerCorpusWithoutResolvingNamesOrChangingSource() throws {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/api-listeners.json").path) { break }
            root.deleteLastPathComponent()
        }
        let cases = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf:
            root.appendingPathComponent("tool/fixtures/compatibility/api-listeners.json"))) as? [[String: Any]])
        for item in cases {
            let config = try XCTUnwrap(item["config"] as? [String: Any])
            let before = try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])
            XCTAssertEqual(XrayPortSpec.apiListenerPorts(configuration: config), Set(item["ports"] as? [Int] ?? []), item["name"] as? String ?? "")
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys]), before)
        }
    }

    func testPrivateAdapterAvoidsAPIAlongsideImportedPortRangesAndPreservesAPI() throws {
        let api: [String: Any] = ["tag": "caller-api", "listen": "127.0.0.1:10808", "services": ["StatsService", "HandlerService"]]
        var config: [String: Any] = ["api": api, "inbounds": [["protocol": "http", "port": "10809-10810"]]]
        let port = try LocalProxyAccessPolicy.applyVPN(to: &config,
            credentials: LocalProxyCredentials(username: "native-user", password: "native-password"))
        XCTAssertEqual(port, 10811)
        XCTAssertEqual(config["api"] as? NSDictionary, api as NSDictionary)
        XCTAssertEqual(((config["inbounds"] as? [[String: Any]])?[1]["port"]) as? String, "10809-10810")
    }

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
