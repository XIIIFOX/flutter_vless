import XCTest
import Darwin
@testable import flutter_vless_macos_tunnel_support

final class LocalProxyAccessPolicyTests: XCTestCase {
    private let credentials = try! LocalProxyCredentials(username: "session-user", password: "session-password")

    func testSessionRotationAndRecoveryLeaveRemoteSecretsUntouched() throws {
        let one = try LocalProxyCredentials.generate()
        let two = try LocalProxyCredentials.generate()
        XCTAssertNotEqual(one, two)
        XCTAssertEqual(one.password.count, 64)
        XCTAssertEqual(one.username.count, 32)
        XCTAssertTrue(one.password.allSatisfy { $0.isHexDigit })
        let remote: [String: Any] = ["protocol": "socks", "settings": ["servers": [["address": "remote.invalid",
            "users": [["user": "remote-user", "pass": "remote-password", "id": "remote-id", "key": "remote-key"]]]]]]
        var config: [String: Any] = ["inbounds": [["listen": "127.0.0.1", "port": 1080, "protocol": "socks"]], "outbounds": [remote]]
        let original = try JSONSerialization.data(withJSONObject: config, options: .sortedKeys)
        try LocalProxyAccessPolicy.applyVPN(to: &config, credentials: one)
        let first = try JSONSerialization.data(withJSONObject: config, options: .sortedKeys)
        try LocalProxyAccessPolicy.applyVPN(to: &config, credentials: one)
        XCTAssertEqual(first, try JSONSerialization.data(withJSONObject: config, options: .sortedKeys))
        XCTAssertEqual((config["outbounds"] as! NSArray), [remote] as NSArray)
        XCTAssertFalse(String(decoding: original, as: UTF8.self).contains(one.password))
        XCTAssertFalse(String(reflecting: one).contains(one.password))
        try LocalProxyAccessPolicy.applyVPN(to: &config, credentials: two)
        let serialized = String(decoding: try JSONSerialization.data(withJSONObject: config), as: UTF8.self)
        XCTAssertFalse(serialized.contains(one.password))
        XCTAssertTrue(serialized.contains(two.password))
    }

    func testCaseInsensitiveLocalFieldsCannotBypassPolicy() throws {
        var config: [String: Any] = ["Inbounds": [["Listen": "::1", "Port": 1080, "Protocol": "socks",
            "Settings": ["Auth": "noauth", "Accounts": [["User": "old", "Pass": "old"]], "UDP": false]]]]
        try LocalProxyAccessPolicy.applyVPN(to: &config, credentials: credentials)
        let inbound = (config["inbounds"] as! [[String: Any]])[0]
        XCTAssertEqual(inbound["listen"] as? String, "127.0.0.1")
        let settings = inbound["settings"] as! [String: Any]
        XCTAssertEqual(settings["auth"] as? String, "password")
        XCTAssertEqual(settings["udp"] as? Bool, true)
        XCTAssertEqual(settings["ip"] as? String, "127.0.0.1")
        XCTAssertEqual(settings["accounts"] as? [[String: String]], [["user": credentials.username, "pass": credentials.password]])
        XCTAssertNil(config["Inbounds"])
    }

    func testGoUnicodeFieldAliasesCannotOverrideManagedAuthentication() throws {
        XCTAssertTrue(XrayJSONField.matches("KeyLogPath", "keyLogPath"))
        XCTAssertFalse(XrayJSONField.matches("paß", "pass"))
        XCTAssertFalse(XrayJSONField.matches("lısten", "listen"))
        let aliasOnly = Data(#"{"inboundſ":[{"protocol":"socks","port":1080,"liſten":"127.0.0.1","\u017Fettings":{"auth":"noauth","accountſ":[{"uſer":"old","paſſ":"old"}]}}]}"#.utf8)
        var config = try LocalProxyAccessPolicy.normalizedConfig(configData: aliasOnly)
        try LocalProxyAccessPolicy.applyVPN(to: &config, credentials: credentials)
        let inbound = try XCTUnwrap((config["inbounds"] as? [[String: Any]])?.first)
        let settings = try XCTUnwrap(inbound["settings"] as? [String: Any])
        XCTAssertEqual(settings["auth"] as? String, "password")
        XCTAssertEqual(settings["accounts"] as? [[String: String]], [["user": credentials.username, "pass": credentials.password]])
        XCTAssertNil(inbound["ſettings"])
        XCTAssertNil(inbound["liſten"])
        XCTAssertNil(settings["accountſ"])
        for source in [
            #"{"inbounds":[{"protocol":"socks","port":1080,"settings":{},"ſettings":{"auth":"noauth"}}]}"#,
            #"{"inbounds":[{"protocol":"socks","port":1080,"listen":"127.0.0.1","liſten":"0.0.0.0"}]}"#,
            #"{"inbounds":[{"protocol":"socks","port":1080,"settings":{"accounts":[],"accountſ":[]}}]}"#,
            #"{"inbounds":[],"inboundſ":[]}"#
        ] {
            XCTAssertThrowsError(try LocalProxyAccessPolicy.validateVPN(configData: Data(source.utf8)))
        }
        let arbitrary = Data(#"{"outbounds":[{"protocol":"socks","settings":{"servers":[{"address":"remote.invalid","users":[{"user":"ſKı","pass":"paß"}]}]}}]}"#.utf8)
        XCTAssertEqual(try LocalProxyAccessPolicy.normalizedConfig(configData: arbitrary) as NSDictionary,
                       try JSONSerialization.jsonObject(with: arbitrary) as? NSDictionary)
    }

    func testAmbiguousFieldsAndIncompatibleExtraListenersRejectBeforeMutation() throws {
        let socks: [String: Any] = ["protocol": "socks", "port": 1080, "listen": "127.0.0.1"]
        for extra in [["protocol": "socks", "port": 1081], ["protocol": "http", "port": 8080]] as [[String: Any]] {
            let config: [String: Any] = ["inbounds": [socks, extra]]
            XCTAssertThrowsError(try LocalProxyAccessPolicy.validateVPN(configData: JSONSerialization.data(withJSONObject: config)))
        }
        for field in ["listen", "port", "protocol", "settings"] {
            var ambiguous = socks
            ambiguous[field.uppercased()] = ambiguous[field] ?? ["auth": "noauth"]
            ambiguous[field] = ambiguous[field] ?? ["auth": "noauth"]
            XCTAssertThrowsError(try LocalProxyAccessPolicy.validateVPN(configData: JSONSerialization.data(withJSONObject: ["inbounds": [ambiguous]])))
        }
        for field in ["auth", "accounts", "udp", "ip"] {
            var inbound = socks
            inbound["settings"] = [field: "x", field.uppercased(): "y"]
            XCTAssertThrowsError(try LocalProxyAccessPolicy.validateVPN(configData: JSONSerialization.data(withJSONObject: ["inbounds": [inbound]])))
        }
        for listen in ["0.0.0.0", "::", "192.168.1.1", "/tmp/custom.sock"] {
            var inbound = socks
            inbound["listen"] = listen
            XCTAssertThrowsError(try LocalProxyAccessPolicy.validateVPN(configData: JSONSerialization.data(withJSONObject: ["inbounds": [inbound]])))
        }
        for port: Any in [true, 0, 65536, 1080.5, "1080"] {
            var inbound = socks
            inbound["port"] = port
            XCTAssertThrowsError(try LocalProxyAccessPolicy.validateVPN(configData: JSONSerialization.data(withJSONObject: ["inbounds": [inbound]])))
        }
        XCTAssertThrowsError(try LocalProxyAccessPolicy.validateVPN(configData: Data("{\"inbounds\":[],\"INBOUNDS\":[]}".utf8)))
    }

    func testCredentialsRejectWireTruncationAndControlCharacters() throws {
        for password in ["", String(repeating: "a", count: 256), "line\nbreak", "null\0byte"] {
            XCTAssertThrowsError(try LocalProxyCredentials(username: "user", password: password))
        }
        XCTAssertEqual(Array(credentials.socksAuthenticationRequest).prefix(2), [1, 12])
    }

    func testMissingInboundsMayBeInsertedByProxyRunnersButVPNStillRejects() throws {
        let input = Data("{\"outbounds\":[{\"protocol\":\"freedom\"}]}".utf8)
        let normalized = try LocalProxyAccessPolicy.normalizedConfig(configData: input)
        XCTAssertNil(normalized["inbounds"])
        XCTAssertThrowsError(try LocalProxyAccessPolicy.validateVPN(configData: input))
        for value: Any in [NSNull(), "bad", 1, ["protocol": "socks"], ["not-an-object"]] {
            let malformed = try JSONSerialization.data(withJSONObject: ["Inbounds": value])
            XCTAssertThrowsError(try LocalProxyAccessPolicy.normalizedConfig(configData: malformed))
        }
        let empty = try LocalProxyAccessPolicy.normalizedConfig(configData: Data("{\"Inbounds\":[]}".utf8))
        XCTAssertEqual((empty["inbounds"] as? [[String: Any]])?.count, 0)
        XCTAssertThrowsError(try LocalProxyAccessPolicy.validateVPN(configData: Data("{\"inbounds\":[]}".utf8)))
    }

    func testSOCKSRequiresExactMethodAndAuthenticationResponses() throws {
        for reply: [UInt8] in [[5, 0], [5, 255], [4, 2]] {
            var sockets: [Int32] = [0, 0]
            XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
            defer { sockets.forEach { close($0) } }
            XCTAssertTrue(LocalSOCKS5Client.sendAll(fd: sockets[1], bytes: reply))
            XCTAssertFalse(LocalSOCKS5Client.authenticate(fd: sockets[0], credentials: credentials))
            XCTAssertEqual(LocalSOCKS5Client.receiveExactly(fd: sockets[1], count: 3), [5, 1, 2])
            var byte: UInt8 = 0
            XCTAssertEqual(recv(sockets[1], &byte, 1, MSG_DONTWAIT), -1, "No retry or credentials sent for a rejected method")
        }
        for (reply, expected) in [([5, 2, 1, 0], true), ([5, 2, 1, 1], false), ([5, 2, 2, 0], false)] {
            var sockets: [Int32] = [0, 0]
            XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
            defer { sockets.forEach { close($0) } }
            for byte in reply { XCTAssertTrue(LocalSOCKS5Client.sendAll(fd: sockets[1], bytes: [UInt8(byte)])) }
            XCTAssertEqual(LocalSOCKS5Client.authenticate(fd: sockets[0], credentials: credentials), expected)
            XCTAssertEqual(LocalSOCKS5Client.receiveExactly(fd: sockets[1], count: 3), [5, 1, 2])
            XCTAssertEqual(LocalSOCKS5Client.receiveExactly(fd: sockets[1], count: credentials.socksAuthenticationRequest.count), Array(credentials.socksAuthenticationRequest))
        }
    }

    func testClosingRuntimeDuringGreetingDoesNotRaiseSIGPIPE() {
        var sockets: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        close(sockets[1])
        defer { close(sockets[0]) }
        XCTAssertFalse(LocalSOCKS5Client.authenticate(fd: sockets[0], credentials: credentials))
    }
}
